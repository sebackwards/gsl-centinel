import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.auth.jwt import create_access_token
from app.auth.password import hash_password
from app.db.session import get_db
from app.main import create_app
from app.models.user import Base, User, UserRole
from app.models.kb import KBEntry, KBChunk
from app.models.jira import JiraConfig

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def app(db_session: AsyncSession):
    application = create_app()

    async def override_get_db():
        yield db_session

    application.dependency_overrides[get_db] = override_get_db
    return application


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    user = User(
        id="00000000-0000-0000-0000-000000000001",
        username="admin",
        email="admin@gsl.local",
        hashed_password=hash_password("admin123"),
        role=UserRole.admin,
        is_active=True,
        api_key="admin-api-key-0000000000000000000000000000000000000000",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def editor_user(db_session: AsyncSession) -> User:
    user = User(
        id="00000000-0000-0000-0000-000000000002",
        username="editor",
        email="editor@gsl.local",
        hashed_password=hash_password("editor123"),
        role=UserRole.editor,
        is_active=True,
        api_key="editor-api-key-000000000000000000000000000000000000000",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def consumer_user(db_session: AsyncSession) -> User:
    user = User(
        id="00000000-0000-0000-0000-000000000003",
        username="consumer",
        email="consumer@gsl.local",
        hashed_password=hash_password("consumer123"),
        role=UserRole.consumer,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def admin_token(admin_user: User) -> str:
    return create_access_token(admin_user.id, admin_user.role.value)


@pytest_asyncio.fixture
async def editor_token(editor_user: User) -> str:
    return create_access_token(editor_user.id, editor_user.role.value)


@pytest_asyncio.fixture
async def consumer_token(consumer_user: User) -> str:
    return create_access_token(consumer_user.id, consumer_user.role.value)


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def mongo_db():
    from unittest.mock import MagicMock

    class MockCursor:
        def __init__(self, results):
            self._results = results

        def sort(self, key, direction=-1):
            try:
                self._results.sort(key=lambda d: d.get(key) or "", reverse=(direction == -1))
            except TypeError:
                pass
            return self

        def limit(self, n):
            self._results = self._results[:n]
            return self

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self._results:
                raise StopAsyncIteration
            return self._results.pop(0)

    class MockCollection:
        def __init__(self):
            self._store: list[dict] = []

        async def create_index(self, *args, **kwargs):
            pass

        async def insert_one(self, doc):
            self._store.append(doc.copy())
            return MagicMock(inserted_id="mock-id")

        def find(self, query=None):
            if query is None:
                query = {}
            results = [doc.copy() for doc in self._store if self._matches(doc, query)]
            return MockCursor(results)

        async def find_one(self, query, sort=None):
            matches = [doc for doc in self._store if self._matches(doc, query)]
            if sort:
                key, direction = sort[0] if isinstance(sort, list) else sort
                try:
                    matches.sort(key=lambda d: d.get(key) or "", reverse=(direction == -1))
                except TypeError:
                    pass
            return matches[0] if matches else None

        async def find_one_and_update(self, query, update, upsert=False, return_document=False):
            for doc in self._store:
                if self._matches(doc, query):
                    self._apply_update(doc, update)
                    return doc
            if upsert:
                new_doc = {}
                if "$setOnInsert" in update:
                    new_doc.update(update["$setOnInsert"])
                if "$set" in update:
                    new_doc.update(update["$set"])
                if "$inc" in update:
                    for k, v in update["$inc"].items():
                        new_doc[k] = new_doc.get(k, 0) + v
                if "$push" in update:
                    for k, v in update["$push"].items():
                        if isinstance(v, dict) and "$each" in v:
                            if k not in new_doc:
                                new_doc[k] = []
                            new_doc[k].extend(v["$each"])
                            if "$slice" in v:
                                new_doc[k] = new_doc[k][v["$slice"]:]
                        else:
                            if k not in new_doc:
                                new_doc[k] = []
                            new_doc[k].append(v)
                self._store.append(new_doc)
                return new_doc
            return None

        def _apply_update(self, doc, update):
            if "$set" in update:
                for k, v in update["$set"].items():
                    doc[k] = v
            if "$inc" in update:
                for k, v in update["$inc"].items():
                    doc[k] = doc.get(k, 0) + v
            if "$push" in update:
                for k, v in update["$push"].items():
                    if isinstance(v, dict) and "$each" in v:
                        if k not in doc:
                            doc[k] = []
                        doc[k].extend(v["$each"])
                        if "$slice" in v:
                            doc[k] = doc[k][v["$slice"]:]
                    else:
                        if k not in doc:
                            doc[k] = []
                        doc[k].append(v)

        async def delete_many(self, query):
            original_len = len(self._store)
            self._store[:] = [d for d in self._store if not self._matches(d, query)]
            return MagicMock(deleted_count=original_len - len(self._store))

        def _matches(self, doc, query):
            for key, value in query.items():
                doc_val = doc.get(key)
                if isinstance(value, dict):
                    for op, op_val in value.items():
                        if op == "$gt":
                            if not (doc_val is not None and doc_val > op_val):
                                return False
                        elif op == "$gte":
                            if not (doc_val is not None and doc_val >= op_val):
                                return False
                        elif op == "$lt":
                            if not (doc_val is not None and doc_val < op_val):
                                return False
                        elif op == "$lte":
                            if not (doc_val is not None and doc_val <= op_val):
                                return False
                        elif op == "$regex":
                            import re
                            if not (doc_val is not None and re.search(op_val, str(doc_val))):
                                return False
                        elif op == "$ne":
                            if doc_val == op_val:
                                return False
                else:
                    if doc_val != value:
                        return False
            return True

    class MockDB:
        def __init__(self):
            self.password_resets = MockCollection()
            self.rate_limits = MockCollection()
            self.user_activity = MockCollection()
            self.webhook_deliveries = MockCollection()
            self.ticket_cache = MockCollection()

    return MockDB()


@pytest_asyncio.fixture(autouse=True)
async def override_mongo(app, mongo_db):
    from unittest.mock import patch
    from app.db.mongo import get_mongo_db

    async def mock_get_mongo_db():
        return mongo_db

    app.dependency_overrides[get_mongo_db] = mock_get_mongo_db

    with patch("app.db.mongo.get_mongo_db", mock_get_mongo_db), \
         patch("app.api.control.auth_routes.get_mongo_db", mock_get_mongo_db):
        yield

    app.dependency_overrides.pop(get_mongo_db, None)
