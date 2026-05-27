from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.control.auth_routes import router as auth_router
from app.api.control.user_routes import router as user_router
from app.api.data.kb_routes import router as kb_router
from app.api.integrations.jira_routes import router as jira_router
from app.api.health import router as health_router
from app.config import settings
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Startup: verify DB connection
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        pass  # Allow app to start even if DB is not yet available
    yield
    # Shutdown: dispose engine
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="GSL Centinel",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)
    app.include_router(user_router)
    app.include_router(kb_router)
    app.include_router(jira_router)
    app.include_router(health_router)

    return app


app = create_app()
