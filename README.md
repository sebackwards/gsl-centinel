# GSL Centinel

LLM-powered security code review platform.

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose

### 1. Start infrastructure

```bash
docker compose up -d
```

This starts PostgreSQL 16 (with pgvector) and Redis 7.

### 2. Install backend dependencies

```bash
cd backend
pip install -e ".[dev]"
```

### 3. Run the API server

```bash
uvicorn app.main:app --reload
```

The API is available at http://localhost:8000.

### 4. Run tests

```bash
cd backend
pytest
```

## Project Structure

```
backend/
├── app/
│   ├── api/          # Route handlers
│   ├── auth/         # JWT, API keys, RBAC
│   ├── db/           # Database session
│   ├── models/       # SQLAlchemy models
│   ├── schemas/      # Pydantic schemas
│   ├── services/     # Business logic
│   ├── config.py     # Settings
│   └── main.py       # App factory
├── tests/
└── pyproject.toml
```

## API Endpoints

- `POST /auth/login` — Authenticate
- `POST /auth/refresh` — Refresh token
- `GET /admin/users` — List users (admin)
- `POST /admin/users` — Create user (admin)
- `GET /admin/users/{id}` — Get user (admin)
- `PUT /admin/users/{id}` — Update user (admin)
- `DELETE /admin/users/{id}` — Soft delete (admin)
- `GET /health` — Health check
