# Database Layer Documentation

## 1. Structure
- `schema.sql`: Reference standard DDL creating all primary relational entities and performance indexes.
- `seeds/`: Initial test payloads and fixtures for mocking network traffic and alerts during development.

## 2. SQLAlchemy ORM Integration
The SQLAlchemy models in `backend/app/models/entities.py` map directly to the tables defined in `schema.sql`. In Phase 1, the session manager in `backend/app/db/session.py` provides database engine configuration for SQLite and PostgreSQL.

## 3. Migration Guidelines
Future schema migrations (Phase 2+) will utilize **Alembic**:
```bash
alembic init alembic
alembic revision --autogenerate -m "initial_schema"
alembic upgrade head
```
