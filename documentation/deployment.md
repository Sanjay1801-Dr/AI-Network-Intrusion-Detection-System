# Production Configuration & Deployment Guide

> **Status:** Deployment-Ready Foundation  
> **Target System:** AI-Based Network Intrusion Detection System (NIDS)  
> **Architecture:** Decoupled FastAPI Backend, React/Vite Frontend, and PostgreSQL/SQLite Database

This document details the deployment-ready foundation of the AI-Based Network Intrusion Detection System (NIDS). It covers local development setup, production configuration parameters, security considerations, and containerized deployment with Docker and Docker Compose.

---

## 1. Local Development Setup

### 1.1 Prerequisites
- **Python**: Version 3.12+
- **Node.js**: Version 20+ LTS
- **Git**

### 1.2 Backend Local Execution
1. Clone the repository and navigate to the project root:
   ```bash
   cd Network_based
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   # Linux / macOS:
   source .venv/bin/activate
   ```
3. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Initialize the development environment file:
   ```bash
   cp .env.example .env
   ```
5. Launch the FastAPI backend using Uvicorn with hot-reloading:
   ```bash
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
6. The backend is accessible at:
   - Base API: `http://127.0.0.1:8000`
   - Health Check: `http://127.0.0.1:8000/api/health`
   - Swagger OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 1.3 Frontend Local Execution
1. Open a separate terminal and navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install frontend dependencies:
   ```bash
   npm install
   ```
3. Optionally configure frontend environment variables:
   ```bash
   cp .env.example .env
   ```
4. Start the Vite development server:
   ```bash
   npm run dev
   ```
5. The React application will be available at:
   - Dashboard URL: `http://127.0.0.1:5173`

---

## 2. Production Configuration

Configuration is managed via environment variables adhering to Twelve-Factor App principles. The backend uses Pydantic Settings with strict validation on startup.

### 2.1 Backend Environment Variables

| Variable | Type | Default (Dev) | Description / Production Rules |
| :--- | :--- | :--- | :--- |
| `NIDS_ENVIRONMENT` | String | `development` | Deployment environment (`development` or `production`). |
| `NIDS_DATABASE_URL` | String | `sqlite:///./network_ids.db` | SQLAlchemy database URL. For production, specify PostgreSQL. |
| `NIDS_JWT_SECRET` | String | `CHANGE_ME_IN_DEVELOPMENT...` | Secret key used to sign and verify HMAC-SHA256 JWT tokens. **In production, must be at least 32 characters and cannot use default placeholders.** |
| `NIDS_JWT_ALGORITHM` | String | `HS256` | Cryptographic signing algorithm. |
| `NIDS_JWT_EXPIRE_MINUTES` | Integer | `480` | Access token lifespan in minutes (default 8 hours). |
| `NIDS_CORS_ORIGINS` | Comma-list | `http://127.0.0.1:5173,...` | Allowed CORS origins. **In production, wildcard (`*`) is strictly forbidden.** |
| `NIDS_HOST` | String | `127.0.0.1` | Binding host address (`0.0.0.0` in Docker). |
| `NIDS_PORT` | Integer | `8000` | Port number (1 to 65535). |
| `NIDS_LOG_LEVEL` | String | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |

### 2.2 Frontend Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | URL | `http://127.0.0.1:8000` | Base URL for FastAPI REST endpoints. In production, points to the reverse proxy domain. |
| `VITE_WS_BASE_URL` | URL | `ws://127.0.0.1:8000/api/v1/ws/monitor` | WebSocket endpoint URL for live security alert streaming. |

> **Security Rule:** Never include secrets, database credentials, or private keys in `frontend/.env` or React code. Only browser-safe public endpoints prefixed with `VITE_` are permissible.

---

## 3. Production Infrastructure Recommendations

For hosting this deployment-ready foundation in a production or staging infrastructure, the following architecture is recommended:

```
                      +-----------------------------+
                      |   Internet / SOC Clients    |
                      +--------------+--------------+
                                     | HTTPS (:443) / WSS (:443)
                                     v
                      +-----------------------------+
                      | Reverse Proxy / TLS Gateway |
                      |    (Nginx / Traefik / ALB)  |
                      +-------+--------------+------+
                              |              |
         / (static web root)  |              | /api/* & /api/v1/ws/*
                              v              v
               +-----------------+     +-----------------+
               | Frontend Bundle |     | FastAPI Backend |
               | (Nginx Alpine)  |     | (Uvicorn / ASGI)|
               +-----------------+     +--------+--------+
                                                |
                               +----------------+----------------+
                               |                                 |
                               v                                 v
                    +--------------------+             +-------------------+
                    | PostgreSQL 16 DB   |             | Pre-trained ML    |
                    | (Persistent Data)  |             | Models (.joblib)  |
                    +--------------------+             +-------------------+
```

### 3.1 Security & Networking Essentials
1. **HTTPS / TLS Termination**: Terminate TLS at the reverse proxy (e.g., Nginx) using valid certificates (Let's Encrypt or corporate CA). Direct unencrypted HTTP traffic to port 80 should redirect to HTTPS.
2. **Secure WebSockets (WSS)**: Ensure the reverse proxy forwards the `Upgrade` and `Connection` headers for WebSocket traffic (`wss://your-domain.com/api/v1/ws/monitor`).
3. **Secret Management**: Inject production credentials (`NIDS_JWT_SECRET`, database passwords) using secrets management tools (e.g., Docker Secrets, HashiCorp Vault, AWS Secrets Manager, or encrypted CI/CD variables).
4. **Production Database**: Replace SQLite with PostgreSQL. Configure connection pooling (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`, `pool_recycle=3600`) as implemented in the database engine layer.
5. **Security Headers**: The backend automatically injects:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: no-referrer`

---

## 4. Docker & Containerized Deployment

The repository includes a multi-container Docker Compose configuration suitable for running a unified deployment stack consisting of:
1. **PostgreSQL 16** (`db`): Relational database with automated health checks and persistent volume storage.
2. **FastAPI Backend** (`backend`): Python 3.12-slim container running the prediction engine, REST APIs, and WebSocket streaming.
3. **React Frontend** (`frontend`): Multi-stage container (Node 20 build -> Nginx Alpine static serving).

### 4.1 Deployment Commands

#### Step 1: Prepare Environment Files
Ensure `.env` exists in the project root:
```bash
cp .env.example .env
```
Ensure `frontend/.env` exists if modifying API endpoints:
```bash
cp frontend/.env.example frontend/.env
```

#### Step 2: Build the Container Images
```bash
docker compose build
```

#### Step 3: Start the Stack
Start all services in detached mode:
```bash
docker compose up -d
```

#### Step 4: Verify Service Health
Check the container status and health:
```bash
docker compose ps
```
Verify the backend operational health endpoint:
```bash
curl http://127.0.0.1:8000/api/health
```
Expected JSON response:
```json
{
  "status": "healthy",
  "service": "Network Intrusion Detection System API",
  "version": "1.0.0",
  "environment": "development",
  "database": "connected",
  "ml_engine": "loaded"
}
```

#### Step 5: Access the Applications
- **Frontend Dashboard**: Open your browser at `http://127.0.0.1:5173`
- **FastAPI Documentation**: Open `http://127.0.0.1:8000/docs`
- **Backend Health Check**: Open `http://127.0.0.1:8000/api/health`

#### Step 6: Viewing Logs
Follow logs for all containers:
```bash
docker compose logs -f
```
Or view logs for a specific service:
```bash
docker compose logs -f backend
```

#### Step 7: Graceful Shutdown
Stop all containers while preserving database volume data:
```bash
docker compose down
```
To shut down and wipe the database volumes:
```bash
docker compose down -v
```

---

## 5. Security Checklist Before Production Deployment

- [ ] `NIDS_ENVIRONMENT` is set to `production`.
- [ ] `NIDS_JWT_SECRET` has been set to a strong random key (e.g., generated with `openssl rand -hex 32`) and is NOT a default placeholder.
- [ ] `NIDS_DATABASE_URL` points to a secured PostgreSQL instance with strong user credentials.
- [ ] `NIDS_CORS_ORIGINS` explicitly specifies the exact frontend origin(s) and does NOT contain wildcards (`*`).
- [ ] Reverse proxy enforces TLS/SSL (HTTPS and WSS).
- [ ] Operator accounts have strong, unique passwords seeded via backend administrative tools.
- [ ] Regular automated backups are scheduled for the PostgreSQL database volume.
