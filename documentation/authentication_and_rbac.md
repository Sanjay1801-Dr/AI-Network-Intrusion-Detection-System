# Phase 9 — Authentication, Role-Based Access Control (RBAC) & Secure Operator Access

## 1. Executive Summary

Phase 9 establishes a secure authentication and RBAC foundation for the AI-Based Network Intrusion Detection System (NIDS). Prior to Phase 9, all REST APIs and WebSocket real-time telemetry streams operated without client verification. 

With Phase 9, operators must authenticate with cryptographically hashed credentials, obtain a signed JSON Web Token (JWT), and undergo server-side authorization checks prior to reading telemetry or executing state transitions. This development-oriented authentication architecture provides a structured baseline for access control while preserving all existing Phase 1–8 capabilities.

---

## 2. Authentication Architecture

The authentication layer follows standard FastAPI clean architecture patterns, separating concerns across security primitives, schemas, domain models, data access repositories, and application services:

```text
backend/app/
├── core/
│   ├── config.py             # Security parameters (SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES)
│   ├── security.py           # Bcrypt hashing & verification, PyJWT creation & decoding
│   ├── errors.py             # Sanitized UnauthorizedException (401) and ForbiddenException (403)
│   └── dependencies.py       # Reusable FastAPI dependencies (get_current_user, require_role)
├── models/
│   └── user.py               # UserRecord SQLAlchemy model (users table)
├── schemas/
│   └── auth.py               # Pydantic schemas (LoginRequest, UserResponse, TokenResponse, etc.)
├── repositories/
│   └── user_repository.py    # Database queries for user retrieval and persistence
├── services/
│   ├── auth_service.py       # Authentication business logic & password verification
│   └── websocket_manager.py  # Authenticated connection tracker & client role registry
└── api/v1/endpoints/
    ├── auth.py               # REST endpoints (/login, /me, /logout)
    ├── prediction.py         # Protected prediction endpoints (RBAC-enforced)
    ├── alerts.py             # Protected alert triage endpoints (RBAC-enforced)
    └── websocket.py          # Authenticated WebSocket monitor with handshake validation
```

---

## 3. Password Security & Hashing

- **Algorithm**: `bcrypt` (Blowfish-based adaptive key-derivation function) using per-password 128-bit cryptographic salts.
- **Library**: `bcrypt` Python native package.
- **Work Factor**: Standard adaptive cost factor (12 rounds) mitigating brute-force and dictionary attacks.
- **Storage Rules**:
  - Plaintext passwords are never logged, persisted, or returned in API responses.
  - Passwords are never placed into URL query parameters or JWT payloads.
  - User records only store the salted one-way hash string (`$2b$12$...`).
- **Timing Defense**: Password checks use constant-time comparisons (`bcrypt.checkpw`) to prevent timing attack side channels.

---

## 4. JWT Architecture & Token Lifetime

- **Format**: JSON Web Token (RFC 7519).
- **Signing Algorithm**: `HS256` (HMAC using SHA-256).
- **Signing Key**: Configured via `SECURITY_SECRET_KEY` environment variable (defaults to local development secret).
- **Default Lifetime**: Configurable via `ACCESS_TOKEN_EXPIRE_MINUTES` (defaults to 480 minutes / 8 hours for operational shifts).
- **Token Claims**:
  ```json
  {
    "sub": "1",
    "username": "admin",
    "role": "ADMIN",
    "type": "access",
    "iat": 1727957200,
    "exp": 1727986000
  }
  ```
- **Trust Model**: The backend validates token signatures, checks token expiration, and resolves the user ID against the database `users` table to guarantee that the user is active and valid. Client-supplied role claims are never blindly trusted.

---

## 5. Roles & Server-Side Permission Matrix

The system implements three operator tiers tailored to SOC workflows:

| Resource / Action | Method & Endpoint | ADMIN | ANALYST | VIEWER | Unauthenticated |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **System Health** | `GET /api/health` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed (Public) |
| **Operator Login** | `POST /api/v1/auth/login` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed (Public) |
| **Current User Info** | `GET /api/v1/auth/me` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 401 Unauthorized |
| **Operator Logout** | `POST /api/v1/auth/logout` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 401 Unauthorized |
| **AI Flow Prediction** | `POST /api/v1/predict` | ✅ Allowed | ✅ Allowed | ❌ 403 Forbidden | ❌ 401 Unauthorized |
| **Prediction History** | `GET /api/v1/predictions` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 401 Unauthorized |
| **Security Alerts Feed** | `GET /api/v1/alerts` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 401 Unauthorized |
| **Alert Details** | `GET /api/v1/alerts/{id}` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 401 Unauthorized |
| **Acknowledge Alert** | `PATCH /api/v1/alerts/{id}/acknowledge` | ✅ Allowed | ✅ Allowed | ❌ 403 Forbidden | ❌ 401 Unauthorized |
| **Resolve Alert** | `PATCH /api/v1/alerts/{id}/resolve` | ✅ Allowed | ✅ Allowed | ❌ 403 Forbidden | ❌ 401 Unauthorized |
| **WebSocket Telemetry** | `WS /api/v1/ws/monitor` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ❌ 1008 Rejected |

---

## 6. WebSocket Authentication Mechanism

Browser WebSockets do not support custom HTTP headers during connection establishment. To prevent token leakage in URLs, reverse-proxy logs, browser histories, and network traces, **URL query parameter authentication (`?token=...`) is strictly removed and rejected**.

The application-level handshake frame is the **sole authentication mechanism**:

```text
Browser
  ↓ WebSocket connection to ws://127.0.0.1:8000/api/v1/ws/monitor
Server accepts socket in unverified state
  ↓
Browser sends initial handshake frame within 5 seconds:
{"type": "auth", "token": "<JWT_ACCESS_TOKEN>"}
  ↓
Server validates token & checks user in database
  ↓
Authenticated connection established (connection_established event)
```

- **Rejection & Error Code**:
  - Missing authentication frame within 5 seconds: Closed with code `1008 (Policy Violation)`.
  - Invalid token / expired token: Closed with code `1008 (Policy Violation)`.
  - Attempting query parameter authentication (`?token=...`) without sending a valid handshake frame: Closed with code `1008 (Policy Violation)`.
- **Server Push Only**: The WebSocket connection serves exclusively as a telemetry broadcast stream; arbitrary client command frames are ignored.

---

## 7. Frontend Integration & Route Protection

### Architecture
- **`AuthContext.jsx`**: Centralized React Context providing session state (`user`, `token`, `role`, `isAuthenticated`, `isLoading`, `login`, `logout`) across all components.
- **`services/auth.js`**: Manages browser `localStorage` persistence (`nids_access_token`, `nids_user`), token retrieval, and auth change notification dispatch.
- **`services/api.js`**: Intercepts outgoing REST requests, attaching `Authorization: Bearer <token>` automatically. Intercepts HTTP 401 responses, clears session, and notifies context to display the login page without infinite redirect loops.
- **`services/websocket.js`**: Checks authentication before connecting, automatically transmits the auth handshake frame on open, disconnects cleanly upon logout, and reconnects on login with exponential backoff (`1s → 2s → 4s → 8s`). Does not expose tokens in URLs.

### Login Interface
- Standard login form containing only Username, Password, and Sign In action.
- Distinct status states: Loading, Invalid Credentials, Backend Unavailable.
- Zero hardcoded credentials or demo preset buttons in frontend source.

### Role-Based UX Gating
- **Security Alerts**: When logged in as `VIEWER`, the `[Acknowledge]` and `[Resolve]` buttons are hidden in the alert table and replaced with a "Read-only access (Viewer)" badge in the incident investigation modal.
- **AI Prediction**: When logged in as `VIEWER`, the prediction submission button is disabled with an explanatory tooltip indicating that Analyst or Admin privileges are required.
- **Security Note**: Frontend gating is exclusively for UX clarity; backend server-side authorization dependency checks (`require_role`) strictly reject unauthorized requests with HTTP 403 Forbidden.

---

## 8. Development User Provisioning

An idempotent CLI provisioning script is provided for local development:

```bash
# Provision single user:
python -m backend.scripts.create_admin --username admin --role ADMIN

# Seed all development roles using environment variables:
python -m backend.scripts.create_admin --seed-all-dev-users
```

Credentials must be supplied securely via environment variables or interactive prompts:

| Environment Variable | Description |
| :--- | :--- |
| `NIDS_ADMIN_USERNAME` | Admin username (default: `admin`) |
| `NIDS_ADMIN_PASSWORD` | Password for Admin account |
| `NIDS_ANALYST_USERNAME` | Analyst username (default: `analyst`) |
| `NIDS_ANALYST_PASSWORD` | Password for Analyst account |
| `NIDS_VIEWER_USERNAME` | Viewer username (default: `viewer`) |
| `NIDS_VIEWER_PASSWORD` | Password for Viewer account |

### Idempotency Behavior
- If an account already exists in the database, the script skips it without overwriting its password or resetting its role.
- If an account does not exist, it is created using the provided password and stored as a salted `bcrypt` hash.
- No default or real passwords are coded into source repositories.

---

## 9. Verification & Automated Testing

### Test Suite Summary
- Total Tests: **89 passing** (0 failures, 0 regressions).
- Execution Time: ~20 seconds.
- Baseline Phase 1–8 tests (70 tests): Maintained with dependency override fixtures.
- Phase 9 Authentication & RBAC tests (19 tests):
  - Valid user credential login (`POST /api/v1/auth/login`)
  - Invalid password / nonexistent user rejection (401)
  - Inactive user rejection (401)
  - Missing credentials validation (422)
  - User identity resolution (`GET /api/v1/auth/me`)
  - Unauthenticated access rejection (401)
  - Expired / malformed token rejection (401)
  - Logout endpoint (`POST /api/v1/auth/logout`)
  - Prediction endpoint RBAC (Admin/Analyst allowed, Viewer rejected with 403)
  - Alert lifecycle triage RBAC (Admin/Analyst allowed, Viewer rejected with 403)
  - WebSocket unauthenticated rejection (code 1008)
  - WebSocket invalid auth frame rejection (code 1008)
  - WebSocket expired token rejection (code 1008)
  - WebSocket authenticated via handshake frame
  - WebSocket query parameter authentication rejected (code 1008)

### Production Frontend Build
- Tool: Vite v5.4.21
- Modules transformed: 1,499 modules
- Compilation errors: 0 errors
- Zero hardcoded passwords or preset credentials in frontend assets.

---

## 10. Security Limitations & Production Recommendations

This is a development-oriented deployment. For production deployments, the following infrastructure measures must be enacted:

1. **Transport Layer Security (TLS)**: HTTPS and WSS must be terminated to protect JWTs and credentials in transit.
2. **Secret Management**: `SECURITY_SECRET_KEY` must be injected via a secure secrets manager rather than local environment files.
3. **Token Revocation / Blacklisting**: In distributed clusters, implement a token revocation list or refresh token rotation pattern.
4. **Login Rate Limiting**: Deploy rate limiting (e.g., slowapi / Redis token bucket) on `/api/v1/auth/login` to mitigate brute-force attempts.
5. **Multi-Factor Authentication (MFA)**: Integrate TOTP-based 2FA for privileged operators.
