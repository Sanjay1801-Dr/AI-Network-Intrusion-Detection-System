# API Rate Limiting & Abuse Protection Specification

> **Capability Level:** Application-Level API Abuse Protection  
> **Layer:** FastAPI ASGI Application Layer (`slowapi` + in-memory token bucket / sliding window)  
> **Target Scope:** Threat classification inference, brute-force mitigation, read query bounding, mutation protection

---

## 1. Overview & Threat Model

Application-level rate limiting is implemented in the AI-Based Network Intrusion Detection System (NIDS) to protect backend services against accidental traffic bursts, automated credential guessing, denial-of-service attempts targeting high-computation ML prediction pipelines, and database query exhaustion.

### What Application-Level Rate Limiting Mitigates:
- **Credential Stuffing & Login Brute-Force:** Prevents rapid automated password guessing against `POST /api/v1/auth/login`.
- **Inference Flooding:** Restricts high-frequency execution of dual-stage machine learning inference (Isolation Forest + Random Forest feature extraction and matrix transformations) on `POST /api/v1/predict`.
- **Query Overload:** Bounds paginated database access for historical prediction telemetry and alerts (`GET /api/v1/predictions`, `GET /api/v1/alerts`).
- **State Churn & Race Conditions:** Regulates alert lifecycle triage actions (`PATCH /alerts/{id}/acknowledge`, `resolve`).

### Important Security Scope & Limitations:
- **Not a Replacement for WAF / Network DDoS Mitigation:** Application-level rate limiting operates inside the Python process runtime. It cannot absorb high-volume volumetric network floods (e.g., SYN floods, UDP amplification, or multi-gigabit botnet attacks). Edge reverse proxies (e.g., Cloudflare, AWS Shield, Nginx rate-limiting modules, or network firewalls) remain necessary in front of production deployments.
- **Single-Node In-Memory Storage:** The default limiter uses in-memory tracking (`limits.storage.MemoryStorage`). Rate limit counters are tracked per-worker process and reset upon application restart.

---

## 2. Configured Endpoints & Default Limits

| Endpoint | HTTP Method | Target Operation | Default Limit | Purpose |
| :--- | :---: | :--- | :---: | :--- |
| `/api/v1/auth/login` | `POST` | Operator Authentication | `5/minute` | Brute-force and credential-stuffing prevention |
| `/api/v1/predict` | `POST` | AI Flow Telemetry Inference | `60/minute` | Bounds CPU-intensive ML model evaluation |
| `/api/v1/auth/me` | `GET` | Operator Profile & RBAC Claims | `120/minute` | Prevents profile query hammering |
| `/api/v1/predictions` | `GET` | Historical Flow Telemetry Audit | `120/minute` | Prevents database query exhaustion |
| `/api/v1/alerts` | `GET` | Incident Alert Feed | `120/minute` | Protects SOC dashboard query routes |
| `/api/v1/alerts/{id}` | `GET` | Incident Alert Investigation | `120/minute` | Protects detailed record queries |
| `/api/v1/alerts/{id}/acknowledge` | `PATCH` | Alert Lifecycle Mutation | `30/minute` | Protects triage state transitions |
| `/api/v1/alerts/{id}/resolve` | `PATCH` | Alert Lifecycle Mutation | `30/minute` | Protects resolution state transitions |

> **Note on Health Check:** The public health endpoint `GET /api/health` is deliberately exempt from aggressive rate limits to ensure container orchestration health checks (e.g., Docker, Kubernetes, AWS ALB) remain uninterrupted.

---

## 3. Rate Limit Identity Strategy

Client identity resolution is managed by `get_rate_limit_identity(request: Request)` in `backend/app/core/limiter.py`:

```
                       Incoming HTTP Request
                                │
                  Does request include a valid
                  Bearer JWT Authorization token?
                                │
                 ┌──────────────┴──────────────┐
                 │ YES                         │ NO
                 ▼                             ▼
       Extract username from             Extract peer socket
       decoded JWT claims:               client host address:
         "user:<username>"                 "ip:<client_ip>"
                 │                             │
                 └──────────────┬──────────────┘
                                ▼
                   Evaluate rate limit window
```

1. **Authenticated Requests (`user:<username>`):**
   - For all authenticated endpoints, the limiter inspects the valid `Bearer` JWT and keys quotas by the operator's unique username.
   - **Advantage:** Prevents IP collision when multiple analysts share a corporate NAT/proxy IP address. Each operator maintains their individual rate limit quota.
   - **Security:** If an attacker acquires a valid token and rotates source IPs, they remain constrained by the operator's account quota.
2. **Unauthenticated Requests (`ip:<client_ip>`):**
   - For unauthenticated endpoints (specifically `POST /api/v1/auth/login`), quotas are keyed by the direct peer socket IP address (`request.client.host`).
   - **Anti-Spoofing Protection:** Arbitrary client-controlled headers such as `X-Forwarded-For` or `X-Real-IP` are **not trusted by default**. An attacker cannot bypass the 5/minute login limit by rotating fake `X-Forwarded-For` headers.

---

## 4. HTTP 429 Response Format & Headers

When an endpoint exceeds its rate limit threshold, the application returns a standardized, production-safe `HTTP 429 Too Many Requests` envelope.

### JSON Error Envelope:
```json
{
  "detail": "Rate limit exceeded. Please try again later."
}
```

### Response Headers:
The server attaches standard rate-limiting metadata headers without revealing internal filesystem paths or database details:

| Header | Description | Example |
| :--- | :--- | :--- |
| `Retry-After` | Number of seconds until the rate limit window resets | `45` |
| `X-RateLimit-Limit` | Maximum allowed requests within the configured window | `5` |
| `X-RateLimit-Remaining` | Remaining requests permitted in the active window | `0` |
| `X-RateLimit-Reset` | UTC epoch timestamp when the active window resets | `1791052800` |
| `X-Content-Type-Options` | Defensive security header (nosniff) | `nosniff` |
| `X-Frame-Options` | Defensive framing protection | `DENY` |

---

## 5. Environment Configuration

Rate limits are configured through environment variables adhering to 12-factor principles:

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `NIDS_RATE_LIMIT_ENABLED` | Boolean | `true` | Globally enable or disable rate limiting. |
| `NIDS_RATE_LIMIT_LOGIN` | String | `5/minute` | Limit for `POST /api/v1/auth/login`. |
| `NIDS_RATE_LIMIT_PREDICT` | String | `60/minute` | Limit for `POST /api/v1/predict`. |
| `NIDS_RATE_LIMIT_READ` | String | `120/minute` | Limit for `GET` queries (history, alerts, profile). |
| `NIDS_RATE_LIMIT_MUTATION` | String | `30/minute` | Limit for `PATCH` alert lifecycle actions. |

### Production Rules:
- When `NIDS_ENVIRONMENT=production`, setting `NIDS_RATE_LIMIT_ENABLED=false` is **strictly rejected on startup** with a validation error.
- All rate-limit string values are validated on startup against standard rate syntax (e.g. `10/second`, `60/minute`, `1000/hour`). Invalid syntax fails application startup immediately.

---

## 6. Frontend Integration & Error Behavior

The React frontend API service (`frontend/src/services/api.js`) captures `HTTP 429` responses and transforms them into user-friendly notifications:

```javascript
if (status === 429) {
  const message = parsedJson?.detail || 'Rate limit exceeded: Too many requests. Please wait a moment and try again.';
  return new ApiError(message, 429, 'RATE_LIMIT_EXCEEDED');
}
```

- **No Automated Polling:** The frontend does not implement automatic retry loops or `setInterval` hammering when throttled.
- **Operator Notice:** The user receives a clear notification informing them that the rate limit was reached and instructing them to wait before submitting new requests.
