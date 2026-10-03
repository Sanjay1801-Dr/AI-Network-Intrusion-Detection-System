# Phase 7: Real-Time Security Monitoring Documentation

## 1. Overview & Architecture

Phase 7 implements real-time event-driven security monitoring for the **AI-Based Network Intrusion Detection System (NIDS)**. When network flow telemetry is submitted and successfully committed to the database, notification events are immediately broadcast over WebSockets to connected client dashboards without requiring manual page reloads or REST polling loops.

The database remains the singular source of truth: WebSocket events serve as ephemeral push notifications only, with zero dual-persistence systems.

```
Flow Telemetry Submission (REST POST /api/v1/predict)
                        │
                        ▼
           Machine Learning Dual-Stage Inference
         (Isolation Forest + Random Forest)
                        │
                        ▼
         Atomic Database Persistence Transaction
     (PredictionRecord #ID  [+  AlertRecord #ID])
                        │
                        ▼
                  Commit Succeeded?
                     ├── NO  --> Rollback, Error Response (No WS broadcast)
                     │
                     └── YES --> Return REST 200 Response
                                   │
                                   ├── Broadcast "prediction_created" Event
                                   │              │
                                   │              ▼
                                   │     WebSocket Clients (/api/v1/ws/monitor)
                                   │              │
                                   └── Alert?    ▼
                                        └── YES --> Broadcast "alert_created" Event
```

---

## 2. WebSocket Endpoint & Connection Lifecycle

- **Endpoint:** `/api/v1/ws/monitor`
- **Protocol:** WebSocket (`ws://` for HTTP, `wss://` for HTTPS)
- **Resolved Development URL:** `ws://127.0.0.1:8000/api/v1/ws/monitor`
- **Connection Manager:** [`backend/app/services/websocket_manager.py`](file:///C:/Users/SANJAY%20SK/Desktop/Network_based/backend/app/services/websocket_manager.py)
- **Endpoint Handler:** [`backend/app/api/v1/endpoints/websocket.py`](file:///C:/Users/SANJAY%20SK/Desktop/Network_based/backend/app/api/v1/endpoints/websocket.py)

### Connection Lifecycle:
1. **Client Connection:** Client opens WebSocket connection to `/api/v1/ws/monitor`.
2. **Server Handshake:** Server accepts connection and immediately transmits `connection_established`.
3. **Event Streaming:** Server pushes `prediction_created` and `alert_created` events as inferences occur.
4. **Heartbeat:** Server periodically transmits `heartbeat` events (every 30s) if connection is idle.
5. **Client Disconnect / Clean Up:** Failed or disconnected clients are removed without impacting other active connections.

---

## 3. Event Types & Schemas

### 3.1 Handshake Event (`connection_established`)
Transmitted immediately by the server upon successful connection establishment:
```json
{
  "event_type": "connection_established",
  "timestamp": "2026-10-03T13:56:25.861118+00:00",
  "data": {
    "service": "NIDS Monitoring",
    "status": "connected"
  }
}
```

### 3.2 Prediction Created Event (`prediction_created`)
Broadcast to all active subscribers after a network flow prediction is committed to the database:
```json
{
  "event_type": "prediction_created",
  "timestamp": "2026-10-03T13:56:26.113491+00:00",
  "data": {
    "prediction_id": 39,
    "predicted_threat": "DoS",
    "intrusion_flag": true,
    "anomaly_score": 0.4996,
    "classification_confidence": 0.61,
    "risk_level": "MEDIUM",
    "recommended_action": "Flow Telemetry Inspection & Behavioral Audit"
  }
}
```

### 3.3 Alert Created Event (`alert_created`)
Broadcast after a security alert (`AlertRecord`) is committed for MEDIUM, HIGH, or CRITICAL risk flows:
```json
{
  "event_type": "alert_created",
  "timestamp": "2026-10-03T13:56:26.113491+00:00",
  "data": {
    "alert_id": 15,
    "prediction_id": 39,
    "severity": "MEDIUM",
    "threat_label": "DoS",
    "anomaly_score": 0.4996,
    "confidence": 0.61,
    "status": "NEW",
    "alert_type": "ANOMALY_MONITORING",
    "recommended_action": "Flow Telemetry Inspection & Behavioral Audit"
  }
}
```

### 3.4 Heartbeat Event (`heartbeat`)
Lightweight keepalive event generated server-side to maintain WebSocket connection state:
```json
{
  "event_type": "heartbeat",
  "timestamp": "2026-10-03T13:56:56.000000+00:00"
}
```

---

## 4. Reconnection Strategy & Resilience

- **Frontend Service:** [`frontend/src/services/websocket.js`](file:///C:/Users/SANJAY%20SK/Desktop/Network_based/frontend/src/services/websocket.js)
- **Controlled Exponential Backoff:** Reconnect attempts back off through a controlled schedule: `1s -> 2s -> 4s -> 8s` (capped at 8 seconds).
- **Single Connection Architecture:** A single application-level WebSocket singleton handles all streaming. Connections are not duplicated across different pages.
- **Connection States:** `CONNECTING`, `CONNECTED`, `DISCONNECTED`, `RECONNECTING`. The UI only displays `CONNECTED` when the socket is in state `WebSocket.OPEN`.

---

## 5. React Dashboard Integration

- **Live Session Counters:**
  - *Session Predictions*: Count of prediction events received during the current browser session.
  - *Session Alerts*: Count of alerts generated during the current browser session.
  - *High Priority (Session)*: Counter of alerts with severity = HIGH.
  - *Critical Priority (Session)*: Counter of alerts with severity = CRITICAL.
  - *Data Consistency Guarantee*: Clearly distinguished from total database records to prevent confusing session metrics with database totals.
- **Bounded In-Memory Lists:**
  - Live Inferences Stream: capped at the 20 most recent events (newest first).
  - Live Alerts Stream: capped at the 20 most recent events (newest first).
  - Memory bounds prevent browser memory exhaustion.
- **Deduplication:**
  - Events are deduplicated by `prediction_id` and `alert_id` before list insertion.
- **REST Fallback:**
  - If the WebSocket server is offline, the dashboard continues to load historical data via REST.
  - Operators can manually refresh REST data via the "Refresh" action button without continuous REST polling loops.

---

## 6. Security Considerations

- **Server-Push-Only Model:** WebSocket communication is strictly server-to-client telemetry push. The server does not execute client-provided commands or evaluate arbitrary code (`eval`).
- **Data Minimization:** Payloads include only required threat telemetry (threat label, score, confidence, risk, and action). Internal exceptions, stack traces, database schema details, and credentials are never transmitted.
- **Failed Client Isolation:** When a client abruptly closes or errors during broadcast, the manager isolates the exception, evicts the dead socket, and continues delivering messages to all other healthy subscribers.

---

## 7. Verification & Testing

### 7.1 Backend Automated Tests
All 57 backend tests pass without errors (`pytest -v`):
- `test_websocket_connection_and_handshake`: Verifies handshake payload on connect.
- `test_websocket_ping_pong`: Verifies ping/pong keepalive.
- `test_prediction_and_alert_broadcast_on_predict`: Verifies end-to-end broadcast after database commit.
- `test_no_broadcast_when_persistence_fails`: Verifies that failed persistence suppresses broadcasts.
- `test_multiple_clients_and_isolation`: Verifies multi-client concurrent broadcasting.
- `test_failed_client_does_not_break_other_clients`: Verifies dead socket isolation.
- `test_heartbeat_manager_method`: Verifies manager heartbeat broadcasting.
- `test_existing_rest_endpoints_unaffected`: Verifies health, predictions, and alerts REST APIs continue working.

### 7.2 Frontend Compilation
`npm run build` compiled 1,495 modules in 6.08s with 0 errors and 0 warnings.

### 7.3 Live End-to-End Verification
Executed live end-to-end test against running server:
- Handshake received: `connection_established`.
- Telemetry POSTed to `/api/v1/predict`.
- Database persisted prediction `#39` and alert `#15`.
- WebSocket received `prediction_created` and `alert_created` within milliseconds.

---

## 8. Phase Boundary Confirmation

Phase 7 implements real-time WebSocket security monitoring and React dashboard integration.
The following features belong to Phase 8 or subsequent phases and were **strictly NOT implemented**:
- No alert status editing / acknowledgement mutations.
- No email, SMS, or webhook notification dispatchers.
- No user authentication or role-based access control (RBAC).
- No live packet capture / PCAP ingestion drivers.
- No automated incident mitigation / blocking rules.
- No Docker or cloud deployment configurations.
