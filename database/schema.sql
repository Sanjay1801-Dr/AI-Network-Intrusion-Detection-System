-- ==============================================================================
-- AI-Based Network Intrusion Detection System (NIDS)
-- Reference Relational Database Schema (PostgreSQL / SQLite Compatible DDL)
-- ==============================================================================

-- 1. System Nodes / Monitored Assets
CREATE TABLE IF NOT EXISTS system_nodes (
    id VARCHAR(36) PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    environment VARCHAR(30) DEFAULT 'production',
    criticality_level INT DEFAULT 2, -- 1=Low, 2=Medium, 3=High, 4=Mission-Critical
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. User Accounts / SOC Analysts
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(30) DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Raw Network Traffic Flow Records
CREATE TABLE IF NOT EXISTS traffic_records (
    id VARCHAR(36) PRIMARY KEY,
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INT NOT NULL CHECK (source_port >= 0 AND source_port <= 65535),
    destination_port INT NOT NULL CHECK (destination_port >= 0 AND destination_port <= 65535),
    protocol VARCHAR(10) NOT NULL,
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    total_packets BIGINT NOT NULL DEFAULT 0,
    total_bytes BIGINT NOT NULL DEFAULT 0,
    syn_flag_count INT NOT NULL DEFAULT 0,
    ack_flag_count INT NOT NULL DEFAULT 0,
    rst_flag_count INT NOT NULL DEFAULT 0,
    fin_flag_count INT NOT NULL DEFAULT 0,
    is_suspicious BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_traffic_captured_at ON traffic_records(captured_at);
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic_records(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip ON traffic_records(destination_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst_port ON traffic_records(destination_port);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON traffic_records(protocol);

-- 4. Threat Events (Detected Anomalies & Classified Threats)
CREATE TABLE IF NOT EXISTS threat_events (
    id VARCHAR(36) PRIMARY KEY,
    traffic_record_id VARCHAR(36) NOT NULL REFERENCES traffic_records(id) ON DELETE CASCADE,
    threat_type VARCHAR(50) NOT NULL,
    anomaly_score REAL NOT NULL DEFAULT 0.0,
    confidence_score REAL NOT NULL DEFAULT 0.0,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(30) NOT NULL DEFAULT 'DETECTED',
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    analysis_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_detected_at ON threat_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_events(threat_type);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_events(severity);

-- 5. Security Alerts (Triage & Incident Notifications)
CREATE TABLE IF NOT EXISTS security_alerts (
    id VARCHAR(36) PRIMARY KEY,
    threat_event_id VARCHAR(36) NOT NULL REFERENCES threat_events(id) ON DELETE CASCADE,
    title VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(30) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
    assigned_user_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at);

-- 6. Machine Learning Predictions Audit Log
CREATE TABLE IF NOT EXISTS ml_predictions (
    id VARCHAR(36) PRIMARY KEY,
    traffic_record_id VARCHAR(36) NOT NULL REFERENCES traffic_records(id) ON DELETE CASCADE,
    model_name VARCHAR(80) NOT NULL,
    model_version VARCHAR(20) NOT NULL,
    inference_latency_ms REAL NOT NULL,
    raw_prediction VARCHAR(100) NOT NULL,
    prediction_probabilities TEXT, -- JSON formatted probability distribution
    executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ml_executed_at ON ml_predictions(executed_at);

-- 7. Phase 5 Prediction Records (Flow Telemetry & AI Audit Log)
CREATE TABLE IF NOT EXISTS prediction_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INT,
    destination_port INT,
    protocol VARCHAR(20),
    flow_duration REAL,
    total_forward_packets BIGINT,
    total_backward_packets BIGINT,
    total_bytes BIGINT,
    anomaly_label VARCHAR(30) NOT NULL,
    anomaly_score REAL NOT NULL,
    raw_decision_score REAL NOT NULL,
    predicted_threat VARCHAR(50) NOT NULL,
    intrusion_flag BOOLEAN NOT NULL,
    classification_confidence REAL NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    recommended_action VARCHAR(255) NOT NULL,
    model_version VARCHAR(50) DEFAULT '1.0.0-phase3',
    raw_flow_data TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pred_created_at ON prediction_records(created_at);
CREATE INDEX IF NOT EXISTS idx_pred_timestamp ON prediction_records(timestamp);
CREATE INDEX IF NOT EXISTS idx_pred_risk_level ON prediction_records(risk_level);
CREATE INDEX IF NOT EXISTS idx_pred_threat ON prediction_records(predicted_threat);
CREATE INDEX IF NOT EXISTS idx_pred_dst_port ON prediction_records(destination_port);

-- 8. Phase 5 Security Incident Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER REFERENCES prediction_records(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    alert_type VARCHAR(50) NOT NULL DEFAULT 'NETWORK_INTRUSION',
    severity VARCHAR(20) NOT NULL,
    threat_label VARCHAR(50) NOT NULL,
    anomaly_score REAL NOT NULL,
    confidence REAL NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    status VARCHAR(30) NOT NULL DEFAULT 'NEW',
    recommended_action VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alert_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alert_threat_label ON alerts(threat_label);
CREATE INDEX IF NOT EXISTS idx_alert_prediction_id ON alerts(prediction_id);

-- 9. Phase 12 Security Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(50),
    user_role VARCHAR(20),
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(50),
    outcome VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    request_method VARCHAR(10),
    request_path VARCHAR(255),
    status_code INT,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_resource_type ON audit_logs(resource_type);

