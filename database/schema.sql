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
