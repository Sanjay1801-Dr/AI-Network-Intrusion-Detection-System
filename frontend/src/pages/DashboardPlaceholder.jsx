import React from 'react';
import { Activity, ShieldAlert, Cpu, Server, HardDrive, Clock, CheckCircle2 } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function DashboardPlaceholder({ backendHealth }) {
  const sampleIncidents = [
    {
      id: 'EVT-9021',
      time: '12:04:18 UTC',
      source: '192.168.1.105',
      destination: '10.0.0.1:443',
      type: 'DoS / SYN Flood',
      severity: 'CRITICAL',
      confidence: '96.4%',
    },
    {
      id: 'EVT-9018',
      time: '11:58:02 UTC',
      source: '203.0.113.88',
      destination: '10.0.0.5:22',
      type: 'SSH Brute Force',
      severity: 'HIGH',
      confidence: '91.2%',
    },
    {
      id: 'EVT-9014',
      time: '11:42:33 UTC',
      source: '198.51.100.12',
      destination: '10.0.0.1:80',
      type: 'TCP Port Sweep',
      severity: 'MEDIUM',
      confidence: '84.0%',
    },
  ];

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Activity color="var(--accent-cyan)" size={28} />
            SOC Telemetry Dashboard
          </h1>
          <p className="page-subtitle">
            Real-time defensive network monitoring and behavioral anomaly detection platform.
          </p>
        </div>
      </div>

      {/* Phase 1 Informational Banner */}
      <div className="phase-banner">
        <span className="phase-tag">PHASE 1 SKELETON</span>
        <div>
          <strong>System Foundation Active:</strong> Full system architecture, database entities, and REST API blueprints are established. The backend health endpoint is online.
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="metrics-grid">
        <div className="metric-card glass-panel">
          <div className="metric-icon-box">
            <ShieldAlert size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Active Threats</div>
            <div className="metric-value">3</div>
            <div className="metric-subtext" style={{ color: 'var(--status-critical)' }}>
              1 Critical Priority
            </div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-icon-box" style={{ background: 'rgba(79, 172, 254, 0.1)', color: 'var(--accent-blue)' }}>
            <Activity size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Total Flow Telemetry</div>
            <div className="metric-value">124,580</div>
            <div className="metric-subtext">3,420 pkts/sec avg</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-icon-box" style={{ background: 'rgba(121, 40, 202, 0.1)', color: 'var(--accent-purple)' }}>
            <Cpu size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">ML Anomaly Rate</div>
            <div className="metric-value">0.42%</div>
            <div className="metric-subtext">Baseline Nominal</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-icon-box" style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--status-healthy)' }}>
            <Server size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Monitored Nodes</div>
            <div className="metric-value">14 / 14</div>
            <div className="metric-subtext">All Sensors Online</div>
          </div>
        </div>
      </div>

      {/* Live Backend Diagnostic Panel */}
      <div className="section-card glass-panel">
        <div className="section-header">
          <h2 className="section-title">
            <HardDrive size={18} color="var(--accent-cyan)" />
            Subsystem Health Diagnostics (Live Telemetry via GET /api/health)
          </h2>
          {backendHealth && (
            <StatusBadge status={backendHealth.status} />
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Relational Database</div>
            <div style={{ marginTop: '0.35rem' }}>
              <StatusBadge status={backendHealth?.components?.database || 'UNKNOWN'} />
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
              SQLite / PostgreSQL Driver
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>ML Inference Engine</div>
            <div style={{ marginTop: '0.35rem' }}>
              <StatusBadge status={backendHealth?.components?.ml_engine || 'READY'} />
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
              Scikit-learn Isolation Forest
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>REST API Gateway</div>
            <div style={{ marginTop: '0.35rem' }}>
              <StatusBadge status={backendHealth?.components?.api || 'ONLINE'} />
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
              FastAPI Asynchronous Workers
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>System Environment</div>
            <div style={{ marginTop: '0.35rem', fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>
              {backendHealth?.environment || 'Development'}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
              Version {backendHealth?.version || '1.0.0-phase1'}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Incident Feed Placeholder */}
      <div className="section-card glass-panel">
        <div className="section-header">
          <h2 className="section-title">
            <Clock size={18} color="var(--accent-cyan)" />
            Recent Security Incidents (Phase 1 Mockup)
          </h2>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Live event pipeline scheduled for Phase 3
          </span>
        </div>

        <div className="table-responsive">
          <table className="ids-table">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Time (UTC)</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Threat Classification</th>
                <th>ML Confidence</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {sampleIncidents.map((incident) => (
                <tr key={incident.id}>
                  <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{incident.id}</td>
                  <td>{incident.time}</td>
                  <td className="font-mono">{incident.source}</td>
                  <td className="font-mono">{incident.destination}</td>
                  <td style={{ fontWeight: 500 }}>{incident.type}</td>
                  <td className="font-mono">{incident.confidence}</td>
                  <td>
                    <StatusBadge status={incident.severity} type="severity" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
