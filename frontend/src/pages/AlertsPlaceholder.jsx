import React, { useState } from 'react';
import { AlertTriangle, Filter, CheckCircle, ShieldAlert, Clock, ArrowRight } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function AlertsPlaceholder() {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const alerts = [
    {
      id: 'ALT-1049',
      title: 'High-Volume TCP SYN Flood Attack',
      description: 'Anomalous surge of 45,000 SYN packets with no corresponding ACK handshakes targeting server 10.0.0.1:443.',
      source: '198.51.100.44',
      target: '10.0.0.1:443',
      severity: 'CRITICAL',
      status: 'NEW',
      time: '12:04:18 UTC',
    },
    {
      id: 'ALT-1048',
      title: 'Automated SSH Brute Force Infiltration',
      description: 'Repeated authentication failures across port 22 exceeding standard baseline thresholds (180 attempts/min).',
      source: '203.0.113.88',
      target: '10.0.0.5:22',
      severity: 'HIGH',
      status: 'ACKNOWLEDGED',
      time: '11:58:02 UTC',
    },
    {
      id: 'ALT-1047',
      title: 'Horizontal Subnet Port Sweep (Nmap)',
      description: 'Systematic sequential probing across port range 1-1024 detected from internal compromised subnet.',
      source: '192.168.1.105',
      target: '192.168.1.0/24',
      severity: 'MEDIUM',
      status: 'INVESTIGATING',
      time: '11:42:33 UTC',
    },
  ];

  const filteredAlerts = filterSeverity === 'ALL'
    ? alerts
    : alerts.filter(a => a.severity === filterSeverity);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <AlertTriangle color="var(--status-critical)" size={28} />
            Security Alert Management
          </h1>
          <p className="page-subtitle">
            SOC incident response triage queue and automated threat escalation center.
          </p>
        </div>
      </div>

      <div className="phase-banner">
        <span className="phase-tag">PHASE 3 BLUEPRINT</span>
        <div>
          <strong>Alert Pipeline Specification:</strong> In Phase 3, this view connects to <code>GET /api/v1/alerts</code> and allows analysts to acknowledge, resolve, or mark alerts as false positives.
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
          <button
            key={severity}
            onClick={() => setFilterSeverity(severity)}
            style={{
              padding: '0.45rem 0.9rem',
              borderRadius: 'var(--radius-sm)',
              border: filterSeverity === severity ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
              backgroundColor: filterSeverity === severity ? 'rgba(0, 242, 254, 0.12)' : 'rgba(0, 0, 0, 0.25)',
              color: filterSeverity === severity ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.8rem',
              fontWeight: 600,
            }}
          >
            {severity}
          </button>
        ))}
      </div>

      {/* Alert Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {filteredAlerts.map((alert) => (
          <div key={alert.id} className="glass-panel" style={{ padding: '1.25rem', borderLeft: `4px solid ${alert.severity === 'CRITICAL' ? 'var(--status-critical)' : alert.severity === 'HIGH' ? 'var(--status-high)' : 'var(--status-medium)'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.65rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '0.88rem' }}>
                  {alert.id}
                </span>
                <StatusBadge status={alert.severity} type="severity" />
                <StatusBadge status={alert.status} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                <Clock size={13} />
                <span>{alert.time}</span>
              </div>
            </div>

            <h3 style={{ fontSize: '1.05rem', color: '#fff', fontWeight: 600, marginBottom: '0.45rem' }}>
              {alert.title}
            </h3>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: '0.85rem', lineHeight: '1.4' }}>
              {alert.description}
            </p>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                <div>Source: <span className="font-mono" style={{ color: '#fff' }}>{alert.source}</span></div>
                <div>Target: <span className="font-mono" style={{ color: '#fff' }}>{alert.target}</span></div>
              </div>

              <button
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  background: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '4px',
                  color: 'var(--accent-cyan)',
                  padding: '0.35rem 0.75rem',
                  fontSize: '0.78rem',
                  cursor: 'pointer',
                }}
              >
                <span>Triage Incident</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
