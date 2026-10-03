import React, { useState, useEffect } from 'react';
import {
  Activity,
  ShieldAlert,
  Cpu,
  HardDrive,
  Clock,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Send,
  Radio,
  Zap,
  ShieldCheck,
  FileText,
} from 'lucide-react';
import api from '../services/api';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime, formatPercentage, formatScore } from '../utils/formatters';

export default function Dashboard({
  backendHealth,
  setActiveTab,
  wsStatus = 'DISCONNECTED',
  sessionCounters = { predictions: 0, alerts: 0, highAlerts: 0, criticalAlerts: 0 },
  livePredictions = [],
  liveAlerts = [],
  latestLivePrediction = null,
  latestLiveAlert = null,
}) {
  const [predictionsData, setPredictionsData] = useState({ items: [], total: 0 });
  const [alertsData, setAlertsData] = useState({ items: [], total: 0 });
  const [auditSummary, setAuditSummary] = useState({
    total_events: 0,
    failed_logins: 0,
    access_denied: 0,
    rate_limit_exceeded: 0,
  });
  const [incidentSummary, setIncidentSummary] = useState({
    total_incidents: 0,
    open_incidents: 0,
    investigating_incidents: 0,
    critical_incidents: 0,
    high_incidents: 0,
    resolved_incidents: 0,
    recently_resolved: [],
  });
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      // Query recent predictions, alerts, audit summary, and incident summary
      const [predsRes, alertsRes, auditRes, incRes] = await Promise.all([
        api.getPredictions({ limit: 5, offset: 0 }),
        api.getAlerts({ limit: 50, offset: 0 }),
        api.getAuditSummary().catch(() => null),
        api.getIncidentSummary().catch(() => null),
      ]);
      setPredictionsData(predsRes || { items: [], total: 0 });
      setAlertsData(alertsRes || { items: [], total: 0 });
      if (auditRes) {
        setAuditSummary(auditRes);
      }
      if (incRes) {
        setIncidentSummary(incRes);
      }
    } catch (err) {
      setApiError(err.message || 'Failed to load historical dashboard telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Compute summary metrics from real database API responses
  const totalPredictions = predictionsData.total || 0;
  const totalAlerts = alertsData.total || 0;
  const recentPredictions = predictionsData.items || [];
  const recentAlerts = alertsData.items || [];

  // Effective latest prediction: prefers newest WebSocket live event, falls back to DB record
  const effectiveLatestPrediction = latestLivePrediction || (recentPredictions.length > 0 ? recentPredictions[0] : null);
  const isLatestFromWs = Boolean(latestLivePrediction);

  // Effective latest alert: prefers newest WebSocket live event, falls back to DB record
  const effectiveLatestAlert = latestLiveAlert || (recentAlerts.length > 0 ? recentAlerts[0] : null);

  // Calculate High/Critical count from retrieved historical alert records
  const historicalHighCriticalCount = recentAlerts.filter(
    (a) => a.severity === 'HIGH' || a.severity === 'CRITICAL'
  ).length;

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
            Operational security operations center overview powered by real-time dual-stage AI detection.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={() => setActiveTab('predict')}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', padding: '0.5rem 1rem' }}
          >
            <Send size={15} />
            <span>New Prediction</span>
          </button>

          <button
            onClick={fetchDashboardData}
            disabled={isLoading}
            className="preset-btn"
            title="Manual metrics refresh (REST)"
          >
            <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* REST Error notification */}
      {apiError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Dashboard Telemetry Notice</div>
            <div style={{ fontSize: '0.85rem' }}>{apiError}</div>
          </div>
          <button
            onClick={fetchDashboardData}
            style={{
              padding: '0.35rem 0.75rem',
              backgroundColor: 'rgba(239, 68, 68, 0.2)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#fff',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.78rem',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Real-Time WebSocket Session Telemetry Card */}
      <div
        className="section-card glass-panel"
        style={{
          borderLeft: '4px solid var(--accent-cyan)',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.75rem',
        }}
      >
        <div className="section-header" style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Radio size={20} color="var(--accent-cyan)" />
            <div>
              <h2 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                Real-Time WebSocket Stream
              </h2>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Live session telemetry received during current browser session (notifications only, DB is source of truth)
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Status:</span>
            <StatusBadge status={wsStatus} />
          </div>
        </div>

        {/* Live Session Counters Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
          }}
        >
          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Session Predictions
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {sessionCounters.predictions}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
              Live stream events
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Session Alerts
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {sessionCounters.alerts}
            </div>
            <div style={{ fontSize: '0.7rem', color: sessionCounters.alerts > 0 ? 'var(--status-critical)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
              Actionable incidents
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              High Priority (Session)
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: 'var(--status-high)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {sessionCounters.highAlerts}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Severity = HIGH
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Critical Priority (Session)
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: 'var(--status-critical)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {sessionCounters.criticalAlerts}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Severity = CRITICAL
            </div>
          </div>
        </div>
      </div>

      {/* Phase 12 Security Monitoring & Audit Summary */}
      <div
        className="section-card glass-panel"
        style={{
          borderLeft: '4px solid #a855f7',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.75rem',
        }}
      >
        <div className="section-header" style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <FileText size={20} color="#a855f7" />
            <div>
              <h2 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                Security Audit & Access Telemetry
              </h2>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Operational security monitoring tracking authentication, access control denials, and rate limit triggers
              </div>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('audit')}
            className="preset-btn"
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <span>View All Audit Logs</span>
            <ArrowRight size={13} />
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
          }}
        >
          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Total Audit Events
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {auditSummary.total_events}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#a855f7', marginTop: '0.2rem' }}>
              Persisted audit trail
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Failed Logins
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: auditSummary.failed_logins > 0 ? 'var(--status-critical)' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {auditSummary.failed_logins}
            </div>
            <div style={{ fontSize: '0.7rem', color: auditSummary.failed_logins > 0 ? 'var(--status-critical)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
              {auditSummary.failed_logins > 0 ? 'Unsuccessful credentials' : 'No failed logins'}
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Access Denied (403)
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: auditSummary.access_denied > 0 ? 'var(--status-high)' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {auditSummary.access_denied}
            </div>
            <div style={{ fontSize: '0.7rem', color: auditSummary.access_denied > 0 ? 'var(--status-high)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
              {auditSummary.access_denied > 0 ? 'RBAC violations blocked' : 'Zero policy violations'}
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Rate Limit Throttles (429)
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: auditSummary.rate_limit_exceeded > 0 ? 'var(--accent-cyan)' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {auditSummary.rate_limit_exceeded}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Abuse protection triggers
            </div>
          </div>
        </div>
      </div>

      {/* Phase 14 Incident Response Operations Summary */}
      <div
        className="section-card glass-panel"
        style={{
          borderLeft: '4px solid #f97316',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.75rem',
        }}
      >
        <div className="section-header" style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <ShieldAlert size={20} color="#f97316" />
            <div>
              <h2 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                Incident Response Summary
              </h2>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Structured SOC analyst workflow managing active investigations, containment, and incident resolution
              </div>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('incidents')}
            className="preset-btn"
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <span>Open Incident Console</span>
            <ArrowRight size={13} />
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem',
          }}
        >
          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Open Incidents
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: incidentSummary.open_incidents > 0 ? '#38bdf8' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {incidentSummary.open_incidents}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Awaiting operator triage
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Investigating
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: incidentSummary.investigating_incidents > 0 ? '#fbbf24' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {incidentSummary.investigating_incidents}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Active analyst handling
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Critical Incidents
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: incidentSummary.critical_incidents > 0 ? 'var(--status-critical)' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {incidentSummary.critical_incidents}
            </div>
            <div style={{ fontSize: '0.7rem', color: incidentSummary.critical_incidents > 0 ? 'var(--status-critical)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
              Severity = CRITICAL
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              High Incidents
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: incidentSummary.high_incidents > 0 ? 'var(--status-high)' : '#fff', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {incidentSummary.high_incidents}
            </div>
            <div style={{ fontSize: '0.7rem', color: incidentSummary.high_incidents > 0 ? 'var(--status-high)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
              Severity = HIGH
            </div>
          </div>

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Recently Resolved
            </div>
            <div style={{ fontSize: '1.45rem', fontWeight: 700, color: 'var(--status-healthy)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {incidentSummary.resolved_incidents || (incidentSummary.recently_resolved ? incidentSummary.recently_resolved.length : 0)}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              {incidentSummary.recently_resolved && incidentSummary.recently_resolved.length > 0
                ? `Latest: ${incidentSummary.recently_resolved[0].incident_key}`
                : 'Closed incidents'}
            </div>
          </div>
        </div>
      </div>

      {/* Persistent Database Metrics Grid */}
      <div className="metrics-grid">
        {/* Total Inferences in DB */}
        <div className="metric-card glass-panel">
          <div className="metric-icon-box">
            <Cpu size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Evaluated Flows (DB)</div>
            <div className="metric-value">{totalPredictions}</div>
            <div className="metric-subtext">Persisted audit history</div>
          </div>
        </div>

        {/* Security Alerts in DB */}
        <div className="metric-card glass-panel">
          <div
            className="metric-icon-box"
            style={{ background: 'rgba(239, 68, 68, 0.1)', color: 'var(--status-critical)' }}
          >
            <ShieldAlert size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Total Alerts (DB)</div>
            <div className="metric-value">{totalAlerts}</div>
            <div className="metric-subtext" style={{ color: historicalHighCriticalCount > 0 ? 'var(--status-critical)' : 'var(--text-muted)' }}>
              {historicalHighCriticalCount} High/Critical in sample
            </div>
          </div>
        </div>

        {/* Latest Threat Classification */}
        <div className="metric-card glass-panel">
          <div
            className="metric-icon-box"
            style={{ background: 'rgba(79, 172, 254, 0.1)', color: 'var(--accent-blue)' }}
          >
            <Activity size={24} />
          </div>
          <div className="metric-info">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <div className="metric-label">Latest Threat</div>
              {isLatestFromWs && (
                <span
                  style={{
                    fontSize: '0.62rem',
                    padding: '0.1rem 0.35rem',
                    borderRadius: '3px',
                    backgroundColor: 'rgba(0, 242, 254, 0.2)',
                    color: 'var(--accent-cyan)',
                    fontWeight: 700,
                  }}
                >
                  LIVE
                </span>
              )}
            </div>
            <div className="metric-value" style={{ fontSize: '1.25rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '170px' }}>
              {effectiveLatestPrediction ? (effectiveLatestPrediction.predicted_threat || 'None') : 'None'}
            </div>
            <div className="metric-subtext">
              {effectiveLatestPrediction ? (
                <span style={{ color: 'var(--accent-cyan)' }}>
                  Conf: {formatPercentage(effectiveLatestPrediction.classification_confidence)}
                </span>
              ) : (
                'No flow data recorded'
              )}
            </div>
          </div>
        </div>

        {/* Latest Risk Rating */}
        <div className="metric-card glass-panel">
          <div
            className="metric-icon-box"
            style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--status-healthy)' }}
          >
            <ShieldCheck size={24} />
          </div>
          <div className="metric-info">
            <div className="metric-label">Latest Risk Rating</div>
            <div style={{ marginTop: '0.35rem' }}>
              {effectiveLatestPrediction ? (
                <StatusBadge status={effectiveLatestPrediction.risk_level} type="risk" />
              ) : (
                <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>N/A</span>
              )}
            </div>
            <div className="metric-subtext" style={{ color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              Composite triage
            </div>
          </div>
        </div>
      </div>

      {/* Subsystem Health Diagnostics Panel (Current Status via GET /api/health) */}
      <div className="section-card glass-panel">
        <div className="section-header">
          <h2 className="section-title">
            <HardDrive size={18} color="var(--accent-cyan)" />
            Subsystem Health Diagnostics (Current Status via GET /api/health)
          </h2>
          {backendHealth && <StatusBadge status={backendHealth.status} />}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.25)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Relational Database</div>
            <div style={{ marginTop: '0.4rem' }}>
              <StatusBadge status={backendHealth?.components?.database || 'UNKNOWN'} />
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              SQLite / PostgreSQL Driver
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.25)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>ML Inference Engine</div>
            <div style={{ marginTop: '0.4rem' }}>
              <StatusBadge status={backendHealth?.components?.ml_engine || 'READY'} />
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              Isolation Forest & Random Forest
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.25)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>REST & WS Gateway</div>
            <div style={{ marginTop: '0.4rem' }}>
              <StatusBadge status={backendHealth?.components?.api || 'ONLINE'} />
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              FastAPI /api/v1/ws/monitor
            </div>
          </div>

          <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.25)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>System Environment</div>
            <div style={{ marginTop: '0.4rem', fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.88rem' }}>
              {backendHealth?.environment || 'Development'}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              Version {backendHealth?.version || '1.0.0'}
            </div>
          </div>
        </div>
      </div>

      {/* Real-Time Live Feed Section (Bounded to 20 events) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '1.5rem', marginBottom: '1.75rem' }}>
        
        {/* Live Inferences Stream */}
        <div className="section-card glass-panel" style={{ margin: 0 }}>
          <div className="section-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Zap size={18} color="var(--accent-cyan)" />
              <h2 className="section-title">Live Inferences Stream</h2>
              <span
                style={{
                  fontSize: '0.68rem',
                  padding: '0.15rem 0.45rem',
                  borderRadius: '3px',
                  backgroundColor: 'rgba(0, 242, 254, 0.15)',
                  color: 'var(--accent-cyan)',
                  fontWeight: 600,
                }}
              >
                {livePredictions.length}/20 Bounded
              </span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              WebSocket Push
            </span>
          </div>

          {livePredictions.length === 0 ? (
            <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.86rem' }}>
              <Radio size={24} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
              <div>Awaiting real-time prediction notifications.</div>
              <div style={{ fontSize: '0.74rem', marginTop: '0.25rem' }}>
                Submit a flow in <strong>AI Prediction</strong> to see it stream here live.
              </div>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="ids-table">
                <thead>
                  <tr>
                    <th>Pred. ID</th>
                    <th>Threat</th>
                    <th>Risk</th>
                    <th>Confidence</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {livePredictions.map((row) => (
                    <tr key={row.prediction_id || row.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                        #{row.prediction_id || row.id}
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>{row.predicted_threat}</td>
                      <td>
                        <StatusBadge status={row.risk_level} type="risk" />
                      </td>
                      <td className="font-mono">{formatPercentage(row.classification_confidence)}</td>
                      <td className="font-mono">{formatScore(row.anomaly_score)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Live Alerts Stream */}
        <div className="section-card glass-panel" style={{ margin: 0 }}>
          <div className="section-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={18} color="var(--status-critical)" />
              <h2 className="section-title">Live Security Alerts</h2>
              <span
                style={{
                  fontSize: '0.68rem',
                  padding: '0.15rem 0.45rem',
                  borderRadius: '3px',
                  backgroundColor: 'rgba(239, 68, 68, 0.15)',
                  color: 'var(--status-critical)',
                  fontWeight: 600,
                }}
              >
                {liveAlerts.length}/20 Bounded
              </span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              WebSocket Push
            </span>
          </div>

          {liveAlerts.length === 0 ? (
            <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.86rem' }}>
              <ShieldAlert size={24} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
              <div>No alerts received during this session.</div>
              <div style={{ fontSize: '0.74rem', marginTop: '0.25rem' }}>
                Flows evaluated with MEDIUM, HIGH, or CRITICAL risk will appear here.
              </div>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="ids-table">
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Pred. ID</th>
                    <th>Severity</th>
                    <th>Threat Label</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {liveAlerts.map((alert) => (
                    <tr key={alert.alert_id || alert.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                        #{alert.alert_id || alert.id}
                      </td>
                      <td className="font-mono" style={{ color: 'var(--text-muted)' }}>
                        #{alert.prediction_id}
                      </td>
                      <td>
                        <StatusBadge status={alert.severity} type="severity" />
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>{alert.threat_label}</td>
                      <td>
                        <StatusBadge status={alert.status} type="status" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>

      {/* Historical Audit Overview Section (Database REST Fallback) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '1.5rem' }}>
        
        {/* Recent Inferences Table (Database) */}
        <div className="section-card glass-panel" style={{ margin: 0 }}>
          <div className="section-header">
            <h2 className="section-title">
              <Clock size={18} color="var(--accent-cyan)" />
              Database Inferences Audit (Latest 5)
            </h2>
            <button
              onClick={() => setActiveTab('history')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-cyan)',
                fontSize: '0.8rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
              }}
            >
              <span>View All ({totalPredictions})</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {recentPredictions.length === 0 ? (
            <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
              No prediction records in database yet.
            </div>
          ) : (
            <div className="table-responsive">
              <table className="ids-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Threat</th>
                    <th>Risk</th>
                    <th>Est. Prob.</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentPredictions.map((row) => (
                    <tr key={row.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                        #{row.id}
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>{row.predicted_threat}</td>
                      <td>
                        <StatusBadge status={row.risk_level} type="risk" />
                      </td>
                      <td className="font-mono">{formatPercentage(row.classification_confidence)}</td>
                      <td style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                        {formatDateTime(row.timestamp || row.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Alerts Table (Database) */}
        <div className="section-card glass-panel" style={{ margin: 0 }}>
          <div className="section-header">
            <h2 className="section-title">
              <AlertTriangle size={18} color="var(--status-critical)" />
              Database Security Alerts (Latest 5)
            </h2>
            <button
              onClick={() => setActiveTab('alerts')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-cyan)',
                fontSize: '0.8rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
              }}
            >
              <span>View All ({totalAlerts})</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {recentAlerts.slice(0, 5).length === 0 ? (
            <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
              No active security alerts recorded in database yet.
            </div>
          ) : (
            <div className="table-responsive">
              <table className="ids-table">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Severity</th>
                    <th>Threat Family</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.slice(0, 5).map((alert) => (
                    <tr key={alert.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                        #{alert.id}
                      </td>
                      <td>
                        <StatusBadge status={alert.severity} type="severity" />
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>{alert.threat_label}</td>
                      <td>
                        <StatusBadge status={alert.status} type="status" />
                      </td>
                      <td style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                        {formatDateTime(alert.timestamp || alert.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
