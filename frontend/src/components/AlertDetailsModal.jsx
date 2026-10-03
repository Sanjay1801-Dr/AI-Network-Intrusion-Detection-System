import React, { useEffect } from 'react';
import {
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  X,
  Radio,
  Network,
  Cpu,
  ArrowRight,
  ShieldCheck,
  Check,
} from 'lucide-react';
import StatusBadge from './StatusBadge';
import { formatDateTime, formatPercentage, formatScore } from '../utils/formatters';

/**
 * AlertDetailsModal component for SOC operator incident investigation (Phase 8).
 * Displays alert telemetry, lifecycle timestamps, linked prediction metadata,
 * and controlled lifecycle actions (Acknowledge, Resolve).
 */
export default function AlertDetailsModal({
  alert,
  onClose,
  onAcknowledge,
  onResolve,
  actionLoadingId = null,
  canManageAlerts = true,
}) {
  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!alert) return null;

  const isActionInProgress = actionLoadingId === alert.id;
  const status = String(alert.status || 'NEW').toUpperCase();
  const prediction = alert.prediction;

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(5, 7, 15, 0.82)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
      }}
    >
      <div
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '780px',
          maxHeight: '90vh',
          overflowY: 'auto',
          borderRadius: 'var(--radius-lg, 12px)',
          border: '1px solid var(--border-subtle)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 242, 254, 0.1)',
          padding: 0,
          background: 'var(--bg-secondary, #0e1222)',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 100%)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                backgroundColor: 'rgba(239, 68, 68, 0.12)',
                color: 'var(--status-critical)',
              }}
            >
              <ShieldAlert size={20} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#fff', margin: 0 }}>
                  Incident Investigation #{alert.id}
                </h2>
                <StatusBadge status={alert.status} type="status" />
                <StatusBadge status={alert.severity} type="severity" />
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                Type: {alert.alert_type} &bull; Target: {alert.threat_label}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.4rem',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.15s ease',
            }}
            title="Close dialog (Esc)"
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          
          {/* Recommended Action Callout */}
          <div
            style={{
              padding: '1rem 1.25rem',
              borderRadius: '8px',
              backgroundColor: 'rgba(0, 242, 254, 0.06)',
              border: '1px solid rgba(0, 242, 254, 0.25)',
              display: 'flex',
              gap: '0.85rem',
              alignItems: 'flex-start',
            }}
          >
            <AlertTriangle size={20} color="var(--accent-cyan)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--accent-cyan)' }}>
                Recommended SOC Action
              </div>
              <div style={{ fontSize: '0.9rem', color: '#fff', marginTop: '0.25rem', lineHeight: 1.45 }}>
                {alert.recommended_action}
              </div>
            </div>
          </div>

          {/* Section: AI Detection Telemetry */}
          <div className="section-card" style={{ margin: 0, padding: '1rem 1.25rem', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Cpu size={14} color="var(--accent-cyan)" />
              AI Threat Detection Telemetry
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.9rem' }}>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Identified Threat</span>
                <span style={{ fontSize: '0.95rem', fontWeight: 600, color: '#fff' }}>{alert.threat_label}</span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Classifier Confidence</span>
                <span className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                  {formatPercentage(alert.confidence)}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Anomaly Score</span>
                <span className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f59e0b' }}>
                  {formatScore(alert.anomaly_score)}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Severity Rating</span>
                <span style={{ fontSize: '0.95rem', fontWeight: 600 }}>{alert.severity}</span>
              </div>
            </div>
          </div>

          {/* Section: Lifecycle Audit Timestamps */}
          <div className="section-card" style={{ margin: 0, padding: '1rem 1.25rem', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Clock size={14} color="var(--accent-cyan)" />
              Lifecycle Audit Timestamps (UTC)
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.9rem' }}>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Created At</span>
                <span className="font-mono" style={{ fontSize: '0.82rem', color: '#e5e7eb' }}>
                  {formatDateTime(alert.created_at || alert.timestamp)}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Acknowledged At</span>
                <span className="font-mono" style={{ fontSize: '0.82rem', color: alert.acknowledged_at ? '#f59e0b' : 'var(--text-muted)' }}>
                  {alert.acknowledged_at ? formatDateTime(alert.acknowledged_at) : '— (Pending)'}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Resolved At</span>
                <span className="font-mono" style={{ fontSize: '0.82rem', color: alert.resolved_at ? '#10b981' : 'var(--text-muted)' }}>
                  {alert.resolved_at ? formatDateTime(alert.resolved_at) : '— (Open)'}
                </span>
              </div>
            </div>
          </div>

          {/* Section: Linked Prediction & Network Telemetry */}
          <div className="section-card" style={{ margin: 0, padding: '1rem 1.25rem', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Network size={14} color="var(--accent-cyan)" />
              Network Flow Telemetry & Linked Prediction
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.9rem' }}>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Prediction Record ID</span>
                <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>
                  {alert.prediction_id ? `#${alert.prediction_id}` : 'Direct Alert (No Ref)'}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Source IP</span>
                <span className="font-mono" style={{ fontSize: '0.85rem', color: '#fff' }}>
                  {alert.source_ip || prediction?.source_ip || '192.168.1.150'}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Destination IP</span>
                <span className="font-mono" style={{ fontSize: '0.85rem', color: '#fff' }}>
                  {alert.destination_ip || prediction?.destination_ip || '10.0.0.1'}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Port & Protocol</span>
                <span className="font-mono" style={{ fontSize: '0.85rem', color: '#fff' }}>
                  {prediction?.destination_port ? `Port ${prediction.destination_port}` : 'Port 80'} &bull; {prediction?.protocol || 'TCP'}
                </span>
              </div>
              {prediction?.flow_duration != null && (
                <div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Flow Duration</span>
                  <span className="font-mono" style={{ fontSize: '0.85rem', color: '#fff' }}>
                    {prediction.flow_duration.toLocaleString()} &mu;s
                  </span>
                </div>
              )}
              {prediction?.total_bytes != null && (
                <div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block' }}>Transmitted Bytes</span>
                  <span className="font-mono" style={{ fontSize: '0.85rem', color: '#fff' }}>
                    {prediction.total_bytes.toLocaleString()} B
                  </span>
                </div>
              )}
            </div>
          </div>

        </div>

        {/* Modal Footer / Controlled Lifecycle Actions */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(0, 0, 0, 0.25)',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Current Status: <strong style={{ color: '#fff' }}>{status}</strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={onClose}
              className="preset-btn"
              style={{ padding: '0.5rem 1rem' }}
            >
              Close
            </button>

            {/* Controlled Action Buttons (ADMIN & ANALYST only) */}
            {!canManageAlerts && status !== 'RESOLVED' && (
              <span
                style={{
                  fontSize: '0.78rem',
                  color: 'var(--text-muted)',
                  fontStyle: 'italic',
                  padding: '0.4rem 0.6rem',
                }}
              >
                Read-only access (Viewer)
              </span>
            )}

            {canManageAlerts && status === 'NEW' && (
              <>
                <button
                  onClick={() => onAcknowledge(alert.id)}
                  disabled={isActionInProgress}
                  className="preset-btn"
                  style={{
                    backgroundColor: 'rgba(245, 158, 11, 0.15)',
                    border: '1px solid rgba(245, 158, 11, 0.4)',
                    color: '#f59e0b',
                    fontWeight: 600,
                    padding: '0.5rem 1rem',
                    opacity: isActionInProgress ? 0.6 : 1,
                    cursor: isActionInProgress ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isActionInProgress ? 'Updating...' : 'Acknowledge'}
                </button>

                <button
                  onClick={() => onResolve(alert.id)}
                  disabled={isActionInProgress}
                  className="preset-btn"
                  style={{
                    backgroundColor: 'rgba(16, 185, 129, 0.15)',
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    color: '#10b981',
                    fontWeight: 600,
                    padding: '0.5rem 1rem',
                    opacity: isActionInProgress ? 0.6 : 1,
                    cursor: isActionInProgress ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isActionInProgress ? 'Updating...' : 'Resolve'}
                </button>
              </>
            )}

            {canManageAlerts && status === 'ACKNOWLEDGED' && (
              <button
                onClick={() => onResolve(alert.id)}
                disabled={isActionInProgress}
                className="preset-btn"
                style={{
                  backgroundColor: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  color: '#10b981',
                  fontWeight: 600,
                  padding: '0.5rem 1rem',
                  opacity: isActionInProgress ? 0.6 : 1,
                  cursor: isActionInProgress ? 'not-allowed' : 'pointer',
                }}
              >
                {isActionInProgress ? 'Updating...' : 'Resolve'}
              </button>
            )}

            {status === 'RESOLVED' && (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  fontSize: '0.82rem',
                  color: '#10b981',
                  fontWeight: 600,
                  padding: '0.4rem 0.8rem',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                }}
              >
                <Check size={15} />
                Resolved
              </span>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
