import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Activity,
  CheckCircle,
  ExternalLink,
  X,
  Search,
  Cpu,
  Radio,
  FileText,
  Lock,
} from 'lucide-react';
import api from '../services/api';
import { formatDateTime, formatPercentage, formatScore } from '../utils/formatters';

export default function InvestigationModal({ predictionId, onClose }) {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let isMounted = true;
    const loadInvestigation = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const res = await api.investigatePrediction(predictionId);
        if (isMounted) setData(res);
      } catch (err) {
        if (isMounted) setError(err.message || 'Failed to load investigation details.');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    if (predictionId) {
      loadInvestigation();
    }

    return () => {
      isMounted = false;
    };
  }, [predictionId]);

  if (!predictionId) return null;

  const renderReputationBadge = (rep) => {
    const norm = String(rep || 'UNKNOWN').toUpperCase();
    let bg = 'rgba(100, 116, 139, 0.2)';
    let color = '#94a3b8';
    let border = 'rgba(100, 116, 139, 0.4)';

    if (norm === 'MALICIOUS') {
      bg = 'rgba(239, 68, 68, 0.2)';
      color = '#ef4444';
      border = 'rgba(239, 68, 68, 0.5)';
    } else if (norm === 'SUSPICIOUS') {
      bg = 'rgba(245, 158, 11, 0.2)';
      color = '#f59e0b';
      border = 'rgba(245, 158, 11, 0.5)';
    } else if (norm === 'BENIGN') {
      bg = 'rgba(16, 185, 129, 0.2)';
      color = '#10b981';
      border = 'rgba(16, 185, 129, 0.5)';
    }

    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.2rem 0.55rem',
          borderRadius: '4px',
          fontSize: '0.75rem',
          fontWeight: 700,
          backgroundColor: bg,
          color,
          border: `1px solid ${border}`,
        }}
      >
        {norm}
      </span>
    );
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.85)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1100,
        backdropFilter: 'blur(5px)',
        padding: '1.5rem',
      }}
      onClick={onClose}
    >
      <div
        className="section-card glass-panel"
        style={{
          width: '100%',
          maxWidth: '740px',
          maxHeight: '92vh',
          overflowY: 'auto',
          border: '1px solid var(--border-active)',
          boxShadow: 'var(--shadow-lg)',
          padding: '1.75rem',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '1.25rem',
            borderBottom: '1px solid var(--border-subtle)',
            paddingBottom: '0.85rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Search size={22} color="var(--accent-cyan)" />
            <div>
              <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#fff', fontWeight: 600 }}>
                Forensic Prediction Investigation #{predictionId}
              </h3>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Deep telemetry evaluation &bull; Rule-based explainability &bull; Threat intelligence correlation
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        {isLoading ? (
          <div style={{ textAlign: 'center', padding: '3.5rem 0' }}>
            <div className="spinner" style={{ width: '32px', height: '32px', margin: '0 auto 1rem' }} />
            <div style={{ color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>
              Aggregating forensic telemetry and intelligence...
            </div>
          </div>
        ) : error ? (
          <div className="alert-box alert-error">
            <AlertTriangle size={18} />
            <div>{error}</div>
          </div>
        ) : data ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Top Overview Cards */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                gap: '0.75rem',
              }}
            >
              <div style={{ padding: '0.75rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Category</div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff', marginTop: '0.2rem' }}>
                  {data.threat_category}
                </div>
              </div>

              <div style={{ padding: '0.75rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity Rating</div>
                <div
                  style={{
                    fontSize: '1.15rem',
                    fontWeight: 700,
                    color:
                      data.severity === 'CRITICAL'
                        ? 'var(--status-critical)'
                        : data.severity === 'HIGH'
                        ? 'var(--status-high)'
                        : data.severity === 'MEDIUM'
                        ? 'var(--status-medium)'
                        : 'var(--status-low)',
                    marginTop: '0.2rem',
                  }}
                >
                  {data.severity}
                </div>
              </div>

              <div style={{ padding: '0.75rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomaly Score</div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
                  {formatScore(data.anomaly_score)}
                </div>
              </div>

              <div style={{ padding: '0.75rem 1rem', background: 'rgba(0,0,0,0.3)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence</div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
                  {formatPercentage(data.classifier_confidence)}
                </div>
              </div>
            </div>

            {/* Rule-based Explainability Section */}
            <div
              style={{
                backgroundColor: 'rgba(0, 242, 254, 0.04)',
                border: '1px solid rgba(0, 242, 254, 0.2)',
                borderRadius: 'var(--radius-sm)',
                padding: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' }}>
                <Cpu size={16} color="var(--accent-cyan)" />
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff' }}>
                  Rule-Based Prediction Explanation:
                </span>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {data.risk_reasons && data.risk_reasons.length > 0 ? (
                  data.risk_reasons.map((reason, idx) => (
                    <li key={idx} style={{ lineHeight: 1.4 }}>{reason}</li>
                  ))
                ) : (
                  <li>Standard baseline network flow evaluation</li>
                )}
              </ul>
            </div>

            {/* Network Flow Telemetry Grid */}
            <div>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Observed Flow Telemetry:
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                  gap: '0.5rem',
                  fontSize: '0.78rem',
                  fontFamily: 'var(--font-mono)',
                  backgroundColor: '#050811',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem',
                }}
              >
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Source IP: </span>
                  <span style={{ color: 'var(--accent-cyan)' }}>{data.flow_telemetry.source_ip || 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Dest IP: </span>
                  <span style={{ color: 'var(--accent-blue)' }}>{data.flow_telemetry.destination_ip || 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Dest Port: </span>
                  <span style={{ color: '#fff' }}>{data.flow_telemetry.destination_port ?? 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Protocol: </span>
                  <span style={{ color: '#fff' }}>{data.flow_telemetry.protocol || 'TCP'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Duration: </span>
                  <span style={{ color: '#fff' }}>{data.flow_telemetry.flow_duration ? `${data.flow_telemetry.flow_duration} μs` : 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Total Bytes: </span>
                  <span style={{ color: '#fff' }}>{data.flow_telemetry.total_bytes ?? 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Threat Intelligence Enrichment (if IP available) */}
            {data.threat_intelligence && (
              <div
                style={{
                  backgroundColor: 'rgba(168, 85, 247, 0.05)',
                  border: '1px solid rgba(168, 85, 247, 0.25)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '1rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Shield size={16} color="#a855f7" />
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff' }}>
                      Threat Intelligence Correlation ({data.threat_intelligence.ip}):
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      padding: '0.1rem 0.35rem',
                      borderRadius: '3px',
                      backgroundColor: 'rgba(168, 85, 247, 0.15)',
                      color: '#a855f7',
                      fontWeight: 700,
                    }}
                  >
                    {data.threat_intelligence.source}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.5rem', fontSize: '0.78rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Reputation: </span>
                    {renderReputationBadge(data.threat_intelligence.reputation)}
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Confidence: </span>
                    <span style={{ color: '#fff', fontWeight: 600 }}>{formatPercentage(data.threat_intelligence.confidence)}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Categories: </span>
                    <span style={{ color: 'var(--accent-cyan)' }}>
                      {data.threat_intelligence.categories && data.threat_intelligence.categories.length > 0
                        ? data.threat_intelligence.categories.join(', ')
                        : 'None'}
                    </span>
                  </div>
                </div>
                {data.threat_intelligence.notes && (
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontStyle: 'italic' }}>
                    Note: {data.threat_intelligence.notes}
                  </div>
                )}
              </div>
            )}

            {/* Related Alert Info */}
            {data.related_alert && (
              <div
                style={{
                  backgroundColor: 'rgba(239, 68, 68, 0.05)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '0.5rem',
                }}
              >
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Linked Security Alert</div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#fff' }}>
                    Alert #{data.related_alert.alert_id} &bull; {data.related_alert.alert_type}
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                    Action: {data.related_alert.recommended_action}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span
                    style={{
                      fontSize: '0.72rem',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(255,255,255,0.1)',
                      color: '#fff',
                      fontWeight: 700,
                    }}
                  >
                    Status: {data.related_alert.status}
                  </span>
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* Modal Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.5rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.85rem' }}>
          <button onClick={onClose} className="btn-primary" style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
