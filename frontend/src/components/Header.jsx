import React from 'react';
import { RefreshCw, CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';
import StatusBadge from './StatusBadge';

export default function Header({ backendHealth, isChecking, checkHealth }) {
  return (
    <header
      style={{
        height: '68px',
        backgroundColor: 'rgba(13, 19, 31, 0.8)',
        backdropFilter: 'blur(10px)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 2rem',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
          <ShieldCheck size={18} color="var(--accent-cyan)" />
          <span>Defensive Network Monitoring Engine</span>
        </div>
        <span style={{ color: 'var(--border-subtle)' }}>|</span>
        <span
          style={{
            fontSize: '0.75rem',
            padding: '0.2rem 0.6rem',
            borderRadius: '4px',
            backgroundColor: 'rgba(0, 242, 254, 0.1)',
            color: 'var(--accent-cyan)',
            fontWeight: 600,
          }}
        >
          PHASE 1 SKELETON
        </span>
      </div>

      {/* Backend Status Telemetry */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
            padding: '0.4rem 0.85rem',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>FastAPI:</span>
          {backendHealth ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: backendHealth.status === 'healthy' ? 'var(--status-healthy)' : 'var(--status-medium)',
                  boxShadow: `0 0 8px ${backendHealth.status === 'healthy' ? 'var(--status-healthy)' : 'var(--status-medium)'}`,
                }}
              />
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fff' }}>
                {backendHealth.status === 'healthy' ? 'CONNECTED' : 'DEGRADED'}
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                ({backendHealth.version || 'v1.0.0'})
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--status-critical)',
                  boxShadow: '0 0 8px var(--status-critical)',
                }}
              />
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--status-critical)' }}>
                DISCONNECTED
              </span>
            </div>
          )}

          <button
            onClick={checkHealth}
            disabled={isChecking}
            title="Refresh backend status"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: '0.2rem',
              marginLeft: '0.25rem',
            }}
          >
            <RefreshCw size={13} style={{ animation: isChecking ? 'spin 1s linear infinite' : 'none' }} />
          </button>
        </div>
      </div>
    </header>
  );
}
