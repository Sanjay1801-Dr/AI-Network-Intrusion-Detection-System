import React from 'react';
import { RefreshCw, ShieldCheck, Radio, User, LogOut, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Header({ backendHealth, isChecking, checkHealth, wsStatus = 'DISCONNECTED' }) {
  const { user, role, logout } = useAuth();
  const isHealthy = backendHealth && backendHealth.status === 'healthy';

  const getWsColor = () => {
    switch (wsStatus) {
      case 'CONNECTED':
        return 'var(--status-healthy)';
      case 'CONNECTING':
      case 'RECONNECTING':
        return 'var(--status-medium)';
      default:
        return 'var(--status-critical)';
    }
  };

  const getRoleBadgeStyle = (roleName) => {
    switch (roleName) {
      case 'ADMIN':
        return {
          backgroundColor: 'rgba(168, 85, 247, 0.15)',
          border: '1px solid rgba(168, 85, 247, 0.4)',
          color: '#c084fc',
        };
      case 'ANALYST':
        return {
          backgroundColor: 'rgba(0, 242, 254, 0.12)',
          border: '1px solid rgba(0, 242, 254, 0.35)',
          color: 'var(--accent-cyan)',
        };
      case 'VIEWER':
      default:
        return {
          backgroundColor: 'rgba(148, 163, 184, 0.15)',
          border: '1px solid rgba(148, 163, 184, 0.35)',
          color: '#cbd5e1',
        };
    }
  };

  return (
    <header
      style={{
        height: '68px',
        backgroundColor: 'rgba(13, 19, 31, 0.85)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
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
      {/* Title & Phase Tag */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
          <ShieldCheck size={20} color="var(--accent-cyan)" />
          <span style={{ fontWeight: 600, color: '#fff' }}>AI-Based Network Intrusion Detection System</span>
        </div>
        <span style={{ color: 'var(--border-subtle)' }}>|</span>
        <span
          style={{
            fontSize: '0.72rem',
            padding: '0.2rem 0.55rem',
            borderRadius: '4px',
            backgroundColor: 'rgba(0, 242, 254, 0.1)',
            color: 'var(--accent-cyan)',
            fontWeight: 700,
            letterSpacing: '0.04em',
            border: '1px solid rgba(0, 242, 254, 0.25)',
          }}
        >
          PHASE 9 SECURE RBAC
        </span>
      </div>

      {/* Telemetry & Authenticated Operator Menu */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        
        {/* Connection Status Telemetry (REST + WebSocket) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          {/* WebSocket Stream Indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.35rem 0.7rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(0, 0, 0, 0.35)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <Radio size={13} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>WS:</span>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: getWsColor(),
                boxShadow: `0 0 8px ${getWsColor()}`,
              }}
            />
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: getWsColor() }}>
              {wsStatus}
            </span>
          </div>

          {/* FastAPI REST Status */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.55rem',
              padding: '0.35rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(0, 0, 0, 0.35)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>API:</span>
            {backendHealth ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: isHealthy ? 'var(--status-healthy)' : 'var(--status-medium)',
                    boxShadow: `0 0 8px ${isHealthy ? 'var(--status-healthy)' : 'var(--status-medium)'}`,
                  }}
                />
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: isHealthy ? 'var(--status-healthy)' : 'var(--status-medium)' }}>
                  {isHealthy ? 'READY' : 'DEGRADED'}
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
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--status-critical)' }}>
                  OFFLINE
                </span>
              </div>
            )}

            <button
              onClick={checkHealth}
              disabled={isChecking}
              title="Manual health refresh"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: isChecking ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                padding: '0.15rem',
                marginLeft: '0.15rem',
                transition: 'color 0.15s ease',
              }}
            >
              <RefreshCw
                size={12}
                style={{
                  animation: isChecking ? 'spin 1s linear infinite' : 'none',
                  opacity: isChecking ? 0.7 : 1,
                }}
              />
            </button>
          </div>
        </div>

        {/* Vertical Divider */}
        <span style={{ color: 'var(--border-subtle)' }}>|</span>

        {/* Authenticated Operator Info */}
        {user && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              backgroundColor: 'rgba(0, 0, 0, 0.4)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.35rem 0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div
                style={{
                  width: '26px',
                  height: '26px',
                  borderRadius: '50%',
                  backgroundColor: 'rgba(0, 242, 254, 0.15)',
                  border: '1px solid rgba(0, 242, 254, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <User size={14} color="var(--accent-cyan)" />
              </div>
              <span style={{ fontSize: '0.84rem', fontWeight: 600, color: '#ffffff' }}>
                {user.username}
              </span>
            </div>

            {/* Role Badge */}
            <span
              style={{
                fontSize: '0.7rem',
                fontWeight: 700,
                letterSpacing: '0.05em',
                padding: '0.18rem 0.5rem',
                borderRadius: '4px',
                ...getRoleBadgeStyle(role),
              }}
            >
              {role}
            </span>

            {/* Logout Action */}
            <button
              onClick={logout}
              title="Logout session"
              className="preset-btn"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                fontSize: '0.75rem',
                padding: '0.25rem 0.6rem',
                backgroundColor: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#ef4444',
                fontWeight: 600,
                marginLeft: '0.25rem',
              }}
            >
              <LogOut size={12} />
              <span>Logout</span>
            </button>
          </div>
        )}

      </div>
    </header>
  );
}
