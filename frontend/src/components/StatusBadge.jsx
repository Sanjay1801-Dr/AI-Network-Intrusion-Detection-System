import React from 'react';

/**
 * StatusBadge component for SOC alerts, risk levels, threat indicators, and system health.
 * Provides accessible, high-contrast, visually distinguishable semantic styling.
 * 
 * @param {Object} props
 * @param {string} props.status - Text label to display
 * @param {'status'|'severity'|'risk'|'threat'} [props.type='status'] - Badge semantic type
 * @param {string} [props.className] - Optional custom class
 */
export default function StatusBadge({ status, type = 'status', className = '' }) {
  const norm = String(status || '').toUpperCase().trim();

  let bg = 'rgba(156, 163, 175, 0.15)';
  let color = '#9ca3af';
  let border = 'rgba(156, 163, 175, 0.3)';

  if (type === 'risk' || type === 'severity') {
    switch (norm) {
      case 'CRITICAL':
        bg = 'rgba(239, 68, 68, 0.18)';
        color = '#ef4444';
        border = 'rgba(239, 68, 68, 0.4)';
        break;
      case 'HIGH':
        bg = 'rgba(249, 115, 22, 0.18)';
        color = '#f97316';
        border = 'rgba(249, 115, 22, 0.4)';
        break;
      case 'MEDIUM':
        bg = 'rgba(245, 158, 11, 0.18)';
        color = '#f59e0b';
        border = 'rgba(245, 158, 11, 0.4)';
        break;
      case 'LOW':
        bg = 'rgba(59, 130, 246, 0.18)';
        color = '#60a5fa';
        border = 'rgba(59, 130, 246, 0.4)';
        break;
      default:
        break;
    }
  } else if (type === 'threat') {
    if (norm === 'BENIGN' || norm === 'NORMAL') {
      bg = 'rgba(16, 185, 129, 0.15)';
      color = '#10b981';
      border = 'rgba(16, 185, 129, 0.35)';
    } else {
      bg = 'rgba(239, 68, 68, 0.18)';
      color = '#f87171';
      border = 'rgba(239, 68, 68, 0.4)';
    }
  } else {
    // Generic status or health badge
    switch (norm) {
      case 'HEALTHY':
      case 'ONLINE':
      case 'CONNECTED':
      case 'READY':
      case 'RESOLVED':
      case 'NORMAL':
        bg = 'rgba(16, 185, 129, 0.15)';
        color = '#10b981';
        border = 'rgba(16, 185, 129, 0.35)';
        break;
      case 'DEGRADED':
      case 'INVESTIGATING':
      case 'ACKNOWLEDGED':
      case 'WARNING':
      case 'CONNECTING':
      case 'RECONNECTING':
        bg = 'rgba(245, 158, 11, 0.15)';
        color = '#f59e0b';
        border = 'rgba(245, 158, 11, 0.35)';
        break;
      case 'UNHEALTHY':
      case 'OFFLINE':
      case 'DISCONNECTED':
      case 'ANOMALOUS':
      case 'CRITICAL':
        bg = 'rgba(239, 68, 68, 0.18)';
        color = '#ef4444';
        border = 'rgba(239, 68, 68, 0.4)';
        break;
      case 'NEW':
      case 'DETECTED':
        bg = 'rgba(0, 242, 254, 0.15)';
        color = '#00f2fe';
        border = 'rgba(0, 242, 254, 0.35)';
        break;
      case 'FALSE_POSITIVE':
        bg = 'rgba(156, 163, 175, 0.15)';
        color = '#d1d5db';
        border = 'rgba(156, 163, 175, 0.3)';
        break;
      default:
        break;
    }
  }

  return (
    <span
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.22rem 0.6rem',
        borderRadius: '4px',
        fontSize: '0.72rem',
        fontWeight: 700,
        letterSpacing: '0.04em',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {status || 'UNKNOWN'}
    </span>
  );
}
