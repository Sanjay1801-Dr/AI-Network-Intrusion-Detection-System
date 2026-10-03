import React from 'react';

export default function StatusBadge({ status, type = 'status' }) {
  const norm = String(status || '').toUpperCase();

  let bg = 'rgba(156, 163, 175, 0.15)';
  let color = '#9ca3af';
  let border = 'rgba(156, 163, 175, 0.3)';

  if (type === 'severity') {
    switch (norm) {
      case 'CRITICAL':
        bg = 'rgba(239, 68, 68, 0.15)';
        color = '#ef4444';
        border = 'rgba(239, 68, 68, 0.35)';
        break;
      case 'HIGH':
        bg = 'rgba(249, 115, 22, 0.15)';
        color = '#f97316';
        border = 'rgba(249, 115, 22, 0.35)';
        break;
      case 'MEDIUM':
        bg = 'rgba(245, 158, 11, 0.15)';
        color = '#f59e0b';
        border = 'rgba(245, 158, 11, 0.35)';
        break;
      case 'LOW':
        bg = 'rgba(59, 130, 246, 0.15)';
        color = '#60a5fa';
        border = 'rgba(59, 130, 246, 0.35)';
        break;
      default:
        break;
    }
  } else {
    switch (norm) {
      case 'HEALTHY':
      case 'ONLINE':
      case 'CONNECTED':
      case 'READY':
      case 'RESOLVED':
        bg = 'rgba(16, 185, 129, 0.15)';
        color = '#10b981';
        border = 'rgba(16, 185, 129, 0.35)';
        break;
      case 'DEGRADED':
      case 'INVESTIGATING':
      case 'ACKNOWLEDGED':
        bg = 'rgba(245, 158, 11, 0.15)';
        color = '#f59e0b';
        border = 'rgba(245, 158, 11, 0.35)';
        break;
      case 'UNHEALTHY':
      case 'OFFLINE':
      case 'DISCONNECTED':
        bg = 'rgba(239, 68, 68, 0.15)';
        color = '#ef4444';
        border = 'rgba(239, 68, 68, 0.35)';
        break;
      case 'NEW':
      case 'DETECTED':
        bg = 'rgba(0, 242, 254, 0.15)';
        color = '#00f2fe';
        border = 'rgba(0, 242, 254, 0.35)';
        break;
      default:
        break;
    }
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.2rem 0.55rem',
        borderRadius: '4px',
        fontSize: '0.74rem',
        fontWeight: 600,
        letterSpacing: '0.04em',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        textTransform: 'uppercase',
      }}
    >
      {status}
    </span>
  );
}
