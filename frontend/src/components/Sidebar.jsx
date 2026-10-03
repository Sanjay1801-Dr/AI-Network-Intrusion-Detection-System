import React from 'react';
import { Shield, AlertTriangle, Activity, Cpu, Database, History, FileText, BarChart3, ShieldAlert, FileDown, Crosshair } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', subtitle: 'SOC Overview', icon: Activity },
    { id: 'hunting', label: 'Threat Hunting', subtitle: 'Search & Correlation', icon: Crosshair },
    { id: 'analytics', label: 'Security Analytics', subtitle: 'Threat Intel & KPIs', icon: BarChart3 },
    { id: 'incidents', label: 'Incident Response', subtitle: 'SOC Cases & Triage', icon: ShieldAlert },
    { id: 'reports', label: 'Security Reports', subtitle: 'Executive & Evidence', icon: FileDown },
    { id: 'predict', label: 'AI Prediction', subtitle: 'Flow Inference', icon: Cpu },
    { id: 'history', label: 'Prediction History', subtitle: 'Inference Records', icon: History },
    { id: 'alerts', label: 'Security Alerts', subtitle: 'Triage Queue', icon: AlertTriangle },
    { id: 'audit', label: 'Security Audit Logs', subtitle: 'Compliance Trail', icon: FileText },
  ];

  return (
    <aside
      style={{
        width: '260px',
        backgroundColor: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        height: '100vh',
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.85rem',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div
          style={{
            width: '38px',
            height: '38px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-glow-cyan)',
          }}
        >
          <Shield size={20} color="#0a0e17" strokeWidth={2.5} />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: '1.05rem', color: '#fff', letterSpacing: '-0.02em' }}>
            NIDS <span style={{ color: 'var(--accent-cyan)', fontSize: '0.8rem' }}>AI CORE</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Defensive SOC Engine</div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ padding: '1.25rem 0.85rem', flex: 1 }}>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0 0.65rem 0.65rem', fontWeight: 600 }}>
          Navigation
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.85rem',
                  width: '100%',
                  padding: '0.75rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isActive ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                  color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  border: isActive ? '1px solid var(--border-active)' : '1px solid transparent',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease-in-out',
                }}
              >
                <Icon size={18} color={isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.88rem', fontWeight: isActive ? 600 : 500, color: isActive ? '#fff' : 'inherit' }}>
                    {item.label}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {item.subtitle}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Footer Info */}
      <div
        style={{
          padding: '1.25rem',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'rgba(0,0,0,0.2)',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
          <Database size={14} color="var(--accent-cyan)" />
          <span style={{ color: 'var(--text-secondary)' }}>SQLite (Local Dev)</span>
        </div>
        <div>AI-NIDS &bull; Phase 16 Threat Hunting</div>
      </div>
    </aside>
  );
}
