import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  CheckCircle2,
  RefreshCw,
  Plus,
  Search,
  ChevronLeft,
  ChevronRight,
  User,
  Filter,
  X,
} from 'lucide-react';
import api from '../services/api';
import StatusBadge from '../components/StatusBadge';
import IncidentDetails from '../components/IncidentDetails';
import { formatDateTime } from '../utils/formatters';
import { useAuth } from '../context/AuthContext';
import websocketService from '../services/websocket';

export default function Incidents() {
  const { role } = useAuth();
  const canManage = role === 'ADMIN' || role === 'ANALYST';

  const [incidents, setIncidents] = useState([]);
  const [summary, setSummary] = useState(null);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(20);
  const [offset, setOffset] = useState(0);

  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Modals
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New Incident Form State
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState('HIGH');
  const [newCategory, setNewCategory] = useState('');
  const [newAlertId, setNewAlertId] = useState('');
  const [newAssignedTo, setNewAssignedTo] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);

  const fetchIncidents = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getIncidents({
        status: statusFilter || null,
        severity: severityFilter || null,
        category: categoryFilter || null,
        limit,
        offset,
      });
      setIncidents(data.items || []);
      setTotal(data.total || 0);

      const sum = await api.getIncidentSummary();
      setSummary(sum);
    } catch (err) {
      setError(err.message || 'Failed to load incident cases.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [limit, offset, statusFilter, severityFilter, categoryFilter]);

  // Subscribe to real-time incident events from WebSocket
  useEffect(() => {
    const unsub = websocketService.subscribe((event) => {
      if (!event || !event.event_type) return;
      if (
        event.event_type === 'incident_created' ||
        event.event_type === 'incident_status_changed' ||
        event.event_type === 'incident_assigned' ||
        event.event_type === 'incident_note_added'
      ) {
        // Refresh incident list and summary smoothly
        fetchIncidents();
      }
    });

    return () => unsub();
  }, [limit, offset, statusFilter, severityFilter, categoryFilter]);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    setIsSubmitting(true);
    setCreateError(null);
    try {
      const payload = {
        title: newTitle.trim(),
        description: newDescription.trim() || undefined,
        severity: newSeverity || undefined,
        category: newCategory.trim() || undefined,
        alert_id: newAlertId ? Number(newAlertId) : undefined,
        assigned_to: newAssignedTo.trim() || undefined,
      };

      const created = await api.createIncident(payload);
      setShowCreateModal(false);
      // Reset form
      setNewTitle('');
      setNewDescription('');
      setNewCategory('');
      setNewAlertId('');
      setNewAssignedTo('');
      // Open created case
      setSelectedIncidentId(created.id);
      fetchIncidents();
    } catch (err) {
      setCreateError(err.message || 'Failed to create incident case.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <ShieldAlert color="var(--status-critical)" size={28} />
            SOC Incident Response Management
          </h1>
          <p className="page-subtitle">
            Structured incident triage workflow, containment lifecycle, analyst case notes, and unified event history.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchIncidents}
            disabled={isLoading}
            className="preset-btn"
            title="Refresh incidents"
          >
            <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>

          {canManage && (
            <button
              onClick={() => {
                setCreateError(null);
                setShowCreateModal(true);
              }}
              className="btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.55rem 1.1rem' }}
            >
              <Plus size={16} />
              Open New Case
            </button>
          )}
        </div>
      </div>

      {/* KPI Ribbon */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="section-card glass-panel" style={{ margin: 0, padding: '1rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Open Incidents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
            {summary?.open_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Pending triage / unacknowledged
          </div>
        </div>

        <div className="section-card glass-panel" style={{ margin: 0, padding: '1rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Active Investigations
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#38bdf8', marginTop: '0.25rem' }}>
            {summary?.investigating_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Under active forensic analysis
          </div>
        </div>

        <div className="section-card glass-panel" style={{ margin: 0, padding: '1rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Critical Incidents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--status-critical)', marginTop: '0.25rem' }}>
            {summary?.critical_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Severe network intrusions
          </div>
        </div>

        <div className="section-card glass-panel" style={{ margin: 0, padding: '1rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            High Incidents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--status-high)', marginTop: '0.25rem' }}>
            {summary?.high_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Elevated priority alerts
          </div>
        </div>

        <div className="section-card glass-panel" style={{ margin: 0, padding: '1rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Resolved Cases
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--status-healthy)', marginTop: '0.25rem' }}>
            {summary?.resolved_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            {summary?.recently_resolved ?? 0} resolved in last 24h
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div
        className="section-card glass-panel"
        style={{
          margin: '0 0 1.25rem 0',
          padding: '0.85rem 1.25rem',
          display: 'flex',
          flexWrap: 'wrap',
          gap: '1rem',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', gap: '0.85rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <Filter size={14} color="var(--accent-cyan)" />
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setOffset(0);
              }}
              style={{
                backgroundColor: 'rgba(0,0,0,0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
              }}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setOffset(0);
              }}
              style={{
                backgroundColor: 'rgba(0,0,0,0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
              }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <span>Category:</span>
            <input
              type="text"
              placeholder="e.g. DoS, Port Scan"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setOffset(0);
              }}
              style={{
                backgroundColor: 'rgba(0,0,0,0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                width: '140px',
              }}
            />
          </div>
        </div>

        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
          Showing <strong>{incidents.length}</strong> of <strong>{total}</strong> cases
        </div>
      </div>

      {/* Error Alert Box */}
      {error && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.25rem' }}>
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Incidents Table Card */}
      <div className="section-card glass-panel" style={{ padding: '0.5rem' }}>
        {isLoading && incidents.length === 0 ? (
          <div style={{ padding: '3.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem', width: '32px', height: '32px' }} />
            <div>Loading incident registry...</div>
          </div>
        ) : incidents.length === 0 ? (
          <div style={{ padding: '4rem 2rem', textAlign: 'center' }}>
            <ShieldAlert size={42} color="var(--text-muted)" style={{ margin: '0 auto 1rem', opacity: 0.6 }} />
            <h3 style={{ color: '#fff', fontSize: '1.1rem', fontWeight: 600 }}>No Incidents Match Active Filters</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', maxWidth: '420px', margin: '0.5rem auto 1.5rem' }}>
              No security incident cases were found matching your query. Create a new case above or from any security alert.
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="ids-table">
              <thead>
                <tr>
                  <th>Case Key</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Status</th>
                  <th>Assigned To</th>
                  <th>Source IP</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((row) => (
                  <tr key={row.id}>
                    <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                      {row.incident_key}
                    </td>
                    <td style={{ fontWeight: 600, color: '#fff', maxWidth: '280px' }} title={row.title}>
                      {row.title}
                    </td>
                    <td>
                      <StatusBadge status={row.severity} type="risk" />
                    </td>
                    <td>
                      <span style={{ fontSize: '0.78rem', color: '#e2e8f0' }}>{row.category}</span>
                    </td>
                    <td>
                      <StatusBadge status={row.status} type="status" />
                    </td>
                    <td style={{ fontSize: '0.8rem', color: row.assigned_to ? '#fff' : 'var(--text-muted)' }}>
                      {row.assigned_to ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                          <User size={12} color="var(--accent-cyan)" />
                          {row.assigned_to}
                        </span>
                      ) : (
                        'Unassigned'
                      )}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.8rem', color: row.source_ip ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                      {row.source_ip || '-'}
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                      {formatDateTime(row.created_at)}
                    </td>
                    <td>
                      <button
                        onClick={() => setSelectedIncidentId(row.id)}
                        className="preset-btn"
                        style={{
                          padding: '0.25rem 0.65rem',
                          fontSize: '0.75rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                          color: 'var(--accent-cyan)',
                          borderColor: 'var(--border-active)',
                        }}
                      >
                        <Search size={12} />
                        View Case
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {total > 0 && (
          <div
            style={{
              padding: '1rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              borderTop: '1px solid var(--border-subtle)',
              flexWrap: 'wrap',
              gap: '1rem',
            }}
          >
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <button
                onClick={() => setOffset(Math.max(0, offset - limit))}
                disabled={offset === 0}
                className="preset-btn"
                style={{ padding: '0.35rem 0.75rem', opacity: offset === 0 ? 0.4 : 1 }}
              >
                <ChevronLeft size={16} />
                Previous
              </button>

              <button
                onClick={() => setOffset(offset + limit)}
                disabled={offset + limit >= total}
                className="preset-btn"
                style={{ padding: '0.35rem 0.75rem', opacity: offset + limit >= total ? 0.4 : 1 }}
              >
                Next
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Incident Details Modal */}
      {selectedIncidentId && (
        <IncidentDetails
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onIncidentUpdated={() => fetchIncidents()}
        />
      )}

      {/* New Incident Creation Modal */}
      {showCreateModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(5, 8, 16, 0.85)',
            backdropFilter: 'blur(8px)',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowCreateModal(false);
          }}
        >
          <div
            className="section-card glass-panel"
            style={{
              width: '100%',
              maxWidth: '560px',
              margin: 0,
              padding: '1.5rem',
              border: '1px solid var(--border-active)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={20} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff' }}>Open New Incident Case</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {createError && (
              <div className="alert-box alert-error" style={{ marginBottom: '1rem' }}>
                <AlertTriangle size={16} />
                <span>{createError}</span>
              </div>
            )}

            <form onSubmit={handleCreateSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div className="form-field">
                <label>Incident Case Title *</label>
                <input
                  type="text"
                  placeholder="e.g. Volumetric SYN Flood Targeting DMZ Web Gateway"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-field">
                  <label>Severity Level</label>
                  <select value={newSeverity} onChange={(e) => setNewSeverity(e.target.value)}>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="form-field">
                  <label>Threat Category (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. DoS, Port Scan"
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-field">
                  <label>Correlate Alert ID (Optional)</label>
                  <input
                    type="number"
                    placeholder="e.g. 5"
                    value={newAlertId}
                    onChange={(e) => setNewAlertId(e.target.value)}
                  />
                </div>

                <div className="form-field">
                  <label>Assignee Username (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. analyst_sec"
                    value={newAssignedTo}
                    onChange={(e) => setNewAssignedTo(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-field">
                <label>Description & Scope</label>
                <textarea
                  rows={3}
                  placeholder="Add case context, impacted subnets, or detected attack telemetry..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(0,0,0,0.4)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    color: '#fff',
                    padding: '0.6rem',
                    fontSize: '0.82rem',
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="preset-btn"
                  style={{ padding: '0.5rem 1rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !newTitle.trim()}
                  className="btn-primary"
                  style={{ padding: '0.5rem 1.25rem' }}
                >
                  {isSubmitting ? 'Creating Case...' : 'Create Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
