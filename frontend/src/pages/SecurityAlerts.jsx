import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  Filter,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Eye,
  CheckCircle,
  Check,
  ShieldCheck,
  Radio,
} from 'lucide-react';
import api from '../services/api';
import websocketService from '../services/websocket';
import StatusBadge from '../components/StatusBadge';
import AlertDetailsModal from '../components/AlertDetailsModal';
import IncidentDetails from '../components/IncidentDetails';
import { formatDateTime, formatScore, formatPercentage } from '../utils/formatters';
import { ALERT_SEVERITIES, ALERT_STATUSES, PAGE_LIMIT_OPTIONS } from '../types';
import { useAuth } from '../context/AuthContext';

export default function SecurityAlerts() {
  const { role } = useAuth();
  const canManageAlerts = role === 'ADMIN' || role === 'ANALYST';
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(20);
  const [offset, setOffset] = useState(0);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);

  // Phase 8: Alert Lifecycle & Investigation State
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [createdIncidentId, setCreatedIncidentId] = useState(null);

  // Fetch paginated alert data from REST API
  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const data = await api.getAlerts({
        limit,
        offset,
        severity: severityFilter,
        status: statusFilter,
      });
      setAlerts(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      setApiError(err.message || 'Failed to retrieve security alerts.');
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, severityFilter, statusFilter]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Phase 8 Real-time WebSocket synchronization for alert lifecycle events
  useEffect(() => {
    const unsub = websocketService.subscribe((event) => {
      if (!event || !event.event_type) return;

      if (event.event_type === 'alert_acknowledged' || event.event_type === 'alert_resolved') {
        const payload = event.data;
        if (!payload || !payload.alert_id) return;

        // Synchronize corresponding alert in active table list in-place
        setAlerts((prevAlerts) =>
          prevAlerts.map((alt) => {
            if (alt.id === payload.alert_id) {
              return {
                ...alt,
                status: payload.status,
                acknowledged_at: payload.acknowledged_at !== undefined ? payload.acknowledged_at : alt.acknowledged_at,
                resolved_at: payload.resolved_at !== undefined ? payload.resolved_at : alt.resolved_at,
              };
            }
            return alt;
          })
        );

        // Synchronize open investigation modal if inspecting this alert
        setSelectedAlert((prev) => {
          if (prev && prev.id === payload.alert_id) {
            return {
              ...prev,
              status: payload.status,
              acknowledged_at: payload.acknowledged_at !== undefined ? payload.acknowledged_at : prev.acknowledged_at,
              resolved_at: payload.resolved_at !== undefined ? payload.resolved_at : prev.resolved_at,
            };
          }
          return prev;
        });
      }
    });

    return () => unsub();
  }, []);

  // Pagination calculations
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const handlePrevPage = () => {
    if (offset >= limit) {
      setOffset(offset - limit);
    }
  };

  const handleNextPage = () => {
    if (offset + limit < total) {
      setOffset(offset + limit);
    }
  };

  const handleSeverityChange = (e) => {
    setSeverityFilter(e.target.value);
    setOffset(0);
  };

  const handleStatusChange = (e) => {
    setStatusFilter(e.target.value);
    setOffset(0);
  };

  const handleLimitChange = (e) => {
    setLimit(Number(e.target.value));
    setOffset(0);
  };

  // Phase 8: Lifecycle Actions
  const handleAcknowledge = async (alertId) => {
    if (actionLoadingId) return; // Prevent duplicate requests
    setActionLoadingId(alertId);
    setActionFeedback(null);

    try {
      const updated = await api.acknowledgeAlert(alertId);
      
      // Update local state immediately from API response
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, ...updated } : a))
      );
      setSelectedAlert((prev) => (prev && prev.id === alertId ? { ...prev, ...updated } : prev));
      
      setActionFeedback({
        type: 'success',
        message: `Alert #${alertId} successfully transitioned to ACKNOWLEDGED.`,
      });
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err.message || `Failed to acknowledge alert #${alertId}.`,
      });
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleResolve = async (alertId) => {
    if (actionLoadingId) return; // Prevent duplicate requests
    setActionLoadingId(alertId);
    setActionFeedback(null);

    try {
      const updated = await api.resolveAlert(alertId);

      // Update local state immediately from API response
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, ...updated } : a))
      );
      setSelectedAlert((prev) => (prev && prev.id === alertId ? { ...prev, ...updated } : prev));

      setActionFeedback({
        type: 'success',
        message: `Alert #${alertId} successfully marked as RESOLVED.`,
      });
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err.message || `Failed to resolve alert #${alertId}.`,
      });
    } finally {
      setActionLoadingId(null);
    }
  };

  // Open investigation details modal and fetch full telemetry
  const handleInvestigate = async (alert) => {
    setSelectedAlert(alert);
    setActionFeedback(null);

    try {
      const fullDetails = await api.getAlert(alert.id);
      setSelectedAlert(fullDetails);
    } catch {
      // Keep existing row alert data if detailed query has transient failure
    }
  };

  // Phase 14: Create SOC Incident from Alert
  const handleCreateIncidentFromAlert = async (alert) => {
    setActionFeedback(null);
    try {
      const res = await api.createIncident({
        title: `Incident: ${alert.threat_label} on Port ${alert.destination_port || 'Unknown'}`,
        description: `Correlated from Alert #${alert.id} (${alert.threat_label}) with ${alert.severity} severity. Recommended action: ${alert.recommended_action || 'Triage immediately'}.`,
        alert_id: alert.id,
        severity: alert.severity,
        category: alert.threat_label,
      });
      setCreatedIncidentId(res.id);
      setActionFeedback({
        type: 'success',
        message: `Created Incident Case ${res.incident_key} from Alert #${alert.id}.`,
      });
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err.message || `Failed to create incident from Alert #${alert.id}.`,
      });
    }
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <AlertTriangle color="var(--status-critical)" size={28} />
            Security Incident Alerts
          </h1>
          <p className="page-subtitle">
            SOC incident response triage queue with real-time lifecycle tracking (Phase 8).
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <Radio size={14} color="var(--accent-cyan)" />
          <span>Real-Time WebSocket Sync Active</span>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionFeedback && (
        <div
          className={`alert-box ${actionFeedback.type === 'success' ? 'alert-success' : 'alert-error'}`}
          style={{
            marginBottom: '1.25rem',
            padding: '0.75rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderRadius: '6px',
            backgroundColor: actionFeedback.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: actionFeedback.type === 'success' ? '1px solid rgba(16, 185, 129, 0.35)' : '1px solid rgba(239, 68, 68, 0.35)',
            color: actionFeedback.type === 'success' ? '#10b981' : '#ef4444',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {actionFeedback.type === 'success' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.8rem' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter and Control Toolbar */}
      <div
        className="glass-panel"
        style={{
          padding: '1rem 1.25rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
          
          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <Filter size={15} color="var(--accent-cyan)" />
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={handleSeverityChange}
              style={{
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                outline: 'none',
              }}
            >
              {ALERT_SEVERITIES.map((sev) => (
                <option key={sev} value={sev}>
                  {sev === 'ALL' ? 'All Severities' : sev}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={handleStatusChange}
              style={{
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                outline: 'none',
              }}
            >
              {ALERT_STATUSES.map((st) => (
                <option key={st} value={st}>
                  {st === 'ALL' ? 'All Statuses' : st}
                </option>
              ))}
            </select>
          </div>

          {/* Page Limit */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <span>Page Size:</span>
            <select
              value={limit}
              onChange={handleLimitChange}
              style={{
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                outline: 'none',
              }}
            >
              {PAGE_LIMIT_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>

        </div>

        {/* Refresh Action */}
        <button
          onClick={fetchAlerts}
          disabled={isLoading}
          className="preset-btn"
          title="Refresh alerts"
        >
          <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
          Refresh
        </button>
      </div>

      {/* Error Alert Box */}
      {apiError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Failed to Retrieve Alerts</div>
            <div style={{ fontSize: '0.85rem' }}>{apiError}</div>
          </div>
          <button
            onClick={fetchAlerts}
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

      {/* Main Alerts Table Card */}
      <div className="section-card glass-panel" style={{ padding: '0.5rem' }}>
        
        {/* Loading Indicator */}
        {isLoading && (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem', width: '30px', height: '30px' }} />
            <div>Querying security alerts from database...</div>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !apiError && alerts.length === 0 && (
          <div style={{ padding: '4rem 2rem', textAlign: 'center' }}>
            <ShieldAlert size={40} color="var(--text-muted)" style={{ margin: '0 auto 1rem' }} />
            <h3 style={{ color: '#fff', fontSize: '1.1rem', fontWeight: 600 }}>No Security Alerts Found</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', maxWidth: '440px', margin: '0.5rem auto 1.5rem' }}>
              {severityFilter !== 'ALL' || statusFilter !== 'ALL'
                ? 'No alerts match the selected filters.'
                : 'No alerts have been recorded yet. Inferences with MEDIUM, HIGH, or CRITICAL risk automatically generate alerts here.'}
            </p>
          </div>
        )}

        {/* Table Content */}
        {!isLoading && !apiError && alerts.length > 0 && (
          <div className="table-responsive">
            <table className="ids-table">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Pred. ID</th>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Threat Label</th>
                  <th>Anomaly Score</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Recommended Action</th>
                  <th style={{ textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => {
                  const isActionBusy = actionLoadingId === alert.id;
                  const alertStatus = String(alert.status || 'NEW').toUpperCase();

                  return (
                    <tr key={alert.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                        #{alert.id}
                      </td>
                      <td className="font-mono" style={{ color: 'var(--text-muted)' }}>
                        {alert.prediction_id ? `#${alert.prediction_id}` : '-'}
                      </td>
                      <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                        {formatDateTime(alert.timestamp || alert.created_at)}
                      </td>
                      <td>
                        <StatusBadge status={alert.severity} type="severity" />
                      </td>
                      <td style={{ fontWeight: 600, color: '#fff' }}>
                        {alert.threat_label}
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.82rem' }}>
                        {formatScore(alert.anomaly_score)}
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.82rem' }}>
                        {formatPercentage(alert.confidence)}
                      </td>
                      <td>
                        <StatusBadge status={alert.status} type="status" />
                      </td>
                      <td
                        style={{
                          fontSize: '0.78rem',
                          color: 'var(--text-secondary)',
                          maxWidth: '220px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                        title={alert.recommended_action}
                      >
                        {alert.recommended_action}
                      </td>
                      
                      {/* Phase 8 Lifecycle Action Buttons */}
                      <td style={{ textAlign: 'center', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
                          
                          {/* Acknowledge Button (For NEW alerts only, ADMIN & ANALYST) */}
                          {canManageAlerts && alertStatus === 'NEW' && (
                            <button
                              onClick={() => handleAcknowledge(alert.id)}
                              disabled={isActionBusy}
                              className="preset-btn"
                              style={{
                                fontSize: '0.72rem',
                                padding: '0.25rem 0.55rem',
                                backgroundColor: 'rgba(245, 158, 11, 0.12)',
                                border: '1px solid rgba(245, 158, 11, 0.35)',
                                color: '#f59e0b',
                                fontWeight: 600,
                                cursor: isActionBusy ? 'not-allowed' : 'pointer',
                                opacity: isActionBusy ? 0.6 : 1,
                              }}
                              title="Acknowledge alert"
                            >
                              {isActionBusy ? '...' : 'Acknowledge'}
                            </button>
                          )}

                          {/* Resolve Button (For NEW or ACKNOWLEDGED alerts, ADMIN & ANALYST) */}
                          {canManageAlerts && (alertStatus === 'NEW' || alertStatus === 'ACKNOWLEDGED') && (
                            <button
                              onClick={() => handleResolve(alert.id)}
                              disabled={isActionBusy}
                              className="preset-btn"
                              style={{
                                fontSize: '0.72rem',
                                padding: '0.25rem 0.55rem',
                                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                                border: '1px solid rgba(16, 185, 129, 0.35)',
                                color: '#10b981',
                                fontWeight: 600,
                                cursor: isActionBusy ? 'not-allowed' : 'pointer',
                                opacity: isActionBusy ? 0.6 : 1,
                              }}
                              title="Resolve alert"
                            >
                              {isActionBusy ? '...' : 'Resolve'}
                            </button>
                          )}

                          {/* Terminal State Indicator (RESOLVED) */}
                          {alertStatus === 'RESOLVED' && (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                fontSize: '0.72rem',
                                color: '#10b981',
                                fontWeight: 600,
                                padding: '0.22rem 0.5rem',
                                borderRadius: '3px',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                              }}
                            >
                              <Check size={12} />
                              Resolved
                            </span>
                          )}

                          {/* Investigate Action Button */}
                          <button
                            onClick={() => handleInvestigate(alert)}
                            className="preset-btn"
                            style={{
                              fontSize: '0.72rem',
                              padding: '0.25rem 0.55rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                              backgroundColor: 'rgba(0, 242, 254, 0.08)',
                              border: '1px solid rgba(0, 242, 254, 0.25)',
                              color: 'var(--accent-cyan)',
                            }}
                            title="Investigate incident details"
                          >
                            <Eye size={12} />
                            Details
                          </button>

                          {/* Phase 14: Open Incident Case Action */}
                          {canManageAlerts && (
                            <button
                              onClick={() => handleCreateIncidentFromAlert(alert)}
                              className="preset-btn"
                              style={{
                                fontSize: '0.72rem',
                                padding: '0.25rem 0.55rem',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.3rem',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                border: '1px solid rgba(239, 68, 68, 0.35)',
                                color: 'var(--status-critical)',
                              }}
                              title="Open SOC incident case from this alert"
                            >
                              <ShieldAlert size={12} />
                              Case
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        {!isLoading && !apiError && total > 0 && (
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
              Showing alerts <strong>{offset + 1}</strong> to <strong>{Math.min(offset + limit, total)}</strong> of <strong>{total}</strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <button
                onClick={handlePrevPage}
                disabled={offset === 0}
                className="preset-btn"
                style={{
                  opacity: offset === 0 ? 0.4 : 1,
                  cursor: offset === 0 ? 'not-allowed' : 'pointer',
                  padding: '0.4rem 0.75rem',
                }}
              >
                <ChevronLeft size={16} />
                Previous
              </button>

              <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
              </span>

              <button
                onClick={handleNextPage}
                disabled={offset + limit >= total}
                className="preset-btn"
                style={{
                  opacity: offset + limit >= total ? 0.4 : 1,
                  cursor: offset + limit >= total ? 'not-allowed' : 'pointer',
                  padding: '0.4rem 0.75rem',
                }}
              >
                Next
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}

      </div>

      {/* Phase 8 Alert Details / Investigation Modal */}
      {selectedAlert && (
        <AlertDetailsModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onAcknowledge={handleAcknowledge}
          onResolve={handleResolve}
          actionLoadingId={actionLoadingId}
          canManageAlerts={canManageAlerts}
        />
      )}

      {/* Phase 14 Incident Details Modal */}
      {createdIncidentId && (
        <IncidentDetails
          incidentId={createdIncidentId}
          onClose={() => setCreatedIncidentId(null)}
          onIncidentUpdated={() => fetchAlerts()}
        />
      )}
    </div>
  );
}
