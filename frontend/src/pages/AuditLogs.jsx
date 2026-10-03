import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  RefreshCw,
  Filter,
  ChevronLeft,
  ChevronRight,
  Eye,
  ShieldAlert,
  AlertTriangle,
  Lock,
  User,
  X,
} from 'lucide-react';
import api from '../services/api';
import { formatDateTime } from '../utils/formatters';

const ACTION_OPTIONS = [
  { value: 'ALL', label: 'All Actions' },
  { value: 'LOGIN_SUCCESS', label: 'LOGIN_SUCCESS' },
  { value: 'LOGIN_FAILURE', label: 'LOGIN_FAILURE' },
  { value: 'LOGOUT', label: 'LOGOUT' },
  { value: 'ACCESS_DENIED', label: 'ACCESS_DENIED' },
  { value: 'PREDICTION_CREATED', label: 'PREDICTION_CREATED' },
  { value: 'ALERT_ACKNOWLEDGED', label: 'ALERT_ACKNOWLEDGED' },
  { value: 'ALERT_RESOLVED', label: 'ALERT_RESOLVED' },
  { value: 'WEBSOCKET_AUTH_SUCCESS', label: 'WEBSOCKET_AUTH_SUCCESS' },
  { value: 'WEBSOCKET_AUTH_FAILURE', label: 'WEBSOCKET_AUTH_FAILURE' },
  { value: 'RATE_LIMIT_EXCEEDED', label: 'RATE_LIMIT_EXCEEDED' },
  { value: 'SECURITY_ERROR', label: 'SECURITY_ERROR' },
];

const OUTCOME_OPTIONS = [
  { value: 'ALL', label: 'All Outcomes' },
  { value: 'SUCCESS', label: 'SUCCESS' },
  { value: 'FAILURE', label: 'FAILURE' },
  { value: 'DENIED', label: 'DENIED' },
];

const RESOURCE_OPTIONS = [
  { value: 'ALL', label: 'All Resources' },
  { value: 'AUTH', label: 'AUTH' },
  { value: 'ACCESS_CONTROL', label: 'ACCESS_CONTROL' },
  { value: 'PREDICTION', label: 'PREDICTION' },
  { value: 'ALERT', label: 'ALERT' },
  { value: 'WEBSOCKET', label: 'WEBSOCKET' },
  { value: 'RATE_LIMIT', label: 'RATE_LIMIT' },
  { value: 'SYSTEM', label: 'SYSTEM' },
];

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(20);
  const [offset, setOffset] = useState(0);
  const [usernameFilter, setUsernameFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState('ALL');
  const [resourceFilter, setResourceFilter] = useState('ALL');

  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);

  // Controlled fetch function (No automatic polling loops)
  const fetchAuditLogs = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const data = await api.getAuditLogs({
        limit,
        offset,
        username: usernameFilter,
        action: actionFilter,
        outcome: outcomeFilter,
        resource_type: resourceFilter,
      });
      setLogs(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      setApiError(err.message || 'Failed to retrieve security audit logs.');
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, usernameFilter, actionFilter, outcomeFilter, resourceFilter]);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    setOffset(0);
    fetchAuditLogs();
  };

  const handleResetFilters = () => {
    setUsernameFilter('');
    setActionFilter('ALL');
    setOutcomeFilter('ALL');
    setResourceFilter('ALL');
    setOffset(0);
  };

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit) || 1;

  const renderOutcomeBadge = (outcome) => {
    const norm = String(outcome || '').toUpperCase();
    if (norm === 'SUCCESS') {
      return (
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '0.2rem 0.55rem',
            borderRadius: '4px',
            fontSize: '0.72rem',
            fontWeight: 700,
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            color: '#10b981',
            border: '1px solid rgba(16, 185, 129, 0.3)',
          }}
        >
          SUCCESS
        </span>
      );
    }
    if (norm === 'DENIED') {
      return (
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '0.2rem 0.55rem',
            borderRadius: '4px',
            fontSize: '0.72rem',
            fontWeight: 700,
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            color: '#ef4444',
            border: '1px solid rgba(239, 68, 68, 0.3)',
          }}
        >
          DENIED
        </span>
      );
    }
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '0.2rem 0.55rem',
          borderRadius: '4px',
          fontSize: '0.72rem',
          fontWeight: 700,
          backgroundColor: 'rgba(245, 158, 11, 0.15)',
          color: '#f59e0b',
          border: '1px solid rgba(245, 158, 11, 0.3)',
        }}
      >
        {norm || 'FAILURE'}
      </span>
    );
  };

  const renderActionBadge = (action) => {
    let color = 'var(--accent-cyan)';
    let bg = 'rgba(0, 242, 254, 0.12)';
    let border = 'rgba(0, 242, 254, 0.25)';

    if (action.includes('DENIED') || action.includes('FAILURE')) {
      color = '#ef4444';
      bg = 'rgba(239, 68, 68, 0.12)';
      border = 'rgba(239, 68, 68, 0.25)';
    } else if (action.includes('RATE_LIMIT')) {
      color = '#f59e0b';
      bg = 'rgba(245, 158, 11, 0.12)';
      border = 'rgba(245, 158, 11, 0.25)';
    } else if (action.includes('RESOLVED')) {
      color = '#10b981';
      bg = 'rgba(16, 185, 129, 0.12)';
      border = 'rgba(16, 185, 129, 0.25)';
    } else if (action.includes('PREDICTION')) {
      color = 'var(--accent-blue)';
      bg = 'rgba(79, 172, 254, 0.12)';
      border = 'rgba(79, 172, 254, 0.25)';
    }

    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.2rem 0.5rem',
          borderRadius: '4px',
          fontSize: '0.72rem',
          fontWeight: 700,
          fontFamily: 'var(--font-mono)',
          color,
          backgroundColor: bg,
          border: `1px solid ${border}`,
        }}
      >
        {action}
      </span>
    );
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <FileText color="var(--accent-cyan)" size={28} />
            Security Audit Trail
          </h1>
          <p className="page-subtitle">
            Immutable chronological record of security operations, authentication events, access control denials, and operator lifecycle mutations.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchAuditLogs}
            disabled={isLoading}
            className="preset-btn"
            title="Refresh audit records"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}
          >
            <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* API Error Notification */}
      {apiError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Audit Query Notification</div>
            <div style={{ fontSize: '0.85rem' }}>{apiError}</div>
          </div>
          <button
            onClick={fetchAuditLogs}
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

      {/* Filter Control Bar */}
      <div className="filter-bar glass-panel" style={{ marginBottom: '1.5rem' }}>
        <form onSubmit={handleFilterSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
            <Filter size={16} />
            <span style={{ fontSize: '0.82rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Filters:
            </span>
          </div>

          {/* Username Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Username:</label>
            <input
              type="text"
              placeholder="Search user..."
              value={usernameFilter}
              onChange={(e) => setUsernameFilter(e.target.value)}
              className="filter-input"
              style={{
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                width: '140px',
              }}
            />
          </div>

          {/* Action Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Action:</label>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setOffset(0);
              }}
              className="filter-select"
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Outcome Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Outcome:</label>
            <select
              value={outcomeFilter}
              onChange={(e) => {
                setOutcomeFilter(e.target.value);
                setOffset(0);
              }}
              className="filter-select"
            >
              {OUTCOME_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Resource Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Resource:</label>
            <select
              value={resourceFilter}
              onChange={(e) => {
                setResourceFilter(e.target.value);
                setOffset(0);
              }}
              className="filter-select"
            >
              {RESOURCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', marginLeft: 'auto' }}>
            <button type="submit" className="preset-btn" style={{ fontSize: '0.8rem' }}>
              Apply
            </button>
            <button
              type="button"
              onClick={handleResetFilters}
              className="preset-btn"
              style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}
            >
              Reset
            </button>
          </div>
        </form>
      </div>

      {/* Audit Log Table */}
      <div className="section-card glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Operator</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Outcome</th>
                <th>HTTP / Path</th>
                <th>Details</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && logs.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '3rem' }}>
                    <div className="spinner" style={{ width: '28px', height: '28px', margin: '0 auto 0.75rem' }} />
                    <div style={{ color: 'var(--accent-cyan)', fontSize: '0.85rem' }}>Loading audit records...</div>
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '3.5rem' }}>
                    <Lock size={32} color="var(--text-muted)" style={{ margin: '0 auto 0.75rem', opacity: 0.5 }} />
                    <div style={{ fontWeight: 600, color: '#fff', marginBottom: '0.25rem' }}>
                      No Audit Records Found
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      No events match the current filter criteria, or no operational events have been recorded yet.
                    </div>
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    {/* Timestamp */}
                    <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {formatDateTime(log.timestamp)}
                    </td>

                    {/* Operator */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <User size={13} color="var(--text-muted)" />
                        <span style={{ fontWeight: 600, color: log.username ? '#fff' : 'var(--text-muted)' }}>
                          {log.username || 'System / Unauth'}
                        </span>
                        {log.user_role && (
                          <span
                            style={{
                              fontSize: '0.65rem',
                              padding: '0.1rem 0.35rem',
                              borderRadius: '3px',
                              backgroundColor: 'rgba(255,255,255,0.08)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {log.user_role}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Action */}
                    <td>{renderActionBadge(log.action)}</td>

                    {/* Resource */}
                    <td>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        <span style={{ fontWeight: 600 }}>{log.resource_type}</span>
                        {log.resource_id && (
                          <span style={{ color: 'var(--accent-cyan)', marginLeft: '0.35rem' }}>
                            #{log.resource_id}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Outcome */}
                    <td>{renderOutcomeBadge(log.outcome)}</td>

                    {/* HTTP / Path */}
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                      {log.request_method && (
                        <span style={{ color: 'var(--accent-blue)', marginRight: '0.35rem', fontWeight: 600 }}>
                          {log.request_method}
                        </span>
                      )}
                      <span style={{ color: 'var(--text-secondary)' }}>{log.request_path || '-'}</span>
                      {log.status_code && (
                        <span
                          style={{
                            marginLeft: '0.45rem',
                            color: log.status_code >= 400 ? 'var(--status-critical)' : 'var(--status-low)',
                            fontWeight: 600,
                          }}
                        >
                          ({log.status_code})
                        </span>
                      )}
                    </td>

                    {/* Details snippet */}
                    <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {log.details || '-'}
                    </td>

                    {/* Inspect button */}
                    <td>
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="btn-icon"
                        title="Inspect full audit record"
                        style={{ padding: '0.35rem' }}
                      >
                        <Eye size={15} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '1rem 1.25rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'rgba(0,0,0,0.2)',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}
        >
          <div>
            Showing {logs.length > 0 ? offset + 1 : 0} to {Math.min(offset + limit, total)} of {total} records
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span>Page {currentPage} of {totalPages}</span>
            <div style={{ display: 'flex', gap: '0.35rem' }}>
              <button
                disabled={offset === 0 || isLoading}
                onClick={() => setOffset(Math.max(0, offset - limit))}
                className="preset-btn"
                style={{ padding: '0.35rem 0.65rem' }}
              >
                <ChevronLeft size={16} />
              </button>
              <button
                disabled={offset + limit >= total || isLoading}
                onClick={() => setOffset(offset + limit)}
                className="preset-btn"
                style={{ padding: '0.35rem 0.65rem' }}
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Audit Detail Modal */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            backdropFilter: 'blur(4px)',
            padding: '1.5rem',
          }}
          onClick={() => setSelectedLog(null)}
        >
          <div
            className="section-card glass-panel"
            style={{
              width: '100%',
              maxWidth: '620px',
              maxHeight: '90vh',
              overflowY: 'auto',
              border: '1px solid var(--border-active)',
              boxShadow: 'var(--shadow-lg)',
              padding: '1.75rem',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <FileText color="var(--accent-cyan)" size={22} />
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#fff', fontWeight: 600 }}>
                    Security Audit Record #{selectedLog.id}
                  </h3>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {formatDateTime(selectedLog.timestamp)}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Content Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Action:</div>
                <div style={{ marginTop: '0.2rem' }}>{renderActionBadge(selectedLog.action)}</div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Outcome:</div>
                <div style={{ marginTop: '0.2rem' }}>{renderOutcomeBadge(selectedLog.outcome)}</div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Operator Username:</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#fff', marginTop: '0.15rem' }}>
                  {selectedLog.username || 'System / Unauthenticated'}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Operator Role:</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#fff', marginTop: '0.15rem' }}>
                  {selectedLog.user_role || 'None'}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Resource:</div>
                <div style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                  {selectedLog.resource_type} {selectedLog.resource_id ? `(#${selectedLog.resource_id})` : ''}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Client Peer IP:</div>
                <div style={{ fontSize: '0.88rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginTop: '0.15rem' }}>
                  {selectedLog.ip_address || 'Unknown'}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>HTTP Method / Status:</div>
                <div style={{ fontSize: '0.88rem', fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '0.15rem' }}>
                  {selectedLog.request_method || 'N/A'} {selectedLog.status_code ? `(${selectedLog.status_code})` : ''}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Endpoint Path:</div>
                <div style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: '0.15rem', wordBreak: 'break-all' }}>
                  {selectedLog.request_path || 'N/A'}
                </div>
              </div>
            </div>

            {/* Sanitized Details JSON / Text */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
                Safe Contextual Metadata (Sanitized):
              </div>
              <pre
                style={{
                  backgroundColor: '#050811',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem',
                  fontSize: '0.75rem',
                  color: 'var(--accent-cyan)',
                  fontFamily: 'var(--font-mono)',
                  overflowX: 'auto',
                  maxHeight: '160px',
                }}
              >
                {selectedLog.details
                  ? (() => {
                      try {
                        return JSON.stringify(JSON.parse(selectedLog.details), null, 2);
                      } catch {
                        return selectedLog.details;
                      }
                    })()
                  : 'No extra details recorded.'}
              </pre>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
              <button
                onClick={() => setSelectedLog(null)}
                className="btn-primary"
                style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
