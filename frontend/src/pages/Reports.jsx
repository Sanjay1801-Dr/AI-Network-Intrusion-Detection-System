import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  FileCheck,
  AlertTriangle,
  Clock,
  ShieldAlert,
  Cpu,
  RefreshCw,
  Table,
  CheckCircle2,
  Calendar,
  Filter,
  Eye,
} from 'lucide-react';
import api from '../services/api';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime, formatPercentage } from '../utils/formatters';

export default function Reports() {
  // Query Filters State
  const [timeRange, setTimeRange] = useState('last_24h');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('');

  // Execution & Preview State
  const [reportData, setReportData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [successNotice, setSuccessNotice] = useState(null);

  // Initial fetch for preview
  const fetchReportPreview = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const params = {
        time_range: timeRange,
        severity: severityFilter,
        category: categoryFilter.trim() || undefined,
      };
      if (timeRange === 'custom') {
        if (!startDate || !endDate) {
          throw new Error('Custom time range requires both start and end datetimes.');
        }
        params.start_date = new Date(startDate).toISOString();
        params.end_date = new Date(endDate).toISOString();
      }

      const data = await api.getSecurityReport(params);
      setReportData(data);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to generate security assessment report.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReportPreview();
  }, []);

  const handleExport = async (format) => {
    setIsExporting(true);
    setErrorMessage(null);
    setSuccessNotice(null);
    try {
      const params = {
        time_range: timeRange,
        severity: severityFilter,
        category: categoryFilter.trim() || undefined,
      };
      if (timeRange === 'custom') {
        if (!startDate || !endDate) {
          throw new Error('Custom time range requires both start and end datetimes.');
        }
        params.start_date = new Date(startDate).toISOString();
        params.end_date = new Date(endDate).toISOString();
      }

      await api.downloadSecurityReport(params, format);
      setSuccessNotice(`Report exported successfully as ${format.toUpperCase()}.`);
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err) {
      setErrorMessage(err.message || `Failed to export ${format.toUpperCase()} report.`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleDatasetExport = async (dataset) => {
    setIsExporting(true);
    setErrorMessage(null);
    setSuccessNotice(null);
    try {
      const params = {
        time_range: timeRange,
        severity: severityFilter,
        category: categoryFilter.trim() || undefined,
      };
      if (timeRange === 'custom') {
        if (startDate && endDate) {
          params.start_date = new Date(startDate).toISOString();
          params.end_date = new Date(endDate).toISOString();
        }
      }

      await api.downloadDatasetCsv(dataset, params);
      setSuccessNotice(`Dataset '${dataset}' exported successfully as CSV.`);
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err) {
      setErrorMessage(err.message || `Failed to export ${dataset} CSV.`);
    } finally {
      setIsExporting(false);
    }
  };

  const ex = reportData?.executive_summary;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <FileText color="var(--accent-cyan)" size={28} />
            Automated Security Reports & Evidence Export
          </h1>
          <p className="page-subtitle">
            Generate executive security assessments, tabular audit datasets, and cryptographically verified forensic packages.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => handleExport('pdf')}
            disabled={isExporting || isLoading}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', padding: '0.5rem 1rem' }}
          >
            <FileText size={15} />
            <span>Export Executive PDF</span>
          </button>

          <button
            onClick={() => handleExport('json')}
            disabled={isExporting || isLoading}
            className="preset-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}
          >
            <Download size={14} color="var(--accent-cyan)" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={() => handleExport('csv')}
            disabled={isExporting || isLoading}
            className="preset-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}
          >
            <Table size={14} color="#10b981" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Status Notifications */}
      {errorMessage && (
        <div className="alert-box alert-error">
          <AlertTriangle size={18} />
          <span>{errorMessage}</span>
        </div>
      )}

      {successNotice && (
        <div className="alert-box" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--status-healthy)', color: '#fff' }}>
          <CheckCircle2 size={18} color="var(--status-healthy)" />
          <span>{successNotice}</span>
        </div>
      )}

      {/* Filter & Configuration Toolbar */}
      <div
        className="section-card glass-panel"
        style={{
          borderLeft: '4px solid var(--accent-cyan)',
          padding: '1.25rem 1.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Filter size={18} color="var(--accent-cyan)" />
          <h2 className="section-title" style={{ fontSize: '1rem', margin: 0 }}>
            Report Parameters & Time Window
          </h2>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
            alignItems: 'end',
          }}
        >
          {/* Time Range Selector */}
          <div>
            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Time Range
            </label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="filter-select"
              style={{ width: '100%', padding: '0.45rem 0.75rem' }}
            >
              <option value="last_1h">Last 1 Hour</option>
              <option value="last_24h">Last 24 Hours</option>
              <option value="last_7d">Last 7 Days</option>
              <option value="last_30d">Last 30 Days</option>
              <option value="custom">Custom Datetime Range</option>
            </select>
          </div>

          {/* Custom Date Pickers */}
          {timeRange === 'custom' && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  Start Datetime (UTC)
                </label>
                <input
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.45rem 0.75rem',
                    backgroundColor: 'rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    color: '#fff',
                    fontSize: '0.82rem',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  End Datetime (UTC)
                </label>
                <input
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.45rem 0.75rem',
                    backgroundColor: 'rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    color: '#fff',
                    fontSize: '0.82rem',
                  }}
                />
              </div>
            </>
          )}

          {/* Severity Filter */}
          <div>
            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Severity Filter
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="filter-select"
              style={{ width: '100%', padding: '0.45rem 0.75rem' }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Threat Category
            </label>
            <input
              type="text"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              placeholder="e.g. DDoS, PortScan"
              style={{
                width: '100%',
                padding: '0.45rem 0.75rem',
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: '#fff',
                fontSize: '0.82rem',
              }}
            />
          </div>

          {/* Generate Preview Action */}
          <div>
            <button
              onClick={fetchReportPreview}
              disabled={isLoading}
              className="btn-primary"
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.4rem',
                padding: '0.5rem 1rem',
              }}
            >
              <Eye size={15} />
              <span>Generate Preview</span>
            </button>
          </div>
        </div>
      </div>

      {/* Dataset Direct Tabular Exports */}
      <div
        className="section-card glass-panel"
        style={{
          padding: '1.25rem 1.5rem',
        }}
      >
        <div className="section-header" style={{ marginBottom: '0.75rem' }}>
          <div>
            <h2 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
              Quick Dataset CSV Exports
            </h2>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
              Export complete raw operational datasets filtered by current reporting parameters
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          <button
            onClick={() => handleDatasetExport('predictions')}
            disabled={isExporting}
            className="preset-btn"
            style={{ padding: '0.65rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}
          >
            <Cpu size={15} color="var(--accent-cyan)" />
            <span>Predictions CSV</span>
          </button>

          <button
            onClick={() => handleDatasetExport('alerts')}
            disabled={isExporting}
            className="preset-btn"
            style={{ padding: '0.65rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}
          >
            <AlertTriangle size={15} color="var(--status-critical)" />
            <span>Alerts CSV</span>
          </button>

          <button
            onClick={() => handleDatasetExport('incidents')}
            disabled={isExporting}
            className="preset-btn"
            style={{ padding: '0.65rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}
          >
            <ShieldAlert size={15} color="#f97316" />
            <span>Incidents CSV</span>
          </button>

          <button
            onClick={() => handleDatasetExport('audit-logs')}
            disabled={isExporting}
            className="preset-btn"
            style={{ padding: '0.65rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}
          >
            <FileCheck size={15} color="#a855f7" />
            <span>Audit Trail CSV</span>
          </button>
        </div>
      </div>

      {/* Loading Indicator */}
      {isLoading && (
        <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <div className="spinner" style={{ margin: '0 auto 1rem', width: '36px', height: '36px' }} />
          <div>Compiling security assessment telemetry...</div>
        </div>
      )}

      {/* Report Preview Content */}
      {!isLoading && reportData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Executive Metrics Overview */}
          <div className="metrics-grid">
            <div className="metric-card glass-panel">
              <div className="metric-icon-box">
                <Cpu size={24} />
              </div>
              <div className="metric-info">
                <div className="metric-label">Evaluated Flows</div>
                <div className="metric-value">{ex?.total_predictions || 0}</div>
                <div className="metric-subtext">Within reporting scope</div>
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-icon-box" style={{ background: 'rgba(239, 68, 68, 0.1)', color: 'var(--status-critical)' }}>
                <AlertTriangle size={24} />
              </div>
              <div className="metric-info">
                <div className="metric-label">Detected Threats</div>
                <div className="metric-value">{ex?.total_threats || 0}</div>
                <div className="metric-subtext">
                  {ex?.total_predictions > 0
                    ? `${formatPercentage((ex.total_threats / ex.total_predictions) * 100)} anomaly ratio`
                    : 'Zero threats'}
                </div>
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-icon-box" style={{ background: 'rgba(249, 115, 22, 0.1)', color: '#f97316' }}>
                <ShieldAlert size={24} />
              </div>
              <div className="metric-info">
                <div className="metric-label">Security Alerts</div>
                <div className="metric-value">{ex?.total_alerts || 0}</div>
                <div className="metric-subtext">
                  {ex?.alerts_by_severity?.CRITICAL || 0} Critical / {ex?.alerts_by_severity?.HIGH || 0} High
                </div>
              </div>
            </div>

            <div className="metric-card glass-panel">
              <div className="metric-icon-box" style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--status-healthy)' }}>
                <FileCheck size={24} />
              </div>
              <div className="metric-info">
                <div className="metric-label">Incident Resolution</div>
                <div className="metric-value">
                  {ex?.total_incidents > 0
                    ? `${Math.round((ex.resolved_incidents / ex.total_incidents) * 100)}%`
                    : '100%'}
                </div>
                <div className="metric-subtext">
                  {ex?.resolved_incidents || 0} resolved of {ex?.total_incidents || 0} cases
                </div>
              </div>
            </div>
          </div>

          {/* Key Findings Callout */}
          {reportData.important_findings && reportData.important_findings.length > 0 && (
            <div
              className="section-card glass-panel"
              style={{
                borderLeft: '4px solid #10b981',
                padding: '1.25rem 1.5rem',
              }}
            >
              <div className="section-header" style={{ marginBottom: '0.75rem' }}>
                <h2 className="section-title" style={{ fontSize: '1rem', margin: 0, color: 'var(--status-healthy)' }}>
                  Executive Security Findings & Assessment
                </h2>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.86rem', color: '#e2e8f0' }}>
                {reportData.important_findings.map((f, idx) => (
                  <li key={idx}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Incidents Snapshot Table */}
          <div className="section-card glass-panel" style={{ margin: 0 }}>
            <div className="section-header">
              <h2 className="section-title">
                <ShieldAlert size={18} color="#f97316" />
                Incident Cases Snapshot ({reportData.incidents.length} records)
              </h2>
            </div>

            {reportData.incidents.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.86rem' }}>
                No incident cases found for the selected reporting parameters.
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
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.incidents.map((inc) => (
                      <tr key={inc.id}>
                        <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                          {inc.incident_key}
                        </td>
                        <td style={{ fontWeight: 600, color: '#fff' }}>{inc.title}</td>
                        <td>
                          <StatusBadge status={inc.severity} type="risk" />
                        </td>
                        <td>{inc.category || 'General'}</td>
                        <td>
                          <StatusBadge status={inc.status} type="status" />
                        </td>
                        <td>{inc.assigned_to || 'Unassigned'}</td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                          {formatDateTime(inc.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Security Alerts Snapshot Table */}
          <div className="section-card glass-panel" style={{ margin: 0 }}>
            <div className="section-header">
              <h2 className="section-title">
                <AlertTriangle size={18} color="var(--status-critical)" />
                Security Alerts Snapshot ({reportData.alerts.length} records)
              </h2>
            </div>

            {reportData.alerts.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.86rem' }}>
                No alerts triggered for the selected reporting parameters.
              </div>
            ) : (
              <div className="table-responsive">
                <table className="ids-table">
                  <thead>
                    <tr>
                      <th>Alert ID</th>
                      <th>Severity</th>
                      <th>Threat Label</th>
                      <th>Status</th>
                      <th>Source IP</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.alerts.map((a) => (
                      <tr key={a.id}>
                        <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                          #{a.id}
                        </td>
                        <td>
                          <StatusBadge status={a.severity} type="severity" />
                        </td>
                        <td style={{ fontWeight: 600, color: '#fff' }}>{a.threat_label}</td>
                        <td>
                          <StatusBadge status={a.status} type="status" />
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.8rem' }}>{a.source_ip || 'N/A'}</td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                          {formatDateTime(a.timestamp)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
