import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  User,
  Tag,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Send,
  UserCheck,
  Activity,
  ArrowRight,
  RefreshCw,
  Download,
  FileArchive,
} from 'lucide-react';
import api from '../services/api';
import StatusBadge from './StatusBadge';
import { formatDateTime } from '../utils/formatters';
import { useAuth } from '../context/AuthContext';

export default function IncidentDetails({ incidentId, onClose, onIncidentUpdated }) {
  const { role, user } = useAuth();
  const canManage = role === 'ADMIN' || role === 'ANALYST';

  const [incident, setIncident] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'notes' | 'timeline'
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Note form state
  const [newNote, setNewNote] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  // Status transition state
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [resolutionPrompt, setResolutionPrompt] = useState(false);
  const [resolutionSummary, setResolutionSummary] = useState('');

  // Assign state
  const [assigneeInput, setAssigneeInput] = useState('');
  const [isAssigning, setIsAssigning] = useState(false);

  // Evidence export state
  const [isExportingEvidence, setIsExportingEvidence] = useState(false);
  const [evidenceNotice, setEvidenceNotice] = useState(null);

  const fetchDetails = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getIncidentById(incidentId);
      setIncident(data);
      if (data.assigned_to) {
        setAssigneeInput(data.assigned_to);
      }
      const tl = await api.getIncidentTimeline(incidentId);
      setTimeline(tl.timeline || []);
    } catch (err) {
      setError(err.message || 'Failed to load incident details.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      fetchDetails();
    }
  }, [incidentId]);

  const handleExportEvidence = async (format = 'json') => {
    setIsExportingEvidence(true);
    setError(null);
    setEvidenceNotice(null);
    try {
      await api.exportIncidentEvidence(incidentId, format);
      setEvidenceNotice(`Forensic evidence (${format.toUpperCase()}) exported successfully.`);
      setTimeout(() => setEvidenceNotice(null), 4000);
    } catch (err) {
      setError(err.message || 'Failed to export incident evidence package.');
    } finally {
      setIsExportingEvidence(false);
    }
  };

  const handleStatusChange = async (targetStatus) => {
    if (targetStatus === 'RESOLVED' && !resolutionPrompt) {
      setResolutionPrompt(true);
      return;
    }

    setIsUpdatingStatus(true);
    setError(null);
    try {
      const updated = await api.updateIncidentStatus(incidentId, {
        new_status: targetStatus,
        resolution_summary: targetStatus === 'RESOLVED' ? resolutionSummary : undefined,
      });
      setIncident(updated);
      setResolutionPrompt(false);
      setResolutionSummary('');
      if (onIncidentUpdated) onIncidentUpdated(updated);
      // Refresh timeline
      const tl = await api.getIncidentTimeline(incidentId);
      setTimeline(tl.timeline || []);
    } catch (err) {
      setError(err.message || 'Failed to update incident status.');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAssign = async (e) => {
    e.preventDefault();
    if (!assigneeInput.trim()) return;

    setIsAssigning(true);
    setError(null);
    try {
      const updated = await api.assignIncident(incidentId, assigneeInput.trim());
      setIncident(updated);
      if (onIncidentUpdated) onIncidentUpdated(updated);
      const tl = await api.getIncidentTimeline(incidentId);
      setTimeline(tl.timeline || []);
    } catch (err) {
      setError(err.message || 'Failed to assign incident.');
    } finally {
      setIsAssigning(false);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;

    setIsSubmittingNote(true);
    setError(null);
    try {
      await api.addIncidentNote(incidentId, newNote.trim());
      setNewNote('');
      // Refresh details to update notes array
      const updated = await api.getIncidentById(incidentId);
      setIncident(updated);
      const tl = await api.getIncidentTimeline(incidentId);
      setTimeline(tl.timeline || []);
    } catch (err) {
      setError(err.message || 'Failed to add analyst note.');
    } finally {
      setIsSubmittingNote(false);
    }
  };

  if (!incidentId) return null;

  return (
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
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="section-card glass-panel"
        style={{
          width: '100%',
          maxWidth: '960px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          margin: 0,
          padding: 0,
          overflow: 'hidden',
          border: '1px solid var(--border-active)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(0, 0, 0, 0.3)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid rgba(239, 68, 68, 0.3)',
              }}
            >
              <ShieldAlert size={20} color="var(--status-critical)" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <span className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.05rem' }}>
                  {incident ? incident.incident_key : `Incident #${incidentId}`}
                </span>
                {incident && (
                  <>
                    <StatusBadge status={incident.severity} type="risk" />
                    <StatusBadge status={incident.status} type="status" />
                  </>
                )}
              </div>
              <div style={{ fontSize: '0.85rem', color: '#fff', fontWeight: 600, marginTop: '0.2rem' }}>
                {incident?.title || 'Loading case details...'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => handleExportEvidence('json')}
              disabled={isExportingEvidence || isLoading}
              className="preset-btn"
              style={{ padding: '0.35rem 0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem' }}
              title="Export forensic evidence package as JSON"
            >
              <Download size={13} color="var(--accent-cyan)" />
              <span>Evidence JSON</span>
            </button>
            <button
              onClick={() => handleExportEvidence('zip')}
              disabled={isExportingEvidence || isLoading}
              className="preset-btn"
              style={{ padding: '0.35rem 0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem' }}
              title="Export complete forensic evidence bundle as ZIP"
            >
              <FileArchive size={13} color="#a855f7" />
              <span>Evidence ZIP</span>
            </button>
            <button
              onClick={fetchDetails}
              className="preset-btn"
              style={{ padding: '0.35rem 0.6rem' }}
              title="Refresh case details"
            >
              <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            </button>
            <button
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '0.35rem',
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
              title="Close modal (Esc)"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div
          style={{
            display: 'flex',
            gap: '1rem',
            padding: '0 1.5rem',
            borderBottom: '1px solid var(--border-subtle)',
            backgroundColor: 'rgba(0, 0, 0, 0.15)',
          }}
        >
          <button
            onClick={() => setActiveTab('overview')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'overview' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === 'overview' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontWeight: 600,
              fontSize: '0.84rem',
              cursor: 'pointer',
            }}
          >
            Overview & Telemetry
          </button>
          <button
            onClick={() => setActiveTab('notes')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'notes' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === 'notes' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontWeight: 600,
              fontSize: '0.84rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>Analyst Notes</span>
            {incident && incident.notes && (
              <span
                style={{
                  fontSize: '0.7rem',
                  padding: '0.1rem 0.4rem',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(0, 242, 254, 0.15)',
                  color: 'var(--accent-cyan)',
                }}
              >
                {incident.notes.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'timeline' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === 'timeline' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontWeight: 600,
              fontSize: '0.84rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>Case Timeline</span>
            <span
              style={{
                fontSize: '0.7rem',
                padding: '0.1rem 0.4rem',
                borderRadius: '10px',
                backgroundColor: 'rgba(255, 255, 255, 0.08)',
                color: 'var(--text-secondary)',
              }}
            >
              {timeline.length}
            </span>
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem' }}>
          {error && (
            <div className="alert-box alert-error" style={{ marginBottom: '1.25rem' }}>
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}

          {evidenceNotice && (
            <div className="alert-box" style={{ marginBottom: '1.25rem', backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--status-healthy)', color: '#fff' }}>
              <CheckCircle2 size={18} color="var(--status-healthy)" />
              <span>{evidenceNotice}</span>
            </div>
          )}

          {isLoading && !incident ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <div className="spinner" style={{ margin: '0 auto 1rem', width: '32px', height: '32px' }} />
              <div>Loading incident case telemetry...</div>
            </div>
          ) : incident ? (
            <>
              {/* TAB 1: OVERVIEW */}
              {activeTab === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  
                  {/* Action Bar for Operators */}
                  {canManage && incident.status !== 'RESOLVED' && (
                    <div
                      style={{
                        padding: '1rem',
                        backgroundColor: 'rgba(0, 242, 254, 0.04)',
                        border: '1px solid rgba(0, 242, 254, 0.15)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.75rem',
                      }}
                    >
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                        Incident Response Triage Actions
                      </div>

                      {resolutionPrompt ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                          <label style={{ fontSize: '0.8rem', color: '#fff' }}>
                            Resolution Summary (Required to mark RESOLVED):
                          </label>
                          <textarea
                            value={resolutionSummary}
                            onChange={(e) => setResolutionSummary(e.target.value)}
                            placeholder="Describe root-cause, containment actions taken, and remediation status..."
                            rows={2}
                            style={{
                              backgroundColor: 'rgba(0, 0, 0, 0.5)',
                              border: '1px solid var(--border-active)',
                              borderRadius: 'var(--radius-sm)',
                              color: '#fff',
                              padding: '0.5rem',
                              fontSize: '0.82rem',
                            }}
                          />
                          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                            <button
                              type="button"
                              onClick={() => setResolutionPrompt(false)}
                              className="preset-btn"
                              style={{ padding: '0.35rem 0.75rem' }}
                            >
                              Cancel
                            </button>
                            <button
                              type="button"
                              onClick={() => handleStatusChange('RESOLVED')}
                              disabled={isUpdatingStatus || !resolutionSummary.trim()}
                              className="btn-primary"
                              style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem', backgroundColor: 'var(--status-healthy)' }}
                            >
                              Confirm Resolution
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem', alignItems: 'center' }}>
                          {incident.status === 'OPEN' && (
                            <button
                              onClick={() => handleStatusChange('ACKNOWLEDGED')}
                              disabled={isUpdatingStatus}
                              className="preset-btn"
                              style={{ color: 'var(--accent-cyan)', borderColor: 'var(--border-active)' }}
                            >
                              <CheckCircle2 size={14} />
                              Acknowledge Case
                            </button>
                          )}

                          {(incident.status === 'OPEN' || incident.status === 'ACKNOWLEDGED') && (
                            <button
                              onClick={() => handleStatusChange('INVESTIGATING')}
                              disabled={isUpdatingStatus}
                              className="preset-btn"
                              style={{ color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.4)' }}
                            >
                              <Activity size={14} />
                              Start Investigation
                            </button>
                          )}

                          {(incident.status === 'ACKNOWLEDGED' || incident.status === 'INVESTIGATING') && (
                            <button
                              onClick={() => handleStatusChange('CONTAINED')}
                              disabled={isUpdatingStatus}
                              className="preset-btn"
                              style={{ color: '#f59e0b', borderColor: 'rgba(245, 158, 11, 0.4)' }}
                            >
                              <AlertTriangle size={14} />
                              Mark Contained
                            </button>
                          )}

                          <button
                            onClick={() => handleStatusChange('RESOLVED')}
                            disabled={isUpdatingStatus}
                            className="preset-btn"
                            style={{ color: 'var(--status-healthy)', borderColor: 'rgba(16, 185, 129, 0.4)' }}
                          >
                            <CheckCircle2 size={14} />
                            Resolve Case
                          </button>

                          {/* Quick Assign Form */}
                          <form onSubmit={handleAssign} style={{ display: 'flex', gap: '0.4rem', marginLeft: 'auto' }}>
                            <input
                              type="text"
                              placeholder="Assignee username..."
                              value={assigneeInput}
                              onChange={(e) => setAssigneeInput(e.target.value)}
                              disabled={isAssigning}
                              style={{
                                backgroundColor: 'rgba(0,0,0,0.4)',
                                border: '1px solid var(--border-subtle)',
                                borderRadius: 'var(--radius-sm)',
                                color: '#fff',
                                padding: '0.3rem 0.6rem',
                                fontSize: '0.78rem',
                                width: '150px',
                              }}
                            />
                            <button
                              type="submit"
                              disabled={isAssigning || !assigneeInput.trim()}
                              className="preset-btn"
                              style={{ padding: '0.3rem 0.6rem', fontSize: '0.78rem' }}
                            >
                              <UserCheck size={13} />
                              Assign
                            </button>
                          </form>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Incident Summary Card */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                    <div style={{ padding: '0.85rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Category</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#fff', marginTop: '0.2rem' }}>
                        {incident.category}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Source IP</div>
                      <div className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: incident.source_ip ? 'var(--accent-cyan)' : 'var(--text-muted)', marginTop: '0.2rem' }}>
                        {incident.source_ip || 'None Specified'}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Assigned Analyst</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 600, color: incident.assigned_to ? '#fff' : 'var(--text-muted)', marginTop: '0.2rem' }}>
                        {incident.assigned_to || 'Unassigned'}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Created By</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#fff', marginTop: '0.2rem' }}>
                        {incident.created_by} &bull; <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{formatDateTime(incident.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Case Description */}
                  {incident.description && (
                    <div style={{ padding: '1rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                        Case Description
                      </div>
                      <div style={{ fontSize: '0.85rem', color: '#e2e8f0', lineHeight: 1.5 }}>
                        {incident.description}
                      </div>
                    </div>
                  )}

                  {/* Resolution Summary (if resolved) */}
                  {incident.resolution_summary && (
                    <div style={{ padding: '1rem', backgroundColor: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--status-healthy)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.35rem' }}>
                        Resolution Summary & Remediation Notes
                      </div>
                      <div style={{ fontSize: '0.85rem', color: '#fff', lineHeight: 1.5 }}>
                        {incident.resolution_summary}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                        Resolved at: {formatDateTime(incident.resolved_at)}
                      </div>
                    </div>
                  )}

                  {/* Correlated Security Alerts */}
                  <div>
                    <h4 style={{ fontSize: '0.9rem', color: '#fff', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <AlertTriangle size={15} color="var(--status-high)" />
                      Correlated Security Incident Alerts ({incident.alerts ? incident.alerts.length : 0})
                    </h4>
                    {incident.alerts && incident.alerts.length > 0 ? (
                      <div className="table-responsive" style={{ maxHeight: '200px' }}>
                        <table className="ids-table">
                          <thead>
                            <tr>
                              <th>Alert ID</th>
                              <th>Threat Label</th>
                              <th>Severity</th>
                              <th>Alert Status</th>
                              <th>Confidence</th>
                              <th>Timestamp</th>
                            </tr>
                          </thead>
                          <tbody>
                            {incident.alerts.map((alt) => (
                              <tr key={alt.id}>
                                <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>#{alt.id}</td>
                                <td style={{ color: '#fff', fontWeight: 600 }}>{alt.threat_label}</td>
                                <td><StatusBadge status={alt.severity} type="risk" /></td>
                                <td><StatusBadge status={alt.status} type="status" /></td>
                                <td className="font-mono">{(alt.confidence * 100).toFixed(1)}%</td>
                                <td style={{ fontSize: '0.78rem' }}>{formatDateTime(alt.created_at)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{ padding: '1rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                        No specific AlertRecord directly attached to this incident.
                      </div>
                    )}
                  </div>

                  {/* Correlated Flow Predictions */}
                  <div>
                    <h4 style={{ fontSize: '0.9rem', color: '#fff', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <Activity size={15} color="var(--accent-cyan)" />
                      Correlated Network Predictions ({incident.predictions ? incident.predictions.length : 0})
                    </h4>
                    {incident.predictions && incident.predictions.length > 0 ? (
                      <div className="table-responsive" style={{ maxHeight: '200px' }}>
                        <table className="ids-table">
                          <thead>
                            <tr>
                              <th>Prediction ID</th>
                              <th>Predicted Threat</th>
                              <th>Risk Level</th>
                              <th>Anomaly Score</th>
                              <th>Classifier Conf</th>
                              <th>Timestamp</th>
                            </tr>
                          </thead>
                          <tbody>
                            {incident.predictions.map((p) => (
                              <tr key={p.id}>
                                <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>#{p.id}</td>
                                <td style={{ color: '#fff', fontWeight: 600 }}>{p.predicted_threat}</td>
                                <td><StatusBadge status={p.risk_level} type="risk" /></td>
                                <td className="font-mono">{(p.anomaly_score).toFixed(3)}</td>
                                <td className="font-mono">{(p.classification_confidence * 100).toFixed(1)}%</td>
                                <td style={{ fontSize: '0.78rem' }}>{formatDateTime(p.timestamp)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{ padding: '1rem', backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                        No underlying PredictionRecord explicitly linked.
                      </div>
                    )}
                  </div>

                </div>
              )}

              {/* TAB 2: ANALYST NOTES */}
              {activeTab === 'notes' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {/* Append Note Form */}
                  {canManage && (
                    <form
                      onSubmit={handleAddNote}
                      style={{
                        padding: '1rem',
                        backgroundColor: 'rgba(0,0,0,0.25)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.75rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: '#fff', fontWeight: 600 }}>
                        <FileText size={16} color="var(--accent-cyan)" />
                        Add Forensic Analyst Note
                      </div>
                      <textarea
                        value={newNote}
                        onChange={(e) => setNewNote(e.target.value)}
                        placeholder="Log forensic findings, firewall rule updates, packet capture analysis, or containment notes..."
                        rows={3}
                        disabled={isSubmittingNote}
                        style={{
                          backgroundColor: 'rgba(0, 0, 0, 0.4)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          color: '#fff',
                          padding: '0.6rem',
                          fontSize: '0.82rem',
                          resize: 'vertical',
                        }}
                      />
                      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <button
                          type="submit"
                          disabled={isSubmittingNote || !newNote.trim()}
                          className="btn-primary"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            padding: '0.4rem 1rem',
                            fontSize: '0.8rem',
                          }}
                        >
                          <Send size={13} />
                          {isSubmittingNote ? 'Saving Note...' : 'Post Case Note'}
                        </button>
                      </div>
                    </form>
                  )}

                  {/* Notes Feed */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {incident.notes && incident.notes.length > 0 ? (
                      incident.notes.map((n) => (
                        <div
                          key={n.id}
                          style={{
                            padding: '0.9rem',
                            backgroundColor: 'rgba(0,0,0,0.2)',
                            borderLeft: '3px solid var(--accent-cyan)',
                            borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', fontWeight: 600, color: '#fff' }}>
                              <User size={13} color="var(--accent-cyan)" />
                              {n.author}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                              {formatDateTime(n.created_at)}
                            </div>
                          </div>
                          <div style={{ fontSize: '0.85rem', color: '#e2e8f0', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>
                            {n.note}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
                        <FileText size={32} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
                        <div>No analyst notes recorded yet on this case.</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 3: TIMELINE */}
              {activeTab === 'timeline' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Unified audit timeline of status changes, operator actions, and correlated telemetry (newest first).
                  </div>

                  <div style={{ position: 'relative', paddingLeft: '1.75rem', marginTop: '0.5rem' }}>
                    {/* Vertical timeline rule */}
                    <div
                      style={{
                        position: 'absolute',
                        left: '7px',
                        top: '10px',
                        bottom: '10px',
                        width: '2px',
                        backgroundColor: 'var(--border-subtle)',
                      }}
                    />

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                      {timeline.map((evt, idx) => (
                        <div key={idx} style={{ position: 'relative' }}>
                          {/* Dot marker */}
                          <div
                            style={{
                              position: 'absolute',
                              left: '-1.75rem',
                              top: '3px',
                              width: '16px',
                              height: '16px',
                              borderRadius: '50%',
                              backgroundColor: '#0a0e17',
                              border: '2px solid var(--accent-cyan)',
                            }}
                          />
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                              <span
                                style={{
                                  fontSize: '0.7rem',
                                  padding: '0.1rem 0.45rem',
                                  borderRadius: '3px',
                                  backgroundColor: 'rgba(0, 242, 254, 0.1)',
                                  color: 'var(--accent-cyan)',
                                  fontWeight: 600,
                                }}
                              >
                                {evt.event_type}
                              </span>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                {formatDateTime(evt.timestamp)}
                              </span>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                by <strong>{evt.actor}</strong>
                              </span>
                            </div>
                            <div style={{ fontSize: '0.84rem', color: '#e2e8f0', marginTop: '0.3rem' }}>
                              {evt.summary}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>

        {/* Modal Footer */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'rgba(0, 0, 0, 0.25)',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <button onClick={onClose} className="preset-btn" style={{ padding: '0.45rem 1.25rem' }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
