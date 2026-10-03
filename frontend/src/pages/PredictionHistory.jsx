import React, { useState, useEffect } from 'react';
import { History, RefreshCw, AlertTriangle, ChevronLeft, ChevronRight, Database, FileText, Search } from 'lucide-react';
import api from '../services/api';
import StatusBadge from '../components/StatusBadge';
import InvestigationModal from '../components/InvestigationModal';
import { formatDateTime, formatScore, formatPercentage, formatProtocol } from '../utils/formatters';
import { PAGE_LIMIT_OPTIONS } from '../types';

export default function PredictionHistory() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(20);
  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [selectedPredictionId, setSelectedPredictionId] = useState(null);

  const fetchHistory = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const data = await api.getPredictions({ limit, offset });
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      setApiError(err.message || 'Failed to retrieve prediction history.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [limit, offset]);

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

  const handleLimitChange = (e) => {
    const newLimit = Number(e.target.value);
    setLimit(newLimit);
    setOffset(0); // Reset to first page
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <History color="var(--accent-cyan)" size={28} />
            Prediction Audit History
          </h1>
          <p className="page-subtitle">
            Historical audit log of all network-flow inferences evaluated by the dual-engine detection pipeline.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <span>Page Size:</span>
            <select
              value={limit}
              onChange={handleLimitChange}
              style={{
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.35rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                outline: 'none',
              }}
            >
              {PAGE_LIMIT_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt} per page
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={fetchHistory}
            disabled={isLoading}
            className="preset-btn"
            title="Refresh prediction records"
          >
            <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error Alert Box */}
      {apiError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Failed to Load History</div>
            <div style={{ fontSize: '0.85rem' }}>{apiError}</div>
          </div>
          <button
            onClick={fetchHistory}
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

      {/* Main Table Card */}
      <div className="section-card glass-panel" style={{ padding: '0.5rem' }}>
        
        {/* Loading Indicator */}
        {isLoading && (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem', width: '30px', height: '30px' }} />
            <div>Querying prediction audit records from database...</div>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !apiError && items.length === 0 && (
          <div style={{ padding: '4rem 2rem', textAlign: 'center' }}>
            <Database size={40} color="var(--text-muted)" style={{ margin: '0 auto 1rem' }} />
            <h3 style={{ color: '#fff', fontSize: '1.1rem', fontWeight: 600 }}>No Prediction Records Found</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', maxWidth: '420px', margin: '0.5rem auto 1.5rem' }}>
              The database currently contains no recorded network flow predictions. Submit a flow from the <strong>AI Prediction</strong> tab to generate audit records.
            </p>
          </div>
        )}

        {/* Table Content */}
        {!isLoading && !apiError && items.length > 0 && (
          <div className="table-responsive">
            <table className="ids-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Threat Label</th>
                  <th>Intrusion</th>
                  <th>Anomaly Score</th>
                  <th>Est. Probability</th>
                  <th>Risk Level</th>
                  <th>Action</th>
                  <th>Investigate</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                      #{row.id}
                    </td>
                    <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {formatDateTime(row.timestamp || row.created_at)}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.82rem' }}>
                      {row.destination_ip ? `${row.destination_ip}:${row.destination_port || '-'}` : (row.destination_port ? `Port ${row.destination_port}` : '-')}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.75rem', padding: '0.15rem 0.4rem', backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: '3px' }}>
                        {formatProtocol(row.protocol)}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#fff' }}>
                      {row.predicted_threat}
                    </td>
                    <td>
                      <StatusBadge
                        status={row.intrusion_flag ? 'INTRUSION' : 'BENIGN'}
                        type={row.intrusion_flag ? 'severity' : 'status'}
                      />
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.82rem' }}>
                      {formatScore(row.anomaly_score)}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.82rem' }}>
                      {formatPercentage(row.classification_confidence)}
                    </td>
                    <td>
                      <StatusBadge status={row.risk_level} type="risk" />
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: '200px' }} title={row.recommended_action}>
                      {row.recommended_action}
                    </td>
                    <td>
                      <button
                        onClick={() => setSelectedPredictionId(row.id)}
                        className="preset-btn"
                        style={{
                          padding: '0.2rem 0.6rem',
                          fontSize: '0.74rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                          color: 'var(--accent-cyan)',
                          border: '1px solid var(--border-active)',
                        }}
                        title="Open forensics and rule-based prediction investigation"
                      >
                        <Search size={12} />
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
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
              Showing records <strong>{offset + 1}</strong> to <strong>{Math.min(offset + limit, total)}</strong> of <strong>{total}</strong>
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
      
      {/* Forensic Prediction Investigation Modal */}
      {selectedPredictionId && (
        <InvestigationModal
          predictionId={selectedPredictionId}
          onClose={() => setSelectedPredictionId(null)}
        />
      )}
    </div>
  );
}
