import React, { useState } from 'react';
import { Cpu, Send, AlertTriangle, ShieldCheck, ShieldAlert, Sparkles, RotateCcw, Activity, Info } from 'lucide-react';
import api, { ApiError } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import { formatPercentage, formatScore, formatProtocol } from '../utils/formatters';
import { useAuth } from '../context/AuthContext';

// Realistic sample presets for live demonstrations and viva presentation
const PRESET_BENIGN_HTTPS = {
  'Destination Port': 443,
  'Flow Duration': 245012,
  'Total Fwd Packets': 14,
  'Total Backward Packets': 18,
  'Total Length of Fwd Packets': 1240,
  'Total Length of Bwd Packets': 18450,
  'Flow Bytes/s': 80363.41,
  'Flow Packets/s': 130.60,
  'Protocol': 6,
  'Flow IAT Mean': 7903.61,
  'Flow IAT Std': 12450.2,
  'Flow IAT Max': 45210,
  'Flow IAT Min': 12,
  'Fwd Packet Length Mean': 88.57,
  'Bwd Packet Length Mean': 1025.0,
  'FIN Flag Count': 1,
  'SYN Flag Count': 1,
  'RST Flag Count': 0,
  'PSH Flag Count': 8,
  'ACK Flag Count': 31,
  'source_ip': '192.168.1.105',
  'destination_ip': '104.244.42.1',
};

const PRESET_DOS_ATTACK = {
  'Destination Port': 80,
  'Flow Duration': 12050,
  'Total Fwd Packets': 850,
  'Total Backward Packets': 0,
  'Total Length of Fwd Packets': 51000,
  'Total Length of Bwd Packets': 0,
  'Flow Bytes/s': 4232365.14,
  'Flow Packets/s': 70539.41,
  'Protocol': 6,
  'Flow IAT Mean': 14.17,
  'Flow IAT Std': 8.35,
  'Flow IAT Max': 42,
  'Flow IAT Min': 2,
  'Fwd Packet Length Mean': 60.0,
  'Bwd Packet Length Mean': 0.0,
  'FIN Flag Count': 0,
  'SYN Flag Count': 850,
  'RST Flag Count': 0,
  'PSH Flag Count': 0,
  'ACK Flag Count': 0,
  'source_ip': '185.220.101.4',
  'destination_ip': '192.168.1.20',
};

const PRESET_PORT_SCAN = {
  'Destination Port': 22,
  'Flow Duration': 512,
  'Total Fwd Packets': 2,
  'Total Backward Packets': 0,
  'Total Length of Fwd Packets': 0,
  'Total Length of Bwd Packets': 0,
  'Flow Bytes/s': 0.0,
  'Flow Packets/s': 3906.25,
  'Protocol': 6,
  'Flow IAT Mean': 512.0,
  'Flow IAT Std': 0.0,
  'Flow IAT Max': 512,
  'Flow IAT Min': 512,
  'Fwd Packet Length Mean': 0.0,
  'Bwd Packet Length Mean': 0.0,
  'FIN Flag Count': 0,
  'SYN Flag Count': 2,
  'RST Flag Count': 0,
  'PSH Flag Count': 0,
  'ACK Flag Count': 0,
  'source_ip': '45.146.164.110',
  'destination_ip': '192.168.1.50',
};

const EMPTY_FORM = {
  'Destination Port': '',
  'Flow Duration': '',
  'Total Fwd Packets': '',
  'Total Backward Packets': '',
  'Total Length of Fwd Packets': '',
  'Total Length of Bwd Packets': '',
  'Flow Bytes/s': '',
  'Flow Packets/s': '',
  'Protocol': '6',
  'Flow IAT Mean': '',
  'Flow IAT Std': '',
  'Flow IAT Max': '',
  'Flow IAT Min': '',
  'Fwd Packet Length Mean': '',
  'Bwd Packet Length Mean': '',
  'FIN Flag Count': '',
  'SYN Flag Count': '',
  'RST Flag Count': '',
  'PSH Flag Count': '',
  'ACK Flag Count': '',
  'source_ip': '',
  'destination_ip': '',
};

export default function AIPrediction({ onPredictionSuccess }) {
  const { role } = useAuth();
  const canPredict = role === 'ADMIN' || role === 'ANALYST';
  const [formData, setFormData] = useState(PRESET_BENIGN_HTTPS);
  const [validationErrors, setValidationErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [predictionResult, setPredictionResult] = useState(null);

  const handleInputChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }));

    // Clear validation error on change
    if (validationErrors[field]) {
      setValidationErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  const applyPreset = (preset) => {
    setFormData({ ...preset });
    setValidationErrors({});
    setApiError(null);
    setPredictionResult(null);
  };

  const clearForm = () => {
    setFormData(EMPTY_FORM);
    setValidationErrors({});
    setApiError(null);
    setPredictionResult(null);
  };

  const validateForm = () => {
    const errors = {};
    const numericFields = [
      'Destination Port',
      'Flow Duration',
      'Total Fwd Packets',
      'Total Backward Packets',
      'Total Length of Fwd Packets',
      'Total Length of Bwd Packets',
      'Flow Bytes/s',
      'Flow Packets/s',
      'Protocol',
      'Flow IAT Mean',
      'Flow IAT Std',
      'Flow IAT Max',
      'Flow IAT Min',
      'Fwd Packet Length Mean',
      'Bwd Packet Length Mean',
      'FIN Flag Count',
      'SYN Flag Count',
      'RST Flag Count',
      'PSH Flag Count',
      'ACK Flag Count',
    ];

    let hasAtLeastOneNumeric = false;

    numericFields.forEach((field) => {
      const val = formData[field];
      if (val !== '' && val !== null && val !== undefined) {
        const num = Number(val);
        if (isNaN(num) || !isFinite(num)) {
          errors[field] = 'Must be a valid finite number.';
        } else if (num < 0) {
          errors[field] = 'Value cannot be negative.';
        } else {
          hasAtLeastOneNumeric = true;
        }
      }
    });

    if (!hasAtLeastOneNumeric) {
      errors._general = 'Please provide at least one valid network flow feature metric.';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError(null);

    if (!validateForm()) {
      return;
    }

    // Prepare payload by stripping empty strings and casting numbers
    const payload = {};
    Object.entries(formData).forEach(([key, val]) => {
      if (val !== '' && val !== null && val !== undefined) {
        if (key === 'source_ip' || key === 'destination_ip') {
          payload[key] = String(val).trim();
        } else {
          const num = Number(val);
          if (!isNaN(num) && isFinite(num)) {
            payload[key] = num;
          }
        }
      }
    });

    setIsLoading(true);
    try {
      const result = await api.predictFlow(payload);
      setPredictionResult(result);
      if (onPredictionSuccess) {
        onPredictionSuccess(result);
      }
    } catch (err) {
      setApiError(err.message || 'An error occurred during AI inference.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto' }}>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Cpu color="var(--accent-cyan)" size={28} />
            AI Network Threat Prediction
          </h1>
          <p className="page-subtitle">
            Submit network flow telemetry for on-demand dual-stage anomaly detection and supervised threat classification.
          </p>
        </div>

        {/* Demo Preset Buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => applyPreset(PRESET_BENIGN_HTTPS)}
            className="preset-btn"
            title="Load standard HTTPS web traffic sample"
          >
            <Sparkles size={14} color="#10b981" />
            Normal HTTPS
          </button>
          <button
            type="button"
            onClick={() => applyPreset(PRESET_DOS_ATTACK)}
            className="preset-btn"
            title="Load high-rate SYN flood DoS attack telemetry"
          >
            <AlertTriangle size={14} color="#ef4444" />
            DoS SYN Flood
          </button>
          <button
            type="button"
            onClick={() => applyPreset(PRESET_PORT_SCAN)}
            className="preset-btn"
            title="Load TCP port scan telemetry"
          >
            <Activity size={14} color="#f97316" />
            Port Scan Probe
          </button>
          <button
            type="button"
            onClick={clearForm}
            className="preset-btn"
            style={{ opacity: 0.8 }}
            title="Clear all inputs"
          >
            <RotateCcw size={14} />
            Clear
          </button>
        </div>
      </div>

      {/* Main Grid: Form Left, Results Right */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '1.75rem', alignItems: 'start' }}>
        
        {/* Input Form Card */}
        <div className="section-card glass-panel" style={{ margin: 0 }}>
          <div className="section-header">
            <h2 className="section-title">
              <Activity size={18} color="var(--accent-cyan)" />
              Flow Telemetry Ingestion
            </h2>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              CIC-IDS2017 Feature Standard
            </span>
          </div>

          {validationErrors._general && (
            <div className="alert-box alert-error" style={{ marginBottom: '1.25rem' }}>
              <AlertTriangle size={16} />
              <span>{validationErrors._general}</span>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* Group 1: Network & Protocol */}
            <div className="form-group-title">Network & Addressing</div>
            <div className="form-grid">
              <div className="form-field">
                <label>Source IP (Optional Telemetry)</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.100"
                  value={formData.source_ip}
                  onChange={(e) => handleInputChange('source_ip', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Destination IP (Optional Telemetry)</label>
                <input
                  type="text"
                  placeholder="e.g. 10.0.0.1"
                  value={formData.destination_ip}
                  onChange={(e) => handleInputChange('destination_ip', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Destination Port *</label>
                <input
                  type="number"
                  placeholder="e.g. 443, 80, 22"
                  value={formData['Destination Port']}
                  onChange={(e) => handleInputChange('Destination Port', e.target.value)}
                  disabled={isLoading}
                />
                {validationErrors['Destination Port'] && (
                  <span className="field-error">{validationErrors['Destination Port']}</span>
                )}
              </div>

              <div className="form-field">
                <label>Protocol</label>
                <select
                  value={formData['Protocol']}
                  onChange={(e) => handleInputChange('Protocol', e.target.value)}
                  disabled={isLoading}
                >
                  <option value="6">TCP (6)</option>
                  <option value="17">UDP (17)</option>
                  <option value="1">ICMP (1)</option>
                </select>
              </div>
            </div>

            {/* Group 2: Flow Volume & Timing */}
            <div className="form-group-title">Flow Duration & Packet Volume</div>
            <div className="form-grid">
              <div className="form-field">
                <label>Flow Duration (μs) *</label>
                <input
                  type="number"
                  step="any"
                  placeholder="e.g. 245000"
                  value={formData['Flow Duration']}
                  onChange={(e) => handleInputChange('Flow Duration', e.target.value)}
                  disabled={isLoading}
                />
                {validationErrors['Flow Duration'] && (
                  <span className="field-error">{validationErrors['Flow Duration']}</span>
                )}
              </div>

              <div className="form-field">
                <label>Total Fwd Packets</label>
                <input
                  type="number"
                  placeholder="e.g. 14"
                  value={formData['Total Fwd Packets']}
                  onChange={(e) => handleInputChange('Total Fwd Packets', e.target.value)}
                  disabled={isLoading}
                />
                {validationErrors['Total Fwd Packets'] && (
                  <span className="field-error">{validationErrors['Total Fwd Packets']}</span>
                )}
              </div>

              <div className="form-field">
                <label>Total Backward Packets</label>
                <input
                  type="number"
                  placeholder="e.g. 18"
                  value={formData['Total Backward Packets']}
                  onChange={(e) => handleInputChange('Total Backward Packets', e.target.value)}
                  disabled={isLoading}
                />
                {validationErrors['Total Backward Packets'] && (
                  <span className="field-error">{validationErrors['Total Backward Packets']}</span>
                )}
              </div>

              <div className="form-field">
                <label>Total Length Fwd Packets (Bytes)</label>
                <input
                  type="number"
                  placeholder="e.g. 1240"
                  value={formData['Total Length of Fwd Packets']}
                  onChange={(e) => handleInputChange('Total Length of Fwd Packets', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Total Length Bwd Packets (Bytes)</label>
                <input
                  type="number"
                  placeholder="e.g. 18450"
                  value={formData['Total Length of Bwd Packets']}
                  onChange={(e) => handleInputChange('Total Length of Bwd Packets', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Flow Throughput (Bytes/s)</label>
                <input
                  type="number"
                  step="any"
                  placeholder="e.g. 80363.4"
                  value={formData['Flow Bytes/s']}
                  onChange={(e) => handleInputChange('Flow Bytes/s', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Flow Rate (Packets/s)</label>
                <input
                  type="number"
                  step="any"
                  placeholder="e.g. 130.6"
                  value={formData['Flow Packets/s']}
                  onChange={(e) => handleInputChange('Flow Packets/s', e.target.value)}
                  disabled={isLoading}
                />
              </div>

              <div className="form-field">
                <label>Flow IAT Mean (μs)</label>
                <input
                  type="number"
                  step="any"
                  placeholder="e.g. 7903.6"
                  value={formData['Flow IAT Mean']}
                  onChange={(e) => handleInputChange('Flow IAT Mean', e.target.value)}
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Group 3: TCP Flags */}
            <div className="form-group-title">TCP Control Flags</div>
            <div className="form-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))' }}>
              <div className="form-field">
                <label>SYN</label>
                <input
                  type="number"
                  min="0"
                  value={formData['SYN Flag Count']}
                  onChange={(e) => handleInputChange('SYN Flag Count', e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <div className="form-field">
                <label>ACK</label>
                <input
                  type="number"
                  min="0"
                  value={formData['ACK Flag Count']}
                  onChange={(e) => handleInputChange('ACK Flag Count', e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <div className="form-field">
                <label>FIN</label>
                <input
                  type="number"
                  min="0"
                  value={formData['FIN Flag Count']}
                  onChange={(e) => handleInputChange('FIN Flag Count', e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <div className="form-field">
                <label>RST</label>
                <input
                  type="number"
                  min="0"
                  value={formData['RST Flag Count']}
                  onChange={(e) => handleInputChange('RST Flag Count', e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <div className="form-field">
                <label>PSH</label>
                <input
                  type="number"
                  min="0"
                  value={formData['PSH Flag Count']}
                  onChange={(e) => handleInputChange('PSH Flag Count', e.target.value)}
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Submit Action */}
            <div style={{ marginTop: '1.75rem', display: 'flex', justifyContent: 'flex-end', gap: '1rem', alignItems: 'center' }}>
              {!canPredict && (
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  Viewer role is read-only (Analyst or Admin required to execute predictions)
                </span>
              )}
              <button
                type="submit"
                disabled={isLoading || !canPredict}
                className="btn-primary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.75rem 1.75rem',
                  opacity: (isLoading || !canPredict) ? 0.6 : 1,
                  cursor: (isLoading || !canPredict) ? 'not-allowed' : 'pointer',
                }}
              >
                {isLoading ? (
                  <>
                    <span className="spinner" />
                    <span>Analyzing Flow Telemetry...</span>
                  </>
                ) : (
                  <>
                    <Send size={16} />
                    <span>Execute AI Prediction</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* Prediction Results Display Card */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* API Error Notification */}
          {apiError && (
            <div className="alert-box alert-error">
              <AlertTriangle size={20} style={{ flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600 }}>Prediction Service Error</div>
                <div style={{ fontSize: '0.85rem', marginTop: '0.2rem' }}>{apiError}</div>
              </div>
            </div>
          )}

          {/* Pending Skeleton / Empty State */}
          {!predictionResult && !apiError && (
            <div className="section-card glass-panel" style={{ textAlign: 'center', padding: '3.5rem 2rem' }}>
              <div
                style={{
                  width: '60px',
                  height: '60px',
                  borderRadius: '50%',
                  background: 'rgba(0, 242, 254, 0.08)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 1.25rem',
                  color: 'var(--accent-cyan)',
                }}
              >
                <Cpu size={30} />
              </div>
              <h3 style={{ color: '#fff', fontSize: '1.15rem', fontWeight: 600 }}>
                Awaiting Telemetry Ingestion
              </h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', maxWidth: '400px', margin: '0.5rem auto 1.5rem' }}>
                Fill in the network flow metrics or select a quick demonstration preset above, then click <strong>Execute AI Prediction</strong>.
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem' }}>
                <span className="phase-tag" style={{ fontSize: '0.72rem' }}>Isolation Forest Ready</span>
                <span className="phase-tag" style={{ fontSize: '0.72rem' }}>Random Forest Ready</span>
              </div>
            </div>
          )}

          {/* Real Prediction Results Card */}
          {predictionResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              
              {/* Card 1: Composite Risk Assessment */}
              <div className="section-card glass-panel" style={{ margin: 0 }}>
                <div className="section-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    {predictionResult.classification.is_intrusion ? (
                      <ShieldAlert size={22} color="var(--status-critical)" />
                    ) : (
                      <ShieldCheck size={22} color="var(--status-healthy)" />
                    )}
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff' }}>
                      Composite Risk Assessment
                    </h3>
                  </div>
                  <StatusBadge status={predictionResult.risk_assessment.risk_level} type="risk" />
                </div>

                <div style={{ padding: '0.9rem', backgroundColor: 'rgba(0,0,0,0.25)', borderRadius: 'var(--radius-sm)', marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                    SOC Triage Recommendation
                  </div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#fff', marginTop: '0.3rem' }}>
                    {predictionResult.risk_assessment.recommended_action}
                  </div>
                </div>

                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {predictionResult.risk_assessment.summary}
                </div>

                {/* Phase 13: Rule-Based Prediction Explanation */}
                {predictionResult.explanation && (
                  <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.5rem' }}>
                      Rule-Based Prediction Explanation
                    </div>
                    {predictionResult.explanation.risk_reasons && predictionResult.explanation.risk_reasons.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        {predictionResult.explanation.risk_reasons.map((reason, idx) => (
                          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: '#e2e8f0' }}>
                            <span style={{ color: 'var(--accent-cyan)' }}>&bull;</span>
                            <span>{reason}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        Nominal baseline parameters; no elevated risk factors flagged.
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Card 2: Dual Model Breakdown (Anomaly + Classification) */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
                
                {/* Unsupervised Anomaly Detection */}
                <div className="section-card glass-panel" style={{ margin: 0, padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                      Isolation Forest Anomaly
                    </span>
                    <StatusBadge
                      status={predictionResult.anomaly.anomaly_label}
                      type={predictionResult.anomaly.is_anomaly ? 'severity' : 'status'}
                    />
                  </div>

                  <div style={{ margin: '1rem 0' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.35rem' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Normalized Outlier Score</span>
                      <span className="font-mono" style={{ color: '#fff', fontWeight: 600 }}>
                        {formatScore(predictionResult.anomaly.anomaly_score)}
                      </span>
                    </div>
                    {/* Score Bar */}
                    <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${Math.min(100, Math.max(0, predictionResult.anomaly.anomaly_score * 100))}%`,
                          backgroundColor: predictionResult.anomaly.is_anomaly ? 'var(--status-critical)' : 'var(--status-healthy)',
                          transition: 'width 0.4s ease-in-out',
                        }}
                      />
                    </div>
                  </div>

                  <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.65rem' }}>
                    <div>Raw Decision: <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{formatScore(predictionResult.anomaly.raw_decision_score)}</span></div>
                    <div style={{ marginTop: '0.25rem' }}>{predictionResult.anomaly.interpretation}</div>
                  </div>
                </div>

                {/* Supervised Threat Classification */}
                <div className="section-card glass-panel" style={{ margin: 0, padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                      Random Forest Threat
                    </span>
                    <StatusBadge
                      status={predictionResult.classification.is_intrusion ? 'INTRUSION' : 'BENIGN'}
                      type={predictionResult.classification.is_intrusion ? 'severity' : 'status'}
                    />
                  </div>

                  <div style={{ marginTop: '0.5rem' }}>
                    <div style={{ fontSize: '1.3rem', fontWeight: 700, color: '#fff' }}>
                      {predictionResult.classification.predicted_label}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                      <span>Estimated Class Probability:</span>
                      <strong style={{ color: 'var(--accent-cyan)' }}>
                        {formatPercentage(predictionResult.classification.confidence)}
                      </strong>
                    </div>
                  </div>

                  {/* Class Probabilities Distribution */}
                  {predictionResult.classification.class_probabilities && (
                    <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                        Class Probability Distribution
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                        {Object.entries(predictionResult.classification.class_probabilities).map(([cls, prob]) => (
                          <div key={cls}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', marginBottom: '0.15rem' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>{cls}</span>
                              <span className="font-mono" style={{ color: '#fff' }}>{formatPercentage(prob)}</span>
                            </div>
                            <div style={{ width: '100%', height: '4px', backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                              <div
                                style={{
                                  height: '100%',
                                  width: `${Math.min(100, Math.max(0, prob * 100))}%`,
                                  backgroundColor: cls === 'BENIGN' ? 'var(--status-healthy)' : 'var(--status-high)',
                                }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div style={{ marginTop: '0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    <Info size={12} />
                    <span>Estimated class probability (non-deterministic heuristic)</span>
                  </div>
                </div>

              </div>

            </div>
          )}

        </div>

      </div>
    </div>
  );
}
