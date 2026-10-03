import React from 'react';
import { Cpu, Award, Zap, Layers, RefreshCw, BarChart2 } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function ModelPerformancePlaceholder() {
  const models = [
    {
      name: 'Isolation Forest Anomaly Detector',
      type: 'Unsupervised Outlier Detection',
      version: 'v1.0.0',
      status: 'READY',
      features: '18 Flow Features',
      contamination: '3.0%',
      latency: '1.2 ms',
      dataset: 'CIC-IDS2017 & NSL-KDD',
    },
    {
      name: 'Random Forest Threat Classifier',
      type: 'Supervised Multi-Class Classifier',
      version: 'v1.0.0',
      status: 'READY',
      accuracy: '97.8%',
      f1Score: '0.972',
      precision: '98.1%',
      recall: '96.5%',
      latency: '2.4 ms',
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Cpu color="var(--accent-purple)" size={28} />
            Machine Learning Diagnostics & Governance
          </h1>
          <p className="page-subtitle">
            Model validation metrics, inference latency telemetry, and drift monitoring.
          </p>
        </div>
      </div>

      <div className="phase-banner">
        <span className="phase-tag">PHASE 4 BLUEPRINT</span>
        <div>
          <strong>Model Monitoring Specification:</strong> In Phase 4, this view connects to <code>GET /api/v1/models/status</code> and visualizes dynamic ROC-AUC curves, confusion matrices, and feature importance rankings.
        </div>
      </div>

      {/* Model Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        {models.map((model, idx) => (
          <div key={idx} className="glass-panel" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.1rem', color: '#fff', fontWeight: 600 }}>{model.name}</h3>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{model.type}</div>
              </div>
              <StatusBadge status={model.status} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.85rem', marginTop: '1rem' }}>
              <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>VERSION</div>
                <div className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600, marginTop: '0.2rem' }}>
                  {model.version}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>AVG LATENCY</div>
                <div className="font-mono" style={{ color: '#fff', fontWeight: 600, marginTop: '0.2rem' }}>
                  {model.latency}
                </div>
              </div>

              {model.accuracy && (
                <>
                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>ACCURACY</div>
                    <div className="font-mono" style={{ color: 'var(--status-healthy)', fontWeight: 600, marginTop: '0.2rem' }}>
                      {model.accuracy}
                    </div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>F1 SCORE</div>
                    <div className="font-mono" style={{ color: 'var(--status-healthy)', fontWeight: 600, marginTop: '0.2rem' }}>
                      {model.f1Score}
                    </div>
                  </div>
                </>
              )}

              {model.contamination && (
                <>
                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>CONTAMINATION</div>
                    <div className="font-mono" style={{ color: '#fff', fontWeight: 600, marginTop: '0.2rem' }}>
                      {model.contamination}
                    </div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>FEATURES</div>
                    <div className="font-mono" style={{ color: '#fff', fontWeight: 600, marginTop: '0.2rem' }}>
                      {model.features}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Confusion Matrix Mockup Grid */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div className="section-header">
          <h2 className="section-title">
            <BarChart2 size={18} color="var(--accent-purple)" />
            Confusion Matrix (Validation Benchmark Layout)
          </h2>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Benchmark Dataset: CIC-IDS2017 Validation Split
          </span>
        </div>

        <div style={{ overflowX: 'auto', marginTop: '1rem' }}>
          <table className="ids-table" style={{ textAlign: 'center' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left' }}>Actual \ Predicted</th>
                <th>Normal Flow</th>
                <th>DoS Attack</th>
                <th>Port Scan</th>
                <th>Brute Force</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ textAlign: 'left', fontWeight: 600 }}>Normal Flow</td>
                <td style={{ background: 'rgba(16, 185, 129, 0.25)', color: '#10b981', fontWeight: 700 }}>98.8%</td>
                <td>0.4%</td>
                <td>0.6%</td>
                <td>0.2%</td>
              </tr>
              <tr>
                <td style={{ textAlign: 'left', fontWeight: 600 }}>DoS Attack</td>
                <td>0.8%</td>
                <td style={{ background: 'rgba(16, 185, 129, 0.25)', color: '#10b981', fontWeight: 700 }}>97.9%</td>
                <td>0.9%</td>
                <td>0.4%</td>
              </tr>
              <tr>
                <td style={{ textAlign: 'left', fontWeight: 600 }}>Port Scan</td>
                <td>1.2%</td>
                <td>0.5%</td>
                <td style={{ background: 'rgba(16, 185, 129, 0.25)', color: '#10b981', fontWeight: 700 }}>96.7%</td>
                <td>1.6%</td>
              </tr>
              <tr>
                <td style={{ textAlign: 'left', fontWeight: 600 }}>Brute Force</td>
                <td>0.5%</td>
                <td>0.3%</td>
                <td>1.8%</td>
                <td style={{ background: 'rgba(16, 185, 129, 0.25)', color: '#10b981', fontWeight: 700 }}>97.4%</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
