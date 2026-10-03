import React, { useState, useEffect, useCallback } from 'react';
import {
  BarChart3,
  RefreshCw,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Activity,
  Radio,
  Search,
  Lock,
  Globe,
  TrendingUp,
  Clock,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import api from '../services/api';
import { formatPercentage, formatScore } from '../utils/formatters';

export default function SecurityAnalytics() {
  const [overview, setOverview] = useState(null);
  const [distribution, setDistribution] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [topSources, setTopSources] = useState(null);
  const [timeRange, setTimeRange] = useState('7d');

  // Threat Intel Lookup State
  const [lookupIp, setLookupIp] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [lookupError, setLookupError] = useState(null);

  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState(null);

  // Controlled fetch function (no automatic polling loops)
  const fetchAllAnalytics = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const [overviewRes, distRes, timeRes, sourcesRes] = await Promise.all([
        api.getAnalyticsOverview(),
        api.getThreatDistribution(),
        api.getSecurityTimeline({ time_range: timeRange, limit: 30 }),
        api.getTopThreatSources({ limit: 10 }),
      ]);
      setOverview(overviewRes);
      setDistribution(distRes);
      setTimeline(timeRes);
      setTopSources(sourcesRes);
    } catch (err) {
      setApiError(err.message || 'Failed to retrieve security analytics.');
    } finally {
      setIsLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchAllAnalytics();
  }, [fetchAllAnalytics]);

  // Execute manual threat intelligence lookup
  const handleThreatIntelSubmit = async (e) => {
    e.preventDefault();
    if (!lookupIp.trim()) return;

    setIsLookingUp(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const res = await api.lookupThreatIntel(lookupIp.trim());
      setLookupResult(res);
    } catch (err) {
      setLookupError(err.message || 'Failed to query threat intelligence.');
    } finally {
      setIsLookingUp(false);
    }
  };

  const renderReputationBadge = (rep) => {
    const norm = String(rep || 'UNKNOWN').toUpperCase();
    let bg = 'rgba(100, 116, 139, 0.2)';
    let color = '#94a3b8';
    let border = 'rgba(100, 116, 139, 0.4)';

    if (norm === 'MALICIOUS') {
      bg = 'rgba(239, 68, 68, 0.2)';
      color = '#ef4444';
      border = 'rgba(239, 68, 68, 0.5)';
    } else if (norm === 'SUSPICIOUS') {
      bg = 'rgba(245, 158, 11, 0.2)';
      color = '#f59e0b';
      border = 'rgba(245, 158, 11, 0.5)';
    } else if (norm === 'BENIGN') {
      bg = 'rgba(16, 185, 129, 0.2)';
      color = '#10b981';
      border = 'rgba(16, 185, 129, 0.5)';
    }

    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.2rem 0.55rem',
          borderRadius: '4px',
          fontSize: '0.75rem',
          fontWeight: 700,
          backgroundColor: bg,
          color,
          border: `1px solid ${border}`,
        }}
      >
        {norm}
      </span>
    );
  };

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <BarChart3 color="var(--accent-cyan)" size={28} />
            Security Analytics & Threat Intelligence
          </h1>
          <p className="page-subtitle">
            Enterprise threat distribution analysis, incident severity metrics, originating attack sources, and demonstration threat intelligence.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={fetchAllAnalytics}
            disabled={isLoading}
            className="preset-btn"
            title="Refresh analytics telemetry"
            style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}
          >
            <RefreshCw size={14} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
            <span>Refresh Analytics</span>
          </button>
        </div>
      </div>

      {/* API Error Notification */}
      {apiError && (
        <div className="alert-box alert-error" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Analytics Telemetry Notice</div>
            <div style={{ fontSize: '0.85rem' }}>{apiError}</div>
          </div>
          <button
            onClick={fetchAllAnalytics}
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

      {/* KPI Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
          marginBottom: '1.75rem',
        }}
      >
        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Total Predictions</div>
            <div className="metric-value">{overview ? overview.total_predictions : '-'}</div>
            <div className="metric-subtext">Persisted flow records</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Malicious Flows</div>
            <div className="metric-value" style={{ color: 'var(--status-critical)' }}>
              {overview ? overview.malicious_predictions : '-'}
            </div>
            <div className="metric-subtext">Classified attack patterns</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Active Alerts</div>
            <div className="metric-value" style={{ color: 'var(--status-high)' }}>
              {overview ? overview.open_alerts : '-'}
            </div>
            <div className="metric-subtext">NEW or ACKNOWLEDGED</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Critical Incidents</div>
            <div className="metric-value" style={{ color: 'var(--status-critical)' }}>
              {overview ? overview.critical_alerts : '-'}
            </div>
            <div className="metric-subtext">Severity = CRITICAL</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Failed Logins</div>
            <div className="metric-value" style={{ color: '#f59e0b' }}>
              {overview ? overview.failed_logins : '-'}
            </div>
            <div className="metric-subtext">Auth failure audits</div>
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <div className="metric-label">Rate Limit Throttles</div>
            <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>
              {overview ? overview.rate_limit_events : '-'}
            </div>
            <div className="metric-subtext">Abuse 429 events</div>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Distributions */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '1.5rem',
          marginBottom: '1.75rem',
        }}
      >
        {/* Threat Category Distribution */}
        <div className="section-card glass-panel">
          <div className="section-header" style={{ marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <TrendingUp size={20} color="var(--accent-cyan)" />
              <div>
                <h3 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                  Threat Category Distribution
                </h3>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  Evaluated attack patterns classified by supervised Random Forest
                </div>
              </div>
            </div>
          </div>

          {distribution && distribution.threat_categories.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {distribution.threat_categories.map((item) => (
                <div key={item.category}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: item.category === 'Benign' ? 'var(--status-low)' : '#fff' }}>
                      {item.category}
                    </span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {item.count} ({item.percentage}%)
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${Math.min(100, Math.max(2, item.percentage))}%`,
                        height: '100%',
                        backgroundColor: item.category === 'Benign' ? 'var(--status-low)' : 'var(--accent-cyan)',
                        borderRadius: '4px',
                        transition: 'width 0.4s ease-in-out',
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No threat evaluation records available.
            </div>
          )}
        </div>

        {/* Severity Distribution */}
        <div className="section-card glass-panel">
          <div className="section-header" style={{ marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <ShieldAlert size={20} color="var(--status-critical)" />
              <div>
                <h3 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                  Incident Severity Triage
                </h3>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  Dual-engine composite risk ratings across all evaluated flows
                </div>
              </div>
            </div>
          </div>

          {distribution && distribution.severity.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {distribution.severity.map((item) => {
                let barColor = 'var(--status-low)';
                if (item.severity === 'CRITICAL') barColor = 'var(--status-critical)';
                else if (item.severity === 'HIGH') barColor = 'var(--status-high)';
                else if (item.severity === 'MEDIUM') barColor = 'var(--status-medium)';

                return (
                  <div key={item.severity}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 600, color: barColor }}>{item.severity}</span>
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {item.count} ({item.percentage}%)
                      </span>
                    </div>
                    <div style={{ width: '100%', height: '8px', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${Math.min(100, Math.max(2, item.percentage))}%`,
                          height: '100%',
                          backgroundColor: barColor,
                          borderRadius: '4px',
                          transition: 'width 0.4s ease-in-out',
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No severity distribution records available.
            </div>
          )}
        </div>
      </div>

      {/* Security Timeline Chart / Time Series */}
      <div className="section-card glass-panel" style={{ marginBottom: '1.75rem' }}>
        <div className="section-header" style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <Clock size={20} color="var(--accent-blue)" />
            <div>
              <h3 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                Security Event Timeline
              </h3>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Temporal trends across predictions, alerts, and access events
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.35rem' }}>
            {['24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className="preset-btn"
                style={{
                  fontSize: '0.75rem',
                  padding: '0.25rem 0.65rem',
                  backgroundColor: timeRange === r ? 'rgba(0, 242, 254, 0.2)' : 'transparent',
                  color: timeRange === r ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  border: timeRange === r ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                }}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {timeline && timeline.timeline.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time Slice</th>
                  <th>Predictions</th>
                  <th>Alerts</th>
                  <th>Failed Logins</th>
                  <th>Access Denied</th>
                  <th>Rate Limits</th>
                </tr>
              </thead>
              <tbody>
                {timeline.timeline.map((bucket) => (
                  <tr key={bucket.bucket_time}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#fff' }}>
                      {bucket.bucket_time}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                      {bucket.predictions}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: bucket.alerts > 0 ? 'var(--status-critical)' : 'var(--text-muted)' }}>
                      {bucket.alerts}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: bucket.failed_logins > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
                      {bucket.failed_logins}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: bucket.access_denied > 0 ? 'var(--status-high)' : 'var(--text-muted)' }}>
                      {bucket.access_denied}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: bucket.rate_limit_events > 0 ? 'var(--accent-blue)' : 'var(--text-muted)' }}>
                      {bucket.rate_limit_events}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No timeline activity recorded in the selected window.
          </div>
        )}
      </div>

      {/* Bottom Grid: Top Sources & Threat Intelligence Lookup */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '1.5rem',
        }}
      >
        {/* Top Threat Sources */}
        <div className="section-card glass-panel">
          <div className="section-header" style={{ marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Globe size={20} color="var(--accent-cyan)" />
              <div>
                <h3 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                  Top Originating Threat Sources
                </h3>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  Aggregated source IP addresses observed in traffic evaluations
                </div>
              </div>
            </div>
          </div>

          {topSources && topSources.items.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Flows</th>
                    <th>Malicious</th>
                    <th>Highest Risk</th>
                    <th>Common Threat</th>
                  </tr>
                </thead>
                <tbody>
                  {topSources.items.map((src) => (
                    <tr key={src.source_ip}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {src.source_ip}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{src.prediction_count}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', color: src.malicious_count > 0 ? 'var(--status-critical)' : 'inherit' }}>
                        {src.malicious_count}
                      </td>
                      <td style={{ fontWeight: 600 }}>{src.highest_severity}</td>
                      <td>{src.most_common_threat}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Globe size={28} color="var(--text-muted)" style={{ margin: '0 auto 0.5rem', opacity: 0.4 }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff', marginBottom: '0.25rem' }}>
                No Source IP Telemetry Available
              </div>
              <div style={{ fontSize: '0.78rem' }}>
                Incoming predictions have not supplied client source IP attributes, or no flow records exist yet.
              </div>
            </div>
          )}
        </div>

        {/* Demonstration Threat Intelligence Tool */}
        <div className="section-card glass-panel">
          <div className="section-header" style={{ marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <Search size={20} color="#a855f7" />
              <div>
                <h3 className="section-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                  Threat Intelligence Lookup
                </h3>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  Offline demonstration threat reputation database (RFC 5737 & lab telemetry)
                </div>
              </div>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleThreatIntelSubmit} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="e.g. 192.0.2.1 or 198.51.100.42"
              value={lookupIp}
              onChange={(e) => setLookupIp(e.target.value)}
              className="filter-input"
              style={{
                flex: 1,
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                padding: '0.45rem 0.75rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <button
              type="submit"
              disabled={isLookingUp || !lookupIp.trim()}
              className="btn-primary"
              style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
            >
              {isLookingUp ? 'Searching...' : 'Lookup IP'}
            </button>
          </form>

          {/* Lookup Error */}
          {lookupError && (
            <div className="alert-box alert-error" style={{ marginBottom: '1rem' }}>
              <AlertTriangle size={16} />
              <div style={{ fontSize: '0.8rem' }}>{lookupError}</div>
            </div>
          )}

          {/* Result Card */}
          {lookupResult && (
            <div
              style={{
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.92rem', fontWeight: 700, color: '#fff' }}>
                  {lookupResult.ip}
                </div>
                <span
                  style={{
                    fontSize: '0.65rem',
                    padding: '0.1rem 0.35rem',
                    borderRadius: '3px',
                    backgroundColor: 'rgba(168, 85, 247, 0.15)',
                    color: '#a855f7',
                    fontWeight: 700,
                  }}
                >
                  {lookupResult.source}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem', fontSize: '0.78rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Reputation: </span>
                  {renderReputationBadge(lookupResult.reputation)}
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Confidence: </span>
                  <span style={{ color: '#fff', fontWeight: 600 }}>
                    {formatPercentage(lookupResult.confidence)}
                  </span>
                </div>
                <div style={{ gridColumn: 'span 2' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Categories: </span>
                  <span style={{ color: 'var(--accent-cyan)' }}>
                    {lookupResult.categories && lookupResult.categories.length > 0
                      ? lookupResult.categories.join(', ')
                      : 'None'}
                  </span>
                </div>
                {lookupResult.first_seen && (
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>First Seen: </span>
                    <span style={{ color: 'var(--text-secondary)' }}>{lookupResult.first_seen.split('T')[0]}</span>
                  </div>
                )}
                {lookupResult.last_seen && (
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Last Seen: </span>
                    <span style={{ color: 'var(--text-secondary)' }}>{lookupResult.last_seen.split('T')[0]}</span>
                  </div>
                )}
              </div>

              {lookupResult.notes && (
                <div style={{ marginTop: '0.65rem', fontSize: '0.74rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  Note: {lookupResult.notes}
                </div>
              )}
            </div>
          )}

          {!lookupResult && !lookupError && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1.25rem 0' }}>
              Enter an IP address and submit to query local demonstration threat reputation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
