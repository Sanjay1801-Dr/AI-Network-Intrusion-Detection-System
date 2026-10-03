import React, { useState, useEffect, useCallback } from 'react';
import {
  Crosshair,
  Search,
  Filter,
  RefreshCw,
  Clock,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Activity,
  History,
  Eye,
  Calendar,
  X,
  ChevronLeft,
  ChevronRight,
  Sliders,
  Layers,
  Globe,
  Radio,
  ExternalLink,
  Info,
  CheckCircle2,
} from 'lucide-react';
import api from '../services/api';
import StatusBadge from '../components/StatusBadge';
import InvestigationModal from '../components/InvestigationModal';
import { formatDateTime, formatPercentage, formatScore } from '../utils/formatters';

export default function ThreatHunting({ setActiveTab }) {
  // ---------------------------------------------------------------------------
  // 1. Summary Metrics State
  // ---------------------------------------------------------------------------
  const [summary, setSummary] = useState(null);
  const [isSummaryLoading, setIsSummaryLoading] = useState(false);

  // ---------------------------------------------------------------------------
  // 2. Filter Form State
  // ---------------------------------------------------------------------------
  const [timeRange, setTimeRange] = useState('24h');
  const [startDatetime, setStartDatetime] = useState('');
  const [endDatetime, setEndDatetime] = useState('');

  const [sourceIp, setSourceIp] = useState('');
  const [destinationIp, setDestinationIp] = useState('');
  const [sourcePort, setSourcePort] = useState('');
  const [destinationPort, setDestinationPort] = useState('');
  const [protocol, setProtocol] = useState('');

  const [threatCategory, setThreatCategory] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [riskLevel, setRiskLevel] = useState('ALL');
  const [minAnomalyScore, setMinAnomalyScore] = useState('');
  const [maxAnomalyScore, setMaxAnomalyScore] = useState('');
  const [minConfidence, setMinConfidence] = useState('');
  const [maxConfidence, setMaxConfidence] = useState('');

  const [alertStatus, setAlertStatus] = useState('ALL');
  const [incidentStatus, setIncidentStatus] = useState('ALL');
  const [queryText, setQueryText] = useState('');

  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);

  // ---------------------------------------------------------------------------
  // 3. Search Execution & Results State
  // ---------------------------------------------------------------------------
  const [searchResults, setSearchResults] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);
  const [activeResultsTab, setActiveResultsTab] = useState('predictions');

  // ---------------------------------------------------------------------------
  // 4. Query History State
  // ---------------------------------------------------------------------------
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [historyItems, setHistoryItems] = useState([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(false);

  // ---------------------------------------------------------------------------
  // 5. Source Investigation State
  // ---------------------------------------------------------------------------
  const [investigatingSourceIp, setInvestigatingSourceIp] = useState(null);
  const [sourceProfile, setSourceProfile] = useState(null);
  const [isSourceLoading, setIsSourceLoading] = useState(false);
  const [sourceError, setSourceError] = useState(null);

  // ---------------------------------------------------------------------------
  // 6. Prediction Deep Investigation Modal (Reusing Phase 13 Component)
  // ---------------------------------------------------------------------------
  const [selectedPredictionId, setSelectedPredictionId] = useState(null);

  // ---------------------------------------------------------------------------
  // Fetch Summary Metrics
  // ---------------------------------------------------------------------------
  const fetchSummary = useCallback(async () => {
    setIsSummaryLoading(true);
    try {
      const data = await api.getHuntingSummary();
      setSummary(data);
    } catch {
      // Non-fatal if summary metrics fail
    } finally {
      setIsSummaryLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  // ---------------------------------------------------------------------------
  // Execute Hunt Search
  // ---------------------------------------------------------------------------
  const executeSearch = async (overrideOffset = 0, customFilters = null) => {
    setIsSearching(true);
    setSearchError(null);

    try {
      const payload = {
        time_range: customFilters ? customFilters.time_range : timeRange,
        source_ip: (customFilters ? customFilters.source_ip : sourceIp).trim() || undefined,
        destination_ip: (customFilters ? customFilters.destination_ip : destinationIp).trim() || undefined,
        source_port: (customFilters ? customFilters.source_port : sourcePort)
          ? parseInt(customFilters ? customFilters.source_port : sourcePort, 10)
          : undefined,
        destination_port: (customFilters ? customFilters.destination_port : destinationPort)
          ? parseInt(customFilters ? customFilters.destination_port : destinationPort, 10)
          : undefined,
        protocol: (customFilters ? customFilters.protocol : protocol).trim() || undefined,
        threat_category: (customFilters ? customFilters.threat_category : threatCategory).trim() || undefined,
        severity: (customFilters ? customFilters.severity : severity) !== 'ALL'
          ? (customFilters ? customFilters.severity : severity)
          : undefined,
        risk_level: (customFilters ? customFilters.risk_level : riskLevel) !== 'ALL'
          ? (customFilters ? customFilters.risk_level : riskLevel)
          : undefined,
        min_anomaly_score: (customFilters ? customFilters.min_anomaly_score : minAnomalyScore) !== ''
          ? parseFloat(customFilters ? customFilters.min_anomaly_score : minAnomalyScore)
          : undefined,
        max_anomaly_score: (customFilters ? customFilters.max_anomaly_score : maxAnomalyScore) !== ''
          ? parseFloat(customFilters ? customFilters.max_anomaly_score : maxAnomalyScore)
          : undefined,
        min_confidence: (customFilters ? customFilters.min_confidence : minConfidence) !== ''
          ? parseFloat(customFilters ? customFilters.min_confidence : minConfidence)
          : undefined,
        max_confidence: (customFilters ? customFilters.max_confidence : maxConfidence) !== ''
          ? parseFloat(customFilters ? customFilters.max_confidence : maxConfidence)
          : undefined,
        alert_status: (customFilters ? customFilters.alert_status : alertStatus) !== 'ALL'
          ? (customFilters ? customFilters.alert_status : alertStatus)
          : undefined,
        incident_status: (customFilters ? customFilters.incident_status : incidentStatus) !== 'ALL'
          ? (customFilters ? customFilters.incident_status : incidentStatus)
          : undefined,
        query_text: (customFilters ? customFilters.query_text : queryText).trim() || undefined,
        limit: limit,
        offset: overrideOffset,
      };

      const effTimeRange = customFilters ? customFilters.time_range : timeRange;
      if (effTimeRange === 'custom') {
        const effStart = customFilters ? customFilters.start_datetime : startDatetime;
        const effEnd = customFilters ? customFilters.end_datetime : endDatetime;
        if (!effStart || !effEnd) {
          throw new Error('Custom time range requires both start and end datetimes.');
        }
        payload.start_datetime = new Date(effStart).toISOString();
        payload.end_datetime = new Date(effEnd).toISOString();
      }

      const res = await api.huntSearch(payload);
      setSearchResults(res);
      setOffset(overrideOffset);
    } catch (err) {
      setSearchError(err.message || 'Threat hunting query execution failed.');
    } finally {
      setIsSearching(false);
    }
  };

  // Initial trigger
  useEffect(() => {
    executeSearch(0);
  }, []); // Run once on mount with defaults

  // ---------------------------------------------------------------------------
  // Reset All Filters
  // ---------------------------------------------------------------------------
  const resetFilters = () => {
    setTimeRange('24h');
    setStartDatetime('');
    setEndDatetime('');
    setSourceIp('');
    setDestinationIp('');
    setSourcePort('');
    setDestinationPort('');
    setProtocol('');
    setThreatCategory('');
    setSeverity('ALL');
    setRiskLevel('ALL');
    setMinAnomalyScore('');
    setMaxAnomalyScore('');
    setMinConfidence('');
    setMaxConfidence('');
    setAlertStatus('ALL');
    setIncidentStatus('ALL');
    setQueryText('');
    setOffset(0);
  };

  // ---------------------------------------------------------------------------
  // Load Query History
  // ---------------------------------------------------------------------------
  const fetchQueryHistory = async () => {
    setIsHistoryLoading(true);
    try {
      const items = await api.getHuntingHistory(20);
      setHistoryItems(items);
      setShowHistoryModal(true);
    } catch (err) {
      setSearchError(err.message || 'Failed to retrieve query history.');
    } finally {
      setIsHistoryLoading(false);
    }
  };

  const applyHistoricalQuery = (item) => {
    const f = item.filters || {};
    setTimeRange(f.time_range || '24h');
    setStartDatetime(f.start_datetime ? f.start_datetime.slice(0, 16) : '');
    setEndDatetime(f.end_datetime ? f.end_datetime.slice(0, 16) : '');
    setSourceIp(f.source_ip || '');
    setDestinationIp(f.destination_ip || '');
    setSourcePort(f.source_port ? String(f.source_port) : '');
    setDestinationPort(f.destination_port ? String(f.destination_port) : '');
    setProtocol(f.protocol || '');
    setThreatCategory(f.threat_category || '');
    setSeverity(f.severity || 'ALL');
    setRiskLevel(f.risk_level || 'ALL');
    setMinAnomalyScore(f.min_anomaly_score !== undefined ? String(f.min_anomaly_score) : '');
    setMaxAnomalyScore(f.max_anomaly_score !== undefined ? String(f.max_anomaly_score) : '');
    setMinConfidence(f.min_confidence !== undefined ? String(f.min_confidence) : '');
    setMaxConfidence(f.max_confidence !== undefined ? String(f.max_confidence) : '');
    setAlertStatus(f.alert_status || 'ALL');
    setIncidentStatus(f.incident_status || 'ALL');
    setQueryText(f.query_text || '');

    setShowHistoryModal(false);
    executeSearch(0, f);
  };

  // ---------------------------------------------------------------------------
  // Source Investigation Fetch
  // ---------------------------------------------------------------------------
  const openSourceInvestigation = async (ip) => {
    if (!ip || ip === 'Unknown' || ip === 'N/A') return;
    setInvestigatingSourceIp(ip);
    setIsSourceLoading(true);
    setSourceError(null);
    setSourceProfile(null);

    try {
      const profile = await api.investigateSource(ip);
      setSourceProfile(profile);
    } catch (err) {
      setSourceError(err.message || `Failed to retrieve source profile for ${ip}`);
    } finally {
      setIsSourceLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* -------------------------------------------------------------------- */}
      {/* Top Banner & Header */}
      {/* -------------------------------------------------------------------- */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '1rem',
          paddingBottom: '0.5rem',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(79, 172, 254, 0.2))',
                border: '1px solid rgba(0, 242, 254, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Crosshair size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fff', margin: 0, letterSpacing: '-0.02em' }}>
                Advanced Threat Hunting & Investigation Workbench
              </h1>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Multi-dimensional search, temporal burst correlation & source-centric forensic analysis
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
          <button
            onClick={fetchQueryHistory}
            disabled={isHistoryLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 0.95rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.82rem',
              fontWeight: 500,
            }}
          >
            <History size={15} color="var(--accent-cyan)" />
            Query History
          </button>

          <button
            onClick={fetchSummary}
            disabled={isSummaryLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 0.95rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.82rem',
              fontWeight: 500,
            }}
          >
            <RefreshCw size={15} className={isSummaryLoading ? 'spin' : ''} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Workbench Telemetry KPI Cards */}
      {/* -------------------------------------------------------------------- */}
      {summary && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem',
          }}
        >
          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Activity size={14} color="var(--accent-cyan)" />
              Flows Ingested
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fff', marginTop: '0.35rem' }}>
              {summary.total_flows_investigated.toLocaleString()}
            </div>
          </div>

          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <ShieldAlert size={14} color="#f59e0b" />
              Threat Detections
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f59e0b', marginTop: '0.35rem' }}>
              {summary.total_threat_detections.toLocaleString()}
            </div>
          </div>

          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <AlertTriangle size={14} color="#ef4444" />
              Active Alerts
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ef4444', marginTop: '0.35rem' }}>
              {summary.total_active_alerts.toLocaleString()}
            </div>
          </div>

          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Layers size={14} color="#3b82f6" />
              Open Incidents
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#3b82f6', marginTop: '0.35rem' }}>
              {summary.total_open_incidents.toLocaleString()}
            </div>
          </div>

          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Globe size={14} color="#10b981" />
              Unique Sources
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#10b981', marginTop: '0.35rem' }}>
              {summary.unique_source_ips.toLocaleString()}
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* Query Builder / Search Filter Panel */}
      {/* -------------------------------------------------------------------- */}
      <div
        style={{
          borderRadius: 'var(--radius-md)',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        {/* Row 1: Time Window & Quick Selectors */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Clock size={14} color="var(--accent-cyan)" />
              Time Window:
            </span>
            {['1h', '24h', '7d', '30d', 'custom'].map((opt) => (
              <button
                key={opt}
                onClick={() => setTimeRange(opt)}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.78rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: timeRange === opt ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                  backgroundColor: timeRange === opt ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255,255,255,0.03)',
                  color: timeRange === opt ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  textTransform: opt === 'custom' ? 'capitalize' : 'uppercase',
                }}
              >
                {opt}
              </button>
            ))}
          </div>

          {timeRange === 'custom' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input
                type="datetime-local"
                value={startDatetime}
                onChange={(e) => setStartDatetime(e.target.value)}
                style={{
                  padding: '0.4rem 0.6rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  color: '#fff',
                  fontSize: '0.78rem',
                }}
              />
              <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>to</span>
              <input
                type="datetime-local"
                value={endDatetime}
                onChange={(e) => setEndDatetime(e.target.value)}
                style={{
                  padding: '0.4rem 0.6rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  color: '#fff',
                  fontSize: '0.78rem',
                }}
              />
            </div>
          )}
        </div>

        {/* Row 2: Network Telemetry Filters */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Source IP
            </label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.100"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Destination IP
            </label>
            <input
              type="text"
              placeholder="e.g. 10.0.0.5"
              value={destinationIp}
              onChange={(e) => setDestinationIp(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Source Port
            </label>
            <input
              type="number"
              placeholder="1 - 65535"
              value={sourcePort}
              onChange={(e) => setSourcePort(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Destination Port
            </label>
            <input
              type="number"
              placeholder="e.g. 80, 443, 22"
              value={destinationPort}
              onChange={(e) => setDestinationPort(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Protocol
            </label>
            <input
              type="text"
              placeholder="e.g. TCP, UDP, 6"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>
        </div>

        {/* Row 3: Threat Detection, Severity & Score Filters */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Threat Category
            </label>
            <input
              type="text"
              placeholder="DoS, DDoS, PortScan..."
              value={threatCategory}
              onChange={(e) => setThreatCategory(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Severity
            </label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Anomaly Score Range
            </label>
            <div style={{ display: 'flex', gap: '0.35rem' }}>
              <input
                type="number"
                step="0.1"
                placeholder="Min (-1.0)"
                value={minAnomalyScore}
                onChange={(e) => setMinAnomalyScore(e.target.value)}
                style={{
                  width: '50%',
                  padding: '0.45rem 0.45rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  color: '#fff',
                  fontSize: '0.75rem',
                }}
              />
              <input
                type="number"
                step="0.1"
                placeholder="Max (1.0)"
                value={maxAnomalyScore}
                onChange={(e) => setMaxAnomalyScore(e.target.value)}
                style={{
                  width: '50%',
                  padding: '0.45rem 0.45rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-subtle)',
                  color: '#fff',
                  fontSize: '0.75rem',
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Min Confidence
            </label>
            <input
              type="number"
              step="0.05"
              placeholder="0.0 - 1.0"
              value={minConfidence}
              onChange={(e) => setMinConfidence(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Free Text Search
            </label>
            <input
              type="text"
              placeholder="Search labels, keys..."
              value={queryText}
              onChange={(e) => setQueryText(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '0.8rem',
              }}
            />
          </div>
        </div>

        {/* Row 4: Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.65rem', marginTop: '0.25rem' }}>
          <button
            onClick={resetFilters}
            style={{
              padding: '0.55rem 1rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(255,255,255,0.05)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              fontSize: '0.82rem',
              fontWeight: 500,
            }}
          >
            Reset Filters
          </button>

          <button
            onClick={() => executeSearch(0)}
            disabled={isSearching}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.55rem 1.25rem',
              borderRadius: 'var(--radius-sm)',
              background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
              border: 'none',
              color: '#080c16',
              fontWeight: 700,
              fontSize: '0.85rem',
              cursor: isSearching ? 'not-allowed' : 'pointer',
              boxShadow: 'var(--shadow-glow-cyan)',
            }}
          >
            {isSearching ? <RefreshCw size={15} className="spin" /> : <Search size={15} />}
            Execute Threat Hunt
          </button>
        </div>
      </div>

      {/* Error Alert Box */}
      {searchError && (
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#ef4444',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertTriangle size={16} />
          <span>{searchError}</span>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* Correlation Insights Banner */}
      {/* -------------------------------------------------------------------- */}
      {searchResults && searchResults.correlations && searchResults.correlations.length > 0 && (
        <div
          style={{
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'rgba(15, 23, 42, 0.7)',
            border: '1px solid rgba(0, 242, 254, 0.25)',
            padding: '1.15rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Crosshair size={18} color="var(--accent-cyan)" />
              <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#fff' }}>
                Correlated Security Findings ({searchResults.correlations.length})
              </span>
            </div>
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--text-muted)',
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
              }}
            >
              Potentially related security activity
            </span>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '0.75rem',
            }}
          >
            {searchResults.correlations.map((c, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.4rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                    {c.title}
                  </span>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      padding: '0.15rem 0.45rem',
                      borderRadius: '4px',
                      backgroundColor:
                        c.confidence === 'HIGH'
                          ? 'rgba(239, 68, 68, 0.15)'
                          : 'rgba(245, 158, 11, 0.15)',
                      color: c.confidence === 'HIGH' ? '#ef4444' : '#f59e0b',
                    }}
                  >
                    {c.confidence} CONFIDENCE
                  </span>
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {c.description}
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: '0.2rem' }}>
                  {c.disclaimer}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* Results View: Tabs & Tables */}
      {/* -------------------------------------------------------------------- */}
      <div
        style={{
          borderRadius: 'var(--radius-md)',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
        }}
      >
        {/* Results Header with Counts & Tabs */}
        <div
          style={{
            padding: '0.85rem 1.25rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
            backgroundColor: 'rgba(0,0,0,0.15)',
          }}
        >
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => setActiveResultsTab('predictions')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.45rem 0.85rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                backgroundColor: activeResultsTab === 'predictions' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                color: activeResultsTab === 'predictions' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: activeResultsTab === 'predictions' ? '1px solid var(--border-active)' : '1px solid transparent',
              }}
            >
              <Cpu size={15} />
              Flow Inferences ({searchResults ? searchResults.total_predictions : 0})
            </button>

            <button
              onClick={() => setActiveResultsTab('alerts')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.45rem 0.85rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                backgroundColor: activeResultsTab === 'alerts' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                color: activeResultsTab === 'alerts' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: activeResultsTab === 'alerts' ? '1px solid var(--border-active)' : '1px solid transparent',
              }}
            >
              <AlertTriangle size={15} />
              Security Alerts ({searchResults ? searchResults.total_alerts : 0})
            </button>

            <button
              onClick={() => setActiveResultsTab('incidents')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.45rem 0.85rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                backgroundColor: activeResultsTab === 'incidents' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                color: activeResultsTab === 'incidents' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: activeResultsTab === 'incidents' ? '1px solid var(--border-active)' : '1px solid transparent',
              }}
            >
              <ShieldAlert size={15} />
              Incidents ({searchResults ? searchResults.total_incidents : 0})
            </button>
          </div>

          {searchResults && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Range: <span style={{ color: '#fff' }}>{searchResults.time_range_label}</span>
            </div>
          )}
        </div>

        {/* Tab 1: Predictions */}
        {activeResultsTab === 'predictions' && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>ID / Timestamp</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Source IP</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Destination</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Protocol</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Predicted Threat</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Risk Level</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Anomaly Score</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Confidence</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {searchResults && searchResults.matching_predictions && searchResults.matching_predictions.length > 0 ? (
                  searchResults.matching_predictions.map((p) => (
                    <tr
                      key={p.id}
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        transition: 'background-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ fontWeight: 600, color: '#fff' }}>#{p.id}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {formatDateTime(p.timestamp)}
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          onClick={() => openSourceInvestigation(p.source_ip)}
                          title="Investigate Source IP"
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--accent-cyan)',
                            cursor: 'pointer',
                            fontSize: '0.8rem',
                            fontWeight: 600,
                            padding: 0,
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                            textDecoration: 'underline',
                          }}
                        >
                          {p.source_ip || 'N/A'}
                        </button>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {p.destination_ip || 'N/A'}:{p.destination_port || 0}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            padding: '0.2rem 0.45rem',
                            borderRadius: '4px',
                            backgroundColor: 'rgba(255,255,255,0.06)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {p.protocol || 'TCP'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: p.predicted_threat === 'BENIGN' ? '#10b981' : '#f59e0b' }}>
                        {p.predicted_threat}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={p.risk_level} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: p.anomaly_score < 0 ? '#ef4444' : 'var(--text-secondary)' }}>
                        {formatScore(p.anomaly_score)}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {formatPercentage(p.classification_confidence)}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <button
                          onClick={() => setSelectedPredictionId(p.id)}
                          title="Deep Flow Investigation"
                          style={{
                            padding: '0.35rem 0.65rem',
                            borderRadius: 'var(--radius-sm)',
                            backgroundColor: 'rgba(0, 242, 254, 0.1)',
                            border: '1px solid rgba(0, 242, 254, 0.25)',
                            color: 'var(--accent-cyan)',
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                          }}
                        >
                          <Eye size={13} />
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={9} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      {isSearching ? 'Executing threat hunt query...' : 'No network flows matched the specified search criteria.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: Alerts */}
        {activeResultsTab === 'alerts' && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Alert ID / Timestamp</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Threat Label</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Source IP</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Destination</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Confidence</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {searchResults && searchResults.matching_alerts && searchResults.matching_alerts.length > 0 ? (
                  searchResults.matching_alerts.map((a) => (
                    <tr
                      key={a.id}
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ fontWeight: 600, color: '#fff' }}>#{a.id}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {formatDateTime(a.timestamp)}
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={a.severity} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#fff' }}>
                        {a.threat_label}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={a.status} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          onClick={() => openSourceInvestigation(a.source_ip)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--accent-cyan)',
                            cursor: 'pointer',
                            fontSize: '0.8rem',
                            fontWeight: 600,
                            padding: 0,
                            textDecoration: 'underline',
                          }}
                        >
                          {a.source_ip || 'N/A'}
                        </button>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {a.destination_ip || 'N/A'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {formatPercentage(a.confidence)}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        {a.prediction_id && (
                          <button
                            onClick={() => setSelectedPredictionId(a.prediction_id)}
                            style={{
                              padding: '0.35rem 0.65rem',
                              borderRadius: 'var(--radius-sm)',
                              backgroundColor: 'rgba(0, 242, 254, 0.1)',
                              border: '1px solid rgba(0, 242, 254, 0.25)',
                              color: 'var(--accent-cyan)',
                              cursor: 'pointer',
                              fontSize: '0.75rem',
                              fontWeight: 600,
                            }}
                          >
                            Flow #{a.prediction_id}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No alerts matched the search criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 3: Incidents */}
        {activeResultsTab === 'incidents' && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Incident Key</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Title</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Category</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Source IP</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Created At</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {searchResults && searchResults.matching_incidents && searchResults.matching_incidents.length > 0 ? (
                  searchResults.matching_incidents.map((inc) => (
                    <tr
                      key={inc.id}
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                    >
                      <td style={{ padding: '0.75rem 1rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                        {inc.incident_key}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#fff', fontWeight: 600 }}>
                        {inc.title}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={inc.severity} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StatusBadge status={inc.status} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {inc.category || 'General'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button
                          onClick={() => openSourceInvestigation(inc.source_ip)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--accent-cyan)',
                            cursor: 'pointer',
                            fontSize: '0.8rem',
                            fontWeight: 600,
                            padding: 0,
                            textDecoration: 'underline',
                          }}
                        >
                          {inc.source_ip || 'N/A'}
                        </button>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {formatDateTime(inc.created_at)}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <button
                          onClick={() => setActiveTab && setActiveTab('incidents')}
                          style={{
                            padding: '0.35rem 0.65rem',
                            borderRadius: 'var(--radius-sm)',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            border: '1px solid rgba(59, 130, 246, 0.3)',
                            color: '#3b82f6',
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                          }}
                        >
                          View Incident Case
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No incidents matched the search criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {searchResults && (
          <div
            style={{
              padding: '0.85rem 1.25rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderTop: '1px solid var(--border-subtle)',
              fontSize: '0.8rem',
              color: 'var(--text-muted)',
            }}
          >
            <div>
              Showing offset {offset} - {offset + limit} (Limit: {limit})
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => executeSearch(Math.max(0, offset - limit))}
                disabled={offset === 0 || isSearching}
                style={{
                  padding: '0.4rem 0.8rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--border-subtle)',
                  color: offset === 0 ? 'var(--text-muted)' : '#fff',
                  cursor: offset === 0 ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                }}
              >
                <ChevronLeft size={14} /> Previous
              </button>

              <button
                onClick={() => executeSearch(offset + limit)}
                disabled={
                  (activeResultsTab === 'predictions' && offset + limit >= searchResults.total_predictions) ||
                  (activeResultsTab === 'alerts' && offset + limit >= searchResults.total_alerts) ||
                  (activeResultsTab === 'incidents' && offset + limit >= searchResults.total_incidents) ||
                  isSearching
                }
                style={{
                  padding: '0.4rem 0.8rem',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--border-subtle)',
                  color: '#fff',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                }}
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Source Investigation Modal */}
      {/* -------------------------------------------------------------------- */}
      {investigatingSourceIp && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem',
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '850px',
              maxHeight: '90vh',
              overflowY: 'auto',
              borderRadius: 'var(--radius-lg)',
              backgroundColor: '#0c1220',
              border: '1px solid rgba(0, 242, 254, 0.3)',
              boxShadow: 'var(--shadow-lg)',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '1.25rem 1.5rem',
                borderBottom: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Globe size={20} color="var(--accent-cyan)" />
                <div>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff', margin: 0 }}>
                    Source Forensic Profile: {investigatingSourceIp}
                  </h2>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    Host Activity & Unified Forensic Timeline
                  </div>
                </div>
              </div>

              <button
                onClick={() => setInvestigatingSourceIp(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '0.4rem',
                }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {isSourceLoading && (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <RefreshCw size={24} className="spin" style={{ margin: '0 auto 0.75rem' }} />
                  <div>Loading source forensic profile...</div>
                </div>
              )}

              {sourceError && (
                <div
                  style={{
                    padding: '0.85rem',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#ef4444',
                    fontSize: '0.82rem',
                  }}
                >
                  {sourceError}
                </div>
              )}

              {sourceProfile && !isSourceLoading && (
                <>
                  {/* Defensive Notice Banner */}
                  <div
                    style={{
                      padding: '0.75rem 1rem',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      color: 'var(--text-secondary)',
                      fontSize: '0.75rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.65rem',
                    }}
                  >
                    <Info size={18} color="#3b82f6" style={{ flexShrink: 0 }} />
                    <div>{sourceProfile.disclaimer}</div>
                  </div>

                  {/* Top Stats Overview */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                      gap: '0.85rem',
                    }}
                  >
                    <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>First Seen</div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff', marginTop: '0.2rem' }}>
                        {formatDateTime(sourceProfile.first_seen)}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Last Seen</div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff', marginTop: '0.2rem' }}>
                        {formatDateTime(sourceProfile.last_seen)}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Total Records</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                        {sourceProfile.total_observations}
                      </div>
                    </div>
                  </div>

                  {/* Threat Categories & Severity Breakdown */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>
                        Observed Threat Categories
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        {sourceProfile.threat_categories.length > 0 ? (
                          sourceProfile.threat_categories.map((tc, idx) => (
                            <span
                              key={idx}
                              style={{
                                fontSize: '0.72rem',
                                padding: '0.2rem 0.5rem',
                                borderRadius: '4px',
                                backgroundColor: 'rgba(255,255,255,0.06)',
                                color: '#fff',
                              }}
                            >
                              {tc.threat}: <strong>{tc.count}</strong>
                            </span>
                          ))
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>No specific threats labeled.</span>
                        )}
                      </div>
                    </div>

                    <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>
                        Severity Breakdown
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {Object.entries(sourceProfile.severity_distribution || {}).map(([sev, cnt]) => (
                          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            <StatusBadge status={sev} />
                            <span style={{ fontSize: '0.75rem', color: '#fff', fontWeight: 600 }}>{cnt}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Observed Destinations */}
                  <div style={{ padding: '0.85rem', borderRadius: 'var(--radius-sm)', backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>
                      Top Observed Destination Endpoints
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                      {sourceProfile.observed_destinations.map((d, idx) => (
                        <span
                          key={idx}
                          style={{
                            fontSize: '0.72rem',
                            padding: '0.25rem 0.55rem',
                            borderRadius: '4px',
                            backgroundColor: 'rgba(0, 242, 254, 0.08)',
                            border: '1px solid rgba(0, 242, 254, 0.2)',
                            color: 'var(--accent-cyan)',
                          }}
                        >
                          {d.destination_ip}:{d.destination_port} ({d.count}x)
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Unified Chronological Timeline */}
                  <div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#fff', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <Clock size={16} color="var(--accent-cyan)" />
                      Chronological Investigation Timeline ({sourceProfile.timeline.length} events)
                    </div>

                    <div
                      style={{
                        maxHeight: '300px',
                        overflowY: 'auto',
                        padding: '0.5rem',
                        backgroundColor: 'rgba(0,0,0,0.2)',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border-subtle)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.65rem',
                      }}
                    >
                      {sourceProfile.timeline.length > 0 ? (
                        sourceProfile.timeline.map((evt, idx) => (
                          <div
                            key={idx}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '0.65rem',
                              padding: '0.5rem',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(255,255,255,0.02)',
                              borderLeft: `3px solid ${
                                evt.severity === 'CRITICAL'
                                  ? '#ef4444'
                                  : evt.severity === 'HIGH'
                                  ? '#f97316'
                                  : 'var(--accent-cyan)'
                              }`,
                            }}
                          >
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', minWidth: '130px' }}>
                              {formatDateTime(evt.timestamp)}
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#fff' }}>
                                  {evt.event_type}
                                </span>
                                {evt.severity && <StatusBadge status={evt.severity} />}
                                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                                  Ref: {evt.resource_id}
                                </span>
                              </div>
                              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                                {evt.description}
                              </div>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          No timeline events logged for this source IP.
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* Query History Modal */}
      {/* -------------------------------------------------------------------- */}
      {showHistoryModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem',
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '650px',
              maxHeight: '80vh',
              overflowY: 'auto',
              borderRadius: 'var(--radius-lg)',
              backgroundColor: '#0c1220',
              border: '1px solid var(--border-subtle)',
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <div
              style={{
                padding: '1.25rem',
                borderBottom: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <History size={18} color="var(--accent-cyan)" />
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#fff', fontWeight: 700 }}>
                  Recent Threat Hunt Queries
                </h3>
              </div>
              <button
                onClick={() => setShowHistoryModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {historyItems.length > 0 ? (
                historyItems.map((item) => (
                  <div
                    key={item.id}
                    style={{
                      padding: '0.85rem',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'rgba(255,255,255,0.03)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '0.75rem',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#fff' }}>
                        {item.filter_summary || 'Default Filter'}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                        {formatDateTime(item.timestamp)} &bull; {item.result_count} items matched
                      </div>
                    </div>

                    <button
                      onClick={() => applyHistoricalQuery(item)}
                      style={{
                        padding: '0.35rem 0.75rem',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'rgba(0, 242, 254, 0.12)',
                        border: '1px solid var(--border-active)',
                        color: 'var(--accent-cyan)',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      Reload Query
                    </button>
                  </div>
                ))
              ) : (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                  No prior threat hunting queries recorded yet.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* -------------------------------------------------------------------- */}
      {/* Prediction Investigation Modal (Phase 13 Deep Forensic Modal) */}
      {/* -------------------------------------------------------------------- */}
      {selectedPredictionId && (
        <InvestigationModal
          predictionId={selectedPredictionId}
          onClose={() => setSelectedPredictionId(null)}
        />
      )}
    </div>
  );
}
