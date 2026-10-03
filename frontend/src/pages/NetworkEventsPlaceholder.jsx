import React from 'react';
import { Radio, Search, Filter, Database, ArrowUpDown } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function NetworkEventsPlaceholder() {
  const sampleFlows = [
    {
      id: 'FLW-001948',
      src: '192.168.1.100',
      dst: '10.0.0.15',
      port: 443,
      proto: 'TCP',
      duration: '1.42s',
      pkts: 38,
      bytes: '4.8 KB',
      flags: 'SYN, ACK, FIN',
      status: 'NORMAL',
    },
    {
      id: 'FLW-001949',
      src: '203.0.113.45',
      dst: '10.0.0.5',
      port: 22,
      proto: 'TCP',
      duration: '0.04s',
      pkts: 120,
      bytes: '7.2 KB',
      flags: 'SYN',
      status: 'SUSPICIOUS',
    },
    {
      id: 'FLW-001950',
      src: '192.168.1.104',
      dst: '8.8.8.8',
      port: 53,
      proto: 'UDP',
      duration: '0.02s',
      pkts: 2,
      bytes: '168 B',
      flags: 'N/A',
      status: 'NORMAL',
    },
    {
      id: 'FLW-001951',
      src: '198.51.100.99',
      dst: '10.0.0.1',
      port: 80,
      proto: 'TCP',
      duration: '0.01s',
      pkts: 1,
      bytes: '60 B',
      flags: 'SYN',
      status: 'SUSPICIOUS',
    },
    {
      id: 'FLW-001952',
      src: '192.168.1.110',
      dst: '10.0.0.10',
      port: 3306,
      proto: 'TCP',
      duration: '4.80s',
      pkts: 92,
      bytes: '32.1 KB',
      flags: 'SYN, ACK, PSH',
      status: 'NORMAL',
    },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Radio color="var(--accent-cyan)" size={28} />
            Network Traffic Telemetry Explorer
          </h1>
          <p className="page-subtitle">
            Inspect raw and preprocessed bidirectional network flows captured by ingest sensors.
          </p>
        </div>
      </div>

      <div className="phase-banner">
        <span className="phase-tag">PHASE 2 BLUEPRINT</span>
        <div>
          <strong>Flow Ingestion Pipeline:</strong> In Phase 2, this view connects to <code>GET /api/v1/traffic</code> and receives live flow batches from the Pandas data pipeline.
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div className="glass-panel" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem 0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', flex: 1, minWidth: '220px' }}>
          <Search size={16} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Filter by Source IP, Destination, Port..."
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#fff',
              fontSize: '0.85rem',
              width: '100%',
            }}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <select
            style={{
              background: 'rgba(0,0,0,0.3)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.5rem 0.75rem',
              fontSize: '0.8rem',
            }}
          >
            <option>All Protocols (TCP, UDP, ICMP)</option>
            <option>TCP Only</option>
            <option>UDP Only</option>
          </select>

          <select
            style={{
              background: 'rgba(0,0,0,0.3)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.5rem 0.75rem',
              fontSize: '0.8rem',
            }}
          >
            <option>Status: All</option>
            <option>Suspicious Flows Only</option>
            <option>Normal Flows Only</option>
          </select>
        </div>
      </div>

      {/* Traffic Table */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div className="table-responsive">
          <table className="ids-table">
            <thead>
              <tr>
                <th>Flow ID</th>
                <th>Source Address</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Duration</th>
                <th>Packets</th>
                <th>Volume</th>
                <th>TCP Flags</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sampleFlows.map((flow) => (
                <tr key={flow.id}>
                  <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{flow.id}</td>
                  <td className="font-mono">{flow.src}</td>
                  <td className="font-mono">{flow.dst}:{flow.port}</td>
                  <td>
                    <span style={{ fontWeight: 600, fontSize: '0.78rem', color: flow.proto === 'TCP' ? '#4facfe' : '#a78bfa' }}>
                      {flow.proto}
                    </span>
                  </td>
                  <td className="font-mono">{flow.duration}</td>
                  <td className="font-mono">{flow.pkts}</td>
                  <td className="font-mono">{flow.bytes}</td>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{flow.flags}</td>
                  <td>
                    <StatusBadge
                      status={flow.status}
                      type={flow.status === 'SUSPICIOUS' ? 'severity' : 'status'}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
