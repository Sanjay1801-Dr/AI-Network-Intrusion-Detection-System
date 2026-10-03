import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import AIPrediction from './pages/AIPrediction';
import PredictionHistory from './pages/PredictionHistory';
import SecurityAlerts from './pages/SecurityAlerts';
import AuditLogs from './pages/AuditLogs';
import SecurityAnalytics from './pages/SecurityAnalytics';
import Incidents from './pages/Incidents';
import Reports from './pages/Reports';
import ThreatHunting from './pages/ThreatHunting';
import Login from './pages/Login';
import { AuthProvider, useAuth } from './context/AuthContext';
import api from './services/api';
import websocketService, { WS_STATUS } from './services/websocket';
import './App.css';

function AppContent() {
  const { isAuthenticated, isLoading, user, role } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendHealth, setBackendHealth] = useState(null);
  const [isChecking, setIsChecking] = useState(false);

  // Phase 7 Real-Time WebSocket Telemetry State
  const [wsStatus, setWsStatus] = useState(WS_STATUS.DISCONNECTED);
  const [sessionCounters, setSessionCounters] = useState({
    predictions: 0,
    alerts: 0,
    highAlerts: 0,
    criticalAlerts: 0,
  });
  const [livePredictions, setLivePredictions] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [latestLivePrediction, setLatestLivePrediction] = useState(null);
  const [latestLiveAlert, setLatestLiveAlert] = useState(null);

  // Single health check query to backend service
  const checkHealth = async () => {
    setIsChecking(true);
    try {
      const data = await api.checkHealth();
      setBackendHealth(data);
    } catch {
      setBackendHealth(null);
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    if (!isAuthenticated) {
      // Disconnect WebSocket cleanly when session ends
      websocketService.disconnect();
      setWsStatus(WS_STATUS.DISCONNECTED);
      return;
    }

    // Initial health check upon authenticated load
    checkHealth();

    // Establish authenticated application-level WebSocket connection
    const unsubStatus = websocketService.onStatusChange(setWsStatus);
    websocketService.connect();

    // Subscribe to incoming WebSocket events
    const unsubEvents = websocketService.subscribe((event) => {
      if (!event || !event.event_type) return;

      if (event.event_type === 'prediction_created') {
        const item = event.data;
        if (!item || !item.prediction_id) return;

        setLatestLivePrediction(item);

        // Increment session prediction counter
        setSessionCounters((prev) => ({
          ...prev,
          predictions: prev.predictions + 1,
        }));

        // Append to bounded in-memory list (max 20, newest first, deduplicated)
        setLivePredictions((prev) => {
          if (prev.some((p) => p.prediction_id === item.prediction_id || p.id === item.prediction_id)) {
            return prev;
          }
          return [item, ...prev].slice(0, 20);
        });
      } else if (event.event_type === 'alert_created') {
        const item = event.data;
        if (!item || !item.alert_id) return;

        setLatestLiveAlert(item);

        const sev = String(item.severity || '').toUpperCase();
        setSessionCounters((prev) => ({
          ...prev,
          alerts: prev.alerts + 1,
          highAlerts: sev === 'HIGH' ? prev.highAlerts + 1 : prev.highAlerts,
          criticalAlerts: sev === 'CRITICAL' ? prev.criticalAlerts + 1 : prev.criticalAlerts,
        }));

        // Append to bounded in-memory list (max 20, newest first, deduplicated)
        setLiveAlerts((prev) => {
          if (prev.some((a) => a.alert_id === item.alert_id || a.id === item.alert_id)) {
            return prev;
          }
          return [item, ...prev].slice(0, 20);
        });
      } else if (event.event_type === 'alert_acknowledged' || event.event_type === 'alert_resolved') {
        const item = event.data;
        if (!item || !item.alert_id) return;

        // Synchronize in-memory bounded live alerts without duplication
        setLiveAlerts((prev) =>
          prev.map((a) => {
            const matches = a.alert_id === item.alert_id || a.id === item.alert_id;
            if (!matches) return a;
            return {
              ...a,
              status: item.status,
              acknowledged_at: item.acknowledged_at !== undefined ? item.acknowledged_at : a.acknowledged_at,
              resolved_at: item.resolved_at !== undefined ? item.resolved_at : a.resolved_at,
            };
          })
        );

        // Update latest alert if matching
        setLatestLiveAlert((prev) => {
          if (!prev) return prev;
          if (prev.alert_id === item.alert_id || prev.id === item.alert_id) {
            return {
              ...prev,
              status: item.status,
              acknowledged_at: item.acknowledged_at !== undefined ? item.acknowledged_at : prev.acknowledged_at,
              resolved_at: item.resolved_at !== undefined ? item.resolved_at : prev.resolved_at,
            };
          }
          return prev;
        });
      }
    });

    return () => {
      unsubStatus();
      unsubEvents();
      websocketService.disconnect();
    };
  }, [isAuthenticated]);

  // Loading state while checking token on refresh
  if (isLoading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#080c16',
          color: '#ffffff',
          gap: '1rem',
        }}
      >
        <div className="spinner" style={{ width: '36px', height: '36px' }} />
        <div style={{ fontSize: '0.9rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
          Initializing Secure SOC Console...
        </div>
      </div>
    );
  }

  // Route protection: redirect unauthenticated sessions to Login page
  if (!isAuthenticated) {
    return <Login />;
  }

  // Authenticated Operator Application Shell
  return (
    <div className="app-container">
      {/* Navigation Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area */}
      <div className="main-content">
        <Header
          backendHealth={backendHealth}
          isChecking={isChecking}
          checkHealth={checkHealth}
          wsStatus={wsStatus}
        />

        <main className="content-body">
          {activeTab === 'dashboard' && (
            <Dashboard
              backendHealth={backendHealth}
              setActiveTab={setActiveTab}
              wsStatus={wsStatus}
              sessionCounters={sessionCounters}
              livePredictions={livePredictions}
              liveAlerts={liveAlerts}
              latestLivePrediction={latestLivePrediction}
              latestLiveAlert={latestLiveAlert}
            />
          )}
          {activeTab === 'analytics' && <SecurityAnalytics />}
          {activeTab === 'hunting' && <ThreatHunting setActiveTab={setActiveTab} />}
          {activeTab === 'incidents' && <Incidents />}
          {activeTab === 'reports' && <Reports />}
          {activeTab === 'predict' && <AIPrediction />}
          {activeTab === 'history' && <PredictionHistory />}
          {activeTab === 'alerts' && <SecurityAlerts />}
          {activeTab === 'audit' && <AuditLogs />}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
