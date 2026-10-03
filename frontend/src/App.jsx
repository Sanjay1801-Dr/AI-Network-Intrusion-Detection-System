import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import DashboardPlaceholder from './pages/DashboardPlaceholder';
import AlertsPlaceholder from './pages/AlertsPlaceholder';
import NetworkEventsPlaceholder from './pages/NetworkEventsPlaceholder';
import ModelPerformancePlaceholder from './pages/ModelPerformancePlaceholder';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendHealth, setBackendHealth] = useState(null);
  const [isChecking, setIsChecking] = useState(false);

  // Health check query to backend
  const checkHealth = async () => {
    setIsChecking(true);
    try {
      // First try relative /api/health (supported via Vite proxy)
      // and fallback to explicit backend URL
      let res;
      try {
        res = await fetch('/api/health');
      } catch (err) {
        res = await fetch('http://127.0.0.1:8000/api/health');
      }

      if (res && res.ok) {
        const data = await res.json();
        setBackendHealth(data);
      } else {
        setBackendHealth(null);
      }
    } catch (err) {
      console.warn('Backend currently unreachable:', err.message);
      setBackendHealth(null);
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    checkHealth();
    // Poll health status every 15 seconds
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

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
        />

        <main className="content-body">
          {activeTab === 'dashboard' && <DashboardPlaceholder backendHealth={backendHealth} />}
          {activeTab === 'alerts' && <AlertsPlaceholder />}
          {activeTab === 'events' && <NetworkEventsPlaceholder />}
          {activeTab === 'models' && <ModelPerformancePlaceholder />}
        </main>
      </div>
    </div>
  );
}
