import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import Dashboard from './components/Dashboard';
import EventsTable from './components/EventsTable';
import FileUpload from './components/FileUpload';
import Simulator from './components/Simulator';
import {
  fetchDetections,
  fetchStatistics,
  fetchFileHistory,
  clearDatabase,
  login,
  logout
} from './services/api';

function App() {
  const [token, setToken] = useState(localStorage.getItem('ids_token'));
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');

  const [detections, setDetections] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [fileHistory, setFileHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [filters, setFilters] = useState({ attackType: '', sourceIp: '', severity: '', detectionSource: '' });
  const [selectedFileId, setSelectedFileId] = useState(null);

  const loadData = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setConnectionError(false);
    try {
      const [dets, stats, history] = await Promise.all([
        fetchDetections(filters.attackType, filters.sourceIp, selectedFileId, filters.severity, filters.detectionSource),
        fetchStatistics(selectedFileId, filters.severity),
        fetchFileHistory(),
      ]);
      setDetections(dets);
      setStatistics(stats);
      setFileHistory(history);
    } catch (error) {
      console.error('Error loading data:', error);
      if (error.response?.status === 401) {
        logout();
        setToken(null);
      } else {
        setConnectionError(true);
      }
      setDetections([]);
      setStatistics(null);
      setFileHistory([]);
    } finally {
      setLoading(false);
    }
  }, [filters.attackType, filters.sourceIp, filters.severity, filters.detectionSource, selectedFileId, token]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const res = await login(username, password);
      setToken(res.token);
    } catch (err) {
      setAuthError('Invalid credentials or server offline.');
    }
  };

  const handleLogout = () => {
    logout();
    setToken(null);
  };

  const handleDataUpdate = () => {
    setSelectedFileId(null);
    loadData();
  };

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters);
  };

  const handleClearDatabase = async () => {
    if (!window.confirm('Are you sure you want to clear all records? This will delete all detections and file history and cannot be undone.')) {
      return;
    }
    try {
      await clearDatabase();
      setSelectedFileId(null);
      loadData();
    } catch (error) {
      console.error('Error clearing database:', error);
      alert('Failed to clear database. Admin privileges required.');
    }
  };

  if (!token) {
    return (
      <div className="auth-container">
        <div className="scanline"></div>
        <div className="cyber-card auth-card">
          <div className="logo-text auth-logo">IDS::GATEWAY</div>
          <div className="auth-subtitle">SECURE SOC AUTHENTICATION REQUIRED</div>
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            <input 
              type="text" 
              placeholder="Operator ID (admin)" 
              value={username} 
              onChange={e => setUsername(e.target.value)} 
              style={{ padding: '12px', textAlign: 'center', letterSpacing: '1px' }}
            />
            <input 
              type="password" 
              placeholder="Access Key" 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
              style={{ padding: '12px', textAlign: 'center', letterSpacing: '2px' }}
            />
            <button type="submit" className="btn btn-primary" style={{ padding: '12px', marginTop: '10px' }}>
              INITIALIZE UPLINK
            </button>
            {authError && <div style={{ color: 'var(--neon-red)', textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>[!] {authError}</div>}
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      <div className="scanline"></div>
      <header>
        <div className="logo-section">
          <div className="logo-text">HYBRID::IDS</div>
        </div>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <div className="status-indicator">
            <div className="status-dot"></div>
            SYSTEM ONLINE
          </div>
          <button className="btn" onClick={handleLogout}>
            TERMINATE SESSION
          </button>
        </div>
      </header>

      {connectionError && (
        <div style={{ background: 'var(--neon-red)', color: '#fff', padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
          [CRITICAL] CONNECTION LOST TO COMMAND SERVER (PORT 5000)
        </div>
      )}

      <div className="container">
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '20px' }}>
          <button className="btn btn-danger" onClick={handleClearDatabase}>
            PURGE DATABASE
          </button>
        </div>
        
        <Simulator onSimulationComplete={handleDataUpdate} />
        
        <div style={{ marginTop: '20px' }}>
            <FileUpload onUpload={handleDataUpdate} />
        </div>

        <Dashboard
          statistics={statistics}
          fileHistory={fileHistory}
          loading={loading}
          selectedFileId={selectedFileId}
          onSelectFile={setSelectedFileId}
        />
        <EventsTable
          detections={detections}
          loading={loading}
          filters={filters}
          onFilterChange={handleFilterChange}
          fileId={selectedFileId}
        />
      </div>
    </div>
  );
}

export default App;
