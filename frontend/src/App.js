/**
 * URL Intrusion Detection System - Main App.
 * This UI mimics real SOC/analyst dashboards: theme toggle, file-based context for statistics,
 * and analyst summary with recommendations. File-based context improves investigation by
 * showing stats per uploaded file instead of only cumulative totals.
 */
import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import Dashboard from './components/Dashboard';
import EventsTable from './components/EventsTable';
import FileUpload from './components/FileUpload';
import Header from './components/Header';
import {
  fetchDetections,
  fetchStatistics,
  fetchFileHistory,
  clearDatabase,
} from './services/api';

const THEME_KEY = 'ids-theme';

function App() {
  const [detections, setDetections] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [fileHistory, setFileHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [filters, setFilters] = useState({ attackType: '', sourceIp: '', severity: '' });
  // File-based context: when set, dashboard and table show only that file's data (analyst workflow).
  const [selectedFileId, setSelectedFileId] = useState(null);
  // Theme: persist during session for analyst comfort (light/dark).
  const [theme, setTheme] = useState(() => {
    try {
      return sessionStorage.getItem(THEME_KEY) || 'light';
    } catch {
      return 'light';
    }
  });

  const loadData = useCallback(async () => {
    setLoading(true);
    setConnectionError(false);
    try {
      const [dets, stats, history] = await Promise.all([
        fetchDetections(filters.attackType, filters.sourceIp, selectedFileId, filters.severity),
        fetchStatistics(selectedFileId, filters.severity),
        fetchFileHistory(),
      ]);
      setDetections(dets);
      setStatistics(stats);
      setFileHistory(history);
    } catch (error) {
      console.error('Error loading data:', error);
      setConnectionError(true);
      setDetections([]);
      setStatistics(null);
      setFileHistory([]);
    } finally {
      setLoading(false);
    }
  }, [filters.attackType, filters.sourceIp, filters.severity, selectedFileId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleThemeToggle = () => {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    try {
      sessionStorage.setItem(THEME_KEY, next);
    } catch {}
  };

  const handleFileUpload = () => {
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
      alert('Failed to clear database.');
    }
  };

  return (
    <div className={`App theme-${theme}`}>
      <Header theme={theme} onThemeToggle={handleThemeToggle} />
      {connectionError && (
        <div className="connection-error-banner">
          Could not connect to the server. Make sure the backend is running on port 5000.
        </div>
      )}
      <div className="container">
        <div className="toolbar">
          <button className="btn btn-danger" onClick={handleClearDatabase}>
            Clear Database
          </button>
        </div>
        <FileUpload onUpload={handleFileUpload} />
        <Dashboard
          statistics={statistics}
          fileHistory={fileHistory}
          loading={loading}
          selectedFileId={selectedFileId}
          onSelectFile={setSelectedFileId}
          theme={theme}
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
