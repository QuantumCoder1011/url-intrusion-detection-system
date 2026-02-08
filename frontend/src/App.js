import React, { useState, useEffect } from 'react';
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

function App() {
  const [detections, setDetections] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [fileHistory, setFileHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [filters, setFilters] = useState({ attackType: '', sourceIp: '' });

  const loadData = async () => {
    setLoading(true);
    setConnectionError(false);
    try {
      const [dets, stats, history] = await Promise.all([
        fetchDetections(filters.attackType, filters.sourceIp),
        fetchStatistics(),
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
  };

  useEffect(() => {
    loadData();
  }, [filters.attackType, filters.sourceIp]);

  const handleFileUpload = () => {
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
      loadData();
    } catch (error) {
      console.error('Error clearing database:', error);
      alert('Failed to clear database.');
    }
  };

  return (
    <div className="App">
      <Header />
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
        />
        <EventsTable
          detections={detections}
          loading={loading}
          filters={filters}
          onFilterChange={handleFilterChange}
        />
      </div>
    </div>
  );
}

export default App;
