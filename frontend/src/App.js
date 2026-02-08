import React, { useState, useEffect } from 'react';
import './App.css';
import Dashboard from './components/Dashboard';
import EventsTable from './components/EventsTable';
import FileUpload from './components/FileUpload';
import Header from './components/Header';
import { fetchDetections, fetchStatistics } from './services/api';

function App() {
  const [detections, setDetections] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [filters, setFilters] = useState({
    attackType: '',
    sourceIp: ''
  });

  useEffect(() => {
    loadData();
  }, [filters]);

  const loadData = async () => {
    setLoading(true);
    setConnectionError(false);
    try {
      const [dets, stats] = await Promise.all([
        fetchDetections(filters.attackType, filters.sourceIp),
        fetchStatistics()
      ]);
      setDetections(dets);
      setStatistics(stats);
    } catch (error) {
      console.error('Error loading data:', error);
      setConnectionError(true);
      setDetections([]);
      setStatistics(null);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = () => {
    // Reload data after file upload
    loadData();
  };

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters);
  };

  const handleClearDatabase = async () => {
    if (window.confirm('Are you sure you want to clear all detections?')) {
      try {
        const response = await fetch('/api/clear', {
          method: 'POST'
        });
        if (response.ok) {
          loadData();
        }
      } catch (error) {
        console.error('Error clearing database:', error);
      }
    }
  };

  return (
    <div className="App">
      <Header onClearDatabase={handleClearDatabase} />
      {connectionError && (
        <div className="connection-error-banner">
          Could not connect to the server. Make sure the backend is running on port 5000.
        </div>
      )}
      <div className="container">
        <FileUpload onUpload={handleFileUpload} />
        <Dashboard statistics={statistics} loading={loading} />
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
