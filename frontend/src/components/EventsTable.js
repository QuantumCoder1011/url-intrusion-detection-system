import React, { useState } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../services/api';

function EventsTable({ detections, loading, filters, onFilterChange }) {
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  const handleSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const sortedDetections = [...detections].sort((a, b) => {
    if (!sortConfig.key) return 0;
    
    const aValue = a[sortConfig.key];
    const bValue = b[sortConfig.key];
    
    if (aValue < bValue) {
      return sortConfig.direction === 'asc' ? -1 : 1;
    }
    if (aValue > bValue) {
      return sortConfig.direction === 'asc' ? 1 : -1;
    }
    return 0;
  });

  const handleFilterChange = (field, value) => {
    onFilterChange({
      ...filters,
      [field]: value
    });
  };

  const handleExport = async (format) => {
    try {
      const params = new URLSearchParams();
      if (filters.attackType) params.append('attack_type', filters.attackType);
      if (filters.sourceIp) params.append('source_ip', filters.sourceIp);

      const url = `${API_BASE_URL}/export/${format}?${params.toString()}`;
      
      if (format === 'csv') {
        const response = await fetch(url);
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = 'detections.csv';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
      } else {
        const response = await axios.get(url);
        const dataStr = JSON.stringify(response.data, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = 'detections.json';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error exporting data:', error);
      alert('Error exporting data');
    }
  };

  const getUniqueValues = (field) => {
    const values = new Set(detections.map(d => d[field]).filter(Boolean));
    return Array.from(values).sort();
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High':
        return '#f44336';
      case 'Medium':
        return '#ff9800';
      case 'Low':
        return '#4caf50';
      default:
        return '#666';
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading detections...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px', flexWrap: 'wrap', gap: '10px' }}>
        <div className="card-title" style={{ margin: 0 }}>Detected Security Events ({detections.length})</div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn btn-primary" onClick={() => handleExport('csv')} disabled={detections.length === 0}>
            Export CSV
          </button>
          <button className="btn btn-primary" onClick={() => handleExport('json')} disabled={detections.length === 0}>
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '15px', flexWrap: 'wrap' }}>
        <select
          value={filters.attackType}
          onChange={(e) => handleFilterChange('attackType', e.target.value)}
          style={{ padding: '8px', border: '1px solid #ddd', borderRadius: '4px', minWidth: '200px' }}
        >
          <option value="">All Attack Types</option>
          {getUniqueValues('attack_type').map(type => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
        <select
          value={filters.sourceIp}
          onChange={(e) => handleFilterChange('sourceIp', e.target.value)}
          style={{ padding: '8px', border: '1px solid #ddd', borderRadius: '4px', minWidth: '200px' }}
        >
          <option value="">All Source IPs</option>
          {getUniqueValues('source_ip').map(ip => (
            <option key={ip} value={ip}>{ip}</option>
          ))}
        </select>
        {(filters.attackType || filters.sourceIp) && (
          <button
            className="btn"
            onClick={() => onFilterChange({ attackType: '', sourceIp: '' })}
            style={{ backgroundColor: '#6c757d', color: 'white' }}
          >
            Clear Filters
          </button>
        )}
      </div>

      {detections.length === 0 ? (
        <p style={{ textAlign: 'center', color: '#666', padding: '40px' }}>
          No detections found. Upload a file to start analysis.
        </p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ backgroundColor: '#f8f9fa' }}>
                <th
                  style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd', cursor: 'pointer' }}
                  onClick={() => handleSort('url')}
                >
                  URL {sortConfig.key === 'url' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd', cursor: 'pointer' }}
                  onClick={() => handleSort('source_ip')}
                >
                  Source IP {sortConfig.key === 'source_ip' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd', cursor: 'pointer' }}
                  onClick={() => handleSort('attack_type')}
                >
                  Attack Type {sortConfig.key === 'attack_type' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd', cursor: 'pointer' }}
                  onClick={() => handleSort('severity')}
                >
                  Severity {sortConfig.key === 'severity' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>Confidence</th>
                <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {sortedDetections.map((detection, index) => (
                <tr key={index} style={{ borderBottom: '1px solid #eee' }}>
                  <td style={{ padding: '12px', maxWidth: '400px', wordBreak: 'break-all' }}>
                    {detection.url}
                  </td>
                  <td style={{ padding: '12px' }}>{detection.source_ip}</td>
                  <td style={{ padding: '12px' }}>{detection.attack_type}</td>
                  <td style={{ padding: '12px' }}>
                    <span
                      style={{
                        padding: '4px 8px',
                        borderRadius: '4px',
                        backgroundColor: getSeverityColor(detection.severity) + '20',
                        color: getSeverityColor(detection.severity),
                        fontWeight: '500',
                        fontSize: '12px'
                      }}
                    >
                      {detection.severity}
                    </span>
                  </td>
                  <td style={{ padding: '12px', fontSize: '12px', color: '#666' }}>
                    {detection.confidence_score != null ? `${detection.confidence_score}%` : '—'}
                  </td>
                  <td style={{ padding: '12px', fontSize: '12px', color: '#666' }}>
                    {detection.timestamp || detection.detected_at || 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default EventsTable;
