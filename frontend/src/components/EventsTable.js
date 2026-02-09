import React, { useState } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../services/api';

// Severity order: High (highest) → Medium → Low (lowest). Used for column sort only.
const SEVERITY_ORDER = ['High', 'Medium', 'Low'];

function EventsTable({ detections, loading, filters, onFilterChange, fileId }) {
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

    if (sortConfig.key === 'severity') {
      const aIdx = SEVERITY_ORDER.indexOf(a.severity);
      const bIdx = SEVERITY_ORDER.indexOf(b.severity);
      const aOrder = aIdx === -1 ? 999 : aIdx;
      const bOrder = bIdx === -1 ? 999 : bIdx;
      if (aOrder < bOrder) return sortConfig.direction === 'asc' ? -1 : 1;
      if (aOrder > bOrder) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    }

    const aValue = a[sortConfig.key];
    const bValue = b[sortConfig.key];
    if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
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
      if (filters.severity) params.append('severity', filters.severity);
      if (fileId != null) params.append('file_id', fileId);

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
          style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', minWidth: '200px', backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)' }}
        >
          <option value="">All Attack Types</option>
          {getUniqueValues('attack_type').map(type => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
        <select
          value={filters.sourceIp}
          onChange={(e) => handleFilterChange('sourceIp', e.target.value)}
          style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', minWidth: '200px', backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)' }}
        >
          <option value="">All Source IPs</option>
          {getUniqueValues('source_ip').map(ip => (
            <option key={ip} value={ip}>{ip}</option>
          ))}
        </select>
        <select
          value={filters.severity}
          onChange={(e) => handleFilterChange('severity', e.target.value)}
          style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', minWidth: '160px', backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)' }}
        >
          <option value="">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        {(filters.attackType || filters.sourceIp || filters.severity) && (
          <button
            className="btn"
            onClick={() => onFilterChange({ attackType: '', sourceIp: '', severity: '' })}
            style={{ backgroundColor: 'var(--btn-secondary-bg)', color: 'white' }}
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
        <div className="table-wrap" style={{ maxHeight: '400px' }}>
          <table className="data-table" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th onClick={() => handleSort('url')} style={{ cursor: 'pointer' }}>
                  URL {sortConfig.key === 'url' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('source_ip')} style={{ cursor: 'pointer' }}>
                  Source IP {sortConfig.key === 'source_ip' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('attack_type')} style={{ cursor: 'pointer' }}>
                  Attack Type {sortConfig.key === 'attack_type' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('severity')} style={{ cursor: 'pointer' }}>
                  Severity {sortConfig.key === 'severity' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                </th>
                <th>Confidence</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {sortedDetections.map((detection, index) => (
                <tr key={detection.id != null ? detection.id : index}>
                  <td style={{ maxWidth: '380px', wordBreak: 'break-all' }} title={detection.url}>
                    {detection.url}
                  </td>
                  <td>{detection.source_ip}</td>
                  <td>{detection.attack_type}</td>
                  <td>
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
                  <td style={{ fontSize: '12px' }}>
                    {detection.confidence_score != null ? `${detection.confidence_score}%` : '—'}
                  </td>
                  <td style={{ fontSize: '12px' }}>
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
