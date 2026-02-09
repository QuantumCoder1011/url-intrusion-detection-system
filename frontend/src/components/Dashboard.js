import React, { useMemo } from 'react';
import { Pie, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
} from 'chart.js';
import { downloadOverallCsv, downloadOverallJson } from '../services/api';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
);

// Slightly reduced chart height for readability (real SOC dashboards keep charts compact).
const CHART_HEIGHT = 200;

// Severity order: High (highest) → Medium → Low (lowest / informational). No severity below Low.
const SEVERITY_ORDER = ['High', 'Medium', 'Low'];

/**
 * Build ordered severity chart data so the bar chart always shows High | Medium | Low left to right.
 */
function getSeverityChartData(bySeverity, isDark) {
  const labels = SEVERITY_ORDER.filter((s) => (bySeverity || {})[s] !== undefined && (bySeverity || {})[s] > 0);
  if (labels.length === 0) return { labels: [], data: [] };
  const data = labels.map((s) => (bySeverity || {})[s] || 0);
  return { labels, data };
}

/**
 * Generate plain-English analyst summary and actionable recommendations from current stats.
 * Mimics how real SOC dashboards summarize findings; recommendations assist security
 * analysts by suggesting concrete actions (e.g. block IP, review permissions) based on
 * severity and attack type.
 */
function getAnalystSummary(statistics, selectedFileId, selectedFileName) {
  if (!statistics || statistics.total_detections === 0) {
    return {
      summary: 'No attacks detected in the current selection.',
      recommendations: ['Upload a CSV or PCAP file to analyze, or select a file from history to view its statistics.'],
    };
  }

  const byType = statistics.by_attack_type || {};
  const bySeverity = statistics.by_severity || {};
  const topIPs = statistics.top_source_ips || [];
  const highCount = bySeverity.High || 0;
  const mediumCount = bySeverity.Medium || 0;
  const lowCount = bySeverity.Low || 0;
  const attackTypes = Object.keys(byType);
  const context = selectedFileId ? `for "${selectedFileName || 'selected file'}"` : 'across all uploaded files';

  let summary = `Analysis ${context}: ${statistics.total_detections} detection(s) in total. `;
  if (attackTypes.length > 0) {
    summary += `Attack types detected: ${attackTypes.join(', ')}. `;
  }
  if (highCount > 0) summary += `High severity: ${highCount}. `;
  if (mediumCount > 0) summary += `Medium severity: ${mediumCount}. `;
  if (lowCount > 0) summary += `Low severity: ${lowCount}. `;
  if (topIPs.length === 1) {
    summary += `All detections originated from a single source IP.`;
  } else if (topIPs.length > 1) {
    summary += `Detections came from ${topIPs.length} or more distinct source IPs.`;
  }

  const recommendations = [];
  if (highCount > 0 && topIPs.length >= 1) {
    const top = topIPs[0];
    if (top && top.count > 1) {
      recommendations.push(`Multiple high-severity attacks detected from the same IP (${top.ip}). Consider blocking or monitoring this source.`);
    } else {
      recommendations.push('High-severity attacks detected. Review affected URLs and consider blocking or alerting on the source.');
    }
  }
  if (mediumCount > 0 && highCount === 0) {
    recommendations.push('Medium-severity activity detected. Review and prioritize; consider tightening rules or monitoring repeat offenders.');
  }
  if (lowCount > 0 && highCount === 0 && mediumCount === 0) {
    recommendations.push('Only low-severity suspicious activity detected. No immediate action required; useful for trend analysis.');
  }
  if (attackTypes.some((t) => t.toLowerCase().includes('directory') || t.toLowerCase().includes('traversal'))) {
    recommendations.push('Directory traversal attempts detected. Review file and path access permissions on the target system.');
  }
  if (recommendations.length === 0 && statistics.total_detections > 0) {
    recommendations.push('Review the events table and apply filters by attack type or source IP as needed.');
  }

  return { summary, recommendations };
}

function Dashboard({ statistics, fileHistory, loading, selectedFileId, onSelectFile, theme }) {
  const handleDownloadOverallCsv = async () => {
    try {
      const blob = await downloadOverallCsv();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'overall_statistics_detections.csv';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e) {
      console.error(e);
      alert('Failed to download overall CSV.');
    }
  };

  const handleDownloadOverallJson = async () => {
    try {
      const data = await downloadOverallJson();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'overall_statistics_detections.json';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e) {
      console.error(e);
      alert('Failed to download overall JSON.');
    }
  };

  const isDark = theme === 'dark';
  const chartTextColor = isDark ? '#e8eaed' : '#333';
  const chartGridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.08)';
  const tooltipBg = isDark ? '#252830' : '#ffffff';
  const tooltipText = isDark ? '#e8eaed' : '#1a1a1a';
  const tooltipBorder = isDark ? '#3c4043' : '#e8eaed';

  const chartOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'bottom', labels: { color: chartTextColor } },
      tooltip: {
        backgroundColor: tooltipBg,
        titleColor: tooltipText,
        bodyColor: tooltipText,
        borderColor: tooltipBorder,
        borderWidth: 1,
      },
    },
    scales: {
      x: { ticks: { color: chartTextColor }, grid: { color: chartGridColor } },
      y: { ticks: { color: chartTextColor }, grid: { color: chartGridColor } },
    },
  }), [chartTextColor, chartGridColor, tooltipBg, tooltipText, tooltipBorder]);

  const pieChartOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    layout: { padding: 8 },
    plugins: {
      legend: { position: 'bottom', labels: { color: chartTextColor } },
      tooltip: {
        backgroundColor: tooltipBg,
        titleColor: tooltipText,
        bodyColor: tooltipText,
        borderColor: tooltipBorder,
        borderWidth: 1,
      },
    },
  }), [chartTextColor, tooltipBg, tooltipText, tooltipBorder]);

  const selectedFileName = useMemo(() => {
    if (!selectedFileId || !fileHistory?.length) return null;
    const row = fileHistory.find((r) => r.id === selectedFileId);
    return row ? row.file_name : null;
  }, [selectedFileId, fileHistory]);

  const { summary, recommendations } = useMemo(
    () => getAnalystSummary(statistics, selectedFileId, selectedFileName),
    [statistics, selectedFileId, selectedFileName]
  );

  if (loading) {
    return (
      <div className="card">
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading statistics...</p>
        </div>
      </div>
    );
  }

  if (!statistics) {
    return (
      <div className="card">
        <div className="card-title">Dashboard</div>
        <p className="chart-empty" style={{ padding: '20px' }}>
          No data available. Upload a file to start analysis.
        </p>
      </div>
    );
  }

  const byAttackType = statistics.by_attack_type || {};
  const attackTypeLabels = Object.keys(byAttackType);
  const attackTypesData = {
    labels: attackTypeLabels,
    datasets: [
      {
        label: 'Attack Types',
        data: Object.values(byAttackType),
        backgroundColor: [
          '#e53935', '#1e88e5', '#43a047', '#fb8c00', '#8e24aa',
          '#00897b', '#d81b60', '#5e35b1', '#039be5', '#7cb342',
        ].slice(0, Math.max(attackTypeLabels.length, 1)),
        borderWidth: 2,
        borderColor: isDark ? '#252830' : '#fff',
      },
    ],
  };

  const { labels: severityLabels, data: severityValues } = getSeverityChartData(statistics.by_severity);
  const severityData = {
    labels: severityLabels,
    datasets: [
      {
        label: 'Detections by Severity',
        data: severityValues,
        backgroundColor: severityLabels.map((s) => (s === 'High' ? '#d32f2f' : s === 'Medium' ? '#f57c00' : '#388e3c')),
        borderColor: severityLabels.map((s) => (s === 'High' ? '#b71c1c' : s === 'Medium' ? '#e65100' : '#2e7d32')),
        borderWidth: 2,
      },
    ],
  };

  const topIPs = statistics.top_source_ips || [];
  const topIPsData = {
    labels: topIPs.map((item) => item.ip),
    datasets: [{
      label: 'Number of Attacks',
      data: topIPs.map((item) => item.count),
      backgroundColor: isDark ? '#5a8bd6' : '#667eea',
      borderColor: isDark ? '#4a7bc6' : '#5a67d8',
      borderWidth: 2,
    }],
  };

  const formatUploadTime = (iso) => {
    if (!iso) return 'N/A';
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  };

  return (
    <div>
      <div className="card">
        <div className="card-title">
          Summary Statistics
          {selectedFileId ? ' (selected file)' : ' (all files)'}
        </div>
        <div className="stats-grid">
          <div className="stat-box">
            <div className="stat-value stat-total">{statistics.total_detections || 0}</div>
            <div className="stat-label">Total Detections</div>
          </div>
          <div className="stat-box">
            <div className="stat-value stat-types">{Object.keys(byAttackType).length}</div>
            <div className="stat-label">Attack Types</div>
          </div>
          <div className="stat-box">
            <div className="stat-value stat-ips">{topIPs.length}</div>
            <div className="stat-label">Unique Source IPs</div>
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card chart-card">
          <div className="card-title">Detections by Attack Type</div>
          <div className="chart-container" style={{ height: CHART_HEIGHT }}>
            {attackTypeLabels.length > 0 ? (
              <Pie data={attackTypesData} options={pieChartOptions} />
            ) : (
              <p className="chart-empty">No data available</p>
            )}
          </div>
        </div>
        <div className="card chart-card">
          <div className="card-title">Detections by Severity (High → Low)</div>
          <div className="chart-container" style={{ height: CHART_HEIGHT }}>
            {severityLabels.length > 0 ? (
              <Bar data={severityData} options={chartOptions} />
            ) : (
              <p className="chart-empty">No data available</p>
            )}
          </div>
        </div>
      </div>

      {topIPs.length > 0 && (
        <div className="card chart-card">
          <div className="card-title">Top Attacking IPs</div>
          <div className="chart-container" style={{ height: CHART_HEIGHT }}>
            <Bar
              data={topIPsData}
              options={{
                ...chartOptions,
                indexAxis: 'y',
                plugins: { ...chartOptions.plugins, legend: { display: false } },
                scales: {
                  x: {
                    beginAtZero: true,
                    title: { display: true, text: 'Number of Attacks', color: chartTextColor },
                    ticks: { color: chartTextColor, stepSize: 1 },
                    grid: { color: chartGridColor },
                  },
                  y: { title: { display: true, text: 'IP Address', color: chartTextColor }, ticks: { color: chartTextColor }, grid: { color: chartGridColor } },
                },
              }}
            />
          </div>
        </div>
      )}

      {/* Analyst summary: plain-English summary and recommendations (SOC-style). */}
      <div className="card">
        <div className="card-title">Final Analysis Summary</div>
        <div className="analyst-summary">
          <p className="summary-text">{summary}</p>
          <div className="recommendations">
            <strong>Recommendations:</strong>
            <ul style={{ margin: '8px 0 0 0', paddingLeft: '20px' }}>
              {recommendations.map((rec, i) => (
                <li key={i} style={{ marginBottom: '4px' }}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Download overall statistics (all files) — does not replace per-file view on screen. */}
      {fileHistory && fileHistory.length > 0 && (
        <div className="card">
          <div className="card-title">Download Overall Statistics</div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '12px' }}>
            Export detections for all files uploaded so far. This does not change the statistics shown above.
          </p>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-primary" onClick={handleDownloadOverallCsv}>
              Download as CSV
            </button>
            <button type="button" className="btn btn-primary" onClick={handleDownloadOverallJson}>
              Download as JSON
            </button>
          </div>
        </div>
      )}

      {/* File history: clickable rows for file-based context (primary analyst workflow). */}
      {fileHistory && fileHistory.length > 0 && (
        <div className="card">
          <div className="card-title">File Analysis History</div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '10px' }}>
            Click a row to show statistics for that file only. Click &quot;Clear selection&quot; to show all files again.
          </p>
          <div style={{ marginBottom: '10px' }}>
            {selectedFileId != null ? (
              <button type="button" className="btn" onClick={() => onSelectFile(null)}>
                Clear selection (show all files)
              </button>
            ) : (
              <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Showing statistics for all files.</span>
            )}
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Type</th>
                  <th>Upload Time</th>
                  <th>Attacks Detected</th>
                </tr>
              </thead>
              <tbody>
                {fileHistory.map((row) => (
                  <tr
                    key={row.id}
                    className={selectedFileId === row.id ? 'file-history-selected' : ''}
                    onClick={() => onSelectFile(row.id)}
                    style={{ cursor: 'pointer' }}
                    title="Click to show statistics for this file"
                  >
                    <td>{row.file_name}</td>
                    <td>{row.file_type}</td>
                    <td>{formatUploadTime(row.upload_time)}</td>
                    <td>{row.total_attacks_detected}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
