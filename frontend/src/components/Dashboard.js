import React from 'react';
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

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
);

const CHART_HEIGHT = 220;

function Dashboard({ statistics, fileHistory, loading }) {
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
        <p style={{ color: '#666', textAlign: 'center', padding: '20px' }}>
          No data available. Upload a file to start analysis.
        </p>
      </div>
    );
  }

  // Prepare data for attack types pie chart
  const attackTypesData = {
    labels: Object.keys(statistics.by_attack_type || {}),
    datasets: [
      {
        label: 'Attack Types',
        data: Object.values(statistics.by_attack_type || {}),
        backgroundColor: [
          '#FF6384',
          '#36A2EB',
          '#FFCE56',
          '#4BC0C0',
          '#9966FF',
          '#FF9F40',
          '#FF6384',
          '#C9CBCF',
          '#4BC0C0',
          '#FF6384'
        ],
        borderWidth: 2,
        borderColor: '#fff'
      }
    ]
  };

  // Prepare data for severity bar chart
  const severityData = {
    labels: Object.keys(statistics.by_severity || {}),
    datasets: [
      {
        label: 'Detections by Severity',
        data: Object.values(statistics.by_severity || {}),
        backgroundColor: [
          '#f44336', // High - Red
          '#ff9800', // Medium - Orange
          '#4caf50'  // Low - Green
        ],
        borderColor: [
          '#d32f2f',
          '#f57c00',
          '#388e3c'
        ],
        borderWidth: 2
      }
    ]
  };

  const topIPs = statistics.top_source_ips || [];
  const topIPsData = {
    labels: topIPs.map((item) => item.ip),
    datasets: [{
      label: 'Number of Attacks',
      data: topIPs.map((item) => item.count),
      backgroundColor: '#667eea',
      borderColor: '#5a67d8',
      borderWidth: 2,
    }],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom' } },
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
        <div className="card-title">Summary Statistics</div>
        <div className="stats-grid">
          <div className="stat-box">
            <div className="stat-value stat-total">{statistics.total_detections || 0}</div>
            <div className="stat-label">Total Detections</div>
          </div>
          <div className="stat-box">
            <div className="stat-value stat-types">{Object.keys(statistics.by_attack_type || {}).length}</div>
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
            {Object.keys(statistics.by_attack_type || {}).length > 0 ? (
              <Pie data={attackTypesData} options={chartOptions} />
            ) : (
              <p className="chart-empty">No data available</p>
            )}
          </div>
        </div>
        <div className="card chart-card">
          <div className="card-title">Detections by Severity</div>
          <div className="chart-container" style={{ height: CHART_HEIGHT }}>
            {Object.keys(statistics.by_severity || {}).length > 0 ? (
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
                plugins: { legend: { display: false } },
                scales: {
                  x: { beginAtZero: true, title: { display: true, text: 'Number of Attacks' } },
                  y: { title: { display: true, text: 'IP Address' } },
                },
              }}
            />
          </div>
        </div>
      )}

      {fileHistory && fileHistory.length > 0 && (
        <div className="card">
          <div className="card-title">File Analysis History</div>
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
                  <tr key={row.id}>
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
