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

function Dashboard({ statistics, loading }) {
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

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        position: 'bottom'
      }
    }
  };

  return (
    <div>
      <div className="card">
        <div className="card-title">Summary Statistics</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '20px' }}>
          <div style={{ textAlign: 'center', padding: '15px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#667eea' }}>
              {statistics.total_detections || 0}
            </div>
            <div style={{ color: '#666', marginTop: '5px' }}>Total Detections</div>
          </div>
          <div style={{ textAlign: 'center', padding: '15px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#f44336' }}>
              {Object.keys(statistics.by_attack_type || {}).length}
            </div>
            <div style={{ color: '#666', marginTop: '5px' }}>Attack Types</div>
          </div>
          <div style={{ textAlign: 'center', padding: '15px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#ff9800' }}>
              {statistics.top_source_ips?.length || 0}
            </div>
            <div style={{ color: '#666', marginTop: '5px' }}>Unique Source IPs</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
        <div className="card">
          <div className="card-title">Detections by Attack Type</div>
          {Object.keys(statistics.by_attack_type || {}).length > 0 ? (
            <Pie data={attackTypesData} options={chartOptions} />
          ) : (
            <p style={{ textAlign: 'center', color: '#666', padding: '20px' }}>No data available</p>
          )}
        </div>

        <div className="card">
          <div className="card-title">Detections by Severity</div>
          {Object.keys(statistics.by_severity || {}).length > 0 ? (
            <Bar data={severityData} options={chartOptions} />
          ) : (
            <p style={{ textAlign: 'center', color: '#666', padding: '20px' }}>No data available</p>
          )}
        </div>
      </div>

      {statistics.top_source_ips && statistics.top_source_ips.length > 0 && (
        <div className="card">
          <div className="card-title">Top Source IPs</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8f9fa' }}>
                  <th style={{ padding: '10px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>Source IP</th>
                  <th style={{ padding: '10px', textAlign: 'right', borderBottom: '2px solid #ddd' }}>Detections</th>
                </tr>
              </thead>
              <tbody>
                {statistics.top_source_ips.map((item, index) => (
                  <tr key={index} style={{ borderBottom: '1px solid #eee' }}>
                    <td style={{ padding: '10px' }}>{item.ip}</td>
                    <td style={{ padding: '10px', textAlign: 'right' }}>{item.count}</td>
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
