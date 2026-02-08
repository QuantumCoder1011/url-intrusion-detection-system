import React, { useState } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../services/api';

function FileUpload({ onUpload }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setMessage('');
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage('Please select a file');
      return;
    }

    setUploading(true);
    setMessage('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setMessage(`✅ ${response.data.message}. Processed ${response.data.total_urls} URLs, detected ${response.data.detected_attacks} attacks.`);
      setFile(null);
      document.getElementById('file-input').value = '';
      
      // Notify parent component to reload data
      if (onUpload) {
        onUpload();
      }
    } catch (error) {
      setMessage(`❌ Error: ${error.response?.data?.error || error.message}`);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="card">
      <div className="card-title">Upload File for Analysis</div>
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          id="file-input"
          type="file"
          accept=".csv,.pcap"
          onChange={handleFileChange}
          style={{ padding: '8px', border: '1px solid #ddd', borderRadius: '4px', flex: '1', minWidth: '200px' }}
        />
        <button
          className="btn btn-primary"
          onClick={handleUpload}
          disabled={uploading || !file}
        >
          {uploading ? 'Uploading...' : 'Upload & Analyze'}
        </button>
      </div>
      {message && (
        <div style={{ marginTop: '10px', padding: '10px', backgroundColor: message.includes('✅') ? '#d4edda' : '#f8d7da', borderRadius: '4px', color: message.includes('✅') ? '#155724' : '#721c24' }}>
          {message}
        </div>
      )}
      <div style={{ marginTop: '10px', fontSize: '12px', color: '#666' }}>
        Supported formats: CSV (log files), PCAP (network capture files)
      </div>
    </div>
  );
}

export default FileUpload;
