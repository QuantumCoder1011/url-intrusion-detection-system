import React, { useState, useRef } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../services/api';

/**
 * Upload area with clear state feedback: before upload, during upload, and after success.
 * After a successful upload, shows "Uploaded: <filename>" and disables re-upload until
 * the user clicks "Upload Another File", so the system state is always clear to the analyst.
 */
function FileUpload({ onUpload }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  const inputRef = useRef(null);

  const handleFileChange = (e) => {
    const chosen = e.target.files?.[0];
    setFile(chosen);
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

      const ext = (file.name || '').split('.').pop()?.toLowerCase() || '';
      const fileTypeLabel = ext === 'csv' ? 'CSV' : ext === 'pcap' ? 'PCAP' : ext.toUpperCase();
      setUploadedFile({ name: file.name, type: fileTypeLabel });
      setMessage(`Success. Processed ${response.data.total_urls} URLs, detected ${response.data.detected_attacks} attacks.`);
      setFile(null);
      if (inputRef.current) inputRef.current.value = '';

      if (onUpload) {
        onUpload();
      }
    } catch (error) {
      setMessage(`Error: ${error.response?.data?.error || error.message}`);
    } finally {
      setUploading(false);
    }
  };

  const handleUploadAnother = () => {
    setUploadedFile(null);
    setMessage('');
    setFile(null);
    if (inputRef.current) inputRef.current.value = '';
  };

  const isSuccess = !!uploadedFile;

  return (
    <div className="card">
      <div className="card-title">Upload File for Analysis</div>

      {!isSuccess ? (
        <>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <input
              ref={inputRef}
              id="file-input"
              type="file"
              accept=".csv,.pcap"
              onChange={handleFileChange}
              disabled={uploading}
              style={{
                padding: '8px',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                flex: '1',
                minWidth: '200px',
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
              }}
            />
            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={uploading || !file}
              title={file ? 'Upload and analyze' : 'Select a CSV or PCAP file first'}
            >
              {uploading ? 'Uploading...' : 'Upload CSV / PCAP File'}
            </button>
          </div>
        </>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
            Uploaded: {uploadedFile.name} ({uploadedFile.type})
          </span>
          <button type="button" className="btn btn-primary" onClick={handleUploadAnother}>
            Upload Another File
          </button>
        </div>
      )}

      {message && (
        <div
          style={{
            marginTop: '10px',
            padding: '10px 12px',
            backgroundColor: message.includes('Error') ? '#f8d7da' : '#d4edda',
            color: message.includes('Error') ? '#721c24' : '#155724',
            borderRadius: '6px',
            fontSize: '14px',
          }}
        >
          {message.includes('Error') ? '❌ ' : '✅ '}{message}
        </div>
      )}

      <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text-muted)' }}>
        Supported formats: CSV (log files), PCAP (network capture files)
      </div>
    </div>
  );
}

export default FileUpload;
