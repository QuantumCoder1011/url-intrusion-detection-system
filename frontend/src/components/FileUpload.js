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
    <div className="cyber-card">
      <div className="card-title">DATA INGESTION MODULE</div>

      {!isSuccess ? (
        <div className="dropzone">
          <div className="dropzone-icon">⇪</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '15px', alignItems: 'center' }}>
            <p style={{ fontFamily: 'var(--font-mono)', color: 'var(--neon-cyan)' }}>AWAITING CSV / PCAP TELEMETRY UPLOAD</p>
            <input
              ref={inputRef}
              id="file-input"
              type="file"
              accept=".csv,.pcap"
              onChange={handleFileChange}
              disabled={uploading}
              style={{
                maxWidth: '300px',
                textAlign: 'center'
              }}
            />
            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={uploading || !file}
              style={{ width: '200px' }}
            >
              {uploading ? 'INGESTING...' : 'INITIALIZE UPLOAD'}
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', padding: '20px', border: '1px solid var(--neon-green)', backgroundColor: 'rgba(0, 255, 102, 0.05)', borderRadius: '8px' }}>
          <span style={{ fontWeight: 500, color: 'var(--neon-green)', fontFamily: 'var(--font-mono)' }}>
            [+] INGESTION COMPLETE: {uploadedFile.name} ({uploadedFile.type})
          </span>
          <button type="button" className="btn btn-primary" onClick={handleUploadAnother}>
            PROCESS ANOTHER FILE
          </button>
        </div>
      )}

      {message && (
        <div className="typing-text" style={{
            marginTop: '15px',
            color: message.includes('Error') ? 'var(--neon-red)' : 'var(--neon-green)',
            fontFamily: 'var(--font-mono)',
            textAlign: 'center'
        }}>
          {message.includes('Error') ? '[!] ' : '[+] '}{message.toUpperCase()}
        </div>
      )}
    </div>
  );
}

export default FileUpload;
