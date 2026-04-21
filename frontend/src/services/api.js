import axios from 'axios';

export const API_BASE_URL = process.env.REACT_APP_API_URL
  ? process.env.REACT_APP_API_URL.replace(/\/$/, '') + '/api'
  : '/api';

// Axios interceptor for JWT Auth
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('ids_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = async (username, password) => {
  const response = await axios.post(`${API_BASE_URL}/login`, { username, password });
  if (response.data.token) {
    localStorage.setItem('ids_token', response.data.token);
    localStorage.setItem('ids_role', response.data.role);
  }
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('ids_token');
  localStorage.removeItem('ids_role');
};

export const simulateAttack = async (url) => {
  const response = await axios.post(`${API_BASE_URL}/simulate-attack`, { url });
  return response.data;
};

export const fetchDetections = async (attackType = '', sourceIp = '', fileId = null, severity = '', detectionSource = '') => {
  const params = new URLSearchParams();
  if (attackType) params.append('attack_type', attackType);
  if (sourceIp) params.append('source_ip', sourceIp);
  if (fileId != null) params.append('file_id', fileId);
  if (severity) params.append('severity', severity);
  if (detectionSource) params.append('detection_source', detectionSource);
  const response = await axios.get(`${API_BASE_URL}/detections?${params.toString()}`);
  return response.data.detections || [];
};

/**
 * Fetch statistics for dashboard. When fileId or severity is set, stats are filtered accordingly.
 */
export const fetchStatistics = async (fileId = null, severity = '') => {
  const params = new URLSearchParams();
  if (fileId != null) params.append('file_id', fileId);
  if (severity) params.append('severity', severity);
  const response = await axios.get(`${API_BASE_URL}/statistics?${params.toString()}`);
  return response.data;
};

export const fetchTopIPs = async (fileId = null) => {
  const params = new URLSearchParams();
  if (fileId != null) params.append('file_id', fileId);
  const response = await axios.get(`${API_BASE_URL}/top-ips?${params.toString()}`);
  return response.data.top_source_ips || [];
};

/**
 * Download overall statistics (all files) as CSV. Used by "Download Overall Statistics".
 */
export const downloadOverallCsv = async () => {
  const response = await fetch(`${API_BASE_URL}/export/csv`, {
    headers: { Authorization: `Bearer ${localStorage.getItem('ids_token')}` }
  });
  const blob = await response.blob();
  return blob;
};

/**
 * Download overall statistics (all files) as JSON.
 */
export const downloadOverallJson = async () => {
  const response = await axios.get(`${API_BASE_URL}/export/json`);
  return response.data;
};

export const fetchFileHistory = async () => {
  const response = await axios.get(`${API_BASE_URL}/file-history`);
  return response.data.file_history || [];
};

export const clearDatabase = async () => {
  await axios.post(`${API_BASE_URL}/clear-database`);
};
