import axios from 'axios';

export const API_BASE_URL = process.env.REACT_APP_API_URL
  ? process.env.REACT_APP_API_URL.replace(/\/$/, '') + '/api'
  : '/api';

/**
 * Fetch detections, optionally scoped to a single file (file_id) for analyst context.
 * When fileId is null/undefined, returns all detections (cumulative).
 */
export const fetchDetections = async (attackType = '', sourceIp = '', fileId = null, severity = '') => {
  const params = new URLSearchParams();
  if (attackType) params.append('attack_type', attackType);
  if (sourceIp) params.append('source_ip', sourceIp);
  if (fileId != null) params.append('file_id', fileId);
  if (severity) params.append('severity', severity);
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
  const response = await fetch(`${API_BASE_URL}/export/csv`);
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
