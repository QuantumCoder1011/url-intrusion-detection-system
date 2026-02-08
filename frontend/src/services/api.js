import axios from 'axios';

export const API_BASE_URL = process.env.REACT_APP_API_URL
  ? process.env.REACT_APP_API_URL.replace(/\/$/, '') + '/api'
  : '/api';

export const fetchDetections = async (attackType = '', sourceIp = '') => {
  const params = new URLSearchParams();
  if (attackType) params.append('attack_type', attackType);
  if (sourceIp) params.append('source_ip', sourceIp);
  const response = await axios.get(`${API_BASE_URL}/detections?${params.toString()}`);
  return response.data.detections || [];
};

export const fetchStatistics = async () => {
  const response = await axios.get(`${API_BASE_URL}/statistics`);
  return response.data;
};

export const fetchTopIPs = async () => {
  const response = await axios.get(`${API_BASE_URL}/top-ips`);
  return response.data.top_source_ips || [];
};

export const fetchFileHistory = async () => {
  const response = await axios.get(`${API_BASE_URL}/file-history`);
  return response.data.file_history || [];
};

export const clearDatabase = async () => {
  await axios.post(`${API_BASE_URL}/clear-database`);
};
