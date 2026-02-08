import axios from 'axios';

// Use relative URL so the dev server proxy (see package.json) forwards to backend
const API_BASE_URL = '/api';

export const fetchDetections = async (attackType = '', sourceIp = '') => {
  try {
    const params = new URLSearchParams();
    if (attackType) params.append('attack_type', attackType);
    if (sourceIp) params.append('source_ip', sourceIp);

    const response = await axios.get(`${API_BASE_URL}/detections?${params.toString()}`);
    return response.data.detections || [];
  } catch (error) {
    console.error('Error fetching detections:', error);
    throw error;
  }
};

export const fetchStatistics = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/statistics`);
    return response.data;
  } catch (error) {
    console.error('Error fetching statistics:', error);
    throw error;
  }
};
