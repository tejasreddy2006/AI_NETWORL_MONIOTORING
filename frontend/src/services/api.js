import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Packets
export const getPackets = (params) => api.get('/packets', { params }).then(r => r.data);
export const getPacketStats = (timeRange) => api.get('/packets/stats', { params: { time_range: timeRange } }).then(r => r.data);
export const getProtocolDist = (timeRange) => api.get('/packets/protocols', { params: { time_range: timeRange } }).then(r => r.data);
export const getTrafficTimeline = (timeRange) => api.get('/packets/timeline', { params: { time_range: timeRange } }).then(r => r.data);

// Alerts
export const getAlerts = (params) => api.get('/alerts', { params }).then(r => r.data);
export const getAlertById = (id) => api.get(`/alerts/${id}`).then(r => r.data);
export const resolveAlert = (id) => api.put(`/alerts/${id}/resolve`).then(r => r.data);
export const getAlertStats = () => api.get('/alerts/stats').then(r => r.data);

// Topology
export const getTopology = () => api.get('/topology/graph').then(r => r.data);

// ML
export const getPredictions = () => api.get('/ml/predictions').then(r => r.data);
export const triggerTraining = () => api.post('/ml/train').then(r => r.data);

// Health
export const getHealthScore = () => api.get('/health/score').then(r => r.data);
export const getHealthHistory = () => api.get('/health/history').then(r => r.data);

// Threat Intel
export const getThreatMap = () => api.get('/threatintel/map').then(r => r.data);
export const lookupIp = (ip) => api.get(`/threatintel/lookup/${ip}`).then(r => r.data);

// Simulation
export const runSimulation = (scenario, config) => api.post('/simulation/run', { scenario_type: scenario, config }).then(r => r.data);
export const getScenarios = () => api.get('/simulation/scenarios').then(r => r.data);

// AI Copilot
export const chatAi = (sessionId, message) => api.post('/ai/chat', { session_id: sessionId, message }).then(r => r.data);

export default api;
