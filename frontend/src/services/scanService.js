import api from './api';

export async function runScan(target) {
  const response = await api.get(`/scan/${encodeURIComponent(target)}`);
  return response.data;
}

export async function scanModule(moduleEndpoint, target) {
  const response = await api.get(`/${moduleEndpoint}/${encodeURIComponent(target)}`);
  return response.data;
}

export async function getHistory(limit = 50, offset = 0) {
  const response = await api.get('/history', { params: { limit, offset } });
  return response.data;
}

export async function getScanReport(scanId) {
  const response = await api.get(`/history/${encodeURIComponent(scanId)}`);
  return response.data;
}