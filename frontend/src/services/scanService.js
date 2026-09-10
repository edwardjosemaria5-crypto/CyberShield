import api from './api';
import { scanReportPath, reportDownloadPath, moduleScanPath } from './paths';

export async function runScan(target, client = api) {
  const response = await client.post('/scan', { target });
  return response.data;
}

export async function scanModule(moduleEndpoint, target, client = api) {
  const response = await client.get(moduleScanPath(moduleEndpoint, target));
  return response.data;
}

export async function getHistory(limit = 50, offset = 0, client = api) {
  const response = await client.get('/history', { params: { limit, offset } });
  return response.data;
}

export async function getScanReport(scanId, client = api) {
  const response = await client.get(scanReportPath(scanId));
  return response.data;
}

export async function exportReport(scanId, format, client = api) {
  const response = await client.get(reportDownloadPath(scanId, format), {
    responseType: 'blob',
  });
  return response;
}