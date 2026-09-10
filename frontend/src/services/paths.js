export const REPORT_FORMATS = ['json', 'csv', 'pdf'];

const SCAN_ID_RE = /^[A-Za-z0-9-]{1,64}$/;

export function scanReportPath(scanId) {
  if (!isSafeScanId(scanId)) {
    throw new Error('Invalid scan identifier.');
  }
  return `/history/${encodeURIComponent(scanId)}`;
}

export function reportDownloadPath(scanId, format) {
  if (!isSafeScanId(scanId)) {
    throw new Error('Invalid scan identifier.');
  }
  if (!REPORT_FORMATS.includes(format)) {
    throw new Error(`Unsupported report format "${format}".`);
  }
  return `/reports/${encodeURIComponent(scanId)}/${format}`;
}

export function moduleScanPath(moduleEndpoint, target) {
  return `/${moduleEndpoint}/${encodeURIComponent(target)}`;
}

function isSafeScanId(value) {
  return typeof value === 'string' && SCAN_ID_RE.test(value);
}
