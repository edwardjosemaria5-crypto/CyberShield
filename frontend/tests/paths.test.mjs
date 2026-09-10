import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_FORMATS,
  scanReportPath,
  reportDownloadPath,
  moduleScanPath,
} from '../src/services/paths.js';

test('K4: report paths use only the allowlisted export formats', () => {
  assert.deepEqual([...REPORT_FORMATS].sort(), ['csv', 'json', 'pdf']);
  for (const format of REPORT_FORMATS) {
    assert.equal(reportDownloadPath('CS-2026-ABC', format), `/reports/CS-2026-ABC/${format}`);
  }
});

test('K5: export formats never accept markup, script or case-variant payloads', () => {
  assert.equal(REPORT_FORMATS.length, 3);
  const bad = ['json"><script>alert(1)</script>', 'pdf;cat', 'JSON', 'Json', 'html', 'svg', '', '../../../svg'];
  for (const value of bad) {
    assert.throws(() => reportDownloadPath('CS-2026-ABC', value), /Unsupported report format/);
  }
});

test('L3: scan ids cannot escape the report path', () => {
  const bad = ['../../admin', 'CS-2026-ABC/foo', '/etc/passwd', '..', 'x'.repeat(65), 'a b', 'CS@evil'];
  for (const value of bad) {
    assert.throws(() => reportDownloadPath(value, 'json'), /Invalid scan identifier/);
    assert.throws(() => scanReportPath(value), /Invalid scan identifier/);
  }
});

test('L4: backend-issued scan ids always produce stable paths', () => {
  assert.equal(scanReportPath('CS-2026-8F4A2C910B7D'), '/history/CS-2026-8F4A2C910B7D');
  assert.equal(
    reportDownloadPath('CS-2026-8F4A2C910B7D', 'json'),
    '/reports/CS-2026-8F4A2C910B7D/json',
  );
});

test('G4: module scan targets are percent-encoded before interpolation', () => {
  assert.equal(moduleScanPath('dns', 'https://example.com/a'), '/dns/https%3A%2F%2Fexample.com%2Fa');
  assert.equal(moduleScanPath('ssl', '2606:4700:4700::1111'), '/ssl/2606%3A4700%3A4700%3A%3A1111');
});