import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isScanResult } from '../src/utils/resultGuard.js';

test('isScanResult accepts a complete backend AnalysisResponse shape', () => {
  assert.equal(
    isScanResult({
      scan_id: 'CS-2026-ABC',
      target: 'x.com',
      trust_score: 50,
      confidence: 60,
      verdict: 'Moderate Risk',
    }),
    true,
  );
});

test('O/P/Q: isScanResult requires authoritative numeric fields', () => {
  assert.equal(isScanResult(null), false);
  assert.equal(isScanResult({}), false);
  assert.equal(isScanResult({ trust_score: 50 }), false);
  assert.equal(
    isScanResult({ scan_id: 'CS-2026-ABC', target: 'x.com', trust_score: '50', confidence: 60, verdict: 'x' }),
    false,
  );
  assert.equal(
    isScanResult({ scan_id: 1, target: 'x.com', trust_score: 50, confidence: 60, verdict: 'x' }),
    false,
  );
});