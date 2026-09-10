import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildOverallAssessment } from '../src/utils/assessment.js';

const SCORED_ONLY = ['dns', 'ssl', 'headers'].map((module, i) => ({
  module,
  score: 100 - i,
  confidence: 80,
  findings: [],
}));

const WITH_INFRA = [...SCORED_ONLY, { module: 'infrastructure', score: 100, confidence: 100, findings: [] }];

test('M: assessment counts only scored modules and names infrastructure as informational context', () => {
  const paragraphs = buildOverallAssessment({
    domain: 'example.com',
    target: 'example.com',
    trust_score: 88,
    confidence: 92,
    verdict: 'Low Risk',
    modules: WITH_INFRA,
    findings: [],
  });
  assert.ok(paragraphs[0].includes('3 security modules plus 1 informational infrastructure context'));
});

test('M2: without infrastructure the strong module count is used exactly', () => {
  const paragraphs = buildOverallAssessment({
    domain: 'example.com',
    target: 'example.com',
    trust_score: 88,
    confidence: 92,
    verdict: 'Low Risk',
    modules: SCORED_ONLY,
    findings: [],
  });
  assert.ok(paragraphs[0].includes('3 security modules'));
  assert.ok(!paragraphs[0].includes('informational'));
});

test('O/P/Q: assessment quotes the backend numbers without recomputing them', () => {
  const paragraphs = buildOverallAssessment({
    domain: 'example.com',
    target: 'example.com',
    trust_score: 42,
    confidence: 31,
    verdict: 'High Risk',
    modules: SCORED_ONLY,
    findings: [{ title: 'Weak TLS', severity: 'high' }],
  });
  const verdictLine = paragraphs.find((p) => p.includes('trust score'));
  assert.ok(verdictLine.includes('42/100'));
  assert.ok(verdictLine.includes('31%'));
  assert.ok(verdictLine.includes('High Risk'));
});

test('M3: infrastructure never appears in the weakest-areas list', () => {
  const modulesWithWeakInfra = [
    { module: 'infrastructure', score: 10, confidence: 50, findings: [] },
    { module: 'dns', score: 95, confidence: 90, findings: [] },
  ];
  const paragraphs = buildOverallAssessment({
    domain: 'example.com',
    target: 'example.com',
    trust_score: 90,
    confidence: 90,
    verdict: 'Trusted',
    modules: modulesWithWeakInfra,
    findings: [],
  });
  const weakLine = paragraphs.find((p) => p.includes('weakest areas'));
  assert.ok(!weakLine);
});