import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateTarget,
  normalizeTarget,
  countScoredModules,
  countInformationalModules,
  isInformationalModule,
  moduleSummary,
  severityTone,
  verdictTone,
  moduleTitle,
} from '../src/utils/formatters.js';

test('validateTarget accepts domains, IPv4 literals and URL forms', () => {
  assert.equal(validateTarget('example.com'), null);
  assert.equal(validateTarget('https://example.com'), null);
  assert.equal(validateTarget('8.8.8.8'), null);
  assert.equal(validateTarget('sub.example.co.uk/path?q=1'), null);
});

test('validateTarget accepts well-formed IPv6 literals the backend supports', () => {
  for (const target of ['2606:4700:4700::1111', 'fe80::1', '::1', 'http://2001:db8::1']) {
    assert.equal(validateTarget(target), null, `${target} should pass UX validation`);
  }
});

test('validateTarget rejects unsafe or malformed input before submission', () => {
  for (const target of ['', 'exa mple.com', 'exa<mple>', 'http://user:pw@example.com', 'example', '::1::2', '2606:4700:4700:1111']) {
    assert.notEqual(validateTarget(target), null, `${target} should fail UX validation`);
  }
});

test('normalizeTarget strips scheme and trailing slashes', () => {
  assert.equal(normalizeTarget('https://example.com/'), 'example.com');
  assert.equal(normalizeTarget('example.com'), 'example.com');
});

test('informational module detection and scored-vs-context counts', () => {
  const modules = [
    { module: 'dns', score: 80, confidence: 90 },
    { module: 'infrastructure', score: 100, confidence: 100 },
    { module: 'threatintel', score: 90, confidence: 90 },
  ];
  assert.equal(isInformationalModule({ module: 'infrastructure' }), true);
  assert.equal(isInformationalModule({ module: 'dns' }), false);
  assert.equal(isInformationalModule(null), false);
  assert.equal(isInformationalModule(undefined), false);
  assert.equal(countScoredModules(modules), 2);
  assert.equal(countInformationalModules(modules), 1);
  assert.equal(countScoredModules(null), 0);
  assert.equal(countScoredModules([]), 0);
});

test('M/N: infrastructure summary is informational and never implies scoring', () => {
  const summary = moduleSummary(
    'infrastructure',
    {
      infrastructure: {
        status: 'available',
        ip_address: '142.250.191.142',
        asn: 'AS15169',
        asn_organization: 'Google LLC',
        country_code: 'US',
      },
    },
    [],
  );
  assert.ok(summary.includes('Available'));
  assert.ok(!/score|critical|finding|risk/i.test(summary));
});

test('M/N2: unavailable infrastructure reports its reason without a score', () => {
  const summary = moduleSummary(
    'infrastructure',
    { infrastructure: { status: 'unavailable', reason: 'network' } },
    [],
  );
  assert.ok(summary.includes('Unavailable'));
  assert.ok(summary.includes('network'));
});

test('severity and verdict tones resolve to text-bearing classes', () => {
  assert.equal(severityTone('critical'), 'danger');
  assert.equal(verdictTone('Critical'), 'danger');
  assert.equal(severityTone('unknown'), 'neutral');
});

test('moduleTitle resolves known modules and falls back safely for unknown ones', () => {
  assert.equal(moduleTitle('dns'), 'DNS');
  assert.equal(moduleTitle('infrastructure'), 'infrastructure');
  assert.equal(typeof moduleTitle('does_not_exist'), 'string');
});