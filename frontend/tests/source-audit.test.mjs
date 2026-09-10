import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../src', import.meta.url));

function collectFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFiles(path));
    } else if (/\.(js|jsx)$/.test(entry.name)) {
      out.push(path);
    }
  }
  return out;
}

const sources = new Map(
  collectFiles(SRC).map((path) => [
    relative(SRC, path).replace(/\\/g, '/'),
    readFileSync(path, 'utf8'),
  ]),
);

test('G/H: no HTML-injection sinks exist in the frontend source', () => {
  for (const [name, src] of sources) {
    assert.ok(!/dangerouslySetInnerHTML/.test(src), `${name} uses dangerouslySetInnerHTML`);
    assert.ok(!/innerHTML\s*=/.test(src), `${name} assigns innerHTML`);
    assert.ok(!/document\.write/.test(src), `${name} uses document.write`);
    assert.ok(/\beval\(/.test(src) === false, `${name} uses eval`);
    assert.ok(!/new Function\(/.test(src), `${name} uses new Function`);
  }
});

test('R/Gate10: no browser secret storage exists in the frontend source', () => {
  for (const [name, src] of sources) {
    assert.ok(!/localStorage/.test(src), `${name} touches localStorage`);
    assert.ok(!/sessionStorage/.test(src), `${name} touches sessionStorage`);
    assert.ok(!/document\.cookie/.test(src), `${name} touches document.cookie`);
  }
});

test('R/Gate11: no automatic navigation or opener-free escape relied on target data', () => {
  for (const [name, src] of sources) {
    assert.ok(!/window\.open\(/.test(src), `${name} calls window.open`);
    assert.ok(!/target=[\"']_blank/.test(src), `${name} opens external links in new tabs`);
  }
});

test('R: frontend environment variables are limited to the public API base URL', () => {
  const envVars = new Set();
  for (const [, src] of sources) {
    for (const match of src.matchAll(/VITE_[A-Z0-9_]+|\bprocess\.env\b/g)) {
      envVars.add(match[0]);
    }
  }
  assert.deepEqual([...envVars].sort(), ['VITE_API_BASE_URL']);
});

test('R: no obvious secret values or provider keys exist in the frontend source', () => {
  const secretPatterns = /AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|password\s*=\s*["'][^"']{6,}/;
  for (const [name, src] of sources) {
    assert.ok(!secretPatterns.test(src), `${name} appears to contain a secret literal`);
  }
});

test('O/P/Q: no risk-engine scoring math exists in the frontend source', () => {
  for (const [name, src] of sources) {
    assert.ok(!/MODULE_WEIGHTS|computeTrustScore|computeConfidence|verdict_for_score/.test(src), `${name} re-implements scoring`);
    assert.ok(!/\btrust_score\s*\*|\bconfidence\s*\*|\bsum(?:\(| of module)/.test(src), `${name} performs score arithmetic`);
    assert.ok(!/(^|[^a-zA-Z])\bweights\b/.test(src), `${name} defines scoring weights`);
  }
});

test('B/C: the scan form guards against duplicate submissions while loading', () => {
  const scanInput = sources.get('components/scan/ScanInput/ScanInput.jsx');
  assert.ok(scanInput);
  assert.ok(scanInput.includes('if (loading) return;'), 'handleSubmit lacks a loading guard');
  assert.ok(/disabled=\{loading/.test(scanInput), 'scan button is not disabled while loading');
});

test('D/J: scan result guard and too-many-history pagination guard exist', () => {
  assert.ok(sources.has('utils/resultGuard.js'), 'result shape guard is missing');
  const history = sources.get('hooks/useHistoryList.js');
  assert.ok(history.includes('getHistory(limit,'), 'history offset argument wiring is missing');
  assert.ok(history.includes('hasMore'), 'history pagination flag is missing');
  assert.ok(history.includes('loadMore'), 'history load-more action is missing');
});