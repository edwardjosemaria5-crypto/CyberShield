import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runScan,
  scanModule,
  getHistory,
  getScanReport,
  exportReport,
} from '../src/services/scanService.js';

function fakeClient() {
  const calls = [];
  return {
    calls,
    async post(url, body) {
      calls.push({ method: 'post', url, body });
      return { data: {} };
    },
    async get(url, config) {
      calls.push({ method: 'get', url, config });
      return { data: {} };
    },
  };
}

test('A: runScan sends the target to the existing POST /scan endpoint', async () => {
  const client = fakeClient();
  await runScan('example.com', client);
  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0].method, 'post');
  assert.equal(client.calls[0].url, '/scan');
  assert.deepEqual(client.calls[0].body, { target: 'example.com' });
});

test('A2: runScan carries special characters safely inside the JSON body', async () => {
  const client = fakeClient();
  const target = 'https://example.com/path?q=1&r=%20#frag';
  await runScan(target, client);
  assert.deepEqual(client.calls[0].body, { target });
});

test('O/P/Q: runScan returns the backend payload unchanged (no score recalculation)', async () => {
  const payload = {
    scan_id: 'CS-2026-ABC',
    target: 'example.com',
    trust_score: 42,
    confidence: 30,
    verdict: 'Suspicious',
    modules: [],
    findings: [],
  };
  const client = { calls: [], async post() { return { data: payload }; } };
  const result = await runScan('example.com', client);
  assert.equal(result, payload);
  assert.equal(result.trust_score, 42);
  assert.equal(result.confidence, 30);
  assert.equal(result.verdict, 'Suspicious');
});

test('J: getHistory uses the existing paginated endpoint with limit/offset params', async () => {
  const client = fakeClient();
  await getHistory(20, 40, client);
  assert.equal(client.calls[0].method, 'get');
  assert.equal(client.calls[0].url, '/history');
  assert.deepEqual(client.calls[0].config, { params: { limit: 20, offset: 40 } });
});

test('J2: getHistory default page size is 50, starting at offset 0', async () => {
  const client = fakeClient();
  await getHistory(undefined, undefined, client);
  assert.deepEqual(client.calls[0].config, { params: { limit: 50, offset: 0 } });
});

test('J3: getScanReport requests the stored report by scan id', async () => {
  const client = fakeClient();
  await getScanReport('CS-2026-ABC', client);
  assert.equal(client.calls[0].url, '/history/CS-2026-ABC');
});

test('O/P/Q2: getScanReport returns the stored snapshot unchanged', async () => {
  const payload = { scan_id: 'CS-2026-ABC', trust_score: 77, confidence: 95, verdict: 'Low Risk' };
  const client = { calls: [], async get() { return { data: payload }; } };
  const result = await getScanReport('CS-2026-ABC', client);
  assert.equal(result, payload);
});

test('K: exportReport requests each supported report format with a valid scan id', async () => {
  for (const format of ['json', 'csv', 'pdf']) {
    const client = fakeClient();
    await exportReport('CS-2026-ABC', format, client);
    assert.equal(client.calls[0].url, `/reports/CS-2026-ABC/${format}`);
  }
});

test('L: exportReport refuses unsupported formats and never issues a request', async () => {
  const client = fakeClient();
  await assert.rejects(() => exportReport('CS-2026-ABC', 'html', client), /Unsupported report format/);
  await assert.rejects(() => exportReport('CS-2026-ABC', 'JSON', client), /Unsupported report format/);
  assert.equal(client.calls.length, 0);
});

test('L2: exportReport refuses user-controlled path-like scan ids', async () => {
  const badIds = ['../../etc/passwd', 'CS/../../admin', 'CS-2026-ABC/../../../x', '', 'A'.repeat(65)];
  for (const badId of badIds) {
    const client = fakeClient();
    await assert.rejects(() => exportReport(badId, 'json', client), /Invalid scan identifier/);
    assert.equal(client.calls.length, 0, `no request issued for ${JSON.stringify(badId)}`);
  }
});

test('G3: scanModule percent-encodes untrusted targets before URL interpolation', async () => {
  const client = fakeClient();
  await scanModule('dns', 'https://example.com/a b', client);
  assert.equal(client.calls[0].url, '/dns/https%3A%2F%2Fexample.com%2Fa%20b');
});