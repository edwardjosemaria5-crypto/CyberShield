import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeApiError } from '../src/services/errors.js';

const FALLBACK = 'The scan service could not be reached.';

test('I: safe backend string detail is used', () => {
  const error = { response: { status: 422, data: { detail: 'Target is too long (max 2048 characters).' } } };
  assert.equal(normalizeApiError(error), 'Target is too long (max 2048 characters).');
});

test('I2: structured FastAPI validation detail is never surfaced', () => {
  const error = {
    response: {
      status: 422,
      data: {
        detail: [
          { type: 'string_too_short', loc: ['body', 'target'], msg: 'String should have at least 1 character', input: '' },
        ],
      },
    },
    message: 'Request failed with status code 422',
  };
  const msg = normalizeApiError(error);
  assert.equal(msg, FALLBACK);
  assert.ok(!msg.includes('String should have at least 1 character'));
});

test('I3: generic transport failures fall back to a controlled message', () => {
  assert.equal(normalizeApiError({ message: 'Network Error' }), FALLBACK);
  assert.equal(normalizeApiError({ message: 'timeout of 120000ms exceeded' }), FALLBACK);
  assert.equal(normalizeApiError({ message: 'Request failed with status code 500' }), FALLBACK);
});

test('I4: stack-trace-shaped strings are never passed through', () => {
  const error = {
    message: 'Traceback (most recent call last):\n  File "/opt/app/main.py", line 12\n    return run_scan(target)',
  };
  const msg = normalizeApiError(error);
  assert.equal(msg, FALLBACK);
  assert.ok(!/Traceback|opt\/app|main\.py/.test(msg));
});

test('I5: missing or non-object errors fall back safely', () => {
  assert.equal(normalizeApiError(null), FALLBACK);
  assert.equal(normalizeApiError(undefined), FALLBACK);
  assert.equal(normalizeApiError('oops'), FALLBACK);
});

test('I6: a specific non-generic message is preserved', () => {
  const error = { message: 'The scan service returned an unexpected response.' };
  assert.equal(normalizeApiError(error), 'The scan service returned an unexpected response.');
});