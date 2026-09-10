/**
 * Shape guard for a completed backend scan result.
 *
 * Only checks that the authoritative fields the risk engine always returns
 * are present, so downstream components can render them. It never computes
 * or modifies any value: Trust Score, Confidence and Verdict must always
 * come straight from the backend payload.
 */
export function isScanResult(data) {
  return (
    data !== null &&
    typeof data === 'object' &&
    typeof data.scan_id === 'string' &&
    typeof data.target === 'string' &&
    typeof data.trust_score === 'number' &&
    typeof data.confidence === 'number' &&
    typeof data.verdict === 'string'
  );
}

export default isScanResult;
