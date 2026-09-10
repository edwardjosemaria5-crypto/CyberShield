import { useState } from 'react';
import { runScan } from '../services/scanService';
import isScanResult from '../utils/resultGuard';

const IDLE = 'idle';
const SCANNING = 'scanning';
const SUCCESS = 'success';
const ERROR = 'error';

export default function useScan() {
  const [status, setStatus] = useState(IDLE);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const loading = status === SCANNING;

  const run = async (target) => {
    setStatus(SCANNING);
    setError(null);
    try {
      const data = await runScan(target);
      if (!isScanResult(data)) {
        throw new Error('The scan service returned an unexpected response.');
      }
      setResult(data);
      setStatus(SUCCESS);
      return data;
    } catch (err) {
      setError(err.message || 'The scan could not be completed.');
      setStatus(ERROR);
      return null;
    }
  };

  const reset = () => {
    setStatus(IDLE);
    setResult(null);
    setError(null);
  };

  return { status, loading, error, result, run, reset, IDLE, SCANNING, SUCCESS, ERROR };
}