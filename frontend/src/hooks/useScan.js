import { useState } from 'react';
import { fetchScanResult } from '../services/api';

export default function useScan() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  const runScan = async (domain) => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchScanResult(domain);
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return { loading, error, data, runScan };
}
