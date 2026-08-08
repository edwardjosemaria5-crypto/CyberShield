import { useCallback, useEffect, useState } from 'react';
import { getHistory } from '../services/scanService';

export default function useHistoryList(limit = 50) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await getHistory(limit, 0);
        if (!cancelled) setItems(data.items ?? []);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Scan history could not be loaded.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [limit]);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getHistory(limit, 0);
      setItems(data.items ?? []);
    } catch (err) {
      setError(err.message || 'Scan history could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [limit]);

  return { items, loading, error, reload };
}