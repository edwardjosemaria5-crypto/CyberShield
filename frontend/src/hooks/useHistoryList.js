import { useCallback, useEffect, useState } from 'react';
import { getHistory } from '../services/scanService';

const PAGE_SIZE = 20;

export default function useHistoryList(limit = PAGE_SIZE) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await getHistory(limit, 0);
        if (!cancelled) {
          setItems(data.items ?? []);
          setTotal(data.total ?? null);
        }
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
      setTotal(data.total ?? null);
    } catch (err) {
      setError(err.message || 'Scan history could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [limit]);

  const loadMore = useCallback(async () => {
    if (loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const data = await getHistory(limit, items.length);
      setItems((prev) => [...prev, ...(data.items ?? [])]);
      setTotal((prev) => data.total ?? prev);
    } catch (err) {
      setError(err.message || 'More history could not be loaded.');
    } finally {
      setLoadingMore(false);
    }
  }, [limit, items.length, loadingMore]);

  const hasMore = total !== null && items.length < total;

  return { items, total, hasMore, loading, loadingMore, error, reload, loadMore };
}