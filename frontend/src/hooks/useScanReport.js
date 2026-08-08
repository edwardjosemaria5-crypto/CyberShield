import { useCallback, useEffect, useState } from 'react';
import { getScanReport } from '../services/scanService';
import useScanContext from './useScanContext';

const LOADING = 'loading';
const SUCCESS = 'success';
const NOT_FOUND = 'notFound';
const ERROR = 'error';

export default function useScanReport(scanId) {
  const { result } = useScanContext();
  const currentScanId = result?.scan_id ?? null;
  const fresh = currentScanId === scanId ? result : null;
  const [state, setState] = useState({ status: LOADING, report: null, error: null });

  useEffect(() => {
    if (fresh) {
      return undefined;
    }
    let cancelled = false;
    getScanReport(scanId)
      .then((report) => {
        if (!cancelled) setState({ status: SUCCESS, report, error: null });
      })
      .catch((err) => {
        if (cancelled) return;
        if (err.status === 404) {
          setState({ status: NOT_FOUND, report: null, error: null });
        } else {
          setState({ status: ERROR, report: null, error: err.message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, fresh, currentScanId]);

  const retry = useCallback(() => {
    setState({ status: LOADING, report: null, error: null });
    getScanReport(scanId)
      .then((report) => setState({ status: SUCCESS, report, error: null }))
      .catch((err) => {
        if (err.status === 404) {
          setState({ status: NOT_FOUND, report: null, error: null });
        } else {
          setState({ status: ERROR, report: null, error: err.message });
        }
      });
  }, [scanId]);

  return {
    status: fresh ? SUCCESS : state.status,
    scan: fresh ?? state.report,
    error: state.error,
    retry,
    LOADING,
    SUCCESS,
    NOT_FOUND,
    ERROR,
  };
}