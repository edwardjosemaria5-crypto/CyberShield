import Button from '../../components/common/Button/Button';
import LoadingState from '../../components/common/StateViews/LoadingState';
import ErrorState from '../../components/common/StateViews/ErrorState';
import EmptyState from '../../components/common/StateViews/EmptyState';
import HistoryTable from '../../components/history/HistoryTable/HistoryTable';
import useHistoryList from '../../hooks/useHistoryList';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './HistoryPage.module.css';

export default function HistoryPage() {
  const { items, loading, error, reload, hasMore, loadingMore, loadMore } = useHistoryList();
  usePageTitle('Scan History');

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <div>
          <h1 className={styles.heading}>Scan History</h1>
          <p className={styles.sub}>Completed scans persisted on the backend.</p>
        </div>
        <Button to="/scan">New Scan</Button>
      </div>

      {loading ? (
        <div className={styles.stateWrap}>
          <LoadingState label="Loading scan history…" />
        </div>
      ) : error ? (
        <div className={styles.stateWrap}>
          <ErrorState
            title="History unavailable"
            message={error}
            onRetry={reload}
            retryLabel="Try Again"
          />
        </div>
      ) : items.length === 0 ? (
        <div className={styles.stateWrap}>
          <EmptyState
            title="No scans yet"
            message="Completed scans will appear here with their trust score, verdict and findings. Run your first analysis to build up a history."
            action={<Button size="lg" to="/scan">Start a Scan</Button>}
          />
        </div>
      ) : (
        <>
          <HistoryTable history={items} />
          {hasMore && (
            <div className={styles.loadMore}>
              <Button variant="secondary" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? 'Loading earlier scans…' : 'Load earlier scans'}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}