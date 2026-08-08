import { Link } from 'react-router-dom';
import Card from '../../components/common/Card/Card';
import Button from '../../components/common/Button/Button';
import Loader from '../../components/common/Loader/Loader';
import Alert from '../../components/common/Alert/Alert';
import HistoryTable from '../../components/history/HistoryTable/HistoryTable';
import useHistoryList from '../../hooks/useHistoryList';
import styles from './HistoryPage.module.css';

export default function HistoryPage() {
  const { items, loading, error, reload } = useHistoryList();

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <div>
          <h1 className={styles.heading}>Scan History</h1>
          <p className={styles.sub}>Completed scans from this browsing session.</p>
        </div>
        <Link to="/scan">
          <Button>New Scan</Button>
        </Link>
      </div>

      {loading ? (
        <div className={styles.stateWrap}>
          <Loader label="Loading scan history…" />
        </div>
      ) : error ? (
        <div className={styles.stateWrap}>
          <Alert tone="error" title="History unavailable">
            <p>{error}</p>
            <div className={styles.stateActions}>
              <Button variant="secondary" onClick={reload}>
                Try Again
              </Button>
            </div>
          </Alert>
        </div>
      ) : items.length === 0 ? (
        <Card className={styles.emptyCard}>
          <span className={styles.emptyIcon} aria-hidden="true">
            ▤
          </span>
          <h2 className={styles.emptyTitle}>No scans yet</h2>
          <p className={styles.emptyText}>
            Completed scans will appear here with their trust score, verdict and
            findings. Run your first analysis to build up a history.
          </p>
          <Link to="/scan" className={styles.emptyAction}>
            <Button size="lg">Start a Scan</Button>
          </Link>
        </Card>
      ) : (
        <HistoryTable history={items} />
      )}
    </div>
  );
}