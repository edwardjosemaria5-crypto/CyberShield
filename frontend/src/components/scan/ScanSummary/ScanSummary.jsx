import Badge from '../../common/Badge/Badge';
import { formatTimestamp, VERDICT_TONES } from '../../../utils/formatters';
import styles from './ScanSummary.module.css';

export default function ScanSummary({ result, className = '' }) {
  if (!result) return null;

  return (
    <section className={[styles.summary, className].join(' ')}>
      <div className={styles.block}>
        <span className={styles.label}>Target</span>
        <span className={styles.value}>{result.target}</span>
      </div>
      <div className={styles.block}>
        <span className={styles.label}>Domain</span>
        <span className={styles.value}>{result.domain}</span>
      </div>
      <div className={styles.block}>
        <span className={styles.label}>Scan ID</span>
        <Badge tone="info">{result.scan_id}</Badge>
      </div>
      <div className={styles.block}>
        <span className={styles.label}>Verdict</span>
        <Badge tone={VERDICT_TONES[result.verdict] ?? 'neutral'}>{result.verdict}</Badge>
      </div>
      <div className={styles.block}>
        <span className={styles.label}>Completed</span>
        <span className={styles.value}>{formatTimestamp(result.completed_at)}</span>
      </div>
    </section>
  );
}