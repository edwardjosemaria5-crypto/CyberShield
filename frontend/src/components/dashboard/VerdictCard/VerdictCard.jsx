import styles from './VerdictCard.module.css';
import { verdictTone } from '../../../utils/formatters';

export default function VerdictCard({ verdict, summary }) {
  const tone = verdictTone(verdict);
  const counts = summary
    ? {
        critical: summary.critical ?? 0,
        high: summary.high ?? 0,
        medium: summary.medium ?? 0,
      }
    : { critical: 0, high: 0, medium: 0 };

  const totalIssues = counts.critical + counts.high + counts.medium;

  return (
    <div className={[styles.card, styles[tone]].join(' ')}>
      <span className={styles.label}>Verdict</span>
      <strong className={styles.verdict}>{verdict ?? '—'}</strong>
      <span className={styles.issues}>
        {totalIssues > 0
          ? `${totalIssues} issue${totalIssues === 1 ? '' : 's'} to review`
          : 'No significant issues detected'}
      </span>
    </div>
  );
}