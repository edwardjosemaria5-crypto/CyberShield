import { Link } from 'react-router-dom';
import Badge from '../../common/Badge/Badge';
import { verdictTone, formatTimestamp } from '../../../utils/formatters';
import styles from './HistoryTable.module.css';

function severityOf(summary) {
  if (!summary) return 'none';
  if (summary.critical > 0) return 'critical';
  if (summary.high > 0) return 'high';
  if (summary.medium > 0) return 'medium';
  if (summary.low > 0) return 'low';
  return 'clean';
}

export default function HistoryTable({ history }) {
  if (!history || history.length === 0) return null;

  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">Target</th>
            <th scope="col">Score</th>
            <th scope="col">Verdict</th>
            <th scope="col">Confidence</th>
            <th scope="col">Severity</th>
            <th scope="col">Completed</th>
            <th scope="col" aria-label="Open report" />
          </tr>
        </thead>
        <tbody>
          {history.map((scan) => (
            <tr key={scan.scan_id} className={styles.row}>
              <td data-label="Target">
                <Link className={styles.link} to={`/report/${scan.scan_id}`}>
                  {scan.target}
                </Link>
              </td>
              <td data-label="Score" className={styles.scoreCell}>
                {scan.trust_score}
              </td>
              <td data-label="Verdict">
                <Badge tone={verdictTone(scan.verdict)}>{scan.verdict}</Badge>
              </td>
              <td data-label="Confidence">{scan.confidence}%</td>
              <td data-label="Severity">
                <Badge tone={severityBadgeTone(severityOf(scan.summary))}>
                  {severityOf(scan.summary)}
                </Badge>
              </td>
              <td data-label="Completed">{formatTimestamp(scan.completed_at)}</td>
              <td className={styles.openCol}>
                <Link
                  className={styles.openLink}
                  to={`/report/${scan.scan_id}`}
                  aria-label={`Open report for ${scan.target}`}
                >
                  Open ▸
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function severityBadgeTone(level) {
  const tones = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'warning',
    clean: 'success',
    none: 'neutral',
  };
  return tones[level] ?? 'neutral';
}