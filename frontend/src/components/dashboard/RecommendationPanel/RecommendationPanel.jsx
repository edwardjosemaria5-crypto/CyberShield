import Badge from '../../common/Badge/Badge';
import { SEVERITY_ORDER, severityTone, severityLabel } from '../../../utils/formatters';
import styles from './RecommendationPanel.module.css';

export default function RecommendationPanel({ findings }) {
  if (!findings) return null;

  const recommendations = (findings ?? [])
    .filter((f) => f.recommendation)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .slice(0, 6);

  if (recommendations.length === 0) {
    return <p className={styles.empty}>No recommendations available.</p>;
  }

  return (
    <ol className={styles.list}>
      {recommendations.map((rec, index) => (
        <li key={`${rec.title}-${index}`} className={styles.item}>
          <span className={styles.meta}>
            <Badge tone={severityTone(rec.severity)}>{severityLabel(rec.severity)}</Badge>
            <span className={styles.title}>{rec.title}</span>
          </span>
          <span className={styles.detail}>{rec.recommendation}</span>
        </li>
      ))}
    </ol>
  );
}