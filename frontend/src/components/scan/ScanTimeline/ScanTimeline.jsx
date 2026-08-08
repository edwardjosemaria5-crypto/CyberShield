import Badge from '../../common/Badge/Badge';
import { moduleStatusTone, moduleTitle } from '../../../utils/formatters';
import styles from './ScanTimeline.module.css';

export default function ScanTimeline({ modules }) {
  if (!modules || modules.length === 0) return null;

  return (
    <ol className={styles.timeline}>
      {modules.map((mod) => (
        <li key={mod.module} className={styles.item}>
          <span className={styles.dot} aria-hidden="true" />
          <span className={styles.name}>{moduleTitle(mod.module)}</span>
          <Badge tone={moduleStatusTone(mod.status)}>{mod.status}</Badge>
          <span className={styles.score}>{mod.score}</span>
        </li>
      ))}
    </ol>
  );
}