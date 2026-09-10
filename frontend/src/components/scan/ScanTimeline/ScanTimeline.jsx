import Badge from '../../common/Badge/Badge';
import {
  isInformationalModule,
  moduleStatusTone,
  moduleTitle,
} from '../../../utils/formatters';
import styles from './ScanTimeline.module.css';

export default function ScanTimeline({ modules }) {
  if (!modules || modules.length === 0) return null;

  return (
    <ol className={styles.timeline}>
      {modules.map((mod) => {
        const informational = isInformationalModule(mod);
        return (
          <li key={mod.module} className={styles.item}>
            <span className={styles.dot} aria-hidden="true" />
            <span className={styles.name}>{moduleTitle(mod.module)}</span>
            <Badge tone={informational ? 'info' : moduleStatusTone(mod.status)}>
              {informational ? 'Informational' : mod.status}
            </Badge>
            <span className={informational ? styles.context : styles.score}>
              {informational ? 'context' : mod.score}
            </span>
          </li>
        );
      })}
    </ol>
  );
}