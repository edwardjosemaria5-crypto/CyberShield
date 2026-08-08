import { SEVERITY_ORDER } from '../../../utils/formatters';
import FindingCard from '../FindingCard/FindingCard';
import styles from './FindingsList.module.css';

export default function FindingsList({ findings }) {
  if (!findings || findings.length === 0) return null;

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <ul className={styles.list}>
      {sorted.map((finding, index) => (
        <li key={`${finding.title}-${index}`} className={styles.item}>
          <FindingCard finding={finding} />
        </li>
      ))}
    </ul>
  );
}