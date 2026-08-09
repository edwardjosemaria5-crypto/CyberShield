import { useId, useState } from 'react';
import Badge from '../../common/Badge/Badge';
import { severityTone, severityLabel } from '../../../utils/formatters';
import FindingDetail from '../../common/FindingDetail/FindingDetail';
import styles from './FindingCard.module.css';

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const hasDetails = finding.description || finding.explanation || finding.evidence || finding.recommendation;

  return (
    <article className={styles.card}>
      <button
        type="button"
        className={styles.head}
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        disabled={!hasDetails}
      >
        <span className={styles.titleRow}>
          <Badge tone={severityTone(finding.severity)}>{severityLabel(finding.severity)}</Badge>
          <span className={styles.title}>{finding.title}</span>
        </span>
        <span className={styles.tail}>
          {typeof finding.confidence === 'number' && (
            <span className={styles.confidence}>Confidence: {finding.confidence}%</span>
          )}
          {hasDetails && (
            <span className={[styles.chevron, open ? styles.chevronOpen : ''].join(' ')} aria-hidden="true">
              ▾
            </span>
          )}
        </span>
      </button>

      {open && (
        <div id={panelId} className={styles.bodyWrap}>
          <FindingDetail finding={finding} />
        </div>
      )}
    </article>
  );
}