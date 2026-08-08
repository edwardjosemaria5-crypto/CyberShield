import { useId, useState } from 'react';
import Badge from '../../common/Badge/Badge';
import { severityTone, severityLabel } from '../../../utils/formatters';
import styles from './FindingCard.module.css';

function Section({ title, children }) {
  if (!children) return null;
  return (
    <div className={styles.section}>
      <h5 className={styles.sectionTitle}>{title}</h5>
      <div className={styles.sectionBody}>{children}</div>
    </div>
  );
}

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
        <div id={panelId} className={styles.body}>
          <Section title="What was detected">{finding.description}</Section>
          <Section title="Why this matters">{finding.explanation}</Section>
          <Section title="Evidence">{finding.evidence}</Section>
          <Section title="Recommendation">{finding.recommendation}</Section>
        </div>
      )}
    </article>
  );
}