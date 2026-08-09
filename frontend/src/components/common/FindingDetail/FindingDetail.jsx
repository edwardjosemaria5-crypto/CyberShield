import styles from './FindingDetail.module.css';

function Section({ title, children }) {
  if (!children) return null;
  return (
    <div className={styles.section}>
      <h5 className={styles.sectionTitle}>{title}</h5>
      <div className={styles.sectionBody}>{children}</div>
    </div>
  );
}

/**
 * Shared expandable body for a single Finding: renders only the fields the
 * record actually carries (description, explanation, evidence,
 * recommendation). Used by FindingCard and ModuleCard details panels.
 */
export default function FindingDetail({ finding }) {
  return (
    <div className={styles.body}>
      <Section title="What was detected">{finding.description}</Section>
      <Section title="Why this matters">{finding.explanation}</Section>
      <Section title="Evidence">{finding.evidence}</Section>
      <Section title="Recommendation">{finding.recommendation}</Section>
    </div>
  );
}