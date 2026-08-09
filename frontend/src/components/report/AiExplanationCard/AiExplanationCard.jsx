import styles from './AiExplanationCard.module.css';

/**
 * Best-effort AI security explanation for a completed report.
 *
 * Rendered ONLY when the backend attached an `ai_explanation` payload. The
 * backend schema forbids the AI from emitting a trust score or verdict, so
 * this card displays only prose fields; the deterministic numbers live in
 * the Trust Score / Risk cards. Absence of this card is not an error — AI
 * is optional, never scan-critical.
 */
export default function AiExplanationCard({ explanation }) {
  if (!explanation) return null;

  const factors = Array.isArray(explanation.key_risk_factors)
    ? explanation.key_risk_factors
    : [];
  const actions = Array.isArray(explanation.recommended_actions)
    ? explanation.recommended_actions
    : [];

  return (
    <section className={styles.card} aria-labelledby="aiexpl-title">
      <header className={styles.header}>
        <h2 id="aiexpl-title" className={styles.heading}>
          AI Security Explanation
        </h2>
        <span className={styles.badge}>AI-generated</span>
      </header>

      <p className={styles.lead}>{explanation.summary}</p>

      {explanation.why_risky && (
        <div className={styles.block}>
          <h3 className={styles.blockTitle}>Why this assessment</h3>
          <p className={styles.bodyText}>{explanation.why_risky}</p>
        </div>
      )}

      {factors.length > 0 && (
        <div className={styles.block}>
          <h3 className={styles.blockTitle}>Key risk factors</h3>
          <ul className={styles.list}>
            {factors.map((factor, index) => (
              <li key={`${index}-${factor}`} className={styles.listItem}>
                {factor}
              </li>
            ))}
          </ul>
        </div>
      )}

      {explanation.technical_explanation && (
        <div className={styles.block}>
          <h3 className={styles.blockTitle}>Technical explanation</h3>
          <p className={styles.blockText}>{explanation.technical_explanation}</p>
        </div>
      )}

      {actions.length > 0 && (
        <div className={styles.block}>
          <h3 className={styles.blockTitle}>Recommended actions</h3>
          <ol className={styles.list}>
            {actions.map((action, index) => (
              <li key={`${index}-${action}`} className={styles.listItem}>
                {action}
              </li>
            ))}
          </ol>
        </div>
      )}

      <footer className={styles.footer}>
        AI-generated text for informational purposes only and based solely on
        this report&apos;s evidence; it does not change the assessment.
      </footer>
    </section>
  );
}