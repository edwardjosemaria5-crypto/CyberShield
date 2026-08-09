import Badge from '../../common/Badge/Badge';
import {
  SEVERITY_ORDER,
  moduleSummary,
  moduleTitle,
  severityLabel,
  severityTone,
} from '../../../utils/formatters';
import styles from './WhyRiskPanel.module.css';

const SEVERITY_ICONS = {
  critical: '✕',
  high: '!',
  medium: '▲',
  low: '•',
  info: 'ℹ',
};

/**
 * "Why is this URL risky?" — a deterministic explanation assembled only
 * from the backend's modules/findings. The panel lists the significant
 * contributing modules (critical/high/medium findings, or module score
 * below the warning threshold), worst finding first, using the module
 * summaries the backend already provides. It never invents explanations.
 */
export default function WhyRiskPanel({ target, verdict, trustScore, modules }) {
  const factors = buildFactors(modules);

  return (
    <section className={styles.panel} aria-labelledby="whyrisk-title">
      <h2 id="whyrisk-title" className={styles.heading}>
        Why this URL is risky
      </h2>

      {factors.length === 0 ? (
        <p className={styles.clean}>
          The scan produced no risk-significant findings for this target, so
          no contributing factors are listed.
        </p>
      ) : (
        <>
          <p className={styles.lead}>
            {target ? `The target ${target}` : 'The target'} was rated
            {typeof verdict === 'string' ? (
              <>
                {' '}
                <strong>{verdict}</strong>
              </>
            ) : null}
            {typeof trustScore === 'number' ? ` (trust score ${trustScore}/100)` : ''}.
            Contributing evidence, most severe first:
          </p>
          <ul className={styles.factors}>
            {factors.map((factor) => (
              <li key={factor.key} className={styles.factor}>
                <span className={styles.factorIcon} aria-hidden="true">
                  {SEVERITY_ICONS[factor.severity] ?? '•'}
                </span>
                <span className={styles.factorBody}>
                  <span className={styles.factorTitle}>
                    {factor.moduleName}
                    {typeof factor.score === 'number' && (
                      <span className={styles.factorScore}>{factor.score}/100</span>
                    )}
                  </span>
                  {factor.summary && <span className={styles.factorSummary}>{factor.summary}</span>}
                </span>
                <Badge tone={severityTone(factor.severity)}>{severityLabel(factor.severity)}</Badge>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function buildFactors(moduleList) {
  if (!Array.isArray(moduleList)) return [];
  return moduleList
    .map((mod) => {
      const worst = [...(mod.findings ?? [])].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
      )[0];
      const severity = worst?.severity ?? 'info';
      const summary =
        moduleSummary(mod.module, mod.details ?? {}, mod.findings ?? []) ??
        worst?.title ??
        null;
      return { key: mod.module, moduleName: moduleTitle(mod.module), severity, summary, score: mod.score };
    })
    .filter((item) => {
      const rank = SEVERITY_ORDER.indexOf(item.severity);
      const significant = (rank >= 0 && rank <= SEVERITY_ORDER.indexOf('medium')) || item.score < 70;
      return significant;
    })
    .sort((a, b) => {
      const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      if (bySeverity !== 0) return bySeverity;
      return (a.score ?? 100) - (b.score ?? 100);
    })
    .slice(0, 6);
}