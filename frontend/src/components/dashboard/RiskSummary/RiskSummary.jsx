import styles from './RiskSummary.module.css';

const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_META = {
  critical: { icon: '✕', label: 'Critical', cls: 'critical' },
  high: { icon: '!', label: 'High', cls: 'high' },
  medium: { icon: '▲', label: 'Medium', cls: 'medium' },
  low: { icon: '•', label: 'Low', cls: 'low' },
  info: { icon: 'ℹ', label: 'Informational', cls: 'info' },
};

export default function RiskSummary({ verdict, summary, modules, findings }) {
  const counts = {
    critical: summary?.critical ?? 0,
    high: summary?.high ?? 0,
    medium: summary?.medium ?? 0,
    low: summary?.low ?? 0,
    info: summary?.info ?? 0,
  };
  const moduleCount = modules?.length ?? 0;
  const findingCount = findings?.length ?? 0;

  const rows = [
    { key: 'level', label: 'Risk Level', value: verdict ?? '—' },
    { key: 'modules', label: 'Modules Analyzed', value: moduleCount },
    { key: 'findings', label: 'Findings', value: findingCount },
  ];

  return (
    <div className={styles.card}>
      <h2 className={styles.heading}>Signal Summary</h2>

      <dl className={styles.rows} aria-label="Scan signal counts">
        {rows.map((row) => (
          <div key={row.key} className={styles.row}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>

      <ul className={styles.breakdown} aria-label="Findings by severity">
        {SEVERITY_KEYS.map((key) => (
          <li
            key={key}
            aria-label={`${SEVERITY_META[key].label}: ${counts[key]}`}
            className={[styles.severity, styles[SEVERITY_META[key].cls]].join(' ')}
          >
            <span className={styles.severityIcon} aria-hidden="true">
              {SEVERITY_META[key].icon}
            </span>
            <span>{SEVERITY_META[key].label}</span>
            <strong className={styles.severityCount}>{counts[key]}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}