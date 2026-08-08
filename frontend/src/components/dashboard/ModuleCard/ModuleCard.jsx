import { useId, useState } from 'react';
import Badge from '../../common/Badge/Badge';
import {
  moduleStatusTone,
  moduleTitle,
  scoreColor,
  healthLabel,
  healthTone,
  moduleSummary,
  severityTone,
  severityLabel,
} from '../../../utils/formatters';
import styles from './ModuleCard.module.css';

export default function ModuleCard({ module: mod }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const color = scoreColor(mod.score);
  const findings = mod.findings ?? [];
  const label = healthLabel(mod.score);
  const summary = moduleSummary(mod.module, mod.details, findings) ?? 'No summary available.';

  return (
    <article className={styles.card}>
      <header className={styles.header}>
        <h4 className={styles.name}>{moduleTitle(mod.module)}</h4>
        <Badge tone={moduleStatusTone(mod.status)}>{mod.status}</Badge>
      </header>

      <div className={styles.healthRow}>
        <span className={[styles.health, styles[healthTone(mod.score)]].join(' ')}>
          <span className={styles.healthIcon} aria-hidden="true">
            {mod.score >= 70 ? '✓' : '⚠'}
          </span>
          {label}
        </span>
        <span className={styles.scoreChip} style={{ color, borderColor: color }}>
          {mod.score}
        </span>
      </div>

      <p className={styles.summary}>{summary}</p>

      <div className={styles.meta}>
        {typeof mod.confidence === 'number' && (
          <span className={styles.confidence}>Confidence {mod.confidence}%</span>
        )}
        <span className={styles.findingCount}>
          {findings.length} finding{findings.length === 1 ? '' : 's'}
        </span>
      </div>

      <button
        type="button"
        className={styles.toggle}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        {open ? 'Hide details' : 'Show details'}
        <span className={[styles.chevron, open ? styles.chevronOpen : ''].join(' ')} aria-hidden="true">
          ▾
        </span>
      </button>

      {open && (
        <div id={panelId} className={styles.details}>
          <ul className={styles.moduleFindings}>
            {findings.length === 0 && <li className={styles.noFindings}>No findings in this module.</li>}
            {findings.map((finding, index) => (
              <li key={`${finding.title}-${index}`} className={styles.moduleFinding}>
                <Badge tone={severityTone(finding.severity)}>{severityLabel(finding.severity)}</Badge>
                <span>{finding.title}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}