import { useId, useState } from 'react';
import Badge from '../../common/Badge/Badge';
import FindingDetail from '../../common/FindingDetail/FindingDetail';
import {
  moduleStatusTone,
  moduleTitle,
  scoreColor,
  healthLabel,
  healthTone,
  moduleSummary,
  severityTone,
  severityLabel,
  isInformationalModule,
} from '../../../utils/formatters';
import styles from './ModuleCard.module.css';

function InfrastructureDetails({ module: mod }) {
  const details = mod?.details ?? {};
  const profile = details.infrastructure;
  const rows = [
    ['IP address', profile?.ip_address],
    ['ASN', profile?.asn],
    ['Organization', profile?.asn_organization],
    ['ISP', profile?.isp],
    ['Hosting', profile?.hosting_provider],
    ['Network', profile?.network],
    ['Country', profile?.country],
    ['Source', profile?.source],
  ].filter(([, value]) => typeof value === 'string' && value);

  return (
    <div className={styles.infoDetails}>
      <p className={styles.infoNote}>
        Informational context only. Infrastructure is never scored, contributes no findings, and
        cannot change the Trust Score, confidence, or verdict.
      </p>
      {rows.length > 0 ? (
        <dl className={styles.infoRows}>
          {rows.map(([label, value]) => (
            <div key={label} className={styles.infoRow}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className={styles.noFindings}>No infrastructure data recorded for this scan.</p>
      )}
    </div>
  );
}

export default function ModuleCard({ module: mod, renderer = null }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const informational = isInformationalModule(mod);
  const color = scoreColor(mod.score);
  const findings = mod.findings ?? [];
  const label = healthLabel(mod.score);
  const summary = moduleSummary(mod.module, mod.details, findings) ?? 'No summary available.';
  const DetailsBody = renderer;

  return (
    <article className={styles.card}>
      <header className={styles.header}>
        <h4 className={styles.name}>{moduleTitle(mod.module)}</h4>
        <Badge tone={informational ? 'info' : moduleStatusTone(mod.status)}>
          {informational ? 'Informational' : mod.status}
        </Badge>
      </header>

      {informational ? (
        <p className={styles.infoSummary}>
          Infrastructure context — not a scored security module.
        </p>
      ) : (
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
      )}

      <p className={styles.summary}>{summary}</p>

      {!informational && (
        <div className={styles.meta}>
          {typeof mod.confidence === 'number' && (
            <span className={styles.confidence}>Confidence {mod.confidence}%</span>
          )}
          <span className={styles.findingCount}>
            {findings.length} finding{findings.length === 1 ? '' : 's'}
          </span>
        </div>
      )}

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
          {informational ? (
            <InfrastructureDetails module={mod} />
          ) : DetailsBody ? (
            <DetailsBody module={mod} />
          ) : findings.length === 0 ? (
            <p className={styles.noFindings}>No findings in this module.</p>
          ) : (
            <ul className={styles.moduleFindings}>
              {findings.map((finding, index) => (
                <li
                  key={`${finding.title}-${index}`}
                  className={[styles.moduleFinding, styles.moduleFindingOpen].join(' ')}
                >
                  <span className={styles.moduleFindingHead}>
                    <Badge tone={severityTone(finding.severity)}>{severityLabel(finding.severity)}</Badge>
                    <span className={styles.moduleFindingTitle}>{finding.title}</span>
                  </span>
                  <FindingDetail finding={finding} />
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </article>
  );
}