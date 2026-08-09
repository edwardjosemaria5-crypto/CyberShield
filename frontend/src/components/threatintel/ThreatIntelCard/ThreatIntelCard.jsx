import { useId } from 'react';
import Badge from '../../common/Badge/Badge';
import { providerDisplayName, providerStatus } from '../../../utils/formatters';
import styles from './ThreatIntelCard.module.css';

const AGREEMENT_LABELS = {
  consistent: 'Providers agree',
  partial: 'Partial agreement',
  conflict: 'Conflicting verdicts',
  none: 'No provider data',
};

const AGREEMENT_TONES = {
  consistent: 'success',
  partial: 'warning',
  conflict: 'danger',
  none: 'neutral',
};

function confidencePhrase(confidence) {
  if (typeof confidence !== 'number' || confidence <= 0) return 'no reported confidence';
  if (confidence >= 80) return `high confidence (${confidence}/100)`;
  if (confidence >= 40) return `medium confidence (${confidence}/100)`;
  return `low confidence (${confidence}/100)`;
}

function aggregateSentence(correlation, countAvailable, flagged) {
  if (correlation && typeof correlation === 'object') {
    const available = correlation.available_count ?? countAvailable;
    if (available === 0) {
      return 'No provider produced a verdict, and an unavailable provider is never treated as a threat.';
    }
    if (correlation.conflict) {
      return `${correlation.malicious_count ?? 0} of ${available} available provider(s) reported the target as malicious while ${correlation.clean_count ?? 0} reported no threat — conflicting evidence.`;
    }
    if (flagged > 0) {
      return `${flagged} of ${available} available provider(s) reported harmful activity.`;
    }
    return `${available} available provider(s) returned no threat match for this target.`;
  }
  if (countAvailable === 0) {
    return 'No external provider evidence was recorded for this scan.';
  }
  return flagged > 0
    ? `${flagged} of ${countAvailable} provider(s) reported harmful activity.`
    : `${countAvailable} provider(s) returned no threat match for this target.`;
}

/**
 * Threat-intelligence presentation for the report and module views.
 *
 * Pass: Aggregate Assessment -> agreement -> provider evidence. Everything
 * is derived from the existing backend payload:
 * - mod.details.threat_intel_correlation (counts, agreement, confidence)
 * - mod.details.external_threat_intel (one normalized signal per provider)
 *
 * Provider slugs are replaced by frontend display names; an unavailable
 * provider is shown as Unavailable, never as Clean.
 */
export default function ThreatIntelCard({ module: mod }) {
  const titleId = useId();
  const correlation = mod?.details?.threat_intel_correlation;
  const signals = Array.isArray(mod?.details?.external_threat_intel)
    ? mod.details.external_threat_intel
    : [];

  const isCorrelation = correlation && typeof correlation === 'object';
  const agreement = isCorrelation ? correlation.agreement : null;
  const conflict = isCorrelation && correlation.conflict === true;
  const consensus = isCorrelation ? correlation.consensus : null;
  const available = isCorrelation ? (correlation.available_count ?? 0) : signals.length;
  const flagged = isCorrelation
    ? (correlation.malicious_count ?? 0) + (correlation.suspicious_count ?? 0)
    : signals.filter((s) => s.malicious || s.suspicious).length;

  const verdictConfidence =
    consensus === 'malicious' || consensus === 'conflict'
      ? correlation?.malicious_confidence
      : consensus === 'suspicious'
        ? correlation?.suspicious_confidence
        : null;

  return (
    <section className={styles.card} aria-labelledby={titleId}>
      {conflict && (
        <div className={[styles.banner, styles.bannerConflict].join(' ')} role="note">
          <strong>Conflicting verdicts.</strong> Providers disagree about this
          target; the disagreement is preserved instead of averaged away.
        </div>
      )}

      <div className={styles.aggregate}>
        <div className={styles.aggregateHead}>
          <h5 id={titleId} className={styles.aggregateTitle}>
            Aggregate Threat Intelligence
          </h5>
          {agreement ? (
            <Badge tone={AGREEMENT_TONES[agreement] ?? 'neutral'}>
              {AGREEMENT_LABELS[agreement] ?? agreement}
            </Badge>
          ) : null}
        </div>
        <p className={styles.aggregateText}>{aggregateSentence(correlation, available, flagged)}</p>

        <ul className={styles.metrics}>
          <li className={styles.metric}>
            <span className={styles.metricLabel}>Providers reporting</span>
            <span className={styles.metricValue}>{available}</span>
          </li>
          <li className={styles.metric}>
            <span className={styles.metricLabel}>Flagged by</span>
            <span className={styles.metricValue}>{flagged}</span>
          </li>
          {typeof verdictConfidence === 'number' && (
            <li className={styles.metric}>
              <span className={styles.metricLabel}>Verdict confidence</span>
              <span className={styles.metricValue}>{confidencePhrase(verdictConfidence)}</span>
            </li>
          )}
        </ul>
      </div>

      <div className={styles.providers}>
        <h6 className={styles.providersTitle}>Provider Evidence</h6>
        {signals.length === 0 ? (
          <p className={styles.noProviders}>
            No external provider evidence in this record.
          </p>
        ) : (
          <ul className={styles.providerList}>
            {signals.map((signal, index) => (
              <ProviderRow key={`${signal.provider}-${index}`} signal={signal} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function ProviderRow({ signal }) {
  const status = providerStatus(signal);
  const categories = Array.isArray(signal.categories) ? signal.categories : [];
  const unavailable = status.label === 'Unavailable';

  return (
    <li className={styles.provider}>
      <div className={styles.providerHead}>
        <span className={styles.providerName}>{providerDisplayName(signal.provider)}</span>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>

      <p className={styles.providerMeta}>
        {unavailable
          ? signal.reason
            ? `Unavailable: ${String(signal.reason).replace(/_/g, ' ')}`
            : 'Unavailable — no verdict produced'
          : [
              confidencePhrase(signal.confidence),
              categories.length > 0 ? categories.join(', ') : null,
            ]
              .filter(Boolean)
              .join(' · ')}
      </p>

      {Array.isArray(signal.evidence) && signal.evidence.length > 0 && (
        <ul className={styles.evidence}>
          {signal.evidence.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      )}

      {!unavailable && (
        <p className={styles.providerNote}>
          {signal.malicious || signal.suspicious
            ? 'This provider flagged the target; the evidence above was factored into the correlation.'
            : 'This provider returned no match. That alone does not prove the domain is globally safe.'}
        </p>
      )}
    </li>
  );
}