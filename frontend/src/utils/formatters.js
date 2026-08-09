export const SEVERITY_TONES = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'warning',
  info: 'info',
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const MODULE_STATUS_TONES = {
  ok: 'success',
  warning: 'warning',
  critical: 'danger',
  error: 'danger',
};

export const VERDICT_TONES = {
  Trusted: 'success',
  'Low Risk': 'success',
  'Moderate Risk': 'warning',
  Suspicious: 'warning',
  'High Risk': 'danger',
  Critical: 'danger',
};

// Central display-naming for threat-intelligence provider slugs. The
// backend contract intentionally uses stable slugs (e.g.
// "google-safe-browsing"); end users must never see them.
export const PROVIDER_DISPLAY_NAMES = {
  'google-safe-browsing': 'Google Safe Browsing',
  'virus_total': 'VirusTotal',
};

export function providerDisplayName(slug) {
  if (!slug) return 'Unknown provider';
  if (PROVIDER_DISPLAY_NAMES[slug]) return PROVIDER_DISPLAY_NAMES[slug];
  // Safe fallback for a future provider: title-case the slug ("provider-b"
  // -> "Provider B").
  return slug
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

// Derived provider status: visual + textual state from the normalized
// ThreatIntelSignals fields the backend already provides.
export function providerStatus(signal) {
  if (!signal || signal.status !== 'available') {
    return { label: 'Unavailable', tone: 'neutral', icon: '✕' };
  }
  if (signal.malicious) return { label: 'Threat', tone: 'danger', icon: '⚠' };
  if (signal.suspicious) return { label: 'Suspicious', tone: 'warning', icon: '⚠' };
  return { label: 'Clean', tone: 'success', icon: '✓' };
}

export function severityTone(severity) {
  return SEVERITY_TONES[severity] ?? 'neutral';
}

export function moduleStatusTone(status) {
  return MODULE_STATUS_TONES[status] ?? 'neutral';
}

export function verdictTone(verdict) {
  return VERDICT_TONES[verdict] ?? 'neutral';
}

export function formatTimestamp(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  });
}

export function scoreColor(score) {
  if (score >= 90) return '#34d399';
  if (score >= 75) return '#4ade80';
  if (score >= 60) return '#fbbf24';
  if (score >= 45) return '#fb923c';
  return '#f87171';
}

export function moduleTitle(moduleName) {
  const titles = {
    url_analysis: 'URL Analysis',
    reputation: 'Reputation',
    whois: 'WHOIS',
    dns: 'DNS',
    ssl: 'SSL/TLS',
    headers: 'Security Headers',
    typosquatting: 'Typosquatting',
    brand_detection: 'Brand Detection',
    threatintel: 'Threat Intel',
    blacklist: 'Blacklist',
    phishing: 'Phishing',
    ports: 'Ports',
  };
  return titles[moduleName] ?? moduleName.replace(/_/g, ' ');
}

export function normalizeTarget(raw) {
  const value = raw.trim().replace(/^[hH][tT][tT][pP][sS]?:\/\//, '').replace(/\/+$/, '');
  return value || null;
}

const HOST_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const TLD_RE = /\.([a-zA-Z]{2,})$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function validateTarget(raw) {
  const value = raw.trim();
  if (!value) return 'Enter a domain or URL to scan.';
  if (/\s/.test(value)) return 'Remove spaces from the target.';
  if (/[<>[\]{}|\\^`"@]/.test(value)) return 'The target contains invalid characters.';
  const rest = value.replace(/^https?:\/\//i, '');
  const host = rest.split(/[/?#]/)[0];
  const validHost = HOST_RE.test(host) && TLD_RE.test(host) && !host.includes('..');
  if (!validHost && !IPV4_RE.test(host)) {
    return 'Enter a valid domain (example.com) or URL (https://example.com).';
  }
  return null;
}

export function healthLabel(score) {
  if (score >= 90) return 'Healthy';
  if (score >= 70) return 'Attention';
  return 'Critical';
}

export function healthTone(score) {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'danger';
}

export function severityLabel(severity) {
  const labels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Informational',
  };
  return labels[severity] ?? severity;
}

function summarizeDetails(moduleKey, details) {
  if (!details || typeof details !== 'object') return null;

  switch (moduleKey) {
    case 'url_analysis':
      if (details.is_valid === undefined) return null;
      return `${details.is_valid ? 'Valid' : 'Invalid'} ${details.uses_https ? 'HTTPS' : 'HTTP'} URL${
        details.is_ip_address ? ' (IP literal)' : ''
      }${typeof details.url_length === 'number' ? `, ${details.url_length} chars` : ''}`;
    case 'reputation': {
      if (details.domain_age === undefined && details.blacklist === undefined) return null;
      const blacklistObj = typeof details.blacklist === 'object' && details.blacklist !== null ? details.blacklist : null;
      const isFlagged = blacklistObj ? blacklistObj.is_blacklisted : details.blacklist;
      return [
        typeof details.domain_age === 'object' && details.domain_age !== null && details.domain_age.age_years
          ? `Domain age ${details.domain_age.age_years} years`
          : typeof details.domain_age === 'number'
            ? `Domain age ${details.domain_age}`
            : null,
        isFlagged ? 'flagged on blacklists' : blacklistObj ? 'not on blacklists' : null,
      ]
        .filter(Boolean)
        .join(', ');
    }
    case 'whois':
      if (details.error) return String(details.error);
      return null;
    case 'dns': {
      if (details.resolves === undefined && details.mx_count === undefined) return null;
      const dnsParts = [
        details.ip_address ? `Resolves to ${details.ip_address}` : details.resolves === false ? 'Does not resolve' : null,
        typeof details.mx_count === 'number' ? `${details.mx_count} MX` : null,
        typeof details.ns_count === 'number' ? `${details.ns_count} NS` : null,
        typeof details.dnssec === 'boolean' ? `DNSSEC ${details.dnssec ? 'on' : 'off'}` : null,
      ].filter(Boolean);
      return dnsParts.length > 0 ? dnsParts.slice(0, 3).join(', ') : null;
    }
    case 'ssl': {
      if (details.certificate_valid === undefined && details.tls_version === undefined) return null;
      const tlsVersion = details.tls_version;
      const tlsLabel = tlsVersion && !String(tlsVersion).toLowerCase().startsWith('tls') ? `TLS ${tlsVersion}` : tlsVersion ?? null;
      const sslParts = [
        tlsLabel,
        details.certificate_valid ? 'Certificate valid' : 'Certificate invalid',
        typeof details.expires_in_days === 'number' && !details.expired
          ? `expires in ${details.expires_in_days}d`
          : null,
        details.expired ? 'expired' : null,
        details.self_signed ? 'self-signed' : null,
      ].filter(Boolean);
      return sslParts.join(', ');
    }
    case 'headers': {
      if (details.grade === undefined && details.summary === undefined) return null;
      const summaryText =
        typeof details.summary === 'object' && details.summary !== null
          ? `${details.summary.missing_headers ?? 0} missing of ${(details.summary.missing_headers ?? 0) + (details.summary.present_headers ?? 0)} headers`
          : details.summary;
      return `Grade ${details.grade ?? '—'}${summaryText ? `, ${summaryText}` : ''}`;
    }
    case 'typosquatting':
      if (details.matches === undefined && details.total_brands_compared === undefined) return null;
      return typeof details.matches === 'number' && details.matches > 0
        ? `${details.matches} brand match${details.matches === 1 ? '' : 'es'}`
        : `No brand matches (${details.total_brands_compared} compared)`;
    case 'brand_detection':
      if (details.suspicious_terms === undefined && details.similarity_match === undefined) return null;
      return Array.isArray(details.suspicious_terms) && details.suspicious_terms.length > 0
        ? `${details.suspicious_terms.length} suspicious signal${details.suspicious_terms.length === 1 ? '' : 's'}`
        : details.similarity_match
          ? 'Similar to a known brand'
          : 'No impersonation signals';
    case 'threatintel': {
      // Prefer the provider correlation summary when present; fall back to
      // the local-heuristic view for legacy/historical records.
      const correlation = details.threat_intel_correlation;
      if (correlation && typeof correlation === 'object') {
        const available = correlation.available_count ?? 0;
        const flagged = (correlation.malicious_count ?? 0) + (correlation.suspicious_count ?? 0);
        if (available > 0) {
          if (correlation.conflict) {
            return `${flagged} of ${available} flagged, conflicting results`;
          }
          return flagged > 0
            ? `${flagged} of ${available} provider(s) flagged a threat`
            : `${available} provider(s) reported none flagged`;
        }
      }
      if (details.phishing_analysis === undefined && details.threat_feed_status === undefined) return null;
      const phishing =
        typeof details.phishing_analysis === 'object' && details.phishing_analysis !== null
          ? details.phishing_analysis.phishing_risk ?? details.phishing_analysis.risk ?? '—'
          : details.phishing_analysis ?? '—';
      const feed =
        typeof details.threat_feed_status === 'object' && details.threat_feed_status !== null
          ? String(details.threat_feed_status.threat_feed_status ?? details.threat_feed_status.status ?? '—')
          : details.threat_feed_status ?? '—';
      const malware =
        typeof details.malware_analysis === 'object' && details.malware_analysis !== null
          ? details.malware_analysis.malware_risk ?? null
          : null;
      return `Phishing: ${phishing}${malware ? `, malware: ${malware}` : ''}, feed: ${feed}`;
    }
    case 'blacklist':
      if (details.is_blacklisted === undefined && details.total_lists_checked === undefined) return null;
      return details.is_blacklisted
        ? `Blacklisted on ${details.total_lists_checked ?? '?'} list${details.total_lists_checked === 1 ? '' : 's'}`
        : `Clean on ${details.total_lists_checked ?? 0} lists`;
    case 'phishing':
      if (details.is_phishing_suspect === undefined) return null;
      return details.is_phishing_suspect ? 'Suspected phishing' : 'No phishing indicators';
    default:
      return null;
  }
}

export function moduleSummary(moduleKey, details, findings) {
  const derived = summarizeDetails(moduleKey, details);
  if (derived) return derived;
  if (!Array.isArray(findings) || findings.length === 0) return null;
  return `${findings.length} finding${findings.length === 1 ? '' : 's'} in this module`;
}