import { useEffect, useState } from 'react';
import Card from '../../components/common/Card/Card';
import Badge from '../../components/common/Badge/Badge';
import api from '../../services/api';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './SettingsPage.module.css';

// Verified against the backend module registry (app/modules/registry.py).
const SCANNER_MODULES = [
  { name: 'URL analysis', description: 'Structural analysis of the target URL' },
  { name: 'Reputation', description: 'Domain reputation assessment' },
  { name: 'WHOIS', description: 'Registrar, registration and expiry metadata' },
  { name: 'DNS', description: 'Record resolution and mail/SPF/DMARC posture' },
  { name: 'SSL/TLS', description: 'Certificate validity, chain and cipher configuration' },
  { name: 'HTTP headers', description: 'Security-header posture and grading' },
  { name: 'Typosquatting', description: 'Brand-similarity typosquatting detection' },
  { name: 'Brand detection', description: 'Brand impersonation and keyword combinations' },
  { name: 'Threat intelligence', description: 'Phishing, malware and blacklist indicator lookup' },
  { name: 'Blacklist', description: 'Blacklist membership check' },
  { name: 'Phishing', description: 'Phishing heuristics on the target hostname' },
];

const SECURITY_GUARANTEES = [
  {
    title: 'SSRF / outbound-target validation',
    text: 'Every outbound connection (ports, SSL, threat providers) validates the target against private, loopback, link-local and CGNAT address ranges before any request is made.',
  },
  {
    title: 'Provider failure isolation',
    text: 'A failing threat-intelligence provider degrades to "unavailable" and can never break a scan or turn into malicious evidence.',
  },
  {
    title: 'Unavailable is not a verdict',
    text: 'Absence of provider data never raises the risk score: a quiet provider contributes zero penalty.',
  },
  {
    title: 'Deterministic scoring',
    text: 'The Trust Score, verdict and findings come from the deterministic Risk Engine. AI explanations never influence the score.',
  },
  {
    title: 'Secrets remain server-side',
    text: 'API keys are read from the environment only — never stored, logged, or returned by any endpoint.',
  },
];

function statusBadge(health, error) {
  if (error) {
    return <Badge tone="danger">Backend unreachable</Badge>;
  }
  if (!health) {
    return <Badge tone="neutral">Checking…</Badge>;
  }
  if (health.status === 'Healthy') {
    return <Badge tone="success">Healthy</Badge>;
  }
  return <Badge tone="warning">{health.status ?? 'Unknown'}</Badge>;
}

export default function SettingsPage() {
  usePageTitle('About · CyberShield');
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get('/health');
        if (!cancelled) setHealth(data);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Backend health could not be checked.');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <div>
          <h1 className={styles.heading}>About</h1>
          <p className={styles.sub}>
            CyberShield{health?.version ? ` v${health.version}` : ''} · professional security
            scanner
          </p>
        </div>
        {statusBadge(health, error)}
      </div>

      {error && (
        <Card title="System status" className={styles.card}>
          <p className={styles.copy}>
            The backend could not be reached from this page, so live status is unavailable.
            Scanning will report a similar problem if the backend is offline.
          </p>
        </Card>
      )}

      <Card title="Scanner modules" subtitle="Eleven modules run on every scan" className={styles.card}>
        <ul className={styles.moduleList}>
          {SCANNER_MODULES.map((module) => (
            <li key={module.name} className={styles.moduleItem}>
              <span className={styles.moduleName}>{module.name}</span>
              <span className={styles.moduleDesc}>{module.description}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Trust Score" subtitle="How the 0–100 score is produced" className={styles.card}>
        <p className={styles.copy}>
          Every module returns a deterministic result and confidence, and the Risk Engine
          combines them into a single Trust Score between 0 and 100 with a verdict. The score
          is computed entirely from module results — AI explanations never influence it, and
          provider unavailability never becomes negative evidence.
        </p>
      </Card>

      <Card title="Threat intelligence" subtitle="External providers" className={styles.card}>
        <ul className={styles.statusList}>
          <li className={styles.statusItem}>
            <span>Google Safe Browsing</span>
            {health?.threat_intel?.google_safe_browsing_configured ? (
              <Badge tone="success">Configured</Badge>
            ) : (
              <Badge tone="neutral">Not configured</Badge>
            )}
          </li>
          <li className={styles.statusItem}>
            <span>VirusTotal</span>
            {health?.threat_intel?.virustotal_configured ? (
              <Badge tone="success">Configured</Badge>
            ) : (
              <Badge tone="neutral">Not configured</Badge>
            )}
          </li>
        </ul>
        <p className={styles.copy}>
          "Configured" means credentials are available to the application — not that the
          provider is currently reachable. Unconfigured providers are skipped, and their
          absence never affects the Trust Score.
        </p>
      </Card>

      <Card title="AI explanations" subtitle="Optional, presentation-layer only" className={styles.card}>
        <ul className={styles.statusList}>
          <li className={styles.statusItem}>
            <span>AI</span>
            {health?.ai?.enabled ? <Badge tone="info">Enabled</Badge> : <Badge tone="neutral">Disabled</Badge>}
          </li>
        </ul>
        <p className={styles.copy}>
          AI is optional and never required: when it is disabled, unconfigured or failing,
          the scan still completes with its full deterministic result. AI writes
          explanations only and cannot control the Trust Score.
        </p>
      </Card>

      <Card title="Security guarantees" subtitle="Verified in the current implementation" className={styles.card}>
        <ul className={styles.guaranteeList}>
          {SECURITY_GUARANTEES.map((guarantee) => (
            <li key={guarantee.title} className={styles.guaranteeItem}>
              <span className={styles.guaranteeTitle}>{guarantee.title}</span>
              <span className={styles.guaranteeText}>{guarantee.text}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}