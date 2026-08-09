import { useEffect, useState } from 'react';
import styles from './ScanProgress.module.css';

const STEPS = [
  'URL Analysis',
  'Reputation',
  'WHOIS',
  'DNS',
  'SSL/TLS',
  'Security Headers',
  'Typosquatting',
  'Brand Detection',
  'Threat Intelligence',
  'Blacklist',
  'Phishing Detection',
];

const STEP_INTERVAL_MS = 420;

export default function ScanProgress({ target, failed = false }) {
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveIndex((index) => {
        if (index >= STEPS.length - 1) return STEPS.length - 1;
        return index + 1;
      });
    }, STEP_INTERVAL_MS);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className={styles.panel} role="status" aria-live="polite">
      <p className={styles.title}>
        Analyzing <span className={styles.target}>{target}</span>
      </p>
      <ol className={styles.list}>
        {STEPS.map((step, index) => {
          const state =
            failed && index === activeIndex
              ? 'failed'
              : index < activeIndex
                ? 'done'
                : index === activeIndex
                  ? 'running'
                  : 'pending';
          return (
            <li key={step} className={[styles.item, styles[state]].join(' ')}>
              <span className={styles.marker} aria-hidden="true">
                {state === 'done' ? '✓' : state === 'failed' ? '✕' : ''}
              </span>
              <span className={styles.name}>{step}</span>
              {state === 'running' && <span className={styles.pulse} aria-hidden="true" />}
            </li>
          );
        })}
      </ol>
      <p className={styles.note}>
        Sequencing the intelligence pipeline. The backend reports the full result on
        completion; per-stage markers here are interface state, not scan findings.
      </p>
    </div>
  );
}