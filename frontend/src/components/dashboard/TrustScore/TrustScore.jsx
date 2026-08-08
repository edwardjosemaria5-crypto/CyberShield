import { useId } from 'react';
import styles from './TrustScore.module.css';
import { scoreColor } from '../../../utils/formatters';

const RADIUS = 62;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export default function TrustScore({ score = 0, confidence, verdict }) {
  const clamped = Math.max(0, Math.min(100, score));
  const dashOffset = CIRCUMFERENCE * (1 - clamped / 100);
  const color = scoreColor(clamped);
  const gradientId = useId();

  const ticks = Array.from({ length: 12 }, (_, i) => (i * 100) / 11);

  return (
    <div className={styles.gauge}>
      <svg viewBox="0 0 160 160" className={styles.svg} role="img" aria-label={`Trust score ${clamped} out of 100`}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={color} />
            <stop offset="100%" stopColor={color} stopOpacity="0.65" />
          </linearGradient>
        </defs>
        <circle className={styles.track} cx="80" cy="80" r={RADIUS} />
        {ticks.map((tick) => {
          const angle = (tick / 100) * 360;
          const rad = (angle - 90) * (Math.PI / 180);
          const x1 = 80 + Math.cos(rad) * (RADIUS + 8);
          const y1 = 80 + Math.sin(rad) * (RADIUS + 8);
          const x2 = 80 + Math.cos(rad) * (RADIUS + 12);
          const y2 = 80 + Math.sin(rad) * (RADIUS + 12);
          return (
            <line key={tick} className={styles.tick} x1={x1} y1={y1} x2={x2} y2={y2} />
          );
        })}
        <circle
          className={styles.progress}
          cx="80"
          cy="80"
          r={RADIUS}
          stroke={`url(#${gradientId})`}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={dashOffset}
        />
        <text x="80" y="80" className={styles.value}>
          {clamped}
        </text>
        <text x="80" y="101" className={styles.max}>
          / 100
        </text>
      </svg>

      <p className={styles.label}>Trust Score</p>

      {verdict && (
        <span className={[styles.verdict, styles[scoreColorTone(clamped)]].join(' ')}>{verdict}</span>
      )}

      {typeof confidence === 'number' && (
        <div className={styles.confidenceWrap}>
          <div className={styles.confidenceRow}>
            <span className={styles.confidenceLabel}>Confidence</span>
            <span className={styles.confidenceValue}>{confidence}%</span>
          </div>
          <div className={styles.confidenceTrack} aria-hidden="true">
            <div
              className={styles.confidenceFill}
              style={{ width: `${Math.max(0, Math.min(100, confidence))}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function scoreColorTone(score) {
  if (score >= 75) return 'good';
  if (score >= 60) return 'medium';
  return 'bad';
}