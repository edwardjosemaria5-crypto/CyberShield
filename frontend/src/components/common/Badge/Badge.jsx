import styles from './Badge.module.css';

const TONES = {
  neutral: styles.neutral,
  success: styles.success,
  warning: styles.warning,
  danger: styles.danger,
  info: styles.info,
};

export default function Badge({ children, tone = 'neutral', className = '' }) {
  return <span className={[styles.badge, TONES[tone], className].join(' ')}>{children}</span>;
}
