import styles from './Alert.module.css';

const TONES = {
  error: styles.error,
  warning: styles.warning,
  success: styles.success,
  info: styles.info,
};

export default function Alert({ children, tone = 'info', title, className = '' }) {
  return (
    <div role="alert" className={[styles.alert, TONES[tone], className].join(' ')}>
      {title && <strong className={styles.title}>{title}</strong>}
      <div className={styles.body}>{children}</div>
    </div>
  );
}