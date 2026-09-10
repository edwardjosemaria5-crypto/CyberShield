import styles from './Loader.module.css';

export default function Loader({ size = 'md', label, className = '' }) {
  return (
    <span
      className={[styles.wrapper, className].join(' ')}
      role={label ? 'status' : undefined}
      aria-live={label ? 'polite' : undefined}
    >
      <span className={[styles.spinner, styles[size]].join(' ')} aria-hidden="true" />
      {label && <span className={styles.label}>{label}</span>}
    </span>
  );
}