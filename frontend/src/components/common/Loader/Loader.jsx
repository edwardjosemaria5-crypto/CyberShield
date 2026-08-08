import styles from './Loader.module.css';

export default function Loader({ size = 'md', label, className = '' }) {
  return (
    <span className={[styles.wrapper, className].join(' ')}>
      <span className={[styles.spinner, styles[size]].join(' ')} aria-hidden="true" />
      {label && <span className={styles.label}>{label}</span>}
    </span>
  );
}