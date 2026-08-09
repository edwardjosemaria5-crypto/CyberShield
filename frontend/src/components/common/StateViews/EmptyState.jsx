import styles from './StateViews.module.css';

export default function EmptyState({ title, message, action, icon = '▤' }) {
  return (
    <div className={styles.center}>
      <span className={styles.emptyIcon} aria-hidden="true">
        {icon}
      </span>
      <h2 className={styles.title}>{title}</h2>
      {message && <p className={styles.text}>{message}</p>}
      {action}
    </div>
  );
}