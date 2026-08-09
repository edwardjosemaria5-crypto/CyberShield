import Button from '../Button/Button';
import styles from './StateViews.module.css';

export default function ErrorState({ title = 'Something went wrong', message, onRetry, retryLabel = 'Try Again' }) {
  return (
    <div className={styles.center} role="alert">
      <span className={styles.errorIcon} aria-hidden="true">
        !
      </span>
      <h2 className={styles.title}>{title}</h2>
      {message && <p className={styles.text}>{message}</p>}
      {onRetry && (
        <Button variant="secondary" onClick={onRetry}>
          {retryLabel}
        </Button>
      )}
    </div>
  );
}