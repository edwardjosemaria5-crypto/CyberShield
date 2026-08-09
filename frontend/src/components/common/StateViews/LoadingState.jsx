import Loader from '../Loader/Loader';
import styles from './StateViews.module.css';

export default function LoadingState({ label = 'Loading…', minHeight = 260 }) {
  return (
    <div className={styles.center} style={{ minHeight }}>
      <Loader size="lg" label={label} />
    </div>
  );
}