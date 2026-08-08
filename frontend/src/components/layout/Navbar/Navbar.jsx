import { Link } from 'react-router-dom';
import styles from './Navbar.module.css';

export default function Navbar() {
  return (
    <header className={styles.navbar}>
      <Link to="/" className={styles.brand}>
        <span className={styles.logo} aria-hidden="true">
          &#128737;
        </span>
        <span className={styles.name}>CyberShield</span>
      </Link>
      <span className={styles.tagline}>Threat Intelligence Platform</span>
    </header>
  );
}