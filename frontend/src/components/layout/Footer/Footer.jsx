import styles from './Footer.module.css';

export default function Footer() {
  return (
    <footer className={styles.footer}>
      <span>CyberShield © 2026</span>
      <span className={styles.muted}>Backend API Frontend Ready v1.0</span>
    </footer>
  );
}