import styles from './Card.module.css';

export default function Card({ title, subtitle, children, className = '', ...rest }) {
  return (
    <section className={[styles.card, className].join(' ')} {...rest}>
      {(title || subtitle) && (
        <header className={styles.header}>
          {title && <h3 className={styles.title}>{title}</h3>}
          {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
        </header>
      )}
      <div className={styles.body}>{children}</div>
    </section>
  );
}
