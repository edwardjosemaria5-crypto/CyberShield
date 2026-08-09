import { Link } from 'react-router-dom';
import styles from './Button.module.css';

const VARIANTS = {
  primary: styles.primary,
  secondary: styles.secondary,
  ghost: styles.ghost,
  danger: styles.danger,
};

const SIZES = {
  sm: styles.sm,
  md: styles.md,
  lg: styles.lg,
};

/**
 * Accessible button or link-button.
 *
 * When `to` is provided the component renders a styled <Link> instead of a
 * <button>, so callers never nest interactive elements (<a><button>) — the
 * original cause of double tab-focus and invalid HTML.
 */
export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  type = 'button',
  disabled = false,
  className = '',
  to,
  ...rest
}) {
  const classes = [styles.base, VARIANTS[variant], SIZES[size], className].join(' ');

  if (to) {
    return (
      <Link to={to} className={classes} {...rest}>
        {children}
      </Link>
    );
  }

  return (
    <button
      type={type}
      disabled={disabled}
      className={classes}
      {...rest}
    >
      {children}
    </button>
  );
}