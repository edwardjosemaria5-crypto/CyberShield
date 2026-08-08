import { useState } from 'react';
import Button from '../../common/Button/Button';
import { validateTarget } from '../../../utils/formatters';
import styles from './ScanInput.module.css';

export default function ScanInput({ onSubmit, loading = false, large = false }) {
  const [target, setTarget] = useState('');
  const [validationError, setValidationError] = useState(null);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (loading) return;
    const error = validateTarget(target);
    if (error) {
      setValidationError(error);
      return;
    }
    setValidationError(null);
    onSubmit(target.trim());
  };

  return (
    <form className={styles.form} onSubmit={handleSubmit} noValidate>
      <div className={styles.field}>
        <input
          className={[styles.input, large ? styles.inputLarge : '', validationError ? styles.invalid : ''].join(' ')}
          type="text"
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
            if (validationError) setValidationError(null);
          }}
          placeholder="https://example.com"
          aria-label="Target domain or URL"
          aria-invalid={validationError ? 'true' : 'false'}
          autoComplete="off"
          spellCheck="false"
          disabled={loading}
          autoFocus
        />
        {validationError && (
          <p className={styles.validation} role="alert">
            {validationError}
          </p>
        )}
      </div>
      <Button type="submit" size={large ? 'lg' : 'md'} disabled={loading || !target.trim()}>
        {loading ? 'Scanning…' : 'Scan'}
      </Button>
    </form>
  );
}