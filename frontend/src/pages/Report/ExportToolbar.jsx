import { useState } from 'react';
import Card from '../../components/common/Card/Card';
import Button from '../../components/common/Button/Button';
import Alert from '../../components/common/Alert/Alert';
import { exportReport } from '../../services/scanService';
import styles from './ReportPage.module.css';

const FORMATS = [
  { format: 'json', label: 'JSON', extension: 'json' },
  { format: 'csv', label: 'CSV', extension: 'csv' },
  { format: 'pdf', label: 'PDF', extension: 'pdf' },
];

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function ExportToolbar({ scanId }) {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(null);

  const handleExport = async (format, extension) => {
    setBusy(format);
    setError(null);
    setDone(null);
    try {
      const response = await exportReport(scanId, format);
      triggerDownload(response.data, `cybershield-${scanId}.${extension}`);
      setDone(format);
    } catch (err) {
      setError(err.message || `The ${format.toUpperCase()} report could not be exported.`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card className={styles.exportToolbar}>
      {error && (
        <Alert tone="error" title="Export failed">
          <p>{error}</p>
        </Alert>
      )}
      <div className={styles.exportButtons}>
        {FORMATS.map(({ format, label, extension }) => (
          <Button
            key={format}
            variant="secondary"
            size="sm"
            disabled={busy !== null}
            onClick={() => handleExport(format, extension)}
          >
            {busy === format ? 'Exporting…' : done === format ? `✓ ${label}` : label}
          </Button>
        ))}
      </div>
    </Card>
  );
}