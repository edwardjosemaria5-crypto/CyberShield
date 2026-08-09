import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../../components/common/Card/Card';
import Alert from '../../components/common/Alert/Alert';
import ScanInput from '../../components/scan/ScanInput/ScanInput';
import ScanProgress from '../../components/scan/ScanProgress/ScanProgress';
import useScanContext from '../../hooks/useScanContext';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './ScanPage.module.css';

export default function ScanPage() {
  const navigate = useNavigate();
  const { loading, error, run } = useScanContext();
  const [activeTarget, setActiveTarget] = useState('');
  usePageTitle('New Scan');

  const handleSubmit = async (target) => {
    setActiveTarget(target);
    const result = await run(target);
    if (result) {
      navigate('/dashboard');
    }
  };

  return (
    <div className={styles.page}>
      <h1 className={styles.heading}>New Scan</h1>
      <p className={styles.sub}>Enter a domain or full URL to run the intelligence pipeline.</p>

      <Card className={styles.card}>
        <ScanInput onSubmit={handleSubmit} loading={loading} large />
        {error && (
          <Alert tone="error" title="Scan failed" className={styles.alert}>
            {error}
          </Alert>
        )}
        {loading && (
          <div className={styles.progressWrap}>
            <ScanProgress target={activeTarget} failed={false} />
          </div>
        )}
      </Card>
    </div>
  );
}