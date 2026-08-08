import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../../components/common/Card/Card';
import Alert from '../../components/common/Alert/Alert';
import ScanInput from '../../components/scan/ScanInput/ScanInput';
import ScanProgress from '../../components/scan/ScanProgress/ScanProgress';
import useScanContext from '../../hooks/useScanContext';
import styles from './HomePage.module.css';

const FOCUS = [
  'DNS, SSL/TLS and WHOIS intelligence',
  'Security header and reputation checks',
  'Phishing, typosquatting & brand detection',
  'Explainable findings with clear recommendations',
];

export default function HomePage() {
  const navigate = useNavigate();
  const { loading, error, run } = useScanContext();
  const [activeTarget, setActiveTarget] = useState('');

  const handleSubmit = async (target) => {
    setActiveTarget(target);
    const result = await run(target);
    if (result) {
      navigate('/dashboard');
    }
  };

  return (
    <div className={styles.page}>
      <section className={styles.hero}>
        <Card className={styles.heroCard}>
          <p className={styles.overline}>Website Security Intelligence</p>
          <h1 className={styles.title}>CyberShield</h1>
          <p className={styles.lead}>
            Analyze a domain or URL for security and threat signals.
          </p>
          <div className={styles.scan}>
            <ScanInput onSubmit={handleSubmit} loading={loading} large />
          </div>
          {error && (
            <Alert tone="error" title="Scan could not be completed" className={styles.alert}>
              {error}
            </Alert>
          )}
          {loading && (
            <div className={styles.progressWrap}>
              <ScanProgress target={activeTarget} />
            </div>
          )}
        </Card>
      </section>

      <section className={styles.focus}>
        <ul>
          {FOCUS.map((item) => (
            <li key={item}>
              <span className={styles.check}>✓</span>
              {item}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}