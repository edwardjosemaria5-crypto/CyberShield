import { Link } from 'react-router-dom';
import Card from '../../components/common/Card/Card';
import Button from '../../components/common/Button/Button';
import Loader from '../../components/common/Loader/Loader';
import ScanSummary from '../../components/scan/ScanSummary/ScanSummary';
import ScanTimeline from '../../components/scan/ScanTimeline/ScanTimeline';
import TrustScore from '../../components/dashboard/TrustScore/TrustScore';
import RiskSummary from '../../components/dashboard/RiskSummary/RiskSummary';
import OverallAssessment from '../../components/dashboard/OverallAssessment/OverallAssessment';
import ModuleGrid from '../../components/dashboard/ModuleGrid/ModuleGrid';
import FindingsList from '../../components/dashboard/FindingsList/FindingsList';
import RecommendationPanel from '../../components/dashboard/RecommendationPanel/RecommendationPanel';
import useScanReport from '../../hooks/useScanReport';
import styles from './ReportPage.module.css';

export default function ReportPage({ scanId }) {
  const { status, scan, error, retry, SUCCESS, NOT_FOUND, ERROR } = useScanReport(scanId);

  if (status !== SUCCESS) {
    return (
      <div className={styles.page}>
        {status === NOT_FOUND ? (
          <Card className={styles.notFound}>
            <h1 className={styles.notFoundTitle}>Report not available</h1>
            <p className={styles.notFoundText}>
              No scan with the identifier “{scanId}” could be found. It may have
              been removed, or the identifier may be incorrect.
            </p>
            <div className={styles.notFoundActions}>
              <Link to="/history">
                <Button variant="secondary">Back to History</Button>
              </Link>
              <Link to="/scan">
                <Button>New Scan</Button>
              </Link>
            </div>
          </Card>
        ) : status === ERROR ? (
          <Card className={styles.notFound}>
            <h1 className={styles.notFoundTitle}>Report unavailable</h1>
            <p className={styles.notFoundText}>{error}</p>
            <div className={styles.notFoundActions}>
              <Button variant="secondary" onClick={retry}>
                Try Again
              </Button>
              <Link to="/history">
                <Button variant="secondary">Back to History</Button>
              </Link>
            </div>
          </Card>
        ) : (
          <div className={styles.loading}>
            <Loader label="Loading report…" />
          </div>
        )}
      </div>
    );
  }

  const {
    trust_score: trustScore,
    confidence,
    verdict,
    summary,
    modules,
    findings,
  } = scan;

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <Link to="/history" className={styles.back}>
          ← Back to history
        </Link>
        <Link to="/scan">
          <Button variant="secondary">New Scan</Button>
        </Link>
      </div>

      <header className={styles.reportHead}>
        <p className={styles.overline}>Security Scan Report</p>
        <h1 className={styles.heading}>{scan.target}</h1>
        <p className={styles.reportId}>
          Scan ID <code>{scan.scan_id}</code> · {scan.verdict}
        </p>
      </header>

      <ScanSummary result={scan} />

      <OverallAssessment result={scan} />

      <div className={styles.overview}>
        <Card className={styles.scoreCard}>
          <TrustScore score={trustScore} confidence={confidence} verdict={verdict} />
        </Card>
        <RiskSummary
          verdict={verdict}
          summary={summary}
          modules={modules}
          findings={findings}
        />
      </div>

      <Card title="Module Analysis" subtitle="Per-module posture scores">
        <ModuleGrid modules={modules} />
      </Card>

      <div className={styles.twoCol}>
        <Card title="Findings" subtitle={`${(findings ?? []).length} total`}>
          <FindingsList findings={findings} />
        </Card>
        <Card title="Recommendations" subtitle="Priority actions from the analysis">
          <RecommendationPanel findings={findings} />
        </Card>
      </div>

      <Card title="Execution Timeline" subtitle="Module execution order">
        <ScanTimeline modules={modules} />
      </Card>
    </div>
  );
}