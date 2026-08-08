import { Link } from 'react-router-dom';
import Button from '../../components/common/Button/Button';
import Card from '../../components/common/Card/Card';
import Loader from '../../components/common/Loader/Loader';
import ScanSummary from '../../components/scan/ScanSummary/ScanSummary';
import ScanTimeline from '../../components/scan/ScanTimeline/ScanTimeline';
import TrustScore from '../../components/dashboard/TrustScore/TrustScore';
import RiskSummary from '../../components/dashboard/RiskSummary/RiskSummary';
import OverallAssessment from '../../components/dashboard/OverallAssessment/OverallAssessment';
import ModuleGrid from '../../components/dashboard/ModuleGrid/ModuleGrid';
import FindingsList from '../../components/dashboard/FindingsList/FindingsList';
import RecommendationPanel from '../../components/dashboard/RecommendationPanel/RecommendationPanel';
import useScanContext from '../../hooks/useScanContext';
import styles from './DashboardPage.module.css';

export default function DashboardPage() {
  const { result, loading, error } = useScanContext();

  if (loading) {
    return (
      <div className={styles.center}>
        <Loader size="lg" label="Running the intelligence pipeline…" />
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.center}>
        <p className={styles.error}>Scan failed: {error}</p>
        <Link to="/scan">
          <Button variant="secondary">Try Again</Button>
        </Link>
      </div>
    );
  }

  if (!result) {
    return (
      <div className={styles.center}>
        <p className={styles.empty}>No scan results yet.</p>
        <Link to="/scan">
          <Button size="lg">Start a Scan</Button>
        </Link>
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
  } = result;

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <div>
          <h1 className={styles.heading}>Scan Dashboard</h1>
          <p className={styles.target}>{result.target}</p>
        </div>
        <div className={styles.actions}>
          <Link to={`/report/${result.scan_id}`}>
            <Button>View Full Report</Button>
          </Link>
          <Link to="/scan">
            <Button variant="secondary">New Scan</Button>
          </Link>
        </div>
      </div>

      <ScanSummary result={result} className={styles.summary} />

      <OverallAssessment result={result} />

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

      <Card title="Module Analysis" subtitle="Per-module posture scores from the pipeline">
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

      <Card title="Timeline" subtitle="Execution order of the intelligence modules">
        <ScanTimeline modules={modules} />
      </Card>
    </div>
  );
}