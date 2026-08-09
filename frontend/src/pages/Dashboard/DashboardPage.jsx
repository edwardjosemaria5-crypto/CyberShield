import Button from '../../components/common/Button/Button';
import Card from '../../components/common/Card/Card';
import ScanSummary from '../../components/scan/ScanSummary/ScanSummary';
import ScanTimeline from '../../components/scan/ScanTimeline/ScanTimeline';
import TrustScore from '../../components/dashboard/TrustScore/TrustScore';
import RiskSummary from '../../components/dashboard/RiskSummary/RiskSummary';
import OverallAssessment from '../../components/dashboard/OverallAssessment/OverallAssessment';
import ModuleGrid from '../../components/dashboard/ModuleGrid/ModuleGrid';
import FindingsList from '../../components/dashboard/FindingsList/FindingsList';
import RecommendationPanel from '../../components/dashboard/RecommendationPanel/RecommendationPanel';
import LoadingState from '../../components/common/StateViews/LoadingState';
import ErrorState from '../../components/common/StateViews/ErrorState';
import EmptyState from '../../components/common/StateViews/EmptyState';
import ThreatIntelCard from '../../components/threatintel/ThreatIntelCard/ThreatIntelCard';
import useScanContext from '../../hooks/useScanContext';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './DashboardPage.module.css';

export default function DashboardPage() {
  const { result, loading, error } = useScanContext();
  usePageTitle('Scan Dashboard');

  if (loading) {
    return (
      <div className={styles.stateWrap}>
        <LoadingState label="Running the intelligence pipeline…" />
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.stateWrap}>
        <ErrorState title="Scan failed" message={error} />
        <div className={styles.fallbackLink}>
          <Button variant="secondary" to="/scan">Try Again</Button>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className={styles.stateWrap}>
        <EmptyState
          title="No scan results yet"
          message="Run your first analysis to see the trust score, findings and risk breakdown."
          action={
            <Button size="lg" to="/scan">Start a Scan</Button>
          }
        />
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
          <Button to={`/report/${result.scan_id}`}>View Full Report</Button>
          <Button variant="secondary" to="/scan">New Scan</Button>
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
        <ModuleGrid modules={modules} renderers={{ threatintel: ThreatIntelCard }} />
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