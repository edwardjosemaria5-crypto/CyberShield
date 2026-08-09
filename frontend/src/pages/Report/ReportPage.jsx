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
import WhyRiskPanel from '../../components/report/WhyRiskPanel/WhyRiskPanel';
import AiExplanationCard from '../../components/report/AiExplanationCard/AiExplanationCard';
import ThreatIntelCard from '../../components/threatintel/ThreatIntelCard/ThreatIntelCard';
import ExportToolbar from './ExportToolbar';
import useScanReport from '../../hooks/useScanReport';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './ReportPage.module.css';

export default function ReportPage({ scanId }) {
  const { status, scan, error, retry, SUCCESS, NOT_FOUND, ERROR } = useScanReport(scanId);
  usePageTitle(scan?.target ? `Report — ${scan.target}` : 'Report');

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
              <Button variant="secondary" to="/history">Back to History</Button>
              <Button to="/scan">New Scan</Button>
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
              <Button variant="secondary" to="/history">Back to History</Button>
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
  } = scan;

  const threatIntelModule = (modules ?? []).find((mod) => mod.module === 'threatintel');

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <Link to="/history" className={styles.back}>
          ← Back to history
        </Link>
        <Button variant="secondary" to="/scan">New Scan</Button>
      </div>

      <header className={styles.reportHead}>
        <p className={styles.overline}>Security Scan Report</p>
        <h1 className={styles.heading}>{scan.target}</h1>
        <p className={styles.reportId}>
          Scan ID <code>{scan.scan_id}</code> · {scan.verdict}
        </p>
      </header>

      <ScanSummary result={scan} />

      <ExportToolbar scanId={scan.scan_id} />

      {/* A. Target + status = header above.
          B. Trust score: first major visual element. */}
      <div className={styles.overview}>
        <Card className={styles.scoreCard} title="Trust Score" subtitle="Overall risk assessment">
          <TrustScore score={trustScore} confidence={confidence} verdict={verdict} />
        </Card>
        <RiskSummary
          verdict={verdict}
          summary={summary}
          modules={modules}
          findings={scan.findings}
        />
      </div>

      {/* C. Why this risk */}
      <OverallAssessment result={scan} />
      <WhyRiskPanel target={scan.target} verdict={verdict} trustScore={trustScore} modules={modules} />

      {/* C.5 Optional AI explanation (sidecar only; absent when AI is off) */}
      <AiExplanationCard explanation={scan.ai_explanation ?? null} />

      {/* D. Threat intelligence */}
      {threatIntelModule && (
        <Card
          title="Threat Intelligence"
          subtitle="Aggregate assessment and per-provider evidence"
        >
          <ThreatIntelCard module={threatIntelModule} />
        </Card>
      )}

      {/* E. Security modules */}
      <Card title="Security Modules" subtitle="Per-module posture scores from the pipeline">
        <ModuleGrid modules={modules} renderers={{ threatintel: ThreatIntelCard }} />
      </Card>

      {/* F. Findings + G. Recommendations */}
      <div className={styles.twoCol}>
        <Card title="Findings" subtitle={`${(scan.findings ?? []).length} total`}>
          <FindingsList findings={scan.findings} />
        </Card>
        <Card title="Recommendations" subtitle="Priority actions from the analysis">
          <RecommendationPanel findings={scan.findings} />
        </Card>
      </div>

      {/* H. Timeline */}
      <Card title="Execution Timeline" subtitle="Module execution order">
        <ScanTimeline modules={modules} />
      </Card>
    </div>
  );
}