import Card from '../../components/common/Card/Card';
import Badge from '../../components/common/Badge/Badge';
import usePageTitle from '../../hooks/usePageTitle';
import styles from './SettingsPage.module.css';

export default function SettingsPage() {
  usePageTitle('Settings');
  return (
    <div className={styles.page}>
      <h1 className={styles.heading}>Settings</h1>
      <Card className={styles.card}>
        <Badge tone="info">Coming soon</Badge>
        <p className={styles.copy}>
          Scan priorities, module toggles and report preferences will be
          configurable here in a future iteration.
        </p>
      </Card>
    </div>
  );
}