import ModuleCard from '../ModuleCard/ModuleCard';
import styles from './ModuleGrid.module.css';

/**
 * Dynamic module grid. ``renderers`` maps a module key to a component that
 * replaces the default findings detail panel (e.g. threatintel →
 * ThreatIntelCard). Unknown modules use the standard card.
 */
export default function ModuleGrid({ modules, renderers = {} }) {
  if (!modules || modules.length === 0) return null;

  return (
    <div className={styles.grid}>
      {modules.map((mod) => (
        <ModuleCard key={mod.module} module={mod} renderer={renderers[mod.module] ?? null} />
      ))}
    </div>
  );
}