import ModuleCard from '../ModuleCard/ModuleCard';
import styles from './ModuleGrid.module.css';

export default function ModuleGrid({ modules }) {
  if (!modules || modules.length === 0) return null;

  return (
    <div className={styles.grid}>
      {modules.map((mod) => (
        <ModuleCard key={mod.module} module={mod} />
      ))}
    </div>
  );
}