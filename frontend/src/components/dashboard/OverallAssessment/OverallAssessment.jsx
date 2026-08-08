import { buildOverallAssessment } from '../../../utils/assessment';
import styles from './OverallAssessment.module.css';

export default function OverallAssessment({ result }) {
  const paragraphs = buildOverallAssessment(result);
  if (!paragraphs || paragraphs.length === 0) return null;

  return (
    <section className={styles.assessment}>
      <div className={styles.ico} aria-hidden="true">
        ◉
      </div>
      <div className={styles.content}>
        <h2 className={styles.heading}>Overall Assessment</h2>
        {paragraphs.map((paragraph, index) => (
          <p key={index} className={index === 0 ? styles.lead : styles.text}>
            {paragraph}
          </p>
        ))}
      </div>
    </section>
  );
}