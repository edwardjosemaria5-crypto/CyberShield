import { SEVERITY_ORDER, moduleTitle, severityLabel } from './formatters';

export function buildOverallAssessment(result) {
  if (!result) return null;

  const { domain, target, trust_score, confidence, verdict, modules, findings } = result;
  const name = domain || target || 'the target';
  const moduleList = Array.isArray(modules) ? modules : [];
  const findingList = Array.isArray(findings) ? findings : [];
  const paragraphs = [];

  const totalText =
    findingList.length === 0
      ? `The scan of ${name} ran ${moduleList.length} intelligence modules and detected no security findings.`
      : `The scan of ${name} ran ${moduleList.length} intelligence modules and detected ${findingList.length} finding${findingList.length === 1 ? '' : 's'}.`;
  paragraphs.push(totalText);

  if (findingList.length > 0) {
    const bySeverity = findingList.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {});
    const parts = ['critical', 'high', 'medium', 'low', 'info']
      .filter((key) => bySeverity[key])
      .map((key) => `${bySeverity[key]} ${severityLabel(key).toLowerCase()}`);
    if (parts.length > 0) {
      paragraphs.push(`Severity breakdown: ${parts.join(', ')}.`);
    }

    const sorted = [...findingList].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
    const worst = sorted[0];
    paragraphs.push(
      `The most significant issue is "${worst.title}" (${severityLabel(worst.severity)}).`,
    );
  }

  const weakModules = moduleList
    .filter((mod) => typeof mod.score === 'number' && mod.score < 70)
    .sort((a, b) => a.score - b.score);
  if (weakModules.length > 0) {
    const weakText = weakModules
      .map((mod) => `${moduleTitle(mod.module)} (${mod.score})`)
      .join(', ');
    paragraphs.push(
      `The weakest areas are ${weakText}. These should be reviewed before the domain is considered hardened.`,
    );
  }

  if (typeof trust_score === 'number' && typeof confidence === 'number' && verdict) {
    paragraphs.push(
      `With a trust score of ${trust_score}/100 and ${confidence}% confidence, the overall verdict is ${verdict}.`,
    );
  }

  return paragraphs;
}