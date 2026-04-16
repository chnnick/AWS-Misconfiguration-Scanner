export type RiskLabel = 'High' | 'Medium' | 'Low' | 'Minimal';

export function getRiskLabel(score: number): RiskLabel {
  if (score >= 4.0) return 'High';
  if (score >= 3.0) return 'Medium';
  if (score >= 2.0) return 'Low';
  return 'Minimal';
}

export function getRiskTextClass(score: number): string {
  const label = getRiskLabel(score);
  switch (label) {
    case 'High':
      return 'text-red-400';
    case 'Medium':
      return 'text-orange-400';
    case 'Low':
      return 'text-yellow-400';
    case 'Minimal':
      return 'text-green-400';
  }
}

export function getRiskTailwindClasses(label: RiskLabel): string {
  switch (label) {
    case 'High':
      return 'bg-red-700 text-white border-red-500';
    case 'Medium':
      return 'bg-orange-600 text-white border-orange-400';
    case 'Low':
      return 'bg-yellow-500 text-black border-yellow-300';
    case 'Minimal':
      return 'bg-green-700 text-white border-green-500';
  }
}

// CSS class names used in the generated HTML report.
export function getRiskHtmlCssClass(label: RiskLabel): string {
  switch (label) {
    case 'High':
      return 'sev-critical';
    case 'Medium':
      return 'sev-high';
    case 'Low':
      return 'sev-medium';
    case 'Minimal':
      return 'sev-minimal';
  }
}

