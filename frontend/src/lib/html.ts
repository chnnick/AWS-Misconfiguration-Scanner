import type { ScanResult } from '@/types/scan';
import { countFindings, extractFindings } from '@/lib/reportUtils';

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityClass(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'sev-critical';
    case 'HIGH':
      return 'sev-high';
    case 'MEDIUM':
      return 'sev-medium';
    case 'LOW':
      return 'sev-low';
    default:
      return 'sev-unknown';
  }
}

export function exportResultsToHtml(results: ScanResult[]) {
  const sections: string[] = [];

  results.forEach((result, index) => {
    const title = `${index + 1}. ${result.resource.toUpperCase()}`;

    if (result.status === 'error') {
      sections.push(`
<section>
  <h2><span class="err">✗</span> ${escapeHtml(title)}</h2>
  <p class="meta">Status: FAILED</p>
  <div class="error-box">
    <strong>Error:</strong> ${escapeHtml(result.error ?? 'Unknown error')}
  </div>
</section>`);
      return;
    }

    const findings = extractFindings(result.data);
    const findingCount = countFindings(result.data);

    const findingsHtml =
      findings.length > 0
        ? findings
            .map(
              (finding) => `
<div class="finding">
  <div class="finding-header">
    <h3>${escapeHtml(finding.title)}</h3>
    <span class="sev ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
  </div>
  <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
  ${
    finding.remediation
      ? `<p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>`
      : ''
  }
  ${
    finding.resourceType
      ? `<p><strong>Resource type:</strong> ${escapeHtml(finding.resourceType)}</p>`
      : ''
  }
  ${
    finding.cisControl
      ? `<p><strong>CIS Control:</strong> ${escapeHtml(finding.cisControl)}</p>`
      : ''
  }
  ${finding.owasp ? `<p><strong>OWASP:</strong> ${escapeHtml(finding.owasp)}</p>` : ''}
</div>`
            )
            .join('\n')
        : `<p>No findings detected.</p>`;

    sections.push(`
<section>
  <h2><span class="ok">✓</span> ${escapeHtml(title)}</h2>
  <p class="meta">Status: SUCCESS · Findings detected: ${findingCount}</p>
  ${findingsHtml}
</section>`);
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AWS Misconfiguration Scan Report</title>
<style>
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: #18181b;
    color: #e4e4e7;
    margin: 0;
    padding: 1.5rem;
    line-height: 1.5;
  }
  h1 { font-size: 1.5rem; margin: 0 0 1rem; }
  h2 { font-size: 1.125rem; margin: 0 0 0.75rem; }
  h3 { font-size: 1rem; margin: 0; }
  .meta { color: #a1a1aa; font-size: 0.875rem; margin: 0 0 1rem; }
  section {
    border: 1px solid #3f3f46;
    border-radius: 0.5rem;
    padding: 1rem;
    margin-bottom: 1rem;
    background: #27272a;
  }
  .ok { color: #22c55e; }
  .err { color: #ef4444; }
  .error-box {
    background: rgba(127, 29, 29, 0.3);
    padding: 1rem;
    border-radius: 0.375rem;
    color: #fca5a5;
  }
  .finding {
    background: #09090b;
    border: 1px solid #3f3f46;
    border-radius: 0.5rem;
    padding: 1rem;
    margin-top: 0.75rem;
  }
  .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }
  .sev {
    display: inline-block;
    border-radius: 999px;
    padding: 0.25rem 0.625rem;
    font-size: 0.75rem;
    font-weight: 700;
  }
  .sev-critical { background: #b91c1c; color: white; }
  .sev-high { background: #ea580c; color: white; }
  .sev-medium { background: #eab308; color: black; }
  .sev-low { background: #2563eb; color: white; }
  .sev-unknown { background: #52525b; color: white; }
  p { margin: 0.35rem 0; }
</style>
</head>
<body>
  <h1>AWS Misconfiguration Scan Report</h1>
  <p class="meta">
    Generated: ${escapeHtml(new Date().toLocaleString())}<br/>
    Collectors included: ${escapeHtml(results.map((r) => r.resource.toUpperCase()).join(', '))}
  </p>
  ${sections.join('\n')}
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.html`;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}