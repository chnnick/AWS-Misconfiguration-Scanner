import type { ScanResult } from '@/types/scan';
import { countFindings } from '@/lib/reportUtils';

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function exportResultsToHtml(results: ScanResult[]) {
  const sections: string[] = [];

  results.forEach((result, index) => {
    const title = `${index + 1}. ${result.resource.toUpperCase()}`;
    if (result.status === 'error') {
      sections.push(`<section>
<h2><span class="err">✗</span> ${escapeHtml(title)}</h2>
<div class="error-box"><strong>Error:</strong> ${escapeHtml(result.error ?? 'Unknown error')}</div>
</section>`);
      return;
    }

    const findingCount = countFindings(result.data);
    const jsonStr = JSON.stringify(result.data, null, 2);
    sections.push(`<section>
<h2><span class="ok">✓</span> ${escapeHtml(title)}</h2>
<p class="meta">Status: SUCCESS · Findings detected: ${findingCount}</p>
<pre><code>${escapeHtml(jsonStr)}</code></pre>
</section>`);
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AWS Misconfiguration Scan Report</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #18181b; color: #e4e4e7; margin: 0; padding: 1.5rem; line-height: 1.5; }
  h1 { font-size: 1.5rem; margin: 0 0 1rem; }
  .meta { color: #a1a1aa; font-size: 0.875rem; margin: 0 0 1rem; }
  section { border: 1px solid #3f3f46; border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; background: #27272a; }
  h2 { font-size: 1.125rem; margin: 0 0 0.75rem; }
  .ok { color: #22c55e; }
  .err { color: #ef4444; }
  pre { background: #09090b; padding: 1rem; border-radius: 0.375rem; overflow-x: auto; font-size: 0.8125rem; margin: 0; white-space: pre-wrap; word-break: break-word; }
  .error-box { background: rgba(127, 29, 29, 0.3); padding: 1rem; border-radius: 0.375rem; color: #fca5a5; }
</style>
</head>
<body>
<h1>AWS Misconfiguration Scan Report</h1>
<p class="meta">Generated: ${escapeHtml(new Date().toLocaleString())}<br/>
Collectors included: ${escapeHtml(results.map((r) => r.resource.toUpperCase()).join(', '))}</p>
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
