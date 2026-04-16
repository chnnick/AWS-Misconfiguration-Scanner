import jsPDF from 'jspdf';
import type { ScanResult } from '@/types/scan';
import { countFindings, extractFindings } from '@/lib/reportUtils';
import { getRiskLabel } from '@/lib/risk';

export function exportResultsToPdf(results: ScanResult[], riskScores: Record<string, number> = {}) {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 14;
  const maxLineWidth = pageWidth - margin * 2;
  const lineHeight = 6;
  let y = 20;

  const ensureSpace = (needed = 10) => {
    if (y + needed > 280) {
      doc.addPage();
      y = 20;
    }
  };

  const writeWrapped = (text: string, gapAfter = 0) => {
    const lines = doc.splitTextToSize(text, maxLineWidth);
    lines.forEach((line: string) => {
      ensureSpace();
      doc.text(line, margin, y);
      y += lineHeight;
    });
    y += gapAfter;
  };

  doc.setFontSize(18);
  doc.text('AWS Misconfiguration Scan Report', margin, y);
  y += 10;

  doc.setFontSize(11);
  writeWrapped(`Generated: ${new Date().toLocaleString()}`);
  writeWrapped(`Collectors included: ${results.map((r) => r.resource.toUpperCase()).join(', ')}`, 4);

  results.forEach((result, index) => {
    ensureSpace(12);
    doc.setFontSize(13);
    writeWrapped(`${index + 1}. ${result.resource.toUpperCase()}`);
    doc.setFontSize(11);

    if (result.status === 'error') {
      writeWrapped('Status: FAILED');
      writeWrapped(`Error: ${result.error ?? 'Unknown error'}`, 4);
      return;
    }

    const findings = extractFindings(result.data);
    writeWrapped('Status: SUCCESS');
    writeWrapped(`Findings detected: ${countFindings(result.data)}`, 2);

    if (findings.length === 0) {
      writeWrapped('No findings detected.', 4);
      return;
    }

    findings.forEach((finding, findingIndex) => {
      ensureSpace(18);
      writeWrapped(`Finding ${findingIndex + 1}: ${finding.title}`);
      const riskScore = riskScores[finding.id];
      if (riskScore != null) {
        writeWrapped(`Severity: ${getRiskLabel(riskScore)}`);
        writeWrapped(`Risk score: ${riskScores[finding.id]}`);
      } else {
        writeWrapped(`Severity: ${finding.severity}`);
      }
      writeWrapped(`Description: ${finding.description}`);

      if (finding.remediation) {
        writeWrapped(`Remediation: ${finding.remediation}`);
      }

      if (finding.resourceType) {
        writeWrapped(`Resource type: ${finding.resourceType}`);
      }

      if (finding.cisControl) {
        writeWrapped(`CIS Control: ${finding.cisControl}`);
      }

      if (finding.owasp) {
        writeWrapped(`OWASP: ${finding.owasp}`);
      }

      y += 2;
    });

    y += 4;
  });

  const fileName = `scan-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.pdf`;
  doc.save(fileName);
}