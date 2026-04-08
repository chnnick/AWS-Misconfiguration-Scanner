import jsPDF from 'jspdf';
import type { ScanResult } from '@/types/scan';
import { countFindings } from '@/lib/reportUtils';

export function exportResultsToPdf(results: ScanResult[]) {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 14;
  const maxLineWidth = pageWidth - margin * 2;
  const lineHeight = 6;
  let y = 20;

  const writeWrapped = (text: string) => {
    const lines = doc.splitTextToSize(text, maxLineWidth);
    lines.forEach((line: string) => {
      if (y > 280) {
        doc.addPage();
        y = 20;
      }
      doc.text(line, margin, y);
      y += lineHeight;
    });
  };

  doc.setFontSize(18);
  doc.text('AWS Misconfiguration Scan Report', margin, y);
  y += 10;

  doc.setFontSize(11);
  writeWrapped(`Generated: ${new Date().toLocaleString()}`);
  y += 2;
  writeWrapped(`Collectors included: ${results.map((r) => r.resource.toUpperCase()).join(', ')}`);
  y += 6;

  results.forEach((result, index) => {
    doc.setFontSize(13);
    writeWrapped(`${index + 1}. ${result.resource.toUpperCase()}`);
    doc.setFontSize(11);

    if (result.status === 'error') {
      writeWrapped(`Status: FAILED`);
      writeWrapped(`Error: ${result.error ?? 'Unknown error'}`);
      y += 4;
      return;
    }

    const findingCount = countFindings(result.data);
    writeWrapped(`Status: SUCCESS`);
    writeWrapped(`Findings detected: ${findingCount}`);
    y += 2;

    const jsonPreview = JSON.stringify(result.data, null, 2);
    const truncated = jsonPreview.length > 1800 ? `${jsonPreview.slice(0, 1800)}\n... (truncated)` : jsonPreview;
    writeWrapped('Data preview:');
    writeWrapped(truncated);
    y += 4;
  });

  const fileName = `scan-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.pdf`;
  doc.save(fileName);
}
