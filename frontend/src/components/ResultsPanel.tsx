import { CircleAlert as AlertCircle, CircleCheck as CheckCircle2 } from 'lucide-react';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { Button } from '@/components/ui/button';
import { exportResultsToHtml } from '@/lib/html';
import { exportResultsToPdf } from '@/lib/pdf';
import { countFindings, extractFindings, type FindingSeverity } from '@/lib/reportUtils';
import type { ScanResult } from '@/types/scan';

interface ResultsPanelProps {
  results: ScanResult[];
}

function severityClasses(severity: FindingSeverity): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-red-700 text-white border-red-500';
    case 'HIGH':
      return 'bg-orange-600 text-white border-orange-400';
    case 'MEDIUM':
      return 'bg-yellow-500 text-black border-yellow-300';
    case 'LOW':
      return 'bg-blue-600 text-white border-blue-400';
    default:
      return 'bg-zinc-700 text-white border-zinc-500';
  }
}

export function ResultsPanel({ results }: ResultsPanelProps) {
  if (results.length === 0) {
    return null;
  }

  return (
    <div className="mx-auto w-full max-w-4xl">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold text-zinc-100">Scan Results</h2>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => exportResultsToHtml(results)} variant="secondary">
            Download HTML
          </Button>
          <Button onClick={() => exportResultsToPdf(results)} variant="secondary">
            Download PDF
          </Button>
        </div>
      </div>

      <Accordion type="multiple" className="space-y-2">
        {results.map((result) => {
          const findings = result.status === 'success' ? extractFindings(result.data) : [];
          const findingCount = result.status === 'success' ? countFindings(result.data) : 0;

          return (
            <AccordionItem
              key={result.resource}
              value={result.resource}
              className="rounded-lg border border-zinc-800 bg-zinc-900 px-4"
            >
              <AccordionTrigger className="hover:no-underline">
                <div className="flex items-center gap-3">
                  {result.status === 'success' ? (
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-500" />
                  )}

                  <span className="font-medium uppercase text-zinc-100">
                    {result.resource} Results
                  </span>

                  {result.status === 'error' ? (
                    <span className="ml-2 text-sm text-red-400">(Failed)</span>
                  ) : (
                    <span className="ml-2 text-sm text-zinc-400">
                      ({findingCount} finding{findingCount === 1 ? '' : 's'})
                    </span>
                  )}
                </div>
              </AccordionTrigger>

              <AccordionContent>
                {result.status === 'error' ? (
                  <div className="rounded-md bg-red-950/30 p-4 text-sm text-red-400">
                    <p className="font-medium">Error:</p>
                    <p className="mt-1">{result.error}</p>
                  </div>
                ) : findings.length > 0 ? (
                  <div className="space-y-4">
                    {findings.map((finding) => (
                      <div
                        key={finding.id}
                        className="rounded-lg border border-zinc-700 bg-zinc-950 p-4"
                      >
                        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                          <h3 className="text-base font-semibold text-zinc-100">
                            {finding.title}
                          </h3>
                          <span
                            className={`rounded border px-2 py-1 text-xs font-semibold ${severityClasses(finding.severity)}`}
                          >
                            {finding.severity}
                          </span>
                        </div>

                        <div className="space-y-2 text-sm text-zinc-300">
                          <p>
                            <span className="font-medium text-zinc-100">Description:</span>{' '}
                            {finding.description}
                          </p>

                          {finding.remediation && (
                            <p>
                              <span className="font-medium text-zinc-100">Remediation:</span>{' '}
                              {finding.remediation}
                            </p>
                          )}

                          {finding.resourceType && (
                            <p>
                              <span className="font-medium text-zinc-100">Resource type:</span>{' '}
                              {finding.resourceType}
                            </p>
                          )}

                          {(finding.cisControl || finding.owasp) && (
                            <div className="flex flex-wrap gap-4">
                              {finding.cisControl && (
                                <p>
                                  <span className="font-medium text-zinc-100">CIS:</span>{' '}
                                  {finding.cisControl}
                                </p>
                              )}
                              {finding.owasp && (
                                <p>
                                  <span className="font-medium text-zinc-100">OWASP:</span>{' '}
                                  {finding.owasp}
                                </p>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-md bg-zinc-950 p-4 text-sm text-zinc-300">
                    No findings detected.
                  </div>
                )}
              </AccordionContent>
            </AccordionItem>
          );
        })}
      </Accordion>
    </div>
  );
}