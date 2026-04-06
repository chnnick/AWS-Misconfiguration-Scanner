import { CircleAlert as AlertCircle, CircleCheck as CheckCircle2 } from 'lucide-react';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import type { ScanResult } from '@/types/scan';

interface ResultsPanelProps {
  results: ScanResult[];
}

export function ResultsPanel({ results }: ResultsPanelProps) {
  if (results.length === 0) {
    return null;
  }

  return (
    <div className="mx-auto w-full max-w-4xl">
      <h2 className="mb-4 text-xl font-semibold text-zinc-100">Scan Results</h2>
      <Accordion type="multiple" className="space-y-2">
        {results.map((result) => (
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
                {result.status === 'error' && (
                  <span className="ml-2 text-sm text-red-400">(Failed)</span>
                )}
              </div>
            </AccordionTrigger>
            <AccordionContent>
              {result.status === 'error' ? (
                <div className="rounded-md bg-red-950/30 p-4 text-sm text-red-400">
                  <p className="font-medium">Error:</p>
                  <p className="mt-1">{result.error}</p>
                </div>
              ) : (
                <pre className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-sm text-zinc-300">
                  <code>{JSON.stringify(result.data, null, 2)}</code>
                </pre>
              )}
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  );
}
