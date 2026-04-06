import { useState } from 'react';
import { Header } from '@/components/Header';
import { ScanControls } from '@/components/ScanControls';
import { GraphPlaceholder } from '@/components/GraphPlaceholder';
import { ResultsPanel } from '@/components/ResultsPanel';
import type { ResourceToggle, ScanResult, ResourceType } from '@/types/scan';

const API_BASE_URL = 'http://localhost:8000';

function App() {
  const [toggles, setToggles] = useState<ResourceToggle[]>([
    { id: 'ec2', label: 'EC2', enabled: true },
    { id: 'iam', label: 'IAM', enabled: true },
    { id: 's3', label: 'S3', enabled: true },
    { id: 'lambda', label: 'Lambda', enabled: true },
  ]);

  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);

  const handleToggleChange = (id: string, enabled: boolean) => {
    setToggles((prev) =>
      prev.map((toggle) =>
        toggle.id === id ? { ...toggle, enabled } : toggle
      )
    );
  };

  const handleScan = async () => {
    const enabledResources = toggles
      .filter((toggle) => toggle.enabled)
      .map((toggle) => toggle.id);

    if (enabledResources.length === 0) return;

    setIsScanning(true);
    setResults([]);

    const scanPromises = enabledResources.map(async (resource) => {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/scanner/${resource}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
          }
        );

        if (!response.ok) {
          const text = await response.text();
          let detail = text || response.statusText;
          try {
            const errBody = JSON.parse(text) as { detail?: unknown };
            if (typeof errBody?.detail === 'string') {
              detail = errBody.detail;
            } else if (errBody?.detail != null) {
              detail = JSON.stringify(errBody.detail);
            }
          } catch {
            if (text) detail = text.slice(0, 500);
          }
          throw new Error(`HTTP ${response.status}: ${detail}`);
        }

        const data = await response.json();

        return {
          resource,
          data,
          status: 'success' as const,
        };
      } catch (error) {
        return {
          resource,
          error:
            error instanceof Error
              ? error.message
              : 'Failed to fetch results — check backend connection',
          status: 'error' as const,
        };
      }
    });

    const scanResults = await Promise.allSettled(scanPromises);

    const processedResults: ScanResult[] = scanResults.map((result) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          resource: 'unknown' as ResourceType,
          error: result.reason?.message || 'Unknown error occurred',
          status: 'error' as const,
        };
      }
    });

    setResults(processedResults);
    setIsScanning(false);
  };

  return (
    <div className="min-h-screen bg-zinc-950">
      <Header />

      <main className="mx-auto max-w-7xl space-y-12 px-8 py-12">
        <ScanControls
          toggles={toggles}
          onToggleChange={handleToggleChange}
          onScan={handleScan}
          isScanning={isScanning}
        />

        <GraphPlaceholder />

        <ResultsPanel results={results} />
      </main>
    </div>
  );
}

export default App;
