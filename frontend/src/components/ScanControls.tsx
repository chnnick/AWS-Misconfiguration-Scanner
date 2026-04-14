import { Loader as Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import type { ResourceToggle } from "@/types/scan";

interface ScanControlsProps {
  toggles: ResourceToggle[];
  onToggleChange: (id: string, enabled: boolean) => void;
  onScan: () => void;
  isScanning: boolean;
  riskScore?: number | null;
}

export function ScanControls({
  toggles,
  onToggleChange,
  onScan,
  isScanning,
  riskScore,
}: ScanControlsProps) {
  return (
    <aside className="flex h-full min-h-0 w-full flex-col rounded-lg border border-zinc-800 bg-zinc-900/80 p-5 shadow-sm">
      <div className="mb-6 shrink-0">
        <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
          Risk score
        </p>
        <div
          className="mt-2 flex min-h-[5.5rem] items-center justify-center rounded-md border border-dashed border-zinc-700 bg-zinc-950/50 px-3 py-4"
          aria-label={
            riskScore != null
              ? `Risk score ${riskScore}`
              : "Risk score not available"
          }
        >
          {riskScore != null ? (
            <div className="flex flex-col items-center gap-1">
              <span className="text-3xl font-semibold tabular-nums text-zinc-100">
                {riskScore}
              </span>
              <span
                className={`text-xs font-medium ${
                  riskScore >= 4.0
                    ? "text-red-400"
                    : riskScore >= 3.0
                      ? "text-orange-400"
                      : riskScore >= 2.0
                        ? "text-yellow-400"
                        : "text-green-400"
                }`}
              >
                {riskScore >= 4.0
                  ? "High"
                  : riskScore >= 3.0
                    ? "Medium"
                    : riskScore >= 2.0
                      ? "Low"
                      : "Minimal"}
              </span>
            </div>
          ) : (
            <span className="text-xs text-zinc-600">Run a scan</span>
          )}
        </div>
      </div>

      <p className="mb-3 shrink-0 text-xs font-semibold uppercase tracking-wide text-zinc-500">
        Resources
      </p>

      <div className="flex min-h-0 flex-1 flex-col gap-2">
        {toggles.map((toggle) => (
          <div
            key={toggle.id}
            className="flex w-full flex-row items-center justify-between gap-3 rounded-md border border-zinc-800/80 bg-zinc-950/50 px-3 py-2.5"
          >
            <Label
              htmlFor={toggle.id}
              className="cursor-pointer text-sm font-medium text-zinc-100"
            >
              {toggle.label}
            </Label>
            <Switch
              id={toggle.id}
              checked={toggle.enabled}
              onCheckedChange={(checked) => onToggleChange(toggle.id, checked)}
              disabled={isScanning}
            />
          </div>
        ))}
      </div>

      <div className="mt-6 shrink-0 border-t border-zinc-800 pt-5">
        <Button
          onClick={onScan}
          disabled={isScanning || !toggles.some((t) => t.enabled)}
          size="lg"
          className="w-full"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning...
            </>
          ) : (
            "Scan Resources"
          )}
        </Button>
      </div>
    </aside>
  );
}
