import { Loader as Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import type { ResourceToggle } from '@/types/scan';

interface ScanControlsProps {
  toggles: ResourceToggle[];
  onToggleChange: (id: string, enabled: boolean) => void;
  onScan: () => void;
  isScanning: boolean;
}

export function ScanControls({
  toggles,
  onToggleChange,
  onScan,
  isScanning,
}: ScanControlsProps) {
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-center gap-8">
        {toggles.map((toggle) => (
          <div key={toggle.id} className="flex items-center gap-3">
            <Switch
              id={toggle.id}
              checked={toggle.enabled}
              onCheckedChange={(checked) => onToggleChange(toggle.id, checked)}
              disabled={isScanning}
            />
            <Label
              htmlFor={toggle.id}
              className="cursor-pointer text-base font-medium text-zinc-100"
            >
              {toggle.label}
            </Label>
          </div>
        ))}
      </div>

      <div className="flex justify-center">
        <Button
          onClick={onScan}
          disabled={isScanning || !toggles.some((t) => t.enabled)}
          size="lg"
          className="min-w-[200px]"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning...
            </>
          ) : (
            'Scan Resources'
          )}
        </Button>
      </div>
    </div>
  );
}
