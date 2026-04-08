import { Network } from 'lucide-react';

export function GraphPlaceholder() {
  return (
    <div className="flex h-full min-h-[min(20rem,40vh)] w-full flex-col sm:min-h-0">
      <div className="flex min-h-0 flex-1 flex-col items-center justify-center rounded-lg border-2 border-dashed border-zinc-700 bg-zinc-900/50 px-8 py-12">
        <div className="text-center">
          <Network className="mx-auto mb-4 h-12 w-12 text-zinc-600" />
          <h3 className="mb-2 text-lg font-medium text-zinc-400">
            Neo4j Graph View
          </h3>
          <p className="text-sm text-zinc-500">Coming Soon</p>
        </div>
      </div>
    </div>
  );
}
