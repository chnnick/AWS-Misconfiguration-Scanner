import { Shield } from 'lucide-react';

export function Header() {
  return (
    <header className="border-b border-zinc-800 bg-zinc-950 px-8 py-6">
      <div className="mx-auto max-w-7xl">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-zinc-100" />
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-100">
              CloudSight AWS Misconfiguration Scanner
            </h1>
            <p className="text-sm text-zinc-400">
              Detect security misconfigurations across your AWS resources
            </p>
          </div>
        </div>
      </div>
    </header>
  );
}
