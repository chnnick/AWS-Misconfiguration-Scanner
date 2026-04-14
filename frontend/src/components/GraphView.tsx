import { useCallback, useEffect, useRef, useState } from "react";
import { Network, RefreshCw } from "lucide-react";

import ForceGraph2D from "react-force-graph-2d";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

interface GraphNode {
  id: string;
  label: string;
  properties: Record<string, unknown>;
  x?: number;
  y?: number;
}

interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  type: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const NODE_COLORS: Record<string, string> = {
  EC2Instance: "#3b82f6",
  S3Bucket: "#22c55e",
  IAMRole: "#f97316",
  IAMUser: "#fb923c",
  LambdaFunction: "#a855f7",
  SecurityGroup: "#eab308",
  SecurityGroupRule: "#fbbf24",
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#16a34a",
};

function getNodeColor(node: GraphNode): string {
  if (node.label === "Finding") {
    const sev = node.properties?.severity as string | undefined;
    return sev ? (SEVERITY_COLORS[sev] ?? "#ef4444") : "#ef4444";
  }
  return NODE_COLORS[node.label] ?? "#94a3b8";
}

function getNodeName(node: GraphNode): string {
  const p = node.properties;
  switch (node.label) {
    case "EC2Instance":
      return (p.instance_id as string) ?? "EC2";
    case "S3Bucket":
      return (p.bucket_name as string) ?? "S3";
    case "IAMRole":
      return (p.role_name as string) ?? "Role";
    case "IAMUser":
      return (p.username as string) ?? "User";
    case "LambdaFunction":
      return (p.function_name as string) ?? "Lambda";
    case "SecurityGroup":
      return (p.group_name as string) ?? (p.group_id as string) ?? "SG";
    case "Finding":
      return (p.type as string) ?? "Finding";
    default:
      return node.label;
  }
}

export interface GraphViewProps {
  refreshTrigger?: number;
}

export function GraphView({ refreshTrigger = 0 }: GraphViewProps) {
  const [graphData, setGraphData] = useState<GraphData>({
    nodes: [],
    links: [],
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });

  const fetchGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const graphUrl = `${API_BASE_URL}/api/graph?limit=200`;
      const res = await fetch(graphUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const raw = (await res.json()) as {
        nodes?: GraphNode[];
        edges?: { source: string; target: string; type: string }[];
        error?: string;
      };
      if (raw.error) throw new Error(raw.error);
      setGraphData({
        nodes: raw.nodes ?? [],
        links: (raw.edges ?? []).map((e) => ({
          source: e.source,
          target: e.target,
          type: e.type,
        })),
      });
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load graph data",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph, refreshTrigger]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ width, height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const handleNodeClick = useCallback((node: object) => {
    setSelectedNode(node as GraphNode);
  }, []);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const isEmpty = !loading && !error && graphData.nodes.length === 0;

  return (
    <div className="relative flex h-full min-h-[min(20rem,40vh)] w-full flex-col sm:min-h-0">
      {isEmpty && (
        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-zinc-950 px-8 py-12">
          <div className="text-center">
            <Network className="mx-auto mb-4 h-12 w-12 text-zinc-600" />
            <h3 className="mb-2 text-lg font-medium text-zinc-400">
              Neo4j Graph View
            </h3>
            <p className="text-sm text-zinc-500">
              Run a scan to populate the graph
            </p>
          </div>
        </div>
      )}
      <div className="relative flex min-h-0 flex-1 overflow-hidden rounded-lg border border-zinc-700 bg-zinc-950">
        {!isEmpty && (
          <>
            {/* Legend */}
            <div className="absolute left-3 top-3 z-10 flex flex-col gap-1 rounded-md bg-zinc-900/90 p-2 text-xs backdrop-blur-sm">
              {Object.entries(NODE_COLORS).map(([label, color]) => (
                <div key={label} className="flex items-center gap-1.5">
                  <span
                    className="h-2 w-2 flex-shrink-0 rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-zinc-400">{label}</span>
                </div>
              ))}
              <div className="mt-1 border-t border-zinc-700 pt-1 text-zinc-500">
                Findings
              </div>
              {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
                <div key={sev} className="flex items-center gap-1.5">
                  <span
                    className="h-2 w-2 flex-shrink-0 rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-zinc-500">{sev}</span>
                </div>
              ))}
            </div>

            {/* Refresh button */}
            <button
              onClick={fetchGraph}
              disabled={loading}
              className="absolute right-3 top-3 z-10 flex items-center gap-1.5 rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-700 disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3 w-3 ${loading ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </>
        )}

        {/* Loading overlay */}
        {loading && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-zinc-950/70">
            <div className="flex items-center gap-2 text-sm text-zinc-400">
              <RefreshCw className="h-4 w-4 animate-spin" />
              Loading graph…
            </div>
          </div>
        )}

        {/* Error overlay */}
        {error && !loading && (
          <div className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-3">
            <p className="text-sm text-red-400">{error}</p>
            <button
              onClick={fetchGraph}
              className="rounded-md bg-zinc-800 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-700"
            >
              Retry
            </button>
          </div>
        )}

        {/* Graph canvas */}
        <div ref={containerRef} className="h-full w-full">
          {!loading && !error && !isEmpty && (
            <ForceGraph2D
              width={dimensions.width}
              height={dimensions.height}
              graphData={graphData}
              backgroundColor="#09090b"
              nodeColor={(node: GraphNode) => getNodeColor(node)}
              nodeLabel={(node: GraphNode) =>
                `${node.label}: ${getNodeName(node)}`
              }
              nodeCanvasObject={(
                node: GraphNode,
                ctx: CanvasRenderingContext2D,
                globalScale: number,
              ) => {
                const radius = node.label === "Finding" ? 5 : 7;
                const color = getNodeColor(node);

                ctx.beginPath();
                ctx.arc(node.x!, node.y!, radius, 0, 2 * Math.PI);
                ctx.fillStyle = color;
                ctx.fill();
                ctx.strokeStyle = "rgba(255,255,255,0.15)";
                ctx.lineWidth = 0.8;
                ctx.stroke();

                // Type abbreviation inside node
                const abbr =
                  node.label === "Finding"
                    ? ((node.properties?.severity as string) ?? "F").charAt(0)
                    : node.label.replace(/[a-z]/g, "").slice(0, 2);
                const fontSize = Math.min(radius * 0.9, 12 / globalScale);
                if (fontSize > 1.5) {
                  ctx.font = `bold ${fontSize}px Sans-Serif`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "middle";
                  ctx.fillStyle = "rgba(255,255,255,0.9)";
                  ctx.fillText(abbr, node.x!, node.y!);
                }

                // Full name below node when zoomed in
                if (globalScale >= 2.5) {
                  const name = getNodeName(node).slice(0, 18);
                  const labelSize = 10 / globalScale;
                  ctx.font = `${labelSize}px Sans-Serif`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "top";
                  ctx.fillStyle = "rgba(255,255,255,0.65)";
                  ctx.fillText(name, node.x!, node.y! + radius + 1.5);
                }
              }}
              linkColor={() => "rgba(148,163,184,0.25)"}
              linkWidth={1}
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={1}
              linkDirectionalArrowColor={() => "rgba(148,163,184,0.5)"}
              linkLabel={(link: GraphLink) => link.type}
              linkCurvature={0.1}
              onNodeClick={handleNodeClick}
              onBackgroundClick={handleBackgroundClick}
              cooldownTicks={80}
            />
          )}
        </div>

        {/* Selected node detail panel */}
        {selectedNode && (
          <div className="absolute bottom-3 right-3 z-10 max-h-52 w-64 overflow-auto rounded-lg bg-zinc-800/95 p-3 text-xs shadow-xl backdrop-blur-sm">
            <div className="mb-2 flex items-center justify-between">
              <span
                className="font-semibold"
                style={{ color: getNodeColor(selectedNode) }}
              >
                {selectedNode.label}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-zinc-500 hover:text-zinc-200"
              >
                ✕
              </button>
            </div>
            <dl className="space-y-0.5">
              {Object.entries(selectedNode.properties ?? {}).map(([k, v]) => (
                <div key={k} className="grid grid-cols-2 gap-1">
                  <dt className="truncate text-zinc-500">{k}</dt>
                  <dd className="truncate text-zinc-300">{String(v)}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}
