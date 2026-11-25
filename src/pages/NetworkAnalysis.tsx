import React, { useCallback, useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { Maximize2, Network, Play, Search, ZoomIn, ZoomOut } from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { LoadingSpinner } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';
import { api } from '../services/api';
import type { NetworkGraphEdge, NetworkGraphNode, NetworkResponse } from '../types/api';

export function NetworkAnalysis() {
  const { activeDatasetId, addToast, dataVersion } = useApp();
  const { isDark } = useTheme();

  const [data, setData] = useState<NetworkResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [startNode, setStartNode] = useState('');
  const [searchNode, setSearchNode] = useState('');
  const [selectedNode, setSelectedNode] = useState<NetworkGraphNode | null>(null);
  const [selectedEdges, setSelectedEdges] = useState<NetworkGraphEdge[]>([]);

  const cyContainerRef = useRef<HTMLDivElement | null>(null);
  const cyInstanceRef = useRef<cytoscape.Core | null>(null);

  const loadNetwork = useCallback(
    async (chosenStart?: string) => {
      if (!activeDatasetId) {
        setLoading(false);
        return;
      }
      setLoading(true);
      try {
        const res = await api.getNetwork(activeDatasetId, chosenStart ?? startNode);
        setData(res);
        if (res.bfs?.start_node) {
          setStartNode(res.bfs.start_node);
        }
      } catch (err) {
        addToast({
          type: 'error',
          title: 'Failed to load network graph',
          message: err instanceof Error ? err.message : 'Error',
        });
      } finally {
        setLoading(false);
      }
    },
    [activeDatasetId, addToast]
  );

  useEffect(() => {
    loadNetwork('');
  }, [activeDatasetId, dataVersion]);

  useEffect(() => {
    if (!cyContainerRef.current || !data || data.nodes.length === 0) return;

    const bfsSet = new Set(data.bfs?.traversal_order.map((s) => s.node_id) || []);
    const bfsEdgeSet = new Set(data.bfs?.edges_traversed || []);

    const elements: cytoscape.ElementDefinition[] = [
      ...data.nodes.map((n) => ({
        data: {
          ...n,
          inBfs: bfsSet.has(n.id) ? 'yes' : 'no',
          isStart: data.bfs?.start_node === n.id ? 'yes' : 'no',
        },
      })),
      ...data.edges.map((e) => ({
        data: {
          ...e,
          inBfs: bfsEdgeSet.has(e.id) ? 'yes' : 'no',
        },
      })),
    ];

    const cy = cytoscape({
      container: cyContainerRef.current,
      elements,
      style: [
        {
          selector: 'node[type="ip"]',
          style: {
            shape: 'diamond',
            width: 34,
            height: 34,
            'background-color': isDark ? '#3f3f46' : '#64748b',
            label: 'data(label)',
            color: isDark ? '#fafafa' : '#18181b',
            'font-size': 10,
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'border-width': 2,
            'border-color': isDark ? '#52525b' : '#94a3b8',
          },
        },
        {
          selector: 'node[type="ip"][?suspicious]',
          style: {
            width: 42,
            height: 42,
            'background-color': '#DC2626',
            'border-color': '#FCA5A5',
            'border-width': 3,
          },
        },
        {
          selector: 'node[type="user"]',
          style: {
            shape: 'ellipse',
            width: 24,
            height: 24,
            'background-color': isDark ? '#27272a' : '#e2e8f0',
            label: 'data(label)',
            color: isDark ? '#d4d4d8' : '#334155',
            'font-size': 9,
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'border-width': 1.5,
            'border-color': isDark ? '#52525b' : '#94a3b8',
          },
        },
        {
          selector: 'node[type="user"][?compromised]',
          style: {
            'background-color': '#D97706',
            'border-color': '#FEF08A',
            'border-width': 2.5,
          },
        },
        {
          selector: 'node[inBfs="yes"]',
          style: {
            'border-color': '#EF4444',
            'border-width': 3,
          },
        },
        {
          selector: 'node[isStart="yes"]',
          style: {
            'border-color': '#FAFAFA',
            'border-width': 4,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.4,
            'line-color': isDark ? '#3f2828' : '#cbd5e1',
            'curve-style': 'bezier',
            opacity: 0.72,
          },
        },
        {
          selector: 'edge[?success_after_failure]',
          style: {
            width: 2.5,
            'line-color': '#EF4444',
            opacity: 0.95,
          },
        },
        {
          selector: 'edge[inBfs="yes"]',
          style: {
            width: 2.4,
            'line-color': '#F87171',
            opacity: 1,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#EF4444',
            'border-width': 4,
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        nodeRepulsion: () => 5200,
        idealEdgeLength: () => 95,
        padding: 28,
      },
    });

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data() as NetworkGraphNode;
      setSelectedNode(nodeData);
      setSelectedEdges(
        data.edges.filter((e) => e.source === nodeData.id || e.target === nodeData.id)
      );
    });

    cyInstanceRef.current = cy;
    return () => {
      cy.destroy();
      cyInstanceRef.current = null;
    };
  }, [data, isDark]);

  const handleSearchFocus = (e: React.FormEvent) => {
    e.preventDefault();
    const cy = cyInstanceRef.current;
    if (!cy || !searchNode.trim()) return;
    const q = searchNode.trim().toLowerCase();
    const match = cy.nodes().filter((n) => String(n.data('label')).toLowerCase().includes(q)).first();
    if (match.length > 0) {
      cy.nodes().unselect();
      match.select();
      cy.animate({ center: { eles: match }, zoom: 1.5, duration: 250 });
      const nodeData = match.data() as NetworkGraphNode;
      setSelectedNode(nodeData);
      if (data) {
        setSelectedEdges(data.edges.filter((ed) => ed.source === nodeData.id || ed.target === nodeData.id));
      }
    } else {
      addToast({ type: 'info', title: 'Node not found', message: `No IP or username matched "${searchNode}".` });
    }
  };

  if (!activeDatasetId && !loading) {
    return <EmptyState onLoaded={() => loadNetwork('')} />;
  }

  return (
    <div className="space-y-6">
      {/* Controls & BFS Header */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Network className="w-5 h-5 text-red-600 dark:text-red-400" />
              <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
                Bipartite Network Visualization & Breadth-First Search
              </h1>
            </div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Interactive IP-to-Username bipartite graph rendered with Cytoscape.js. Select any starting node to execute BFS relationship discovery.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <select
              value={startNode}
              onChange={(e) => setStartNode(e.target.value)}
              aria-label="Select BFS starting node"
              className="px-3 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100 max-w-[230px]"
            >
              {(data?.nodes || []).map((n) => (
                <option key={n.id} value={n.id}>
                  {n.type === 'ip' ? 'IP' : 'User'}: {n.label} {n.suspicious ? '(Suspicious)' : ''}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={() => loadNetwork(startNode)}
              disabled={!startNode || loading}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Run BFS Traversal</span>
            </button>
          </div>
        </div>

        {/* Search + Zoom + Legend Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-zinc-200 dark:border-[#332020]">
          <form onSubmit={handleSearchFocus} className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 top-2 pointer-events-none" />
              <input
                type="search"
                value={searchNode}
                onChange={(e) => setSearchNode(e.target.value)}
                placeholder="Locate IP or account node..."
                className="pl-8 pr-3 py-1 text-xs rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
            >
              Locate
            </button>
          </form>

          <div className="flex flex-wrap items-center gap-4 text-[11px] text-zinc-600 dark:text-zinc-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 rotate-45 bg-red-600 inline-block" /> Suspicious IP
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 rotate-45 bg-slate-500 inline-block" /> Normal IP
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-amber-600 inline-block" /> Post-Failure Success User
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-slate-300 dark:bg-zinc-700 inline-block" /> User Account
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => cyInstanceRef.current?.zoom(cyInstanceRef.current.zoom() * 1.25)}
              className="p-1.5 rounded-lg border border-zinc-200 dark:border-[#332020] hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
              title="Zoom in"
              aria-label="Zoom in"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => cyInstanceRef.current?.zoom(cyInstanceRef.current.zoom() * 0.8)}
              className="p-1.5 rounded-lg border border-zinc-200 dark:border-[#332020] hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
              title="Zoom out"
              aria-label="Zoom out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => cyInstanceRef.current?.fit(undefined, 30)}
              className="p-1.5 rounded-lg border border-zinc-200 dark:border-[#332020] hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
              title="Fit graph"
              aria-label="Fit graph"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      {loading ? (
        <LoadingSpinner label="Constructing bipartite graph and running BFS..." />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Cytoscape Canvas */}
          <div className="lg:col-span-8 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#141111] overflow-hidden relative">
            <div ref={cyContainerRef} className="w-full h-[540px]" />
          </div>

          {/* BFS Traversal Order & Node Inspector */}
          <div className="lg:col-span-4 space-y-5">
            {selectedNode && (
              <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-red-600 dark:text-red-400">
                    Selected {selectedNode.type === 'ip' ? 'IP Address' : 'Username'}
                  </span>
                  <button
                    type="button"
                    onClick={() => loadNetwork(selectedNode.id)}
                    className="text-xs font-medium text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                  >
                    Run BFS from here
                  </button>
                </div>
                <div className="text-base font-bold font-mono text-zinc-900 dark:text-zinc-50">
                  {selectedNode.label}
                </div>
                <div className="text-xs text-zinc-500 dark:text-zinc-400 tabular-nums">
                  Connected edges: {selectedEdges.length} · Total attempts: {selectedNode.total_attempts ?? 0}
                  {selectedNode.suspicious ? ` · Risk Score ${selectedNode.risk_score}/100` : ''}
                </div>
                <div className="max-h-36 overflow-y-auto divide-y divide-zinc-200 dark:divide-[#332020] text-xs">
                  {selectedEdges.slice(0, 15).map((ed) => (
                    <div key={ed.id} className="py-1.5 flex items-center justify-between gap-2">
                      <span className="font-mono truncate text-zinc-700 dark:text-zinc-300">
                        {ed.source === selectedNode.id ? ed.target.replace('user:', '') : ed.source.replace('ip:', '')}
                      </span>
                      <span className="font-mono tabular-nums text-zinc-500 dark:text-zinc-400 shrink-0">
                        {ed.failures}F / {ed.successes}S
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5 space-y-3">
              <div>
                <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  BFS Traversal Order
                </h2>
                {data?.bfs_metrics && (
                  <p className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 tabular-nums mt-0.5">
                    Visited {String(data.bfs_metrics.vertices_visited)}/{String(data.bfs_metrics.vertices_total)} nodes in{' '}
                    {String(data.bfs_metrics.execution_time_ms)} ms · {String(data.bfs_metrics.time_complexity)}
                  </p>
                )}
              </div>

              {data?.bfs && (
                <>
                  <div className="grid grid-cols-2 gap-2 text-xs bg-slate-50 dark:bg-[#211515] p-3 rounded-lg">
                    <div>
                      <div className="text-zinc-500 dark:text-zinc-400 text-[11px]">Connected IPs</div>
                      <div className="font-mono font-bold tabular-nums text-zinc-900 dark:text-zinc-100">
                        {data.bfs.discovered_ips.length}
                      </div>
                    </div>
                    <div>
                      <div className="text-zinc-500 dark:text-zinc-400 text-[11px]">Connected Accounts</div>
                      <div className="font-mono font-bold tabular-nums text-zinc-900 dark:text-zinc-100">
                        {data.bfs.discovered_accounts.length}
                      </div>
                    </div>
                  </div>

                  <div className="max-h-72 overflow-y-auto divide-y divide-zinc-200 dark:divide-[#332020] text-xs">
                    {data.bfs.traversal_order.map((step) => (
                      <div key={step.node_id} className="py-2 flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono text-[11px] text-zinc-400 w-6 tabular-nums">#{step.step}</span>
                          <span
                            className={`font-mono truncate ${
                              step.suspicious || step.compromised
                                ? 'text-red-600 dark:text-red-400 font-semibold'
                                : 'text-zinc-800 dark:text-zinc-200'
                            }`}
                          >
                            {step.label}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 shrink-0 tabular-nums">
                          {step.node_type.toUpperCase()} · d={step.depth}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
