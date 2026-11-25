import React, { useCallback, useEffect, useState } from 'react';
import { Cpu, Play } from 'lucide-react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { LoadingSpinner } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';
import { api } from '../services/api';
import type { AlgorithmMetricRow, BenchmarkPoint } from '../types/api';

interface AlgorithmDoc {
  id: string;
  name: string;
  matchKey: string;
  timeComplexity: string;
  spaceComplexity: string;
  description: string;
  purpose: string;
  pseudocode: string;
}

const ALGORITHM_DOCS: AlgorithmDoc[] = [
  {
    id: 'merge_sort',
    name: 'Merge Sort',
    matchKey: 'Merge Sort',
    timeComplexity: 'O(n log n) best / avg / worst',
    spaceComplexity: 'O(n) auxiliary',
    description:
      'Divide-and-conquer stable comparison sort that recursively splits the authentication log array into halves and merges them in chronological order.',
    purpose:
      'Orders raw, out-of-sequence authentication logs by timestamp so Binary Search and Sliding Window operate deterministically.',
    pseudocode: `function MERGE_SORT(events):
  if length(events) <= 1: return events
  mid = length(events) / 2
  left = MERGE_SORT(events[0..mid])
  right = MERGE_SORT(events[mid..n])
  return MERGE(left, right, key=epoch_ts)`,
  },
  {
    id: 'hash_table',
    name: 'Hash Table (Separate Chaining)',
    matchKey: 'Hash Table',
    timeComplexity: 'O(1) average / O(n) worst-case',
    spaceComplexity: 'O(n)',
    description:
      'Custom bucketed hash table using FNV-1a 32-bit hashing, separate chaining collision resolution, and dynamic resizing when load factor exceeds 0.75.',
    purpose:
      'Groups incoming authentication records by source IP address and aggregates distinct targeted usernames in linear amortized time.',
    pseudocode: `function HASH_GROUP(events):
  table = HashTable(capacity=initial_cap)
  for ev in events:
    bucket = FNV1A(ev.source_ip) mod table.capacity
    entry = table.get_or_create(ev.source_ip)
    entry.update_counts(ev.username, ev.status)`,
  },
  {
    id: 'binary_search',
    name: 'Binary Search',
    matchKey: 'Binary Search',
    timeComplexity: 'O(log n + k)',
    spaceComplexity: 'O(1) search / O(k) slice',
    description:
      'Computes lower_bound and upper_bound indices on the Merge-Sorted epoch timestamp array to extract matching time intervals without scanning the entire log.',
    purpose:
      'Powers sub-millisecond time-range filtering in the Log Analyzer across large historical authentication datasets.',
    pseudocode: `function RANGE_QUERY(sorted_events, t_start, t_end):
  left = LOWER_BOUND(sorted_events, t_start)
  right = UPPER_BOUND(sorted_events, t_end)
  return sorted_events[left : right]`,
  },
  {
    id: 'sliding_window',
    name: 'Sliding Window Algorithm',
    matchKey: 'Sliding Window',
    timeComplexity: 'O(n) per sorted IP stream',
    spaceComplexity: 'O(u + w)',
    description:
      'Maintains a two-pointer window [left, right] constrained by window_minutes and a live frequency map of failed usernames inside the active window.',
    purpose:
      'Core password-spray engine identifying IPs targeting >= N distinct accounts within a short time window and flagging success-after-failure sequences.',
    pseudocode: `function SLIDING_WINDOW(ip_events, W_sec, min_users):
  left = 0; failed_map = {}
  for right in 0..n-1:
    if ip_events[right].status == FAILED:
      failed_map[ip_events[right].user] += 1
    while ip_events[right].ts - ip_events[left].ts > W_sec:
      decrement(failed_map, ip_events[left]); left += 1
    if size(failed_map) >= min_users: flag_spray_window()`,
  },
  {
    id: 'bfs',
    name: 'Breadth-First Search (BFS)',
    matchKey: 'Breadth-First Search',
    timeComplexity: 'O(V + E)',
    spaceComplexity: 'O(V)',
    description:
      'Level-order traversal over the undirected bipartite graph linking Source IP vertices and Username vertices via a FIFO queue.',
    purpose:
      'Discovers blast radius, shared targeted accounts across multiple attacking IPs, and multi-hop relationships in Network Analysis.',
    pseudocode: `function BFS(graph, start_node):
  visited = {start_node}; queue = [start_node]
  while queue not empty:
    curr = queue.pop_front()
    for neighbor in graph.adj[curr]:
      if neighbor not in visited:
        visited.add(neighbor); queue.push_back(neighbor)`,
  },
];

export function AlgorithmLab() {
  const { activeDatasetId, addToast, dataVersion } = useApp();
  const { isDark } = useTheme();

  const [selectedTab, setSelectedTab] = useState<string>('merge_sort');
  const [metrics, setMetrics] = useState<AlgorithmMetricRow[]>([]);
  const [envInfo, setEnvInfo] = useState<{ python_version: string; platform: string; architecture: string; timer: string } | null>(null);
  const [benchmarks, setBenchmarks] = useState<BenchmarkPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [benchmarking, setBenchmarking] = useState(false);

  const loadMetrics = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getAlgorithms(activeDatasetId);
      setMetrics(res.metrics);
      setEnvInfo(res.environment);
    } catch (err) {
      addToast({ type: 'error', title: 'Failed to load algorithm telemetry', message: String(err) });
    } finally {
      setLoading(false);
    }
  }, [activeDatasetId, addToast]);

  const runLiveBenchmarks = useCallback(async () => {
    setBenchmarking(true);
    try {
      const res = await api.runAlgorithmBenchmarks([100, 1000, 5000, 10000]);
      setBenchmarks(res.benchmarks);
      setEnvInfo(res.environment);
      addToast({
        type: 'success',
        title: 'DAA Benchmark Complete',
        message: 'Measured actual Python execution times for 100, 1,000, 5,000, and 10,000 records.',
      });
    } catch (err) {
      addToast({ type: 'error', title: 'Benchmark failed', message: String(err) });
    } finally {
      setBenchmarking(false);
    }
  }, [addToast]);

  useEffect(() => {
    loadMetrics();
  }, [loadMetrics, dataVersion]);

  useEffect(() => {
    // Run real measured benchmark on initial visit so academic evaluation charts show real measurements immediately
    runLiveBenchmarks();
  }, []);

  const currentDoc = ALGORITHM_DOCS.find((d) => d.id === selectedTab) || ALGORITHM_DOCS[0];
  const matchedMetric = metrics.find((m) =>
    m.algorithm_name.toLowerCase().includes(currentDoc.matchKey.toLowerCase())
  );

  const gridColor = isDark ? '#2a1a1a' : '#e4e4e7';
  const tickColor = isDark ? '#a1a1aa' : '#71717a';
  const tooltipStyle = {
    backgroundColor: isDark ? '#181313' : '#ffffff',
    borderColor: isDark ? '#332020' : '#e4e4e7',
    color: isDark ? '#fafafa' : '#18181b',
    fontSize: '12px',
  };

  return (
    <div className="space-y-6">
      {/* Header & Environment Metadata */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-5 h-5 text-red-600 dark:text-red-400" />
            <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
              DAA Algorithm Performance Lab
            </h1>
          </div>
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            Explicit Python implementations measured in real time with monotonic nanosecond precision.
            {envInfo && (
              <span className="ml-1 font-mono">
                Python {envInfo.python_version} ({envInfo.platform}/{envInfo.architecture}) · {envInfo.timer}
              </span>
            )}
          </p>
        </div>

        <button
          type="button"
          onClick={runLiveBenchmarks}
          disabled={benchmarking}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
        >
          <Play className="w-3.5 h-3.5" />
          <span>{benchmarking ? 'Running 100–10k Benchmarks...' : 'Re-run Live Benchmarks (100–10,000)'}</span>
        </button>
      </section>

      {/* Algorithm Selector & Academic Deep-Dive */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-5">
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-lg bg-slate-100 dark:bg-[#211515] w-fit">
          {ALGORITHM_DOCS.map((doc) => (
            <button
              key={doc.id}
              type="button"
              onClick={() => setSelectedTab(doc.id)}
              className={`px-3.5 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                selectedTab === doc.id
                  ? 'bg-white dark:bg-[#0D0D0D] text-red-600 dark:text-red-400 shadow-xs'
                  : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100'
              }`}
            >
              {doc.name}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 space-y-4">
            <div>
              <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-50">{currentDoc.name}</h2>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1 leading-relaxed">
                {currentDoc.description}
              </p>
            </div>
            <div>
              <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Role in Password Spray Analyzer
              </h3>
              <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">{currentDoc.purpose}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 pt-1">
              <div className="rounded-lg bg-slate-50 dark:bg-[#211515] p-3">
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400">Time Complexity</div>
                <div className="text-xs font-mono font-semibold text-red-600 dark:text-red-400 mt-0.5">
                  {currentDoc.timeComplexity}
                </div>
              </div>
              <div className="rounded-lg bg-slate-50 dark:bg-[#211515] p-3">
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400">Space Complexity</div>
                <div className="text-xs font-mono font-semibold text-zinc-900 dark:text-zinc-100 mt-0.5">
                  {currentDoc.spaceComplexity}
                </div>
              </div>
            </div>

            {matchedMetric && (
              <div className="rounded-lg border border-zinc-200 dark:border-[#332020] p-4 space-y-2">
                <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Active Dataset Measured Result
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs font-mono tabular-nums">
                  <div>
                    <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-sans">Input Size</div>
                    <div className="font-bold">{matchedMetric.input_size.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-sans">Execution Time</div>
                    <div className="font-bold text-red-600 dark:text-red-400">
                      {matchedMetric.execution_time_ms.toFixed(4)} ms
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-sans">Measured At</div>
                    <div className="truncate text-[11px]">
                      {matchedMetric.measured_at ? matchedMetric.measured_at.slice(11, 19) + 'Z' : 'Live'}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="lg:col-span-6">
            <div className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-2">Algorithm Pseudocode</div>
            <pre className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#0D0D0D] p-4 text-xs font-mono text-zinc-800 dark:text-zinc-200 overflow-x-auto leading-relaxed">
              {currentDoc.pseudocode}
            </pre>
          </div>
        </div>
      </section>

      {/* Measured Scaling Charts & Benchmark Comparison Table */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-5">
        <div>
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
            Measured Execution Time vs. Dataset Size (100 · 1,000 · 5,000 · 10,000 Records)
          </h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            Actual wall-clock timings recorded directly by the Python backend using time.perf_counter_ns()
          </p>
        </div>

        {benchmarking && benchmarks.length === 0 ? (
          <LoadingSpinner label="Benchmarking algorithms across 100 to 10,000 authentication records..." />
        ) : (
          <>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={benchmarks}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                  <XAxis dataKey="size" tick={{ fill: tickColor, fontSize: 11 }} />
                  <YAxis tick={{ fill: tickColor, fontSize: 11 }} unit=" ms" />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                  <Line type="monotone" dataKey="merge_sort_ms" name="Merge Sort O(n log n)" stroke="#DC2626" strokeWidth={2} />
                  <Line type="monotone" dataKey="sliding_window_ms" name="Sliding Window O(n)" stroke="#F59E0B" strokeWidth={2} />
                  <Line type="monotone" dataKey="hash_table_ms" name="Hash Table O(n)" stroke="#16A34A" strokeWidth={2} />
                  <Line type="monotone" dataKey="bfs_ms" name="BFS O(V+E)" stroke="#A1A1AA" strokeWidth={2} />
                  <Line type="monotone" dataKey="binary_search_ms" name="Binary Search O(log n)" stroke="#F87171" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold">Dataset Size (n)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Merge Sort (ms)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Hash Table (ms)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Binary Search (ms)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Sliding Window (ms)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">BFS (ms)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Merge Comparisons</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                  {benchmarks.map((b) => (
                    <tr key={b.size} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                      <td className="px-4 py-2.5 font-mono font-semibold tabular-nums">
                        {b.size.toLocaleString()} records
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{b.merge_sort_ms.toFixed(4)}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{b.hash_table_ms.toFixed(4)}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{b.binary_search_ms.toFixed(4)}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{b.sliding_window_ms.toFixed(4)}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{b.bfs_ms.toFixed(4)}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums text-zinc-500 dark:text-zinc-400">
                        {b.merge_comparisons.toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* Theoretical Complexity Matrix */}
        <div className="pt-2">
          <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 mb-2">
            Theoretical Complexity Reference
          </h3>
          <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                <tr>
                  <th className="px-4 py-2 font-semibold">Algorithm</th>
                  <th className="px-4 py-2 font-semibold">Best Time</th>
                  <th className="px-4 py-2 font-semibold">Average Time</th>
                  <th className="px-4 py-2 font-semibold">Worst Time</th>
                  <th className="px-4 py-2 font-semibold">Space</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-[#332020] font-mono">
                <tr>
                  <td className="px-4 py-2 font-sans font-medium">Merge Sort</td>
                  <td className="px-4 py-2">O(n log n)</td>
                  <td className="px-4 py-2">O(n log n)</td>
                  <td className="px-4 py-2">O(n log n)</td>
                  <td className="px-4 py-2">O(n)</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 font-sans font-medium">Hash Table Grouping</td>
                  <td className="px-4 py-2">O(1) lookup</td>
                  <td className="px-4 py-2">O(1) lookup</td>
                  <td className="px-4 py-2">O(n) chain</td>
                  <td className="px-4 py-2">O(n)</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 font-sans font-medium">Binary Search Range</td>
                  <td className="px-4 py-2">O(1)</td>
                  <td className="px-4 py-2">O(log n + k)</td>
                  <td className="px-4 py-2">O(log n + k)</td>
                  <td className="px-4 py-2">O(1) aux</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 font-sans font-medium">Sliding Window</td>
                  <td className="px-4 py-2">O(n)</td>
                  <td className="px-4 py-2">O(n)</td>
                  <td className="px-4 py-2">O(n)</td>
                  <td className="px-4 py-2">O(u + w)</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 font-sans font-medium">Breadth-First Search</td>
                  <td className="px-4 py-2">O(V + E)</td>
                  <td className="px-4 py-2">O(V + E)</td>
                  <td className="px-4 py-2">O(V + E)</td>
                  <td className="px-4 py-2">O(V)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
