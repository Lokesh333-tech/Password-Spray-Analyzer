import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  FileDown,
  Play,
  ShieldAlert,
  Upload,
  XCircle,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { AnimatedCounter } from '../components/AnimatedCounter';
import { EmptyState } from '../components/EmptyState';
import { SeverityBadge } from '../components/SeverityBadge';
import { ShieldLogo, SkeletonGrid } from '../components/ShieldLogo';
import { ThreatDetailModal } from '../components/ThreatDetailModal';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';
import { api } from '../services/api';
import type { DashboardResponse } from '../types/api';

export function OverviewDashboard() {
  const { activeDatasetId, setActiveDatasetId, refreshDatasets, addToast, dataVersion, bumpDataVersion } = useApp();
  const { isDark } = useTheme();
  const navigate = useNavigate();

  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getDashboard(activeDatasetId);
      setData(res);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to load dashboard',
        message: err instanceof Error ? err.message : 'Unable to reach analysis engine',
      });
    } finally {
      setLoading(false);
    }
  }, [activeDatasetId, addToast]);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard, dataVersion]);

  const handleLoadSample = async () => {
    setBusyAction('sample');
    try {
      const res = await api.loadSampleDataset();
      await refreshDatasets(res.dataset_id);
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'Synthetic dataset analyzed',
        message: `${res.valid_rows} events processed and saved to SQLite.`,
      });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Sample load failed',
        message: err instanceof Error ? err.message : 'Error',
      });
    } finally {
      setBusyAction(null);
    }
  };

  const handleRerunDetection = async () => {
    if (!activeDatasetId) return;
    setBusyAction('analyze');
    try {
      const res = await api.runAnalysis({ dataset_id: activeDatasetId });
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'Detection pipeline completed',
        message: `Identified ${res.suspicious_ip_count ?? 0} suspicious IP address(es).`,
      });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Analysis failed',
        message: err instanceof Error ? err.message : 'Error',
      });
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportPdf = async () => {
    if (!activeDatasetId) return;
    setBusyAction('pdf');
    try {
      await api.exportReport({ dataset_id: activeDatasetId, format: 'pdf' });
      addToast({ type: 'success', title: 'Security PDF report downloaded' });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Export failed',
        message: err instanceof Error ? err.message : 'Error',
      });
    } finally {
      setBusyAction(null);
    }
  };

  const gridColor = isDark ? '#2a1a1a' : '#e4e4e7';
  const tickColor = isDark ? '#a1a1aa' : '#71717a';
  const tooltipStyle = {
    backgroundColor: isDark ? '#181313' : '#ffffff',
    borderColor: isDark ? '#332020' : '#e4e4e7',
    color: isDark ? '#fafafa' : '#18181b',
    borderRadius: '0.5rem',
    fontSize: '12px',
  };

  const sevColors: Record<string, string> = {
    Critical: '#DC2626',
    High: '#EF4444',
    Medium: '#D97706',
    Low: isDark ? '#71717A' : '#A1A1AA',
  };

  return (
    <div className="space-y-6">
      {/* Welcome Banner & Quick Actions */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
        <div className="flex items-start sm:items-center gap-4">
          <ShieldLogo size={46} className="shrink-0" />
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
              Password Spray Analyzer
            </h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-0.5">
              Intelligent Authentication Threat Detection · Sliding Window, Merge Sort, Hash Table & Bipartite BFS
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => navigate('/logs')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Logs</span>
          </button>
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] text-zinc-900 dark:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
          >
            <Database className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
            <span>{busyAction === 'sample' ? 'Loading Sample...' : 'Load Sample Dataset'}</span>
          </button>
          {data?.has_data && (
            <>
              <button
                type="button"
                onClick={handleRerunDetection}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] hover:bg-slate-50 dark:hover:bg-[#211515] text-zinc-900 dark:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
              >
                <Play className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
                <span>{busyAction === 'analyze' ? 'Analyzing...' : 'Run Detection'}</span>
              </button>
              <button
                type="button"
                onClick={handleExportPdf}
                disabled={busyAction !== null}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] hover:bg-slate-50 dark:hover:bg-[#211515] text-zinc-900 dark:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
              >
                <FileDown className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
                <span>{busyAction === 'pdf' ? 'Exporting...' : 'Export PDF'}</span>
              </button>
            </>
          )}
        </div>
      </section>

      {loading ? (
        <SkeletonGrid count={5} />
      ) : !data?.has_data ? (
        <EmptyState onLoaded={loadDashboard} />
      ) : (
        <>
          {/* Top 5 KPI Cards */}
          <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" aria-label="Security key metrics">
            <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-3">
                <span>Total Authentication Events</span>
                <Activity className="w-4 h-4 text-zinc-400" />
              </div>
              <div className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
                <AnimatedCounter value={data.kpis.total_events} />
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1.5 truncate">
                {data.dataset?.name}
              </div>
            </div>

            <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-3">
                <span>Failed Login Attempts</span>
                <XCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                <AnimatedCounter value={data.kpis.failed_attempts} />
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1.5 tabular-nums">
                {data.kpis.total_events > 0
                  ? `${((data.kpis.failed_attempts / data.kpis.total_events) * 100).toFixed(1)}% failure rate`
                  : '0%'}
              </div>
            </div>

            <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-3">
                <span>Successful Login Attempts</span>
                <CheckCircle2 className="w-4 h-4 text-green-600 dark:text-green-400" />
              </div>
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                <AnimatedCounter value={data.kpis.successful_attempts} />
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1.5 tabular-nums">
                {data.kpis.total_events > 0
                  ? `${((data.kpis.successful_attempts / data.kpis.total_events) * 100).toFixed(1)}% success rate`
                  : '0%'}
              </div>
            </div>

            <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-3">
                <span>Suspicious IP Addresses</span>
                <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              </div>
              <div className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
                <AnimatedCounter value={data.kpis.suspicious_ips} />
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1.5">
                Flagged by Sliding Window
              </div>
            </div>

            <div
              className={`rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5 ${
                data.kpis.critical_alerts > 0 ? 'psa-critical-glow' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-3">
                <span>Critical Threat Alerts</span>
                <AlertOctagon className="w-4 h-4 text-red-600 dark:text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                <AnimatedCounter value={data.kpis.critical_alerts} />
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1.5">
                Risk score 80–100
              </div>
            </div>
          </section>

          {/* Primary Charts Grid (Row 1: Timeline + Status Distribution + Severity Distribution) */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-6 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                    Authentication Activity Timeline
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    Chronological volume sorted via Merge Sort
                  </p>
                </div>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data.charts.timeline}>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                    <XAxis dataKey="time" tick={{ fill: tickColor, fontSize: 11 }} />
                    <YAxis tick={{ fill: tickColor, fontSize: 11 }} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: '12px' }} />
                    <Area
                      type="monotone"
                      dataKey="failed"
                      name="Failed"
                      stroke="#DC2626"
                      fill="#DC2626"
                      fillOpacity={isDark ? 0.28 : 0.16}
                    />
                    <Area
                      type="monotone"
                      dataKey="success"
                      name="Successful"
                      stroke={isDark ? '#22C55E' : '#16A34A'}
                      fill={isDark ? '#22C55E' : '#16A34A'}
                      fillOpacity={0.14}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="lg:col-span-3 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Success vs Failure Distribution
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">Authentication outcome ratio</p>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={data.charts.status_distribution}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={52}
                      outerRadius={78}
                      paddingAngle={3}
                    >
                      <Cell fill={isDark ? '#22C55E' : '#16A34A'} />
                      <Cell fill="#DC2626" />
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: '12px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="lg:col-span-3 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Threat Severity Distribution
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">Detected IPs by risk tier</p>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.charts.severity_distribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                    <XAxis dataKey="severity" tick={{ fill: tickColor, fontSize: 11 }} />
                    <YAxis allowDecimals={false} tick={{ fill: tickColor, fontSize: 11 }} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="count" name="Threats" radius={[6, 6, 0, 0]}>
                      {data.charts.severity_distribution.map((entry) => (
                        <Cell key={entry.severity} fill={sevColors[entry.severity] || '#DC2626'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </section>

          {/* Secondary Charts Grid (Row 2: Top Suspicious IPs + Most Targeted Accounts + Hourly Activity) */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-4 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Top Suspicious IP Addresses
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">Ranked by heuristic risk score (0–100)</p>
              <div className="h-64">
                {data.charts.top_suspicious_ips.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-zinc-500 dark:text-zinc-400">
                    No suspicious IPs detected
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.charts.top_suspicious_ips} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                      <XAxis type="number" domain={[0, 100]} tick={{ fill: tickColor, fontSize: 11 }} />
                      <YAxis dataKey="ip" type="category" width={112} tick={{ fill: tickColor, fontSize: 11 }} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="risk_score" name="Risk Score" fill="#EF4444" radius={[0, 6, 6, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="lg:col-span-4 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Most Targeted User Accounts
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">Accounts with highest spray failure count</p>
              <div className="h-64">
                {data.charts.top_targeted_accounts.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-zinc-500 dark:text-zinc-400">
                    No targeted account telemetry
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.charts.top_targeted_accounts}>
                      <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                      <XAxis dataKey="username" tick={{ fill: tickColor, fontSize: 10 }} />
                      <YAxis allowDecimals={false} tick={{ fill: tickColor, fontSize: 11 }} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="failed_attempts" name="Failed Attempts" fill="#DC2626" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="lg:col-span-4 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
                Hourly Login Activity
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">UTC 24-hour distribution</p>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.charts.hourly_activity}>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                    <XAxis dataKey="label" tick={{ fill: tickColor, fontSize: 10 }} interval={3} />
                    <YAxis allowDecimals={false} tick={{ fill: tickColor, fontSize: 11 }} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: '12px' }} />
                    <Bar dataKey="failed" name="Failed" stackId="a" fill="#DC2626" />
                    <Bar dataKey="success" name="Success" stackId="a" fill={isDark ? '#22C55E' : '#16A34A'} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </section>

          {/* Bottom Grid: Recent Security Alerts + Algorithm Processing Summary + Datasets */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Recent Security Alerts */}
            <div className="lg:col-span-6 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                    Recent Security Alerts
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">Greedy-prioritized threat queue</p>
                </div>
                <button
                  type="button"
                  onClick={() => navigate('/detection')}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                >
                  <span>View all</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {data.recent_alerts.length === 0 ? (
                <p className="text-xs text-zinc-500 dark:text-zinc-400 py-6">
                  No password-spraying threats detected in the current dataset.
                </p>
              ) : (
                <div className="divide-y divide-zinc-200 dark:divide-[#332020]">
                  {data.recent_alerts.map((alert) => (
                    <div
                      key={alert.id}
                      onClick={() => setSelectedThreatId(alert.id)}
                      className="py-3 flex items-center justify-between gap-4 hover:bg-slate-50 dark:hover:bg-[#211515]/70 px-2 rounded-lg transition-colors cursor-pointer"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2.5">
                          <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                            {alert.source_ip}
                          </span>
                          <SeverityBadge severity={alert.severity} />
                        </div>
                        <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5 tabular-nums">
                          {alert.distinct_accounts} distinct accounts · {alert.failed_attempts} failures ·{' '}
                          {alert.success_after_failure_count} post-failure logins
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="text-sm font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
                          {alert.risk_score}/100
                        </div>
                        <div className="text-[11px] text-zinc-500 dark:text-zinc-400">Rank #{alert.greedy_rank}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Algorithm Processing Summary & Latest Datasets */}
            <div className="lg:col-span-6 space-y-5">
              <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-red-600 dark:text-red-400" />
                    <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                      Algorithm Processing Summary
                    </h2>
                  </div>
                  <button
                    type="button"
                    onClick={() => navigate('/algorithms')}
                    className="text-xs font-semibold text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                  >
                    Open Algorithm Lab
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-zinc-500 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                      <tr>
                        <th className="py-2 font-medium">Algorithm</th>
                        <th className="py-2 font-medium text-right">Size (n)</th>
                        <th className="py-2 font-medium text-right">Time (ms)</th>
                        <th className="py-2 font-medium text-right">Complexity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                      {data.algorithm_metrics.map((m, i) => (
                        <tr key={`${m.algorithm_name}_${i}`}>
                          <td className="py-2 font-medium text-zinc-900 dark:text-zinc-100">{m.algorithm_name}</td>
                          <td className="py-2 text-right font-mono tabular-nums">{m.input_size.toLocaleString()}</td>
                          <td className="py-2 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                            {m.execution_time_ms.toFixed(4)}
                          </td>
                          <td className="py-2 text-right font-mono text-zinc-500 dark:text-zinc-400">
                            {m.time_complexity}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5">
                <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-3">
                  Latest Uploaded Datasets
                </h2>
                <div className="divide-y divide-zinc-200 dark:divide-[#332020]">
                  {data.datasets.map((ds) => (
                    <div
                      key={ds.id}
                      onClick={() => setActiveDatasetId(ds.id)}
                      className="py-2.5 flex items-center justify-between gap-3 cursor-pointer hover:bg-slate-50 dark:hover:bg-[#211515]/60 px-2 rounded-lg transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                          {ds.name}
                          {ds.id === data.dataset?.id && (
                            <span className="ml-2 text-[11px] font-medium text-red-600 dark:text-red-400">
                              (Active)
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-mono tabular-nums">
                          {ds.valid_row_count.toLocaleString()} records · {ds.duplicate_count} duplicates
                        </div>
                      </div>
                      <span className="text-xs font-mono tabular-nums text-zinc-600 dark:text-zinc-300 shrink-0">
                        {ds.suspicious_ip_count ?? 0} threats
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        </>
      )}

      <ThreatDetailModal threatId={selectedThreatId} onClose={() => setSelectedThreatId(null)} />
    </div>
  );
}
