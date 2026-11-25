import React, { useCallback, useEffect, useState } from 'react';
import { Eye, Play, Search, ShieldAlert } from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/ShieldLogo';
import { ThreatDetailModal } from '../components/ThreatDetailModal';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import type { ThreatRecord } from '../types/api';

const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low'];

export function AttackDetection() {
  const { activeDatasetId, globalSearch, addToast, dataVersion, bumpDataVersion } = useApp();

  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  // Sliding window threshold configuration
  const [windowMinutes, setWindowMinutes] = useState(10);
  const [minAccounts, setMinAccounts] = useState(8);

  // Filters
  const [severity, setSeverity] = useState('All');
  const [search, setSearch] = useState(globalSearch);
  const [ipFilter, setIpFilter] = useState('');
  const [accountFilter, setAccountFilter] = useState('');
  const [startFilter, setStartFilter] = useState('');
  const [endFilter, setEndFilter] = useState('');
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null);

  useEffect(() => {
    setSearch(globalSearch);
  }, [globalSearch]);

  useEffect(() => {
    api
      .getSettings()
      .then((res) => {
        setWindowMinutes(res.settings.window_minutes);
        setMinAccounts(res.settings.min_distinct_accounts);
      })
      .catch(() => {});
  }, []);

  const loadThreats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getThreats({
        datasetId: activeDatasetId,
        severity,
        ip: ipFilter,
        account: accountFilter,
        search,
        start: startFilter,
        end: endFilter,
      });
      setThreats(res.threats);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to load threat detections',
        message: err instanceof Error ? err.message : 'Error',
      });
    } finally {
      setLoading(false);
    }
  }, [activeDatasetId, severity, ipFilter, accountFilter, search, startFilter, endFilter, addToast]);

  useEffect(() => {
    loadThreats();
  }, [loadThreats, dataVersion]);

  const handleRunSlidingWindow = async () => {
    if (!activeDatasetId) return;
    setRunning(true);
    try {
      const res = await api.runAnalysis({
        dataset_id: activeDatasetId,
        window_minutes: windowMinutes,
        min_distinct_accounts: minAccounts,
      });
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'Sliding Window Detection Complete',
        message: `Detected ${res.suspicious_ip_count ?? 0} suspicious IP(s) within ${windowMinutes}m window.`,
      });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Detection run failed',
        message: err instanceof Error ? err.message : 'Invalid parameters',
      });
    } finally {
      setRunning(false);
    }
  };

  if (!activeDatasetId && !loading) {
    return <EmptyState onLoaded={loadThreats} />;
  }

  return (
    <div className="space-y-6">
      {/* Sliding Window Engine Parameters Bar */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400" />
              <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
                Sliding Window Attack Detection Engine
              </h1>
            </div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Evaluates per-IP chronological authentication streams using a two-pointer sliding window and greedy heuristic scoring (0–100).
            </p>
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label
                htmlFor="sw-window-min"
                className="block text-[11px] font-medium text-zinc-600 dark:text-zinc-400 mb-1"
              >
                Window (minutes)
              </label>
              <input
                id="sw-window-min"
                type="number"
                min={1}
                max={1440}
                value={windowMinutes}
                onChange={(e) => setWindowMinutes(Number(e.target.value))}
                className="w-28 px-3 py-1.5 text-xs font-mono tabular-nums rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
              />
            </div>

            <div>
              <label
                htmlFor="sw-min-accounts"
                className="block text-[11px] font-medium text-zinc-600 dark:text-zinc-400 mb-1"
              >
                Min Distinct Accounts
              </label>
              <input
                id="sw-min-accounts"
                type="number"
                min={2}
                max={500}
                value={minAccounts}
                onChange={(e) => setMinAccounts(Number(e.target.value))}
                className="w-32 px-3 py-1.5 text-xs font-mono tabular-nums rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
              />
            </div>

            <button
              type="button"
              onClick={handleRunSlidingWindow}
              disabled={running || !activeDatasetId}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{running ? 'Detecting...' : 'Re-run Sliding Window'}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Filter Toolbar */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Severity Segmented Filter */}
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#211515]">
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverity(sev)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  severity === sev
                    ? 'bg-white dark:bg-[#0D0D0D] text-red-600 dark:text-red-400 shadow-xs'
                    : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 top-2.5 pointer-events-none" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search alerts..."
                className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
              />
            </div>
            <input
              type="text"
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              placeholder="Filter IP"
              className="w-32 px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
            <input
              type="text"
              value={accountFilter}
              onChange={(e) => setAccountFilter(e.target.value)}
              placeholder="Filter Account"
              className="w-36 px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
            <input
              type="text"
              value={startFilter}
              onChange={(e) => setStartFilter(e.target.value)}
              placeholder="From ISO date"
              className="w-36 px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
            <input
              type="text"
              value={endFilter}
              onChange={(e) => setEndFilter(e.target.value)}
              placeholder="To ISO date"
              className="w-36 px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>
        </div>

        {/* Threat Detections Table */}
        {loading ? (
          <LoadingSpinner label="Evaluating threat detections..." />
        ) : threats.length === 0 ? (
          <div className="py-12 text-center text-sm text-zinc-500 dark:text-zinc-400">
            No suspicious IP addresses matched your filter criteria or detection threshold.
          </div>
        ) : (
          <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                <tr>
                  <th className="px-4 py-3 font-semibold">Priority</th>
                  <th className="px-4 py-3 font-semibold">Suspicious Source IP</th>
                  <th className="px-4 py-3 font-semibold text-right">Total</th>
                  <th className="px-4 py-3 font-semibold text-right">Failed</th>
                  <th className="px-4 py-3 font-semibold text-right">Success</th>
                  <th className="px-4 py-3 font-semibold text-right">Distinct Accounts</th>
                  <th className="px-4 py-3 font-semibold">First / Last Observed</th>
                  <th className="px-4 py-3 font-semibold text-right">Window</th>
                  <th className="px-4 py-3 font-semibold text-right">Risk Score</th>
                  <th className="px-4 py-3 font-semibold">Severity</th>
                  <th className="px-4 py-3 font-semibold text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                {threats.map((t) => (
                  <tr
                    key={t.id}
                    onClick={() => setSelectedThreatId(t.id)}
                    className="hover:bg-slate-50 dark:hover:bg-[#211515]/70 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 font-mono tabular-nums text-zinc-500 dark:text-zinc-400">
                      #{t.greedy_rank}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-mono font-semibold text-zinc-900 dark:text-zinc-100">{t.source_ip}</div>
                      <div className="text-[11px] text-zinc-500 dark:text-zinc-400 max-w-xs truncate mt-0.5">
                        {t.explanation}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums">{t.total_attempts}</td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                      {t.failed_attempts}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-green-600 dark:text-green-400">
                      {t.successful_attempts}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums font-semibold">
                      {t.distinct_accounts}{' '}
                      <span className="text-[11px] font-normal text-zinc-500 dark:text-zinc-400">
                        ({t.window_peak_accounts} peak)
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
                      <div>{t.first_seen}</div>
                      <div>{t.last_seen}</div>
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums">{t.window_minutes}m</td>
                    <td className="px-4 py-3 text-right font-mono font-bold tabular-nums text-red-600 dark:text-red-400">
                      {t.risk_score}/100
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={t.severity} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedThreatId(t.id);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium border border-zinc-200 dark:border-[#332020] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] text-zinc-800 dark:text-zinc-200 cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <ThreatDetailModal threatId={selectedThreatId} onClose={() => setSelectedThreatId(null)} />
    </div>
  );
}
