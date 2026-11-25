import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Radar, ShieldAlert, UserCheck } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { EmptyState } from '../components/EmptyState';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/ShieldLogo';
import { ThreatDetailModal } from '../components/ThreatDetailModal';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';
import { api } from '../services/api';
import type { TargetedAccountRow, ThreatRecord } from '../types/api';

export function ThreatIntelligence() {
  const { activeDatasetId, addToast, dataVersion } = useApp();
  const { isDark } = useTheme();

  const [loading, setLoading] = useState(true);
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [targeted, setTargeted] = useState<TargetedAccountRow[]>([]);
  const [safEvents, setSafEvents] = useState<TargetedAccountRow[]>([]);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null);

  const loadIntel = useCallback(async () => {
    if (!activeDatasetId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await api.getThreats({ datasetId: activeDatasetId });
      setThreats(res.threats);
      setTargeted(res.targeted_accounts);
      setSafEvents(res.success_after_failure);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to load threat intelligence',
        message: err instanceof Error ? err.message : 'Error',
      });
    } finally {
      setLoading(false);
    }
  }, [activeDatasetId, addToast]);

  useEffect(() => {
    loadIntel();
  }, [loadIntel, dataVersion]);

  if (!activeDatasetId && !loading) {
    return <EmptyState onLoaded={loadIntel} />;
  }

  if (loading) {
    return <LoadingSpinner label="Aggregating threat intelligence..." />;
  }

  const severityCounts = ['Critical', 'High', 'Medium', 'Low'].map((sev) => ({
    severity: sev,
    count: threats.filter((t) => t.severity === sev).length,
  }));

  const sevColors: Record<string, string> = {
    Critical: '#DC2626',
    High: '#EF4444',
    Medium: '#D97706',
    Low: '#71717A',
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Radar className="w-5 h-5 text-red-600 dark:text-red-400" />
          <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
            Threat Intelligence & Compromise Triage
          </h1>
        </div>
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          Cross-account spray intelligence, repeated failure velocities, and success-after-failure compromise indicators.
        </p>
      </section>

      {/* Success-After-Failure High-Priority Compromise Indicators */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              Success-After-Failure Patterns (Potential Credential Compromise)
            </h2>
          </div>
          <span className="text-xs font-mono tabular-nums text-red-600 dark:text-red-400 font-semibold">
            {safEvents.length} pattern(s)
          </span>
        </div>

        {safEvents.length === 0 ? (
          <p className="text-xs text-zinc-500 dark:text-zinc-400 py-3">
            No accounts exhibited a successful authentication following failed spray attempts.
          </p>
        ) : (
          <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                <tr>
                  <th className="px-4 py-2.5 font-semibold">Compromised Username</th>
                  <th className="px-4 py-2.5 font-semibold">Attacking Source IP</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Failures Before Success</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Total Failures</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Successful Logins</th>
                  <th className="px-4 py-2.5 font-semibold">Last Observed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                {safEvents.map((ev, idx) => (
                  <tr key={`${ev.username}_${ev.source_ip}_${idx}`} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                    <td className="px-4 py-2.5 font-mono font-semibold text-red-600 dark:text-red-400">
                      {ev.username}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-zinc-900 dark:text-zinc-100">{ev.source_ip}</td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums font-bold">
                      {ev.failures_before_success ?? ev.failed_attempts}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                      {ev.failed_attempts}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums text-green-600 dark:text-green-400">
                      {ev.successful_attempts}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">
                      {ev.last_attempt}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Top Suspicious IP Intelligence */}
        <section className="lg:col-span-7 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              Top Suspicious IP Addresses & Attack Frequency
            </h2>
          </div>
          <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                <tr>
                  <th className="px-3.5 py-2.5 font-semibold">Source IP</th>
                  <th className="px-3.5 py-2.5 font-semibold">Severity</th>
                  <th className="px-3.5 py-2.5 font-semibold text-right">Score</th>
                  <th className="px-3.5 py-2.5 font-semibold text-right">Distinct Users</th>
                  <th className="px-3.5 py-2.5 font-semibold text-right">Repeated Failures</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                {threats.map((t) => (
                  <tr
                    key={t.id}
                    onClick={() => setSelectedThreatId(t.id)}
                    className="hover:bg-slate-50 dark:hover:bg-[#211515]/60 cursor-pointer"
                  >
                    <td className="px-3.5 py-2.5 font-mono font-semibold text-zinc-900 dark:text-zinc-100">
                      {t.source_ip}
                    </td>
                    <td className="px-3.5 py-2.5">
                      <SeverityBadge severity={t.severity} />
                    </td>
                    <td className="px-3.5 py-2.5 text-right font-mono font-bold tabular-nums text-red-600 dark:text-red-400">
                      {t.risk_score}
                    </td>
                    <td className="px-3.5 py-2.5 text-right font-mono tabular-nums">{t.distinct_accounts}</td>
                    <td className="px-3.5 py-2.5 text-right font-mono tabular-nums">{t.failed_attempts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Threat Severity Breakdown Chart */}
        <section className="lg:col-span-5 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6">
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-1">
            Threat Severity Distribution
          </h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-4">Active threat alerts by severity tier</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityCounts}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#2a1a1a' : '#e4e4e7'} />
                <XAxis dataKey="severity" tick={{ fill: isDark ? '#a1a1aa' : '#71717a', fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fill: isDark ? '#a1a1aa' : '#71717a', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#181313' : '#ffffff',
                    borderColor: isDark ? '#332020' : '#e4e4e7',
                    color: isDark ? '#fafafa' : '#18181b',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" name="Threats" radius={[6, 6, 0, 0]}>
                  {severityCounts.map((s) => (
                    <Cell key={s.severity} fill={sevColors[s.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      {/* Most Targeted User Accounts */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
        <div className="flex items-center gap-2">
          <UserCheck className="w-4 h-4 text-red-600 dark:text-red-400" />
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
            Most Targeted User Accounts ({targeted.length})
          </h2>
        </div>
        <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
              <tr>
                <th className="px-4 py-2.5 font-semibold">Username</th>
                <th className="px-4 py-2.5 font-semibold text-right">Attacking IPs</th>
                <th className="px-4 py-2.5 font-semibold text-right">Total Attempts</th>
                <th className="px-4 py-2.5 font-semibold text-right">Failed</th>
                <th className="px-4 py-2.5 font-semibold text-right">Succeeded</th>
                <th className="px-4 py-2.5 font-semibold">Post-Failure Success</th>
                <th className="px-4 py-2.5 font-semibold">Last Targeted</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
              {targeted.slice(0, 25).map((acc) => (
                <tr key={acc.username} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                  <td className="px-4 py-2.5 font-mono font-medium text-zinc-900 dark:text-zinc-100">
                    {acc.username}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono tabular-nums">{acc.attacking_ips ?? 1}</td>
                  <td className="px-4 py-2.5 text-right font-mono tabular-nums">{acc.total_attempts}</td>
                  <td className="px-4 py-2.5 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                    {acc.failed_attempts}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono tabular-nums text-green-600 dark:text-green-400">
                    {acc.successful_attempts}
                  </td>
                  <td className="px-4 py-2.5">
                    {acc.had_success_after_failure ? (
                      <span className="font-semibold text-red-600 dark:text-red-400">Compromise Indicator</span>
                    ) : (
                      <span className="text-zinc-500 dark:text-zinc-400">Blocked</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">
                    {acc.last_attempt}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <ThreatDetailModal threatId={selectedThreatId} onClose={() => setSelectedThreatId(null)} />
    </div>
  );
}
