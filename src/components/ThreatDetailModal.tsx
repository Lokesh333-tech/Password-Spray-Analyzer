import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock, ShieldAlert, Users, X } from 'lucide-react';
import { api } from '../services/api';
import type { ThreatRecord } from '../types/api';
import { SeverityBadge } from './SeverityBadge';

interface ThreatDetailModalProps {
  threatId: number | null;
  onClose: () => void;
}

export function ThreatDetailModal({ threatId, onClose }: ThreatDetailModalProps) {
  const [threat, setThreat] = useState<ThreatRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!threatId) {
      setThreat(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getThreatDetail(threatId)
      .then((res) => {
        if (!cancelled) setThreat(res.threat);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load threat details');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [threatId]);

  if (!threatId) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="threat-modal-title"
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313]">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0" />
            <div>
              <h2 id="threat-modal-title" className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
                {threat ? `Threat Alert — ${threat.source_ip}` : 'Threat Alert Details'}
              </h2>
              {threat && (
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Greedy Priority #{threat.greedy_rank} · {threat.window_minutes}-minute sliding window
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100 hover:bg-slate-100 dark:hover:bg-[#211515] transition-colors cursor-pointer"
            aria-label="Close threat detail modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {loading && <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading threat telemetry...</p>}
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

          {threat && (
            <>
              {/* Key metrics strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pb-5 border-b border-zinc-200 dark:border-[#332020]">
                <div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Heuristic Risk Score</div>
                  <div className="flex items-center gap-2.5">
                    <span className="text-2xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
                      {threat.risk_score}/100
                    </span>
                    <SeverityBadge severity={threat.severity} />
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Distinct Accounts</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-zinc-900 dark:text-zinc-50">
                    {threat.distinct_accounts}
                  </div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400">
                    Peak {threat.window_peak_accounts} in window
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Attempts (Fail / Ok)</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-zinc-900 dark:text-zinc-50">
                    {threat.total_attempts}
                  </div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 tabular-nums">
                    {threat.failed_attempts} failed · {threat.successful_attempts} succeeded
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Success After Failure</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-zinc-900 dark:text-zinc-50">
                    {threat.success_after_failure_count}
                  </div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400">
                    {threat.success_after_failure_count > 0 ? 'Potential compromise' : 'None observed'}
                  </div>
                </div>
              </div>

              {/* Detection Explanation */}
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-2">
                  Detection Rationale
                </h3>
                <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed bg-slate-50 dark:bg-[#211515] p-4 rounded-lg">
                  {threat.explanation}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-zinc-500 dark:text-zinc-400 font-mono">
                  <span className="inline-flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> First seen: {threat.first_seen}
                  </span>
                  <span>Last seen: {threat.last_seen}</span>
                  <span>Peak window: {threat.peak_window_start} → {threat.peak_window_end}</span>
                </div>
              </div>

              {/* Explainable Heuristic Score Breakdown */}
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-3">
                  Explainable Heuristic Score Breakdown (Deterministic Weights)
                </h3>
                <div className="space-y-3">
                  {threat.score_breakdown.map((item) => {
                    const pct = Math.round((item.points / item.max_points) * 100);
                    return (
                      <div key={item.factor} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium text-zinc-800 dark:text-zinc-200">{item.factor}</span>
                          <span className="font-mono tabular-nums text-zinc-600 dark:text-zinc-400">
                            {item.points} / {item.max_points} pts
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-slate-100 dark:bg-[#211515] overflow-hidden">
                          <div
                            className="h-full rounded-full bg-red-600 dark:bg-red-500 transition-all"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <p className="text-xs text-zinc-500 dark:text-zinc-400">{item.detail}</p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Targeted Accounts */}
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-3 flex items-center gap-2">
                  <Users className="w-4 h-4 text-red-600 dark:text-red-400" />
                  <span>Targeted User Accounts ({threat.targeted_accounts?.length || 0})</span>
                </h3>
                <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                      <tr>
                        <th className="px-3 py-2.5 font-semibold">Username</th>
                        <th className="px-3 py-2.5 font-semibold text-right">Attempts</th>
                        <th className="px-3 py-2.5 font-semibold text-right">Failed</th>
                        <th className="px-3 py-2.5 font-semibold text-right">Succeeded</th>
                        <th className="px-3 py-2.5 font-semibold">Compromise Indicator</th>
                        <th className="px-3 py-2.5 font-semibold">Last Attempt</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                      {(threat.targeted_accounts || []).map((acc) => (
                        <tr key={acc.username} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                          <td className="px-3 py-2 font-mono font-medium text-zinc-900 dark:text-zinc-100">
                            {acc.username}
                          </td>
                          <td className="px-3 py-2 text-right font-mono tabular-nums">{acc.total_attempts}</td>
                          <td className="px-3 py-2 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                            {acc.failed_attempts}
                          </td>
                          <td className="px-3 py-2 text-right font-mono tabular-nums text-green-600 dark:text-green-400">
                            {acc.successful_attempts}
                          </td>
                          <td className="px-3 py-2">
                            {acc.had_success_after_failure ? (
                              <span className="inline-flex items-center gap-1 font-semibold text-red-600 dark:text-red-400">
                                <AlertTriangle className="w-3.5 h-3.5" />
                                Success after {acc.failures_before_success} failure(s)
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-zinc-500 dark:text-zinc-400">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                Blocked / Failed only
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2 font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">
                            {acc.last_attempt}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
