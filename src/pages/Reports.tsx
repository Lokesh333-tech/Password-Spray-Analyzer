import React, { useCallback, useEffect, useState } from 'react';
import { FileDown, FileSpreadsheet, FileText } from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { LoadingSpinner, ShieldLogo } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import type { ReportEntry } from '../types/api';

export function Reports() {
  const { activeDatasetId, activeDataset, addToast, dataVersion } = useApp();

  const [reports, setReports] = useState<ReportEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [startFilter, setStartFilter] = useState('');
  const [endFilter, setEndFilter] = useState('');
  const [exporting, setExporting] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getReports({
        severity: severityFilter,
        start: startFilter,
        end: endFilter,
      });
      setReports(res.reports);
    } catch (err) {
      addToast({ type: 'error', title: 'Failed to load reports', message: String(err) });
    } finally {
      setLoading(false);
    }
  }, [severityFilter, startFilter, endFilter, addToast]);

  useEffect(() => {
    loadReports();
  }, [loadReports, dataVersion]);

  const handleExport = async (datasetId: number, format: 'pdf' | 'csv') => {
    const key = `${datasetId}_${format}`;
    setExporting(key);
    try {
      await api.exportReport({
        dataset_id: datasetId,
        format,
        severity: severityFilter,
      });
      addToast({
        type: 'success',
        title: `${format.toUpperCase()} security report downloaded`,
      });
    } catch (err) {
      addToast({ type: 'error', title: 'Export failed', message: String(err) });
    } finally {
      setExporting(null);
    }
  };

  if (!activeDatasetId && reports.length === 0 && !loading) {
    return <EmptyState onLoaded={loadReports} />;
  }

  return (
    <div className="space-y-6">
      {/* Header & Active Report Export Card */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <ShieldLogo size={40} className="shrink-0" />
            <div>
              <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
                Security Report Center
              </h1>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Generate and download branded PDF and CSV reports containing dataset metrics, suspicious IPs, targeted accounts, and DAA execution telemetry.
              </p>
            </div>
          </div>

          {activeDataset && (
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => handleExport(activeDataset.id, 'pdf')}
                disabled={exporting !== null}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>{exporting === `${activeDataset.id}_pdf` ? 'Generating PDF...' : 'Download PDF Report'}</span>
              </button>
              <button
                type="button"
                onClick={() => handleExport(activeDataset.id, 'csv')}
                disabled={exporting !== null}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] text-zinc-900 dark:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
                <span>{exporting === `${activeDataset.id}_csv` ? 'Generating CSV...' : 'Download CSV Report'}</span>
              </button>
            </div>
          )}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 pt-4 border-t border-zinc-200 dark:border-[#332020]">
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#211515]">
            {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-white dark:bg-[#0D0D0D] text-red-600 dark:text-red-400 shadow-xs'
                    : 'text-zinc-600 dark:text-zinc-400'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={startFilter}
            onChange={(e) => setStartFilter(e.target.value)}
            placeholder="Filter from date (YYYY-MM-DD)"
            className="px-3 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
          />
          <input
            type="text"
            value={endFilter}
            onChange={(e) => setEndFilter(e.target.value)}
            placeholder="Filter to date (YYYY-MM-DD)"
            className="px-3 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
          />
        </div>
      </section>

      {/* Previous Analysis Reports Table */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-red-600 dark:text-red-400" />
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
            Analysis Runs & Downloadable Reports ({reports.length})
          </h2>
        </div>

        {loading ? (
          <LoadingSpinner label="Loading security report archive..." />
        ) : reports.length === 0 ? (
          <p className="text-xs text-zinc-500 dark:text-zinc-400 py-8 text-center">
            No analysis reports matched the selected severity or date filters.
          </p>
        ) : (
          <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                <tr>
                  <th className="px-4 py-2.5 font-semibold">Dataset</th>
                  <th className="px-4 py-2.5 font-semibold">Analyzed At (UTC)</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Events</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Suspicious IPs</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Critical / High</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Avg Score</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Exports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                {reports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                    <td className="px-4 py-2.5">
                      <div className="font-semibold text-zinc-900 dark:text-zinc-100">{rep.dataset_name}</div>
                      <div className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400">
                        {rep.window_minutes}m window · min {rep.min_distinct_accounts} accts
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono tabular-nums text-zinc-500 dark:text-zinc-400">
                      {rep.executed_at}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums">
                      {rep.total_events.toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums font-semibold">
                      {rep.suspicious_ip_count}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                      {rep.critical_alert_count} / {rep.high_alert_count}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono tabular-nums">{rep.avg_risk_score}</td>
                    <td className="px-4 py-2.5 text-right">
                      <div className="inline-flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleExport(rep.dataset_id, 'pdf')}
                          disabled={exporting !== null}
                          className="px-2.5 py-1 rounded-md text-xs font-medium bg-red-600 hover:bg-red-700 text-white cursor-pointer disabled:opacity-50"
                        >
                          PDF
                        </button>
                        <button
                          type="button"
                          onClick={() => handleExport(rep.dataset_id, 'csv')}
                          disabled={exporting !== null}
                          className="px-2.5 py-1 rounded-md text-xs font-medium border border-zinc-200 dark:border-[#332020] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] cursor-pointer disabled:opacity-50"
                        >
                          CSV
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
