import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  ArrowUpDown,
  CheckCircle2,
  Database,
  FileSpreadsheet,
  Hash,
  Search,
  Upload,
} from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { LoadingSpinner } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import type { LogsResponse } from '../types/api';

export function LogAnalyzer() {
  const { activeDatasetId, refreshDatasets, addToast, globalSearch, dataVersion, bumpDataVersion } = useApp();

  const [data, setData] = useState<LogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const [uploadReport, setUploadReport] = useState<{
    filename: string;
    total_rows: number;
    valid_rows: number;
    duplicate_rows: number;
    invalid_rows: number;
    validation_errors: Array<{ row: number; field: string; value?: string; message: string }>;
    parser_engine?: string;
  } | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Binary search & filter state
  const [startFilter, setStartFilter] = useState('');
  const [endFilter, setEndFilter] = useState('');
  const [searchFilter, setSearchFilter] = useState(globalSearch);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [ipFilter, setIpFilter] = useState('');
  const [page, setPage] = useState(1);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    setSearchFilter(globalSearch);
  }, [globalSearch]);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getLogs({
        datasetId: activeDatasetId,
        start: startFilter,
        end: endFilter,
        search: searchFilter,
        status: statusFilter,
        ip: ipFilter,
        page,
        pageSize: 25,
      });
      setData(res);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to load authentication logs',
        message: err instanceof Error ? err.message : 'Unexpected error',
      });
    } finally {
      setLoading(false);
    }
  }, [activeDatasetId, startFilter, endFilter, searchFilter, statusFilter, ipFilter, page, addToast]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs, dataVersion]);

  const processFileUpload = async (file: File) => {
    setUploadError(null);
    setUploadReport(null);

    if (!file.name.toLowerCase().endsWith('.csv')) {
      setUploadError('Invalid file format. Please upload a .csv file.');
      return;
    }
    if (file.size === 0) {
      setUploadError('The selected CSV file is empty.');
      return;
    }
    if (file.size > 25 * 1024 * 1024) {
      setUploadError('File exceeds the 25 MB upload limit.');
      return;
    }

    setUploading(true);
    setUploadProgress(5);
    try {
      const res = await api.uploadCsv(file, undefined, (pct) => setUploadProgress(pct));
      setUploadReport({
        filename: res.filename,
        total_rows: res.total_rows,
        valid_rows: res.valid_rows,
        duplicate_rows: res.duplicate_rows,
        invalid_rows: res.invalid_rows,
        validation_errors: res.validation_errors || [],
        parser_engine: res.parser_engine,
      });
      setStartFilter('');
      setEndFilter('');
      setIpFilter('');
      setPage(1);
      await refreshDatasets(res.dataset_id);
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'CSV uploaded and analyzed',
        message: `${res.valid_rows} valid events indexed in SQLite.`,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'CSV upload failed';
      setUploadError(message);
      addToast({ type: 'error', title: 'CSV validation failed', message });
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processFileUpload(file);
  };

  const handleLoadSample = async () => {
    setUploading(true);
    try {
      const res = await api.loadSampleDataset();
      await refreshDatasets(res.dataset_id);
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'Sample dataset loaded',
        message: `${res.valid_rows} synthetic records analyzed.`,
      });
    } catch (err) {
      addToast({ type: 'error', title: 'Sample load failed', message: String(err) });
    } finally {
      setUploading(false);
    }
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-6">
      {/* CSV Upload Section */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
          <div>
            <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
              Authentication Log Ingestion & Optimization
            </h1>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
              Required CSV columns: <span className="font-mono">timestamp, username, source_ip, status</span> · Optional:{' '}
              <span className="font-mono">user_agent, application</span>
            </p>
          </div>
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={uploading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] text-zinc-900 dark:text-zinc-100 whitespace-nowrap cursor-pointer disabled:opacity-60"
          >
            <Database className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
            <span>Load Sample CSV</span>
          </button>
        </div>

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          className={`rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
            dragActive
              ? 'border-red-500 bg-red-50/50 dark:bg-red-950/20'
              : 'border-zinc-200 dark:border-[#332020] bg-slate-50/70 dark:bg-[#141111]'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,text/csv"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) processFileUpload(file);
              e.target.value = '';
            }}
          />
          <FileSpreadsheet className="w-9 h-9 mx-auto text-red-600 dark:text-red-400 mb-3" />
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
            Drag and drop an authentication CSV log file here
          </p>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 mb-4">
            Supports up to 25 MB · Automatic timestamp, IPv4/IPv6, status, and duplicate validation
          </p>
          <button
            type="button"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors cursor-pointer disabled:opacity-60"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>{uploading ? `Uploading (${uploadProgress}%)` : 'Browse CSV File'}</span>
          </button>

          {uploading && (
            <div className="max-w-md mx-auto mt-4">
              <div className="h-2 rounded-full bg-zinc-200 dark:bg-[#211515] overflow-hidden">
                <div
                  className="h-full bg-red-600 transition-all duration-150"
                  style={{ width: `${Math.max(10, uploadProgress)}%` }}
                />
              </div>
            </div>
          )}
        </div>

        {uploadError && (
          <div className="mt-4 rounded-lg border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 p-3.5 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{uploadError}</span>
          </div>
        )}

        {uploadReport && (
          <div className="mt-4 rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] p-4 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-green-700 dark:text-green-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Ingested {uploadReport.filename}</span>
              </div>
              <div className="text-xs text-zinc-600 dark:text-zinc-300 font-mono tabular-nums">
                Total: {uploadReport.total_rows} · Valid: {uploadReport.valid_rows} · Duplicates:{' '}
                {uploadReport.duplicate_rows} · Invalid: {uploadReport.invalid_rows}
              </div>
            </div>
            {uploadReport.validation_errors.length > 0 && (
              <div className="text-xs text-amber-700 dark:text-amber-300 pt-1">
                Skipped {uploadReport.validation_errors.length} malformed row(s):{' '}
                {uploadReport.validation_errors
                  .slice(0, 3)
                  .map((e) => `Row ${e.row} (${e.field}: ${e.message})`)
                  .join(' · ')}
              </div>
            )}
          </div>
        )}
      </section>

      {loading && !data ? (
        <LoadingSpinner label="Sorting and indexing authentication logs..." />
      ) : !data?.dataset ? (
        <EmptyState onLoaded={fetchLogs} />
      ) : (
        <>
          {/* Merge Sort Comparison Panel */}
          <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="flex items-center gap-2">
                <ArrowUpDown className="w-4 h-4 text-red-600 dark:text-red-400" />
                <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  Merge Sort Chronological Ordering
                </h2>
              </div>
              {data.merge_sort_metrics && (
                <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-600 dark:text-zinc-400 font-mono tabular-nums">
                  <span>Records: {String(data.merge_sort_metrics.input_size)}</span>
                  <span>·</span>
                  <span>Time: {String(data.merge_sort_metrics.execution_time_ms)} ms</span>
                  <span>·</span>
                  <span>Comparisons: {Number(data.merge_sort_metrics.comparisons).toLocaleString()}</span>
                  <span>·</span>
                  <span className="text-red-600 dark:text-red-400 font-semibold">
                    Time {String(data.merge_sort_metrics.time_complexity)} · Space{' '}
                    {String(data.merge_sort_metrics.space_complexity)}
                  </span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="rounded-lg border border-zinc-200 dark:border-[#332020] overflow-hidden">
                <div className="px-3.5 py-2 bg-slate-50 dark:bg-[#211515] text-xs font-semibold text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-[#332020]">
                  Before Sorting (Raw Ingestion Order)
                </div>
                <div className="divide-y divide-zinc-200 dark:divide-[#332020] text-xs">
                  {data.before_sort_preview.map((ev) => (
                    <div key={`raw_${ev.id}`} className="px-3.5 py-2 flex items-center justify-between gap-2">
                      <span className="font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">{ev.timestamp}</span>
                      <span className="font-mono text-zinc-900 dark:text-zinc-100 truncate">{ev.username}</span>
                      <span className="font-mono text-zinc-500 dark:text-zinc-400">{ev.source_ip}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-zinc-200 dark:border-[#332020] overflow-hidden">
                <div className="px-3.5 py-2 bg-slate-50 dark:bg-[#211515] text-xs font-semibold text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-[#332020]">
                  After Merge Sort (Chronological Ascending)
                </div>
                <div className="divide-y divide-zinc-200 dark:divide-[#332020] text-xs">
                  {data.after_sort_preview.map((ev) => (
                    <div key={`sorted_${ev.id}`} className="px-3.5 py-2 flex items-center justify-between gap-2">
                      <span className="font-mono text-red-600 dark:text-red-400 tabular-nums">{ev.timestamp}</span>
                      <span className="font-mono text-zinc-900 dark:text-zinc-100 truncate">{ev.username}</span>
                      <span className="font-mono text-zinc-500 dark:text-zinc-400">{ev.source_ip}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* Hash Table IP Grouping Section */}
          <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="flex items-center gap-2">
                <Hash className="w-4 h-4 text-red-600 dark:text-red-400" />
                <div>
                  <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                    Hash Table Source IP Grouping
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    Average lookup O(1) via FNV-1a bucket hashing · Worst-case O(n) on chain collisions
                  </p>
                </div>
              </div>
              {data.hash_table_metrics && (
                <div className="text-xs font-mono tabular-nums text-zinc-500 dark:text-zinc-400">
                  Buckets: {String(data.hash_table_metrics.bucket_capacity)} · Load factor:{' '}
                  {String(data.hash_table_metrics.load_factor)} · Collisions:{' '}
                  {String(data.hash_table_metrics.collisions)} · {String(data.hash_table_metrics.execution_time_ms)} ms
                </div>
              )}
            </div>

            <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold">Source IP</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Login Attempts</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Distinct Usernames</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Successful</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Failed</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Failure Rate</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Filter Logs</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                  {data.ip_groups.slice(0, 15).map((g) => (
                    <tr key={g.source_ip} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                      <td className="px-4 py-2.5 font-mono font-medium text-zinc-900 dark:text-zinc-100">
                        {g.source_ip}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{g.total_attempts}</td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums font-semibold">
                        {g.distinct_usernames}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums text-green-600 dark:text-green-400">
                        {g.successful_attempts}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                        {g.failed_attempts}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums">{g.failure_rate}%</td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          type="button"
                          onClick={() => {
                            setIpFilter(ipFilter === g.source_ip ? '' : g.source_ip);
                            setPage(1);
                          }}
                          className={`text-xs font-medium cursor-pointer ${
                            ipFilter === g.source_ip
                              ? 'text-red-600 dark:text-red-400 underline'
                              : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100'
                          }`}
                        >
                          {ipFilter === g.source_ip ? 'Clear Filter' : 'Inspect IP'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Binary Search Time-Range Retrieval & Paginated Event Table */}
          <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  Binary Search Time-Range Query & Event Explorer
                </h2>
                {data.binary_search_metrics && (
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 font-mono tabular-nums mt-0.5">
                    Slice [{String(data.binary_search_metrics.left_index)} :{' '}
                    {String(data.binary_search_metrics.right_index)}] ·{' '}
                    {String(data.binary_search_metrics.comparisons)} binary comparisons ·{' '}
                    {String(data.binary_search_metrics.execution_time_ms)} ms ·{' '}
                    {String(data.binary_search_metrics.time_complexity)}
                  </p>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 top-2.5 pointer-events-none" />
                  <input
                    type="search"
                    value={searchFilter}
                    onChange={(e) => {
                      setSearchFilter(e.target.value);
                      setPage(1);
                    }}
                    placeholder="Filter user, IP, app..."
                    className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-red-500/40"
                  />
                </div>

                <input
                  type="text"
                  value={startFilter}
                  onChange={(e) => {
                    setStartFilter(e.target.value);
                    setPage(1);
                  }}
                  placeholder={`Start ISO (e.g. ${data.min_timestamp || '2026-11-24T06:00:00Z'})`}
                  aria-label="Start timestamp for Binary Search"
                  className="px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100 w-48 focus:outline-none focus:ring-2 focus:ring-red-500/40"
                />

                <input
                  type="text"
                  value={endFilter}
                  onChange={(e) => {
                    setEndFilter(e.target.value);
                    setPage(1);
                  }}
                  placeholder={`End ISO (e.g. ${data.max_timestamp || '2026-11-24T23:59:59Z'})`}
                  aria-label="End timestamp for Binary Search"
                  className="px-2.5 py-1.5 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100 w-48 focus:outline-none focus:ring-2 focus:ring-red-500/40"
                />

                <select
                  value={statusFilter}
                  onChange={(e) => {
                    setStatusFilter(e.target.value);
                    setPage(1);
                  }}
                  aria-label="Filter by status"
                  className="px-2.5 py-1.5 text-xs rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="FAILED">FAILED</option>
                  <option value="SUCCESS">SUCCESS</option>
                </select>

                {(startFilter || endFilter || searchFilter || statusFilter !== 'ALL' || ipFilter) && (
                  <button
                    type="button"
                    onClick={() => {
                      setStartFilter('');
                      setEndFilter('');
                      setSearchFilter('');
                      setStatusFilter('ALL');
                      setIpFilter('');
                      setPage(1);
                    }}
                    className="px-2.5 py-1.5 text-xs font-medium text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            <div className="overflow-x-auto border border-zinc-200 dark:border-[#332020] rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 dark:bg-[#211515] text-zinc-600 dark:text-zinc-400 border-b border-zinc-200 dark:border-[#332020]">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold">Timestamp (UTC)</th>
                    <th className="px-4 py-2.5 font-semibold">Username</th>
                    <th className="px-4 py-2.5 font-semibold">Source IP</th>
                    <th className="px-4 py-2.5 font-semibold">Status</th>
                    <th className="px-4 py-2.5 font-semibold">Application</th>
                    <th className="px-4 py-2.5 font-semibold">Duplicate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 dark:divide-[#332020]">
                  {data.logs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-zinc-500 dark:text-zinc-400">
                        No authentication events match the selected Binary Search range or filters.
                      </td>
                    </tr>
                  ) : (
                    data.logs.map((ev) => (
                      <tr key={ev.id} className="hover:bg-slate-50 dark:hover:bg-[#211515]/60">
                        <td className="px-4 py-2 font-mono tabular-nums text-zinc-600 dark:text-zinc-300">
                          {ev.timestamp}
                        </td>
                        <td className="px-4 py-2 font-mono font-medium text-zinc-900 dark:text-zinc-100">
                          {ev.username}
                        </td>
                        <td className="px-4 py-2 font-mono text-zinc-700 dark:text-zinc-300">{ev.source_ip}</td>
                        <td className="px-4 py-2">
                          <span
                            className={`font-mono font-semibold ${
                              ev.status === 'FAILED'
                                ? 'text-red-600 dark:text-red-400'
                                : 'text-green-600 dark:text-green-400'
                            }`}
                          >
                            {ev.status}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-zinc-600 dark:text-zinc-400">{ev.application || '—'}</td>
                        <td className="px-4 py-2 text-zinc-500 dark:text-zinc-400">
                          {ev.is_duplicate ? 'Duplicate' : 'Unique'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between text-xs text-zinc-500 dark:text-zinc-400">
              <span className="tabular-nums">
                Showing page {page} of {totalPages} ({data.total.toLocaleString()} matching records)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-[#332020] disabled:opacity-40 hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-[#332020] disabled:opacity-40 hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
