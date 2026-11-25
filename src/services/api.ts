import type {
  AlgorithmMetricRow,
  AppSettings,
  BenchmarkPoint,
  DashboardResponse,
  DatasetRecord,
  LogsResponse,
  NetworkResponse,
  ReportEntry,
  TargetedAccountRow,
  ThreatRecord,
} from '../types/api';

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const errMsg = (data && typeof data.error === 'string' && data.error) || `Request failed (${res.status})`;
    const error = new Error(errMsg) as Error & { details?: unknown };
    error.details = data;
    throw error;
  }
  return data as T;
}

export const api = {
  getDashboard(datasetId?: number | null): Promise<DashboardResponse> {
    const q = datasetId ? `?dataset_id=${datasetId}` : '';
    return requestJson<DashboardResponse>(`/api/dashboard${q}`);
  },

  listDatasets(): Promise<{ datasets: DatasetRecord[] }> {
    return requestJson<{ datasets: DatasetRecord[] }>('/api/datasets');
  },

  deleteDataset(datasetId: number): Promise<{ deleted: boolean; dataset_id: number }> {
    return requestJson<{ deleted: boolean; dataset_id: number }>(`/api/datasets/${datasetId}`, {
      method: 'DELETE',
    });
  },

  loadSampleDataset(): Promise<{
    dataset_id: number;
    name: string;
    valid_rows: number;
    analysis: Record<string, unknown>;
  }> {
    return requestJson('/api/datasets/sample', { method: 'POST' });
  },

  uploadCsv(
    file: File,
    datasetName?: string,
    onProgress?: (pct: number) => void
  ): Promise<{
    dataset_id: number;
    name: string;
    filename: string;
    total_rows: number;
    valid_rows: number;
    duplicate_rows: number;
    invalid_rows: number;
    validation_errors: Array<{ row: number; field: string; value?: string; message: string }>;
    parser_engine: string;
    analysis: Record<string, unknown>;
  }> {
    return new Promise((resolve, reject) => {
      const formData = new FormData();
      formData.append('file', file);
      if (datasetName) {
        formData.append('name', datasetName);
      }

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && onProgress) {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      };

      xhr.onload = () => {
        try {
          const parsed = JSON.parse(xhr.responseText || '{}');
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(parsed);
          } else {
            const err = new Error(parsed.error || `Upload failed (${xhr.status})`) as Error & { details?: unknown };
            err.details = parsed;
            reject(err);
          }
        } catch {
          reject(new Error(`Upload failed (${xhr.status})`));
        }
      };

      xhr.onerror = () => reject(new Error('Network error during file upload.'));
      xhr.send(formData);
    });
  },

  getLogs(params: {
    datasetId?: number | null;
    start?: string;
    end?: string;
    search?: string;
    status?: string;
    ip?: string;
    page?: number;
    pageSize?: number;
  }): Promise<LogsResponse> {
    const sp = new URLSearchParams();
    if (params.datasetId) sp.set('dataset_id', String(params.datasetId));
    if (params.start) sp.set('start', params.start);
    if (params.end) sp.set('end', params.end);
    if (params.search) sp.set('search', params.search);
    if (params.status) sp.set('status', params.status);
    if (params.ip) sp.set('ip', params.ip);
    if (params.page) sp.set('page', String(params.page));
    if (params.pageSize) sp.set('page_size', String(params.pageSize));
    return requestJson<LogsResponse>(`/api/logs?${sp.toString()}`);
  },

  runAnalysis(payload: {
    dataset_id?: number | null;
    window_minutes?: number;
    min_distinct_accounts?: number;
  }): Promise<Record<string, unknown>> {
    return requestJson('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  },

  getThreats(params: {
    datasetId?: number | null;
    severity?: string;
    ip?: string;
    account?: string;
    search?: string;
    start?: string;
    end?: string;
  }): Promise<{
    dataset_id: number | null;
    threats: ThreatRecord[];
    targeted_accounts: TargetedAccountRow[];
    success_after_failure: TargetedAccountRow[];
  }> {
    const sp = new URLSearchParams();
    if (params.datasetId) sp.set('dataset_id', String(params.datasetId));
    if (params.severity && params.severity !== 'All') sp.set('severity', params.severity);
    if (params.ip) sp.set('ip', params.ip);
    if (params.account) sp.set('account', params.account);
    if (params.search) sp.set('search', params.search);
    if (params.start) sp.set('start', params.start);
    if (params.end) sp.set('end', params.end);
    return requestJson(`/api/threats?${sp.toString()}`);
  },

  getThreatDetail(threatId: number): Promise<{ threat: ThreatRecord }> {
    return requestJson(`/api/threats/${threatId}`);
  },

  getNetwork(datasetId?: number | null, startNode?: string): Promise<NetworkResponse> {
    const sp = new URLSearchParams();
    if (datasetId) sp.set('dataset_id', String(datasetId));
    if (startNode) sp.set('start_node', startNode);
    return requestJson<NetworkResponse>(`/api/network?${sp.toString()}`);
  },

  getAlgorithms(datasetId?: number | null): Promise<{
    dataset_id: number | null;
    environment: { python_version: string; platform: string; architecture: string; timer: string };
    metrics: AlgorithmMetricRow[];
  }> {
    const q = datasetId ? `?dataset_id=${datasetId}` : '';
    return requestJson(`/api/algorithms${q}`);
  },

  runAlgorithmBenchmarks(sizes: number[] = [100, 1000, 5000, 10000]): Promise<{
    environment: { python_version: string; platform: string; architecture: string; timer: string };
    benchmarks: BenchmarkPoint[];
  }> {
    return requestJson('/api/algorithms/benchmark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sizes }),
    });
  },

  getReports(params: { severity?: string; start?: string; end?: string } = {}): Promise<{ reports: ReportEntry[] }> {
    const sp = new URLSearchParams();
    if (params.severity && params.severity !== 'All') sp.set('severity', params.severity);
    if (params.start) sp.set('start', params.start);
    if (params.end) sp.set('end', params.end);
    return requestJson(`/api/reports?${sp.toString()}`);
  },

  async exportReport(payload: { dataset_id?: number | null; format: 'pdf' | 'csv'; severity?: string }): Promise<void> {
    const res = await fetch('/api/reports/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || 'Failed to generate report.');
    }
    const blob = await res.blob();
    const disp = res.headers.get('Content-Disposition') || '';
    const match = disp.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : `psa_report.${payload.format}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  getSettings(): Promise<{ settings: AppSettings }> {
    return requestJson('/api/settings');
  },

  updateSettings(payload: Partial<AppSettings>): Promise<{ settings: AppSettings }> {
    return requestJson('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  },
};
