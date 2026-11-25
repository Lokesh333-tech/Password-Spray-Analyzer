export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface DatasetRecord {
  id: number;
  name: string;
  filename: string;
  file_size_bytes: number;
  row_count: number;
  valid_row_count: number;
  duplicate_count: number;
  invalid_row_count: number;
  uploaded_at: string;
  status: string;
  suspicious_ip_count?: number;
  critical_alert_count?: number;
  last_analyzed_at?: string;
}

export interface AuthLogEvent {
  id: number;
  timestamp: string;
  epoch_ts: number;
  username: string;
  source_ip: string;
  status: 'SUCCESS' | 'FAILED';
  raw_status: string;
  user_agent: string;
  application: string;
  is_duplicate: number;
}

export interface ScoreBreakdownItem {
  factor: string;
  points: number;
  max_points: number;
  detail: string;
}

export interface TargetedAccountRow {
  id?: number;
  threat_id?: number;
  dataset_id?: number;
  username: string;
  source_ip?: string;
  attacking_ips?: number;
  total_attempts: number;
  failed_attempts: number;
  successful_attempts: number;
  failures_before_success?: number;
  max_failures_before_success?: number;
  had_success_after_failure: number | boolean;
  first_attempt?: string;
  last_attempt: string;
}

export interface ThreatRecord {
  id: number;
  dataset_id: number;
  source_ip: string;
  total_attempts: number;
  failed_attempts: number;
  successful_attempts: number;
  distinct_accounts: number;
  first_seen: string;
  last_seen: string;
  window_minutes: number;
  window_peak_accounts: number;
  window_peak_attempts: number;
  peak_window_start: string;
  peak_window_end: string;
  success_after_failure_count: number;
  risk_score: number;
  severity: Severity;
  explanation: string;
  score_breakdown: ScoreBreakdownItem[];
  greedy_rank: number;
  created_at: string;
  targeted_accounts?: TargetedAccountRow[];
  events?: AuthLogEvent[];
}

export interface IpGroupSummary {
  source_ip: string;
  total_attempts: number;
  distinct_usernames: number;
  usernames_sample: string[];
  successful_attempts: number;
  failed_attempts: number;
  failure_rate: number;
  first_seen: string;
  last_seen: string;
}

export interface AlgorithmMetricRow {
  id?: number;
  algorithm_name: string;
  input_size: number;
  execution_time_ms: number;
  time_complexity: string;
  space_complexity: string;
  measured_at?: string;
  details?: Record<string, unknown>;
}

export interface DashboardResponse {
  has_data: boolean;
  dataset: DatasetRecord | null;
  analysis?: Record<string, unknown>;
  kpis: {
    total_events: number;
    failed_attempts: number;
    successful_attempts: number;
    suspicious_ips: number;
    critical_alerts: number;
  };
  charts: {
    timeline: Array<{ time: string; success: number; failed: number; total: number }>;
    status_distribution: Array<{ name: string; value: number }>;
    severity_distribution: Array<{ severity: string; count: number }>;
    top_suspicious_ips: Array<{
      ip: string;
      risk_score: number;
      distinct_accounts: number;
      failed_attempts: number;
      severity: Severity;
    }>;
    top_targeted_accounts: Array<{
      username: string;
      failed_attempts: number;
      successful_attempts: number;
      attacking_ips: number;
      compromised: number;
    }>;
    hourly_activity: Array<{ hour: number; label: string; success: number; failed: number }>;
  };
  recent_alerts: ThreatRecord[];
  datasets: DatasetRecord[];
  algorithm_metrics: AlgorithmMetricRow[];
}

export interface LogsResponse {
  dataset: DatasetRecord | null;
  logs: AuthLogEvent[];
  total: number;
  page: number;
  page_size: number;
  min_timestamp?: string | null;
  max_timestamp?: string | null;
  before_sort_preview: AuthLogEvent[];
  after_sort_preview: AuthLogEvent[];
  ip_groups: IpGroupSummary[];
  merge_sort_metrics: Record<string, unknown> | null;
  hash_table_metrics: Record<string, unknown> | null;
  binary_search_metrics: Record<string, unknown> | null;
}

export interface NetworkGraphNode {
  id: string;
  label: string;
  type: 'ip' | 'user';
  suspicious?: boolean;
  risk_score?: number;
  severity?: string;
  total_attempts?: number;
  compromised?: boolean;
}

export interface NetworkGraphEdge {
  id: string;
  source: string;
  target: string;
  attempts: number;
  failures: number;
  successes: number;
  success_after_failure: boolean;
}

export interface BFSStep {
  step: number;
  node_id: string;
  label: string;
  node_type: string;
  depth: number;
  parent: string | null;
  suspicious: boolean;
  compromised: boolean;
}

export interface NetworkResponse {
  dataset_id?: number;
  nodes: NetworkGraphNode[];
  edges: NetworkGraphEdge[];
  bfs: {
    start_node: string;
    traversal_order: BFSStep[];
    discovered_ips: string[];
    discovered_accounts: string[];
    levels: Record<string, string[]>;
    edges_traversed: string[];
  } | null;
  bfs_metrics?: Record<string, unknown> | null;
}

export interface BenchmarkPoint {
  size: number;
  merge_sort_ms: number;
  hash_table_ms: number;
  binary_search_ms: number;
  sliding_window_ms: number;
  bfs_ms: number;
  merge_comparisons: number;
  hash_collisions: number;
  bsearch_comparisons: number;
  windows_evaluated: number;
  bfs_visited: number;
}

export interface AppSettings {
  window_minutes: number;
  min_distinct_accounts: number;
  success_statuses: string[];
  failure_statuses: string[];
  max_upload_mb: number;
  default_theme: 'light' | 'dark' | 'system';
  updated_at?: string;
}

export interface ReportEntry {
  id: number;
  dataset_id: number;
  dataset_name: string;
  filename: string;
  duplicate_count: number;
  executed_at: string;
  window_minutes: number;
  min_distinct_accounts: number;
  total_events: number;
  failed_events: number;
  success_events: number;
  suspicious_ip_count: number;
  critical_alert_count: number;
  high_alert_count: number;
  medium_alert_count: number;
  low_alert_count: number;
  avg_risk_score: number;
}
