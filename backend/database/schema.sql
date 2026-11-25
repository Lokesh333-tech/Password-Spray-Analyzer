-- Password Spray Analyzer SQLite Schema
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL DEFAULT 0,
    row_count INTEGER NOT NULL DEFAULT 0,
    valid_row_count INTEGER NOT NULL DEFAULT 0,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    invalid_row_count INTEGER NOT NULL DEFAULT 0,
    uploaded_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS authentication_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    epoch_ts REAL NOT NULL,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_status TEXT NOT NULL,
    user_agent TEXT DEFAULT '',
    application TEXT DEFAULT '',
    is_duplicate INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_logs_dataset_epoch ON authentication_logs(dataset_id, epoch_ts);
CREATE INDEX IF NOT EXISTS idx_logs_dataset_ip ON authentication_logs(dataset_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_dataset_user ON authentication_logs(dataset_id, username);
CREATE INDEX IF NOT EXISTS idx_logs_dataset_status ON authentication_logs(dataset_id, status);

CREATE TABLE IF NOT EXISTS detected_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    total_attempts INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL,
    successful_attempts INTEGER NOT NULL,
    distinct_accounts INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    window_minutes INTEGER NOT NULL,
    window_peak_accounts INTEGER NOT NULL,
    window_peak_attempts INTEGER NOT NULL,
    peak_window_start TEXT NOT NULL,
    peak_window_end TEXT NOT NULL,
    success_after_failure_count INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    explanation TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL DEFAULT '[]',
    greedy_rank INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_threats_dataset_score ON detected_threats(dataset_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threats_dataset_severity ON detected_threats(dataset_id, severity);

CREATE TABLE IF NOT EXISTS targeted_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    dataset_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    total_attempts INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL,
    successful_attempts INTEGER NOT NULL,
    failures_before_success INTEGER NOT NULL DEFAULT 0,
    had_success_after_failure INTEGER NOT NULL DEFAULT 0,
    first_attempt TEXT NOT NULL,
    last_attempt TEXT NOT NULL,
    FOREIGN KEY (threat_id) REFERENCES detected_threats(id) ON DELETE CASCADE,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_targeted_dataset_user ON targeted_accounts(dataset_id, username);
CREATE INDEX IF NOT EXISTS idx_targeted_threat ON targeted_accounts(threat_id);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    executed_at TEXT NOT NULL,
    window_minutes INTEGER NOT NULL,
    min_distinct_accounts INTEGER NOT NULL,
    total_events INTEGER NOT NULL,
    failed_events INTEGER NOT NULL,
    success_events INTEGER NOT NULL,
    suspicious_ip_count INTEGER NOT NULL,
    critical_alert_count INTEGER NOT NULL DEFAULT 0,
    high_alert_count INTEGER NOT NULL DEFAULT 0,
    medium_alert_count INTEGER NOT NULL DEFAULT 0,
    low_alert_count INTEGER NOT NULL DEFAULT 0,
    avg_risk_score REAL NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_dataset ON analysis_results(dataset_id, executed_at DESC);

CREATE TABLE IF NOT EXISTS algorithm_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    algorithm_name TEXT NOT NULL,
    input_size INTEGER NOT NULL,
    execution_time_ms REAL NOT NULL,
    time_complexity TEXT NOT NULL,
    space_complexity TEXT NOT NULL,
    result_summary TEXT NOT NULL DEFAULT '{}',
    measured_at TEXT NOT NULL,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_algo_dataset ON algorithm_metrics(dataset_id);

CREATE TABLE IF NOT EXISTS application_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    window_minutes INTEGER NOT NULL DEFAULT 10,
    min_distinct_accounts INTEGER NOT NULL DEFAULT 8,
    success_statuses_json TEXT NOT NULL DEFAULT '["SUCCESS","OK","ALLOWED","AUTHENTICATED","PASS","200"]',
    failure_statuses_json TEXT NOT NULL DEFAULT '["FAILED","FAILURE","DENIED","INVALID","REJECTED","ERROR","401","403"]',
    max_upload_mb INTEGER NOT NULL DEFAULT 25,
    default_theme TEXT NOT NULL DEFAULT 'system',
    updated_at TEXT NOT NULL
);
