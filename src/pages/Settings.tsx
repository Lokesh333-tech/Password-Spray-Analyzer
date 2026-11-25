import React, { useEffect, useState } from 'react';
import { Save, Settings as SettingsIcon, Trash2 } from 'lucide-react';
import { LoadingSpinner } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { useTheme, type ThemePreference } from '../context/ThemeContext';
import { api } from '../services/api';

export function Settings() {
  const { datasets, activeDatasetId, setActiveDatasetId, refreshDatasets, addToast, requestConfirm, bumpDataVersion } =
    useApp();
  const { preference, setThemePreference } = useTheme();

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [windowMinutes, setWindowMinutes] = useState(10);
  const [minAccounts, setMinAccounts] = useState(8);
  const [successTokens, setSuccessTokens] = useState('SUCCESS,OK,ALLOWED,AUTHENTICATED,PASS,200');
  const [failureTokens, setFailureTokens] = useState('FAILED,FAILURE,DENIED,INVALID,REJECTED,ERROR,401,403');
  const [maxUploadMb, setMaxUploadMb] = useState(25);
  const [defaultTheme, setDefaultTheme] = useState<ThemePreference>(preference);

  useEffect(() => {
    api
      .getSettings()
      .then((res) => {
        const s = res.settings;
        setWindowMinutes(s.window_minutes);
        setMinAccounts(s.min_distinct_accounts);
        setSuccessTokens(s.success_statuses.join(','));
        setFailureTokens(s.failure_statuses.join(','));
        setMaxUploadMb(s.max_upload_mb);
        setDefaultTheme(s.default_theme);
      })
      .catch((err) => addToast({ type: 'error', title: 'Failed to load settings', message: String(err) }))
      .finally(() => setLoading(false));
  }, [addToast]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await api.updateSettings({
        window_minutes: windowMinutes,
        min_distinct_accounts: minAccounts,
        success_statuses: successTokens.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean),
        failure_statuses: failureTokens.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean),
        max_upload_mb: maxUploadMb,
        default_theme: defaultTheme,
      });
      setThemePreference(res.settings.default_theme);
      addToast({
        type: 'success',
        title: 'Settings persisted to SQLite',
        message: 'Detection thresholds and theme preference updated.',
      });
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to save settings',
        message: err instanceof Error ? err.message : 'Validation error',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteDataset = (id: number, name: string) => {
    requestConfirm({
      title: 'Delete Dataset',
      message: `Permanently delete "${name}" and all associated authentication logs, detected threats, and algorithm metrics from SQLite?`,
      confirmLabel: 'Delete Dataset',
      destructive: true,
      onConfirm: async () => {
        await api.deleteDataset(id);
        await refreshDatasets(activeDatasetId === id ? null : activeDatasetId);
        bumpDataVersion();
        addToast({ type: 'success', title: 'Dataset deleted', message: name });
      },
    });
  };

  if (loading) {
    return <LoadingSpinner label="Loading engine settings..." />;
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <form
        onSubmit={handleSave}
        className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-6"
      >
        <div className="flex items-center gap-2.5 border-b border-zinc-200 dark:border-[#332020] pb-4">
          <SettingsIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
          <div>
            <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-50">
              Detection Engine & Application Settings
            </h1>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Configure Sliding Window parameters, CSV status mappings, upload limits, and persistent UI theme.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label htmlFor="cfg-window" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Default Sliding Window (minutes)
            </label>
            <input
              id="cfg-window"
              type="number"
              min={1}
              max={1440}
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs font-mono tabular-nums rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>
          <div>
            <label htmlFor="cfg-min-acc" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Min Distinct Targeted Accounts
            </label>
            <input
              id="cfg-min-acc"
              type="number"
              min={2}
              max={500}
              value={minAccounts}
              onChange={(e) => setMinAccounts(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs font-mono tabular-nums rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>
          <div>
            <label htmlFor="cfg-max-mb" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Max CSV Upload Size (MB)
            </label>
            <input
              id="cfg-max-mb"
              type="number"
              min={1}
              max={100}
              value={maxUploadMb}
              onChange={(e) => setMaxUploadMb(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs font-mono tabular-nums rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <label htmlFor="cfg-success" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Success Status Tokens (comma-separated)
            </label>
            <input
              id="cfg-success"
              type="text"
              value={successTokens}
              onChange={(e) => setSuccessTokens(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>

          <div>
            <label htmlFor="cfg-failure" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Failure Status Tokens (comma-separated)
            </label>
            <input
              id="cfg-failure"
              type="text"
              value={failureTokens}
              onChange={(e) => setFailureTokens(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>

          <div>
            <span className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-2">
              Theme Mode Preference
            </span>
            <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#211515]">
              {(['light', 'dark', 'system'] as ThemePreference[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => {
                    setDefaultTheme(mode);
                    setThemePreference(mode);
                  }}
                  className={`px-3.5 py-1.5 rounded-md text-xs font-medium capitalize transition-colors cursor-pointer ${
                    defaultTheme === mode
                      ? 'bg-white dark:bg-[#0D0D0D] text-red-600 dark:text-red-400 shadow-xs'
                      : 'text-zinc-600 dark:text-zinc-400'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors cursor-pointer disabled:opacity-60"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </form>

      {/* Dataset Management */}
      <section className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 space-y-4">
        <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
          Stored SQLite Datasets ({datasets.length})
        </h2>
        {datasets.length === 0 ? (
          <p className="text-xs text-zinc-500 dark:text-zinc-400">No datasets currently stored.</p>
        ) : (
          <div className="divide-y divide-zinc-200 dark:divide-[#332020] border border-zinc-200 dark:border-[#332020] rounded-lg">
            {datasets.map((ds) => (
              <div key={ds.id} className="p-3.5 flex items-center justify-between gap-4 text-xs">
                <div className="min-w-0">
                  <div className="font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                    {ds.name}{' '}
                    {ds.id === activeDatasetId && (
                      <span className="text-red-600 dark:text-red-400 font-medium">(Active)</span>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
                    {ds.filename} · {ds.valid_row_count.toLocaleString()} valid rows · {ds.uploaded_at}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {ds.id !== activeDatasetId && (
                    <button
                      type="button"
                      onClick={() => setActiveDatasetId(ds.id)}
                      className="px-3 py-1 rounded-md border border-zinc-200 dark:border-[#332020] hover:bg-slate-50 dark:hover:bg-[#211515] cursor-pointer"
                    >
                      Activate
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => handleDeleteDataset(ds.id, ds.name)}
                    className="p-1.5 rounded-md text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-[#211515] cursor-pointer"
                    aria-label={`Delete ${ds.name}`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
