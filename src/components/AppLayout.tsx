import React, { useState } from 'react';
import {
  Activity,
  Bell,
  ChevronLeft,
  ChevronRight,
  Cpu,
  FileSpreadsheet,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Radar,
  Search,
  Settings as SettingsIcon,
  ShieldAlert,
  Sun,
  User,
  X,
} from 'lucide-react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';
import { SeverityBadge } from './SeverityBadge';
import { ShieldLogo } from './ShieldLogo';
import { ThreatDetailModal } from './ThreatDetailModal';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Overview Dashboard', icon: LayoutDashboard },
  { to: '/logs', label: 'Log Analyzer', icon: FileSpreadsheet },
  { to: '/detection', label: 'Attack Detection', icon: ShieldAlert },
  { to: '/intelligence', label: 'Threat Intelligence', icon: Radar },
  { to: '/network', label: 'Network Analysis', icon: Network },
  { to: '/algorithms', label: 'Algorithm Lab', icon: Cpu },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
];

const ROUTE_TITLES: Record<string, string> = {
  '/': 'Overview Dashboard',
  '/logs': 'Log Analyzer',
  '/detection': 'Attack Detection',
  '/intelligence': 'Threat Intelligence',
  '/network': 'Network Analysis',
  '/algorithms': 'Algorithm Lab',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

export function AppLayout() {
  const { isDark, toggleTheme } = useTheme();
  const {
    datasets,
    activeDataset,
    setActiveDatasetId,
    recentThreats,
    globalSearch,
    setGlobalSearch,
    toasts,
    dismissToast,
    confirmState,
    closeConfirm,
    analyst,
  } = useApp();

  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  const location = useLocation();
  const navigate = useNavigate();
  const currentTitle = ROUTE_TITLES[location.pathname] || 'Overview Dashboard';

  const handleGlobalSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!globalSearch.trim()) return;
    if (location.pathname !== '/logs' && location.pathname !== '/detection') {
      navigate('/detection');
    }
  };

  const criticalOrHigh = recentThreats.filter((t) => t.severity === 'Critical' || t.severity === 'High');

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-[#090909] text-zinc-900 dark:text-zinc-50">
      {/* Mobile Sidebar Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Sidebar */}
      <aside
        className={`fixed lg:sticky top-0 left-0 z-40 h-screen flex flex-col border-r border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#0D0D0D] transition-[width,transform] duration-200 ease-out shrink-0 ${
          collapsed ? 'w-[74px]' : 'w-[256px]'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-zinc-200 dark:border-[#332020] shrink-0">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="flex items-center gap-3 text-left min-w-0 cursor-pointer"
          >
            <ShieldLogo size={34} className="shrink-0" />
            {!collapsed && (
              <div className="min-w-0">
                <div className="text-sm font-bold tracking-tight text-zinc-900 dark:text-zinc-50 truncate font-display">
                  Password Spray
                </div>
                <div className="text-[11px] font-medium text-red-600 dark:text-red-400 truncate">
                  Analyzer
                </div>
              </div>
            )}
          </button>

          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            className="hidden lg:inline-flex items-center justify-center w-7 h-7 rounded-md text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100 hover:bg-slate-100 dark:hover:bg-[#211515] transition-colors cursor-pointer"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>

          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            className="lg:hidden p-1.5 rounded-md text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
            aria-label="Close navigation menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                onClick={() => setMobileOpen(false)}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  `group relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-red-600/10 dark:bg-red-500/15 text-red-600 dark:text-red-400'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-[#181313] hover:text-zinc-900 dark:hover:text-zinc-100'
                  } ${collapsed ? 'justify-center px-2' : ''}`
                }
              >
                <Icon className="w-[18px] h-[18px] shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
                {collapsed && (
                  <span className="pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity absolute left-full ml-3 px-2.5 py-1.5 rounded-md text-xs font-medium bg-zinc-900 text-white dark:bg-[#211515] dark:border dark:border-[#332020] shadow-lg z-50 whitespace-nowrap">
                    {item.label}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Active Dataset Switcher in Sidebar Footer */}
        {!collapsed && (
          <div className="p-3 border-t border-zinc-200 dark:border-[#332020] space-y-2">
            <label
              htmlFor="sidebar-dataset-select"
              className="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400"
            >
              Active Dataset
            </label>
            <select
              id="sidebar-dataset-select"
              value={activeDataset?.id ?? ''}
              onChange={(e) => setActiveDatasetId(e.target.value ? Number(e.target.value) : null)}
              className="w-full rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#181313] px-2.5 py-1.5 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-red-500/40"
            >
              {datasets.length === 0 ? (
                <option value="">No datasets uploaded</option>
              ) : (
                datasets.map((ds) => (
                  <option key={ds.id} value={ds.id}>
                    {ds.name} ({ds.valid_row_count})
                  </option>
                ))
              )}
            </select>
          </div>
        )}
      </aside>

      {/* Main Content Shell */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Navigation Bar */}
        <header className="sticky top-0 z-30 h-16 flex items-center justify-between gap-4 px-4 sm:px-6 border-b border-zinc-200 dark:border-[#332020] bg-white/95 dark:bg-[#0D0D0D]/95 backdrop-blur-xs shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 rounded-lg text-zinc-600 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-[#211515]"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
                <span className="hidden sm:inline">Password Spray Analyzer</span>
                <span className="hidden sm:inline" aria-hidden="true">/</span>
                <span className="text-zinc-900 dark:text-zinc-100 font-semibold truncate">{currentTitle}</span>
              </div>
              <div className="hidden md:flex items-center gap-2 text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                <Activity className="w-3 h-3 text-red-600 dark:text-red-400 shrink-0" />
                {activeDataset ? (
                  <span className="truncate">
                    Analysis ready · {activeDataset.name} ·{' '}
                    <span className="font-mono tabular-nums">{activeDataset.valid_row_count.toLocaleString()}</span> events
                  </span>
                ) : (
                  <span>Awaiting authentication log upload</span>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            {/* Global Search */}
            <form onSubmit={handleGlobalSearchSubmit} className="hidden md:flex items-center relative">
              <Search className="w-4 h-4 text-zinc-400 absolute left-3 pointer-events-none" />
              <input
                type="search"
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
                placeholder="Search IP, username, or alert..."
                aria-label="Global search"
                className="w-56 lg:w-64 pl-9 pr-3 py-1.5 text-xs rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#181313] text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-red-500/40"
              />
            </form>

            {/* Theme Switcher */}
            <button
              type="button"
              onClick={toggleTheme}
              className="inline-flex items-center justify-center w-9 h-9 rounded-lg border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] text-zinc-700 dark:text-zinc-200 hover:bg-slate-100 dark:hover:bg-[#211515] transition-colors cursor-pointer"
              aria-label={isDark ? 'Switch to Bright White Light Mode' : 'Switch to Reddish Black Dark Mode'}
              title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-zinc-700" />}
            </button>

            {/* Notification Center */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setNotifOpen((o) => !o);
                  setProfileOpen(false);
                }}
                className="relative inline-flex items-center justify-center w-9 h-9 rounded-lg border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] text-zinc-700 dark:text-zinc-200 hover:bg-slate-100 dark:hover:bg-[#211515] transition-colors cursor-pointer"
                aria-label="Security notifications"
                title="Security Alerts"
              >
                <Bell className="w-4 h-4" />
                {criticalOrHigh.length > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 rounded-full bg-red-600 text-white text-[10px] font-bold flex items-center justify-center font-mono tabular-nums">
                    {criticalOrHigh.length}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div className="absolute right-0 mt-2 w-80 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] shadow-xl z-50 overflow-hidden">
                  <div className="px-4 py-3 border-b border-zinc-200 dark:border-[#332020] flex items-center justify-between">
                    <span className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                      Detected Threat Alerts
                    </span>
                    <span className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">
                      {recentThreats.length} active
                    </span>
                  </div>
                  <div className="max-h-72 overflow-y-auto divide-y divide-zinc-200 dark:divide-[#332020]">
                    {recentThreats.length === 0 ? (
                      <div className="p-4 text-xs text-zinc-500 dark:text-zinc-400">
                        No suspicious spray threats detected in the active dataset.
                      </div>
                    ) : (
                      recentThreats.map((t) => (
                        <button
                          key={t.id}
                          type="button"
                          onClick={() => {
                            setSelectedThreatId(t.id);
                            setNotifOpen(false);
                          }}
                          className="w-full text-left px-4 py-3 hover:bg-slate-50 dark:hover:bg-[#211515] transition-colors cursor-pointer"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                              {t.source_ip}
                            </span>
                            <SeverityBadge severity={t.severity} />
                          </div>
                          <div className="text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
                            Risk {t.risk_score}/100 · {t.distinct_accounts} accounts · {t.failed_attempts} failures
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* User Profile Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setProfileOpen((o) => !o);
                  setNotifOpen(false);
                }}
                className="inline-flex items-center gap-2 h-9 px-2.5 rounded-lg border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] hover:bg-slate-100 dark:hover:bg-[#211515] transition-colors cursor-pointer"
                aria-label="User profile menu"
              >
                <span className="w-6 h-6 rounded-md bg-red-600 text-white flex items-center justify-center text-xs font-bold shrink-0">
                  {analyst.name.slice(0, 1).toUpperCase()}
                </span>
                <span className="hidden sm:inline text-xs font-medium text-zinc-800 dark:text-zinc-200 whitespace-nowrap">
                  {analyst.name}
                </span>
              </button>

              {profileOpen && (
                <div className="absolute right-0 mt-2 w-60 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] shadow-xl z-50 overflow-hidden">
                  <div className="px-4 py-3 border-b border-zinc-200 dark:border-[#332020]">
                    <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">{analyst.name}</div>
                    <div className="text-[11px] text-zinc-500 dark:text-zinc-400">{analyst.role}</div>
                    <div className="text-[11px] font-mono text-zinc-400 mt-0.5 truncate">{analyst.email}</div>
                  </div>
                  <div className="p-1.5 space-y-0.5">
                    <button
                      type="button"
                      onClick={() => {
                        setProfileOpen(false);
                        navigate('/settings');
                      }}
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs text-zinc-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-[#211515] cursor-pointer"
                    >
                      <User className="w-3.5 h-3.5" />
                      <span>Detection Settings</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setProfileOpen(false);
                        navigate('/login');
                      }}
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-[#211515] cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Switch Analyst Console</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Active Page Outlet */}
        <main className="flex-1 p-4 sm:p-6 max-w-[1600px] w-full mx-auto">
          <Outlet />
        </main>
      </div>

      {/* Toast Notification Stack */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none px-4 sm:px-0">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className="pointer-events-auto flex items-start justify-between gap-3 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-4 shadow-lg"
          >
            <div className="min-w-0">
              <div
                className={`text-xs font-semibold ${
                  t.type === 'error'
                    ? 'text-red-600 dark:text-red-400'
                    : t.type === 'success'
                    ? 'text-green-600 dark:text-green-400'
                    : 'text-zinc-900 dark:text-zinc-100'
                }`}
              >
                {t.title}
              </div>
              {t.message && <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{t.message}</p>}
            </div>
            <button
              type="button"
              onClick={() => dismissToast(t.id)}
              className="text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 cursor-pointer"
              aria-label="Dismiss notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>

      {/* Confirmation Dialog */}
      {confirmState && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-semibold text-zinc-900 dark:text-zinc-50">{confirmState.title}</h3>
            <p className="text-sm text-zinc-600 dark:text-zinc-400">{confirmState.message}</p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={closeConfirm}
                disabled={confirmBusy}
                className="px-4 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-[#332020] text-zinc-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-[#211515] cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={confirmBusy}
                onClick={async () => {
                  setConfirmBusy(true);
                  try {
                    await confirmState.onConfirm();
                  } finally {
                    setConfirmBusy(false);
                    closeConfirm();
                  }
                }}
                className={`px-4 py-2 rounded-lg text-xs font-semibold text-white cursor-pointer ${
                  confirmState.destructive !== false
                    ? 'bg-red-600 hover:bg-red-700'
                    : 'bg-zinc-900 hover:bg-zinc-800 dark:bg-red-600 dark:hover:bg-red-700'
                }`}
              >
                {confirmBusy ? 'Working...' : confirmState.confirmLabel || 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Global Notification Threat Modal */}
      <ThreatDetailModal threatId={selectedThreatId} onClose={() => setSelectedThreatId(null)} />
    </div>
  );
}
