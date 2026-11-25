import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from '../services/api';
import type { DatasetRecord, ThreatRecord } from '../types/api';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
}

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  destructive?: boolean;
  onConfirm: () => Promise<void> | void;
}

export interface AnalystProfile {
  name: string;
  role: string;
  email: string;
  workspace: string;
}

interface AppContextValue {
  datasets: DatasetRecord[];
  activeDatasetId: number | null;
  activeDataset: DatasetRecord | null;
  setActiveDatasetId: (id: number | null) => void;
  refreshDatasets: (selectId?: number | null) => Promise<void>;
  recentThreats: ThreatRecord[];
  refreshNotifications: () => Promise<void>;
  globalSearch: string;
  setGlobalSearch: (q: string) => void;
  toasts: ToastMessage[];
  addToast: (toast: Omit<ToastMessage, 'id'>) => void;
  dismissToast: (id: string) => void;
  confirmState: ConfirmOptions | null;
  requestConfirm: (opts: ConfirmOptions) => void;
  closeConfirm: () => void;
  analyst: AnalystProfile;
  setAnalyst: (profile: AnalystProfile) => void;
  dataVersion: number;
  bumpDataVersion: () => void;
}

const AppContext = createContext<AppContextValue | undefined>(undefined);

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [datasets, setDatasets] = useState<DatasetRecord[]>([]);
  const [activeDatasetId, setActiveDatasetId] = useState<number | null>(null);
  const [recentThreats, setRecentThreats] = useState<ThreatRecord[]>([]);
  const [globalSearch, setGlobalSearch] = useState('');
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmOptions | null>(null);
  const [dataVersion, setDataVersion] = useState(0);
  const [analyst, setAnalyst] = useState<AnalystProfile>({
    name: 'SOC Analyst',
    role: 'Threat Detection Lead',
    email: 'analyst@secops.local',
    workspace: 'Enterprise Auth Defense',
  });

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (toast: Omit<ToastMessage, 'id'>) => {
      const id = `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev.slice(-3), { ...toast, id }]);
      setTimeout(() => dismissToast(id), 4500);
    },
    [dismissToast]
  );

  const refreshNotifications = useCallback(async (targetId?: number | null) => {
    try {
      const res = await api.getThreats({ datasetId: targetId ?? activeDatasetId });
      setRecentThreats(res.threats.slice(0, 8));
    } catch {
      // Non-blocking notification refresh
    }
  }, [activeDatasetId]);

  const refreshDatasets = useCallback(
    async (selectId?: number | null) => {
      try {
        const res = await api.listDatasets();
        setDatasets(res.datasets);
        let nextId: number | null = selectId ?? activeDatasetId;
        if (nextId && !res.datasets.some((d) => d.id === nextId)) {
          nextId = null;
        }
        if (nextId === null && res.datasets.length > 0) {
          nextId = res.datasets[0].id;
        }
        setActiveDatasetId(nextId);
        await refreshNotifications(nextId);
      } catch {
        // Ignore initial load error
      }
    },
    [activeDatasetId, refreshNotifications]
  );

  useEffect(() => {
    refreshDatasets();
  }, []);

  useEffect(() => {
    refreshNotifications(activeDatasetId);
  }, [activeDatasetId, dataVersion]);

  const bumpDataVersion = useCallback(() => {
    setDataVersion((v) => v + 1);
  }, []);

  const requestConfirm = useCallback((opts: ConfirmOptions) => {
    setConfirmState(opts);
  }, []);

  const closeConfirm = useCallback(() => {
    setConfirmState(null);
  }, []);

  const activeDataset = datasets.find((d) => d.id === activeDatasetId) ?? null;

  return (
    <AppContext.Provider
      value={{
        datasets,
        activeDatasetId,
        activeDataset,
        setActiveDatasetId,
        refreshDatasets,
        recentThreats,
        refreshNotifications: () => refreshNotifications(activeDatasetId),
        globalSearch,
        setGlobalSearch,
        toasts,
        addToast,
        dismissToast,
        confirmState,
        requestConfirm,
        closeConfirm,
        analyst,
        setAnalyst,
        dataVersion,
        bumpDataVersion,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside AppProvider');
  return ctx;
}
