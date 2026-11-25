import React, { useState } from 'react';
import { Database, Upload } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { ShieldLogo } from './ShieldLogo';

interface EmptyStateProps {
  title?: string;
  description?: string;
  onLoaded?: () => void;
}

export function EmptyState({
  title = 'No Authentication Dataset Loaded',
  description = 'Upload a CSV authentication log file or load the built-in synthetic enterprise sample dataset to run Merge Sort, Hash Table grouping, Sliding Window detection, and Bipartite BFS analysis.',
  onLoaded,
}: EmptyStateProps) {
  const navigate = useNavigate();
  const { refreshDatasets, addToast, bumpDataVersion } = useApp();
  const [loadingSample, setLoadingSample] = useState(false);

  const handleLoadSample = async () => {
    setLoadingSample(true);
    try {
      const res = await api.loadSampleDataset();
      await refreshDatasets(res.dataset_id);
      bumpDataVersion();
      addToast({
        type: 'success',
        title: 'Sample dataset analyzed',
        message: `Processed ${res.valid_rows} authentication events through the DAA pipeline.`,
      });
      if (onLoaded) onLoaded();
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Failed to load sample dataset',
        message: err instanceof Error ? err.message : 'Unexpected error',
      });
    } finally {
      setLoadingSample(false);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-10 flex flex-col items-center text-center max-w-2xl mx-auto my-8">
      <div className="mb-5">
        <ShieldLogo size={56} />
      </div>
      <h2 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-2">{title}</h2>
      <p className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed max-w-lg mb-7">
        {description}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-3">
        <button
          type="button"
          onClick={() => navigate('/logs')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap cursor-pointer"
        >
          <Upload className="w-4 h-4" />
          <span>Upload Authentication CSV</span>
        </button>
        <button
          type="button"
          onClick={handleLoadSample}
          disabled={loadingSample}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] hover:bg-slate-100 dark:hover:bg-[#2c1c1c] text-zinc-900 dark:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-60"
        >
          <Database className="w-4 h-4 text-red-600 dark:text-red-400" />
          <span>{loadingSample ? 'Running DAA Pipeline...' : 'Load Synthetic Sample Dataset'}</span>
        </button>
      </div>
    </div>
  );
}
