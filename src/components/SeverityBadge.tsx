import React from 'react';
import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from 'lucide-react';
import type { Severity } from '../types/api';

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  switch (severity) {
    case 'Critical':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 dark:text-red-400 whitespace-nowrap">
          <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
          <span>Critical</span>
        </span>
      );
    case 'High':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-600 dark:text-red-400 whitespace-nowrap">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
          <span>High</span>
        </span>
      );
    case 'Medium':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 dark:text-amber-400 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>Medium</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-600 dark:text-zinc-400 whitespace-nowrap">
          <Info className="w-3.5 h-3.5 shrink-0" />
          <span>{severity || 'Low'}</span>
        </span>
      );
  }
}
