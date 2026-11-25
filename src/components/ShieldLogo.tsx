import React from 'react';

interface ShieldLogoProps {
  size?: number;
  className?: string;
}

export function ShieldLogo({ size = 32, className = '' }: ShieldLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="Password Spray Analyzer Shield Logo"
    >
      <rect width="64" height="64" rx="14" className="fill-zinc-950 dark:fill-[#141111]" />
      <path
        d="M32 9L51 16.5V30C51 42.6 42.9 52.6 32 56C21.1 52.6 13 42.6 13 30V16.5L32 9Z"
        className="fill-[#181313] stroke-[#EF4444]"
        strokeWidth="2.8"
        strokeLinejoin="round"
      />
      <path
        d="M32 16L43.5 20.8V30.2C43.5 38.6 38.5 45.2 32 47.7C25.5 45.2 20.5 38.6 20.5 30.2V20.8L32 16Z"
        className="fill-[#DC2626]/20"
      />
      <circle cx="32" cy="28" r="4.5" stroke="#FAFAFA" strokeWidth="2.4" />
      <path d="M30.2 32.2L29.2 40.5H34.8L33.8 32.2" fill="#EF4444" />
    </svg>
  );
}

export function LoadingSpinner({ label = 'Processing authentication dataset...' }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 gap-4" role="status" aria-live="polite">
      <div className="relative flex items-center justify-center w-14 h-14">
        <div className="absolute inset-0 rounded-full border-2 border-zinc-200 dark:border-[#332020]" />
        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-red-600 dark:border-t-red-500 animate-spin" />
        <ShieldLogo size={28} />
      </div>
      <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">{label}</p>
    </div>
  );
}

export function SkeletonGrid({ count = 5 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {Array.from({ length: count }).map((_, idx) => (
        <div
          key={idx}
          className="h-28 rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-5 animate-pulse"
        >
          <div className="h-3 w-24 rounded bg-zinc-200 dark:bg-[#2a1c1c] mb-4" />
          <div className="h-7 w-16 rounded bg-zinc-200 dark:bg-[#2a1c1c]" />
        </div>
      ))}
    </div>
  );
}
