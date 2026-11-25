import React, { useState } from 'react';
import { ArrowRight, Moon, Sun } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ShieldLogo } from '../components/ShieldLogo';
import { useApp } from '../context/AppContext';
import { useTheme } from '../context/ThemeContext';

export function LoginPage() {
  const navigate = useNavigate();
  const { analyst, setAnalyst, addToast } = useApp();
  const { isDark, toggleTheme } = useTheme();

  const [name, setName] = useState(analyst.name);
  const [role, setRole] = useState(analyst.role);
  const [email, setEmail] = useState(analyst.email);

  const handleContinue = (e: React.FormEvent) => {
    e.preventDefault();
    setAnalyst({
      name: name.trim() || 'SOC Analyst',
      role: role.trim() || 'Threat Detection Lead',
      email: email.trim() || 'analyst@secops.local',
      workspace: 'Enterprise Auth Defense',
    });
    addToast({ type: 'success', title: 'Operator session active', message: `Signed in as ${name.trim() || 'SOC Analyst'}` });
    navigate('/');
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-[#090909] text-zinc-900 dark:text-zinc-50 relative">
      <button
        type="button"
        onClick={toggleTheme}
        className="absolute top-6 right-6 inline-flex items-center justify-center w-9 h-9 rounded-lg border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] cursor-pointer"
        aria-label="Toggle theme"
      >
        {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-zinc-700" />}
      </button>

      <div className="w-full max-w-md rounded-xl border border-zinc-200 dark:border-[#332020] bg-white dark:bg-[#181313] p-8 shadow-sm space-y-6">
        <div className="flex flex-col items-center text-center space-y-3">
          <ShieldLogo size={54} />
          <div>
            <h1 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
              Password Spray Analyzer
            </h1>
            <p className="text-xs text-red-600 dark:text-red-400 font-medium mt-0.5">
              Intelligent Authentication Threat Detection
            </p>
          </div>
        </div>

        <form onSubmit={handleContinue} className="space-y-4">
          <div>
            <label htmlFor="op-name" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Analyst Name
            </label>
            <input
              id="op-name"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>

          <div>
            <label htmlFor="op-role" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              SOC Role
            </label>
            <input
              id="op-role"
              type="text"
              required
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>

          <div>
            <label htmlFor="op-email" className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              Operator Email
            </label>
            <input
              id="op-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-zinc-200 dark:border-[#332020] bg-slate-50 dark:bg-[#211515] text-zinc-900 dark:text-zinc-100"
            />
          </div>

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold bg-red-600 hover:bg-red-700 text-white transition-colors cursor-pointer"
          >
            <span>Enter Security Console</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
