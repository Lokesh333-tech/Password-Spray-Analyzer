import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppLayout } from './components/AppLayout';
import { AppProvider } from './context/AppContext';
import { ThemeProvider } from './context/ThemeContext';
import { AlgorithmLab } from './pages/AlgorithmLab';
import { AttackDetection } from './pages/AttackDetection';
import { LogAnalyzer } from './pages/LogAnalyzer';
import { LoginPage } from './pages/LoginPage';
import { NetworkAnalysis } from './pages/NetworkAnalysis';
import { OverviewDashboard } from './pages/OverviewDashboard';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { ThreatIntelligence } from './pages/ThreatIntelligence';

export default function App() {
  return (
    <ThemeProvider>
      <AppProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<AppLayout />}>
              <Route path="/" element={<OverviewDashboard />} />
              <Route path="/logs" element={<LogAnalyzer />} />
              <Route path="/detection" element={<AttackDetection />} />
              <Route path="/intelligence" element={<ThreatIntelligence />} />
              <Route path="/network" element={<NetworkAnalysis />} />
              <Route path="/algorithms" element={<AlgorithmLab />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AppProvider>
    </ThemeProvider>
  );
}
