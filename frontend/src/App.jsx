import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import ScanProvider from './context/ScanProvider';
import PageLayout from './components/layout/PageLayout/PageLayout';
import HomePage from './pages/Home/HomePage';
import ScanPage from './pages/Scan/ScanPage';
import DashboardPage from './pages/Dashboard/DashboardPage';
import HistoryPage from './pages/History/HistoryPage';
import ReportPage from './pages/Report/ReportPage';
import SettingsPage from './pages/Settings/SettingsPage';

function ReportRoute() {
  const { scanId } = useParams();
  return <ReportPage key={scanId} scanId={scanId} />;
}

function App() {
  return (
    <ScanProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<PageLayout />}>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/report/:scanId" element={<ReportRoute />} />
            <Route path="/report" element={<Navigate to="/history" replace />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ScanProvider>
  );
}

export default App;