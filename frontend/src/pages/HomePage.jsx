import React, { useState } from 'react';
import Navbar from '../components/Navbar';
import SearchBar from '../components/SearchBar';
import ScoreGauge from '../components/ScoreGauge';
import RiskSummary from '../components/RiskSummary';
import HeaderCard from '../components/HeaderCard';
import ModuleCard from '../components/ModuleCard';
import RecommendationCard from '../components/RecommendationCard';
import Footer from '../components/Footer';
import { fetchScanResult } from '../services/api';

export default function HomePage() {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await fetchScanResult(target);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Unable to fetch scan result');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <Navbar />
      <main style={{ padding: '1.5rem' }}>
        <HeaderCard title="Threat Intelligence Overview">
          <SearchBar value={target} onChange={(event) => setTarget(event.target.value)} onSubmit={handleSubmit} />
        </HeaderCard>

        <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', marginTop: '1rem' }}>
          <ScoreGauge score={result?.security_score ?? 0} />
          <RiskSummary title="Risk Level" description={result ? `${result.overall_risk} risk detected.` : 'Enter a target to start scanning.'} />
          <ModuleCard title="DNS" value={result?.modules?.dns?.ip_address ? 'Resolved' : 'Pending'} />
          <ModuleCard title="WHOIS" value={result?.modules?.whois?.registrar ? 'Active' : 'Pending'} />
        </div>

        {loading && <p style={{ marginTop: '1rem' }}>Scanning…</p>}
        {error && <p style={{ marginTop: '1rem', color: '#b91c1c' }}>{error}</p>}
        {result && (
          <div style={{ marginTop: '1.5rem' }}>
            <RecommendationCard text={`Target ${result.target} scored ${result.security_score} with ${result.overall_risk.toLowerCase()} risk.`} />
          </div>
        )}
      </main>
      <Footer />
    </div>
  );
}
