const API_BASE_URL = 'http://localhost:8000';

export async function fetchScanResult(domain) {
  const response = await fetch(`${API_BASE_URL}/scan/${encodeURIComponent(domain)}`);
  if (!response.ok) {
    throw new Error('Failed to fetch scan result');
  }
  return response.json();
}
