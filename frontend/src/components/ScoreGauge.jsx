export default function ScoreGauge({ score = 0 }) {
  return (
    <div style={{ padding: '1rem', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
      <h3>Security Score</h3>
      <p style={{ fontSize: '2rem', margin: 0 }}>{score}</p>
    </div>
  );
}
