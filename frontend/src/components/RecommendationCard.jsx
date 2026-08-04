import React from 'react';

export default function RecommendationCard({ text }) {
  return (
    <div style={{ padding: '1rem', border: '1px solid #e5e7eb', borderRadius: '12px', background: '#f8fafc' }}>
      <p>{text}</p>
    </div>
  );
}
