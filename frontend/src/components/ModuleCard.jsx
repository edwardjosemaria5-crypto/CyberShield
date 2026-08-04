import React from 'react';

export default function ModuleCard({ title, value }) {
  return (
    <div style={{ padding: '1rem', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
      <h3>{title}</h3>
      <p>{value}</p>
    </div>
  );
}
