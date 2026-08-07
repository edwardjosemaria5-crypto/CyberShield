export default function SearchBar({ value, onChange, onSubmit }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem' }}>
      <input
        value={value}
        onChange={onChange}
        placeholder="Enter a domain or URL"
        style={{ flex: 1, padding: '0.75rem', borderRadius: '8px', border: '1px solid #d1d5db' }}
      />
      <button type="submit" style={{ padding: '0.75rem 1rem', borderRadius: '8px', border: 'none', background: '#2563eb', color: 'white' }}>
        Scan
      </button>
    </form>
  );
}
