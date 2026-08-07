export default function HeaderCard({ title, children }) {
  return (
    <section style={{ padding: '1rem', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}
