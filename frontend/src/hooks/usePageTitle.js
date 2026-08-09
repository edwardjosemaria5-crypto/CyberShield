import { useEffect } from 'react';

export default function usePageTitle(title) {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · CyberShield` : 'CyberShield';
    return () => {
      document.title = previous;
    };
  }, [title]);
}