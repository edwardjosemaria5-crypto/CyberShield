import { useContext } from 'react';
import { ScanContext } from '../context/ScanContext';

export default function useScanContext() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
}