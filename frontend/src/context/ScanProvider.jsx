import useScan from '../hooks/useScan';
import { ScanContext } from './ScanContext';

export default function ScanProvider({ children }) {
  const scan = useScan();
  return <ScanContext.Provider value={scan}>{children}</ScanContext.Provider>;
}