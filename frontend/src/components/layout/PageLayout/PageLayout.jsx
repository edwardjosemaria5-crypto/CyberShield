import { Outlet } from 'react-router-dom';
import Navbar from '../Navbar/Navbar';
import Sidebar from '../Sidebar/Sidebar';
import Footer from '../Footer/Footer';
import styles from './PageLayout.module.css';

export default function PageLayout() {
  return (
    <div className={styles.container}>
      <a href="#main-content" className={styles.skipLink}>
        Skip to content
      </a>
      <Navbar />
      <div className={styles.main}>
        <Sidebar />
        <main id="main-content" className={styles.content} tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      <Footer />
    </div>
  );
}