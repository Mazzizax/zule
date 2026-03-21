import React, { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function Layout() {
  const { user, signOut } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleSignOut = async () => {
    try {
      await signOut();
    } catch (err: any) {
      console.error('Sign out error:', err.message);
    }
  };

  const closeMobileMenu = () => setMobileMenuOpen(false);

  const navItems = [
    { to: '/', label: 'Dashboard', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 256 256" className="nav-svg">
        <path d="M104,44H56A12,12,0,0,0,44,56v48a12,12,0,0,0,12,12h48a12,12,0,0,0,12-12V56A12,12,0,0,0,104,44Zm4,60a4,4,0,0,1-4,4H56a4,4,0,0,1-4-4V56a4,4,0,0,1,4-4h48a4,4,0,0,1,4,4Zm92-60H152a12,12,0,0,0-12,12v48a12,12,0,0,0,12,12h48a12,12,0,0,0,12-12V56A12,12,0,0,0,200,44Zm4,60a4,4,0,0,1-4,4H152a4,4,0,0,1-4-4V56a4,4,0,0,1,4-4h48a4,4,0,0,1,4,4ZM104,140H56a12,12,0,0,0-12,12v48a12,12,0,0,0,12,12h48a12,12,0,0,0,12-12V152A12,12,0,0,0,104,140Zm4,60a4,4,0,0,1-4,4H56a4,4,0,0,1-4-4V152a4,4,0,0,1,4-4h48a4,4,0,0,1,4,4Zm92-60H152a12,12,0,0,0-12,12v48a12,12,0,0,0,12,12h48a12,12,0,0,0,12-12V152A12,12,0,0,0,200,140Zm4,60a4,4,0,0,1-4,4H152a4,4,0,0,1-4-4V152a4,4,0,0,1,4-4h48a4,4,0,0,1,4,4Z" />
      </svg>
    ), end: true },
    { to: '/profile', label: 'Identity', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 256 256" className="nav-svg">
        <path d="M227.46,214c-16.52-28.56-43-48.06-73.68-55.09a68,68,0,1,0-51.56,0c-30.64,7-57.16,26.53-73.68,55.09a4,4,0,0,0,6.92,4C55,184.19,89.62,164,128,164s73,20.19,92.54,54a4,4,0,0,0,3.46,2,3.93,3.93,0,0,0,2-.54A4,4,0,0,0,227.46,214ZM68,96a60,60,0,1,1,60,60A60.07,60.07,0,0,1,68,96Z" />
      </svg>
    )},
    { to: '/security', label: 'Security', icon: (
      <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 256 256" className="nav-svg">
        <path d="M208,44H48A12,12,0,0,0,36,56v56c0,51.16,24.73,82.12,45.47,99.1,22.4,18.32,44.55,24.5,45.48,24.76a4,4,0,0,0,2.1,0c.93-.26,23.08-6.44,45.48-24.76,20.74-17,45.47-47.94,45.47-99.1V56A12,12,0,0,0,208,44Zm4,68c0,38.44-14.23,69.63-42.29,92.71A132.45,132.45,0,0,1,128,227.82a132.23,132.23,0,0,1-41.71-23.11C58.23,181.63,44,150.44,44,112V56a4,4,0,0,1,4-4H208a4,4,0,0,1,4,4Z" />
      </svg>
    )},
  ];

  return (
    <div className="layout">
      {/* Mobile Header */}
      <header className="mobile-header">
        <div className="mobile-brand">
          <img src="/icon-192.png" alt="" className="brand-icon" />
          <h1 style={{ fontSize: '20px', letterSpacing: '0.15em', fontFamily: "'Cormorant Garamond', serif", fontWeight: 400 }}>
            <span className="metal-text" style={{ display: 'inline-block' }}>Z</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>U</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>L</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>E</span>
          </h1>
        </div>
        <button
          className="mobile-menu-btn"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle menu"
        >
          {mobileMenuOpen ? '✕' : '☰'}
        </button>
      </header>

      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="mobile-menu-overlay" onClick={closeMobileMenu}>
          <nav className="mobile-menu" onClick={(e) => e.stopPropagation()}>
            <div className="mobile-menu-header">
              <p className="user-email">{user?.email}</p>
            </div>
            <div className="mobile-nav-links">
              {navItems.map(({ to, label, icon, end }) => (
                <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} end={end} onClick={closeMobileMenu}>
                  {icon}
                  {label}
                </NavLink>
              ))}
            </div>
            <div className="mobile-menu-footer">
              <button className="btn-signout-sidebar" onClick={handleSignOut}>
                Sign Out
              </button>
            </div>
          </nav>
        </div>
      )}

      <nav className="sidebar">
        <div className="sidebar-header">
          <img src="/icon-192.png" alt="" className="brand-icon" />
          <h1 style={{ fontSize: '24px', letterSpacing: '0.15em', fontFamily: "'Cormorant Garamond', serif", fontWeight: 400 }}>
            <span className="metal-text" style={{ display: 'inline-block' }}>Z</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>U</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>L</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>E</span>
          </h1>
          <p className="user-email">{user?.email}</p>
        </div>

        <div className="nav-links">
          {navItems.map(({ to, label, icon, end }) => (
            <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} end={end}>
              {icon}
              {label}
            </NavLink>
          ))}
        </div>

        <div className="sidebar-footer">
          <div style={{ fontSize: '11px', opacity: 0.5, padding: '4px 12px' }}>
            <a href="/privacy" style={{ color: 'inherit' }}>Privacy</a> · <a href="/terms" style={{ color: 'inherit' }}>Terms</a>
          </div>
          <button className="btn-signout-sidebar" onClick={handleSignOut}>
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 256 256" className="nav-svg">
              <path d="M116,216a4,4,0,0,1-4,4H48a12,12,0,0,1-12-12V48A12,12,0,0,1,48,36h64a4,4,0,0,1,0,8H48a4,4,0,0,0-4,4V208a4,4,0,0,0,4,4h64A4,4,0,0,1,116,216Zm108.24-90.83-40-40a4,4,0,0,0-5.66,5.66L211.17,124H112a4,4,0,0,0,0,8h99.17l-32.59,33.17a4,4,0,1,0,5.66,5.66l40-40A4,4,0,0,0,224.24,125.17Z" />
            </svg>
            Sign Out
          </button>
        </div>
      </nav>

      <main className="main-content">
        <div style={{
          position: 'sticky', top: 0, zIndex: 10,
          background: 'linear-gradient(180deg, var(--bg-deep) 70%, transparent)',
          paddingTop: '32px', paddingBottom: '32px', marginTop: '-32px',
        }}>
          <h1 style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 300, letterSpacing: '0.18em', color: 'var(--zule-gold-dim)' }}>
            <span className="metal-text" style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400, fontSize: '28px', letterSpacing: '0.04em', display: 'inline-block' }}>Z</span>ero-knowledge{' '}
            <span className="metal-text" style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400, fontSize: '28px', letterSpacing: '0.04em', display: 'inline-block' }}>U</span>ser{' '}
            <span className="metal-text" style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400, fontSize: '28px', letterSpacing: '0.04em', display: 'inline-block' }}>L</span>icense{' '}
            <span className="metal-text" style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400, fontSize: '28px', letterSpacing: '0.04em', display: 'inline-block' }}>E</span>nclave
          </h1>
        </div>
        <Outlet />
      </main>
    </div>
  );
}
