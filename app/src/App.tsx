import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import Security from './pages/Security';
import Developer from './pages/Developer';
import Auth from './pages/Auth';
import Privacy from './pages/Privacy';
import Terms from './pages/Terms';
import Subscriptions from './pages/Subscriptions';
import Apps from './pages/Apps';
import Loyalty from './pages/Loyalty';
import './styles.css';

/**
 * Zule Web App
 *
 * Routes:
 * - / (Dashboard): Account overview, subscription status
 * - /profile: Edit display name, timezone, preferences
 * - /security: Password, sessions, passkey management
 * - /developer: Register and manage apps (for developers)
 * - /auth: Vinzrik authentication endpoint (passkey auth with callback)
 *
 * NOTE: App connections page has been removed.
 * User app connections are now managed by Vinzrik on-device.
 */

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = window.location;

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner" />
        <p>Loading...</p>
      </div>
    );
  }

  if (!user) {
    const returnTo = location.pathname !== '/' ? `?return=${encodeURIComponent(location.pathname)}` : '';
    return <Navigate to={`/login${returnTo}`} replace />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner" />
        <p>Loading...</p>
      </div>
    );
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      {/* Public routes */}
      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />
      <Route
        path="/register"
        element={
          <PublicRoute>
            <Register />
          </PublicRoute>
        }
      />

      {/* Auth route for Vinzrik (no session required, uses passkey) */}
      <Route path="/auth" element={<Auth />} />

      {/* Public pages */}
      <Route path="/privacy" element={<Privacy />} />
      <Route path="/terms" element={<Terms />} />

      {/* Protected routes with layout */}
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/security" element={<Security />} />
        <Route path="/subscriptions" element={<Subscriptions />} />
        <Route path="/apps" element={<Apps />} />
        <Route path="/loyalty" element={<Loyalty />} />
      </Route>

      {/* Developer page — no layout, no sidebar */}
      <Route path="/developer" element={
        <ProtectedRoute>
          <Developer />
        </ProtectedRoute>
      } />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
