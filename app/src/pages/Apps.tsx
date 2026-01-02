import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

interface ConnectedApp {
  app_id: string;
  app_name: string;
  app_icon_url: string | null;
  authorized_at: string;
  last_used_at: string | null;
  tokens_issued: number;
  granted_scopes: string[];
}

export default function Apps() {
  const { session } = useAuth();
  const [apps, setApps] = useState<ConnectedApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  useEffect(() => {
    fetchApps();
  }, []);

  const fetchApps = async () => {
    if (!session?.access_token) return;

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(
        `${import.meta.env.VITE_GATEKEEPER_URL}/functions/v1/app-connections`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch connected apps');
      }

      const data = await response.json();
      setApps(data.connections || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (appId: string, appName: string) => {
    if (!session?.access_token) return;
    if (!confirm(`Are you sure you want to revoke access for ${appName}? This app will no longer be able to access your data.`)) {
      return;
    }

    try {
      setRevoking(appId);
      setError(null);

      const response = await fetch(
        `${import.meta.env.VITE_GATEKEEPER_URL}/functions/v1/app-connections`,
        {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ app_id: appId }),
        }
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to revoke access');
      }

      // Remove from list
      setApps(apps.filter(app => app.app_id !== appId));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRevoking(null);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString();
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>Loading connected apps...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Connected Apps</h1>
        <p>Manage which apps can access your ghost identity</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="privacy-banner">
        <span className="privacy-icon">🔗</span>
        <div>
          <strong>App Connections</strong>
          <p>Apps only receive your anonymous ghost_id. They never see your email, name, or other personal information.</p>
        </div>
      </div>

      {apps.length === 0 ? (
        <div className="card empty-state">
          <div className="empty-icon">📱</div>
          <h3>No Connected Apps</h3>
          <p>When you authorize apps to use your Gatekeeper identity, they'll appear here.</p>
        </div>
      ) : (
        <div className="apps-list">
          {apps.map((app) => (
            <div key={app.app_id} className="card app-card">
              <div className="app-header">
                <div className="app-icon">
                  {app.app_icon_url ? (
                    <img src={app.app_icon_url} alt={app.app_name} />
                  ) : (
                    <span className="app-icon-placeholder">📱</span>
                  )}
                </div>
                <div className="app-info">
                  <h3>{app.app_name}</h3>
                  <p className="app-id">ID: {app.app_id.substring(0, 16)}...</p>
                </div>
              </div>

              <div className="app-details">
                <div className="info-row">
                  <span className="label">Authorized:</span>
                  <span className="value">{formatDate(app.authorized_at)}</span>
                </div>
                <div className="info-row">
                  <span className="label">Last Used:</span>
                  <span className="value">{formatDate(app.last_used_at)}</span>
                </div>
                <div className="info-row">
                  <span className="label">Tokens Issued:</span>
                  <span className="value">{app.tokens_issued}</span>
                </div>
                {app.granted_scopes && app.granted_scopes.length > 0 && (
                  <div className="info-row">
                    <span className="label">Permissions:</span>
                    <span className="value scopes">
                      {app.granted_scopes.map((scope) => (
                        <span key={scope} className="scope-badge">{scope}</span>
                      ))}
                    </span>
                  </div>
                )}
              </div>

              <div className="app-actions">
                <button
                  className="btn-danger"
                  onClick={() => handleRevoke(app.app_id, app.app_name)}
                  disabled={revoking === app.app_id}
                >
                  {revoking === app.app_id ? 'Revoking...' : 'Revoke Access'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
