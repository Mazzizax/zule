import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { exportGhostSecretForQR } from '../lib/ghostKeys';

export default function Dashboard() {
  const { user, session, ghostId } = useAuth();
  const [qrData, setQrData] = useState<string | null>(null);
  const [showQR, setShowQR] = useState(false);

  const handleExportQR = () => {
    if (user) {
      try {
        const data = exportGhostSecretForQR(user.id);
        setQrData(data);
        setShowQR(true);
      } catch (err: any) {
        console.error('Export error:', err.message);
      }
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p>Your identity overview</p>
      </div>

      {/* Privacy Notice */}
      <div className="privacy-banner">
        <span className="privacy-icon">🔒</span>
        <div>
          <strong>Ghost Identity Active</strong>
          <p>Your ghost_id is derived locally. The server cannot link your identity to your data.</p>
        </div>
      </div>

      {/* Ghost Identity - THE KEY FEATURE */}
      <div className="card ghost-info">
        <h2>Ghost Identity</h2>
        <div className="info-row highlight">
          <span className="label">Ghost ID:</span>
          <span className="value code">{ghostId}</span>
        </div>
        <p className="info-note">
          This ID is what apps see. It's derived from your user_id + a secret stored only on this device.
          The server never knows the connection between your email and this ID.
        </p>

        <div className="qr-section">
          <button className="btn-secondary" onClick={handleExportQR}>
            Export Ghost Secret (Backup)
          </button>
        </div>
      </div>

      <div className="card-grid">
        {/* Account Info */}
        <div className="card">
          <h2>Account</h2>
          <div className="info-row">
            <span className="label">Email:</span>
            <span className="value">{user?.email}</span>
          </div>
          <div className="info-row">
            <span className="label">User ID:</span>
            <span className="value code small">{user?.id}</span>
          </div>
          <div className="info-row">
            <span className="label">Created:</span>
            <span className="value">{user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</span>
          </div>
        </div>

        {/* Session Info */}
        <div className="card">
          <h2>Session</h2>
          <div className="info-row">
            <span className="label">Status:</span>
            <span className="value status-active">Active</span>
          </div>
          <div className="info-row">
            <span className="label">Expires:</span>
            <span className="value">{session?.expires_at ? new Date(session.expires_at * 1000).toLocaleString() : 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* QR Modal */}
      {showQR && qrData && (
        <div className="qr-modal">
          <div className="qr-content">
            <h3>Ghost Secret Backup</h3>
            <p className="warning">
              Keep this secret safe! Anyone with this can access your data as you.
            </p>
            <pre className="qr-data">{qrData}</pre>
            <p className="info-note">
              In a real app, this would be a scannable QR code for device-to-device transfer.
            </p>
            <button className="btn-secondary" onClick={() => setShowQR(false)}>
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
