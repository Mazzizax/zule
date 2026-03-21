import React from 'react';

const g = "'Cormorant Garamond', serif";

interface AppInfo {
  id: string;
  name: string;
  description: string;
  status: 'available' | 'coming_soon';
  icon: string;
}

const apps: AppInfo[] = [
  {
    id: 'samsung-health',
    name: 'Samsung Health',
    description: 'Steps, workouts, sleep, and heart rate data from Samsung Health',
    status: 'coming_soon',
    icon: '❤️‍🔥',
  },
  {
    id: 'playstation',
    name: 'PlayStation',
    description: 'Trophy data, game activity, and playtime from PlayStation Network',
    status: 'coming_soon',
    icon: '🎮',
  },
];

export default function Apps() {
  return (
    <div className="page-container">
      <h2 className="metal-text" style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '8px', display: 'inline-block' }}>App Connections</h2>
      <p style={{ opacity: 0.5, fontSize: '13px', marginBottom: '24px' }}>Connect your daily use apps for automated challenge verification and other features.</p>

      <div className="card-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
        {apps.map(app => (
          <div key={app.id} className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
              <span style={{ fontSize: '28px' }}>{app.icon}</span>
              <h3 style={{ fontSize: '16px', fontWeight: 500 }}>{app.name}</h3>
            </div>
            <p style={{ fontSize: '13px', opacity: 0.6, marginBottom: '16px' }}>{app.description}</p>
            <div style={{
              padding: '8px 16px', borderRadius: '4px', textAlign: 'center',
              fontSize: '12px', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
              border: '1px solid #333', color: '#666',
            }}>
              Coming Soon
            </div>
          </div>
        ))}
      </div>

      <div className="info-note" style={{ marginTop: '24px' }}>
        <p>Don't see an app you use? Let us know and we'll see what we can do.</p>
      </div>
    </div>
  );
}
