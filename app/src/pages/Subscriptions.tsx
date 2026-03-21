import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const g = "'Cormorant Garamond', serif";

const services = [
  {
    id: 'goals',
    name: 'Goals',
    description: 'Rewards platform — XP, gear, quests, brand engagement',
    tiers: [
      { id: 'standard', name: 'Standard', features: ['Basic XP tracking', '5 gear slots', 'Community quests'] },
      { id: 'premium', name: 'Premium', features: ['Full XP tracking', 'All 20 gear slots', 'Loadouts', 'Sponsor pools', 'Priority quest matching'] },
      { id: 'sovereign', name: 'Sovereign', features: ['Everything in Premium', 'Advanced analytics', 'Custom loadout themes', 'Early access features', 'Direct brand engagement'] },
    ],
  },
];

export default function Subscriptions() {
  const { user } = useAuth();
  const [selectedService, setSelectedService] = useState<string | null>(null);

  const service = services.find(s => s.id === selectedService);

  return (
    <div className="page-container">

      {!selectedService ? (
        <div>
          {services.map(svc => (
            <div
              key={svc.id}
              className="card"
              onClick={() => setSelectedService(svc.id)}
              style={{ cursor: 'pointer' }}
            >
              <h2 className="metal-text" style={{ fontFamily: g, fontSize: '22px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase', display: 'inline-block' }}>{svc.name}</h2>
              <p style={{ opacity: 0.6, fontSize: '13px' }}>{svc.description}</p>
            </div>
          ))}
        </div>
      ) : (
        <div>
          <button
            className="btn-secondary"
            onClick={() => setSelectedService(null)}
            style={{ marginBottom: '16px', width: 'auto' }}
          >
            Back
          </button>

          <h2 className="metal-text" style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '16px' }}>{service?.name}</h2>

          <div className="card-grid">
            {service?.tiers.map(tier => (
              <div key={tier.id} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <h3 style={{ fontFamily: g, fontSize: '20px', fontWeight: 400, letterSpacing: '0.04em', marginBottom: '12px' }}>{tier.name}</h3>
                  <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {tier.features.map((f, i) => (
                      <li key={i} style={{ fontSize: '12px', padding: '4px 0', opacity: 0.7 }}>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>
                <div style={{
                  marginTop: '16px', width: '100%', padding: '12px',
                  background: 'var(--metal-surface)', backgroundSize: '200% auto',
                  borderRadius: '8px', textAlign: 'center',
                  fontFamily: g, fontSize: '14px', fontWeight: 500,
                  color: '#0a0908', letterSpacing: '0.1em', textTransform: 'uppercase',
                }}>
                  Purchased
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
