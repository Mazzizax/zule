import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const g = "'Cormorant Garamond', serif";

const metals: Record<string, { gradient: string, border: string, shadow: string, text: string, highlight: string }> = {
  rose: {
    gradient: 'linear-gradient(145deg, #8a7560 0%, #C4A882 15%, #E0D0B8 30%, #D4BC9A 45%, #A08968 55%, #C4A882 70%, #E0D0B8 85%, #8a7560 100%)',
    border: 'rgba(224,208,184,0.4)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.25), inset 0 -1px 0 rgba(0,0,0,0.3), 0 2px 4px rgba(0,0,0,0.5), 0 1px 0 rgba(196,168,130,0.15)',
    text: '#1a1510',
    highlight: 'rgba(224,208,184,0.4)',
  },
  titanium: {
    gradient: 'linear-gradient(145deg, #7a8590 0%, #B0BEC5 15%, #CFD8DC 30%, #B0BEC5 45%, #8a9aa5 55%, #B0BEC5 70%, #CFD8DC 85%, #7a8590 100%)',
    border: 'rgba(207,216,220,0.4)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.3), inset 0 -1px 0 rgba(0,0,0,0.3), 0 2px 4px rgba(0,0,0,0.5), 0 1px 0 rgba(176,190,197,0.15)',
    text: '#1a1e22',
    highlight: 'rgba(207,216,220,0.5)',
  },
  gunmetal: {
    gradient: 'linear-gradient(145deg, #2d3035 0%, #3d4248 12%, #515760 25%, #5a6068 35%, #4a5058 45%, #3d4248 55%, #515760 68%, #5a6068 78%, #4a5058 88%, #2d3035 100%)',
    border: 'rgba(90,96,104,0.4)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.1), inset 0 -1px 0 rgba(0,0,0,0.35), 0 2px 6px rgba(0,0,0,0.5), 0 1px 0 rgba(74,78,82,0.15)',
    text: '#111214',
    highlight: 'rgba(120,126,134,0.3)',
  },
};

const services = [
  {
    id: 'goals',
    name: 'Goals',
    description: 'Rewards platform — XP, gear, quests, brand engagement',
    tiers: [
      { id: 'standard', name: 'Standard', metal: 'rose', features: ['Basic XP tracking', '5 gear slots', 'Community quests'] },
      { id: 'premium', name: 'Premium', metal: 'titanium', features: ['Full XP tracking', 'All 20 gear slots', 'Loadouts', 'Sponsor pools', 'Priority quest matching'] },
      { id: 'citizen', name: 'Citizen', metal: 'gunmetal', features: ['Everything in Premium', 'Advanced analytics', 'Custom loadout themes', 'Early access features', 'Direct brand engagement'] },
    ],
  },
];

export default function Subscriptions() {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const [selectedService, setSelectedService] = useState<string | null>(searchParams.get('service'));

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
            onClick={() => { setSelectedService(null); window.history.replaceState(null, '', '/subscriptions'); }}
            style={{ marginBottom: '16px', width: 'auto' }}
          >
            All Services
          </button>

          <h2 className="metal-text" style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '16px' }}>{service?.name}</h2>

          <div className="card-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
            {service?.tiers.map(tier => (
              <div key={tier.id} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '16px' }}>
                <div>
                  <h3 className="metal-text" style={{ fontFamily: g, fontSize: '20px', fontWeight: 400, letterSpacing: '0.08em', marginBottom: '12px', display: 'inline-block' }}>{tier.name}</h3>
                  <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {tier.features.map((f, i) => (
                      <li key={i} style={{ fontSize: '12px', padding: '4px 0', opacity: 0.7 }}>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>
                {(() => {
                  const m = metals[tier.metal] || metals.rose;
                  return (
                    <div style={{
                      marginTop: '16px', width: '100%', padding: '10px 12px',
                      background: m.gradient,
                      backgroundSize: '200% auto',
                      borderRadius: '4px', textAlign: 'center',
                      fontFamily: g, fontSize: '13px', fontWeight: 500,
                      color: m.text, letterSpacing: '0.14em', textTransform: 'uppercase',
                      fontWeight: 600, fontSize: '12px',
                      boxShadow: m.shadow,
                      borderTop: `1px solid ${m.border}`,
                      borderBottom: '1px solid rgba(0,0,0,0.4)',
                      textShadow: `0 1px 0 ${m.highlight}`,
                      position: 'relative',
                      overflow: 'hidden',
                    }}>
                      <span style={{ position: 'relative', zIndex: 1 }}>Purchased</span>
                      <div style={{
                        position: 'absolute', top: 0, left: 0, right: 0, height: '50%',
                        background: 'linear-gradient(180deg, rgba(255,255,255,0.12) 0%, transparent 100%)',
                        pointerEvents: 'none',
                      }} />
                      <div style={{
                        position: 'absolute', top: '1px', left: '4px', right: '4px', height: '1px',
                        background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)',
                        pointerEvents: 'none',
                      }} />
                    </div>
                  );
                })()}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
