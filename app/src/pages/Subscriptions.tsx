import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';

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
    gradient: 'linear-gradient(145deg, #3a3e44 0%, #4d5259 12%, #626870 25%, #6e747c 35%, #5a6068 45%, #4d5259 55%, #626870 68%, #6e747c 78%, #5a6068 88%, #3a3e44 100%)',
    border: 'rgba(110,116,124,0.5)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.2), inset 0 -1px 0 rgba(0,0,0,0.35), 0 2px 6px rgba(0,0,0,0.5), 0 1px 0 rgba(90,96,104,0.2)',
    text: '#e8e8ea',
    highlight: 'rgba(160,166,174,0.35)',
  },
};

interface Subscription {
  service_id: string;
  tier: string;
  status: string;
}

const services = [
  {
    id: 'goals',
    name: 'Goals',
    description: 'Rewards platform — XP, gear, quests, brand engagement',
    tiers: [
      { id: 'standard', name: 'Standard', metal: 'rose', price: null, stripe_price_id: null, features: ['Basic XP tracking', '5 gear slots', 'Community quests'] },
      { id: 'premium', name: 'Premium', metal: 'titanium', price: null, stripe_price_id: null, features: ['Full XP tracking', 'All 20 gear slots', 'Loadouts', 'Sponsor pools', 'Priority quest matching'] },
      { id: 'citizen', name: 'Citizen', metal: 'gunmetal', price: null, stripe_price_id: null, features: ['Everything in Premium', 'Advanced analytics', 'Custom loadout themes', 'Early access features', 'Direct brand engagement'] },
    ],
  },
  {
    id: 'aca',
    name: 'Advanced Cognitive Assistant',
    description: 'Harness 4 frontier AI models to power your daily life',
    tiers: [
      { id: 'standard', name: 'Standard', metal: 'rose', price: '$65/mo', stripe_price_id: 'price_1SuhgaDRpCHsf7InZqtoYRA3', features: [] },
      { id: 'enthusiast', name: 'Enthusiast', metal: 'titanium', price: '$125/mo', stripe_price_id: 'price_1SuhqgDRpCHsf7InpPL2w5d9', features: [] },
      { id: 'padawan', name: 'Padawan', metal: 'gunmetal', price: '$215/mo', stripe_price_id: 'price_1SuhvuDRpCHsf7In7c52Ovn1', features: [] },
    ],
  },
];

export default function Subscriptions() {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const [selectedService, setSelectedService] = useState<string | null>(searchParams.get('service'));
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [cancelConfirm, setCancelConfirm] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [upgradeTarget, setUpgradeTarget] = useState<{ serviceId: string; tierId: string; tierName: string; priceId: string; price: string } | null>(null);
  const [upgradeLoading, setUpgradeLoading] = useState(false);

  useEffect(() => {
    fetchSubscriptions();
  }, []);

  const fetchSubscriptions = async () => {
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) return;

    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/user-profile`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );
      if (res.ok) {
        const data = await res.json();
        setSubscriptions(data.subscriptions || []);
      }
    } catch {
      // Silently fail — subscriptions just won't show active state
    }
  };

  const handleSubscribe = async (serviceId: string, stripePriceId: string) => {
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) return;

    setCheckoutLoading(`${serviceId}-${stripePriceId}`);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/create-checkout`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({
            price_id: stripePriceId,
            service_id: serviceId,
            success_url: `${window.location.origin}/subscriptions?success=true&service=${serviceId}`,
            cancel_url: `${window.location.origin}/subscriptions?service=${serviceId}`,
          }),
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to create checkout session');
      }

      const { url } = await res.json();
      if (url) {
        window.location.href = url;
      }
    } catch (err: any) {
      console.error('Checkout error:', err.message);
    } finally {
      setCheckoutLoading(null);
    }
  };

  const handleUpgrade = async (serviceId: string, newPriceId: string) => {
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) return;

    setUpgradeLoading(true);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/upgrade-subscription`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({ service_id: serviceId, new_price_id: newPriceId }),
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to upgrade');
      }

      setUpgradeTarget(null);
      // Wait for webhook to update the DB, then refresh
      await new Promise(r => setTimeout(r, 2000));
      await fetchSubscriptions();
    } catch (err: any) {
      console.error('Upgrade error:', err.message);
    } finally {
      setUpgradeLoading(false);
    }
  };

  const handleCancel = async (serviceId: string) => {
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;
    if (!token) return;

    setCancelLoading(true);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/cancel-subscription`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({ service_id: serviceId }),
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to cancel');
      }

      setCancelConfirm(false);
      await fetchSubscriptions();
    } catch (err: any) {
      console.error('Cancel error:', err.message);
    } finally {
      setCancelLoading(false);
    }
  };

  const getActiveSubscription = (serviceId: string): Subscription | undefined => {
    return subscriptions.find(s => s.service_id === serviceId && s.status === 'active');
  };

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
                  <h3 className="metal-text" style={{ fontFamily: g, fontSize: '20px', fontWeight: 400, letterSpacing: '0.08em', marginBottom: '4px', display: 'inline-block' }}>{tier.name}</h3>
                  {tier.price && (
                    <p style={{ fontFamily: g, fontSize: '18px', fontWeight: 500, color: 'var(--zule-gold)', marginBottom: '8px' }}>{tier.price}</p>
                  )}
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
                  const activeSub = getActiveSubscription(service!.id);
                  const isActive = activeSub?.tier === tier.id;
                  const isGoals = service!.id === 'goals';
                  const hasExisting = !!activeSub;
                  const canChange = tier.stripe_price_id && !isActive;
                  const loadingKey = `${service!.id}-${tier.stripe_price_id}`;

                  let label = 'Subscribe';
                  if (isGoals) label = 'Purchased';
                  else if (isActive) label = 'Active';
                  else if (hasExisting && canChange) label = 'Switch';

                  return (
                    <div
                      onClick={() => {
                        if (canChange && tier.stripe_price_id) {
                          if (hasExisting) {
                            setUpgradeTarget({ serviceId: service!.id, tierId: tier.id, tierName: tier.name, priceId: tier.stripe_price_id, price: tier.price || '' });
                          } else {
                            handleSubscribe(service!.id, tier.stripe_price_id);
                          }
                        }
                      }}
                      style={{
                        marginTop: '16px', width: '100%', padding: '10px 12px',
                        background: m.gradient,
                        backgroundSize: '200% auto',
                        borderRadius: '4px', textAlign: 'center',
                        fontFamily: g,
                        color: m.text, letterSpacing: '0.14em', textTransform: 'uppercase',
                        fontWeight: 600, fontSize: '12px',
                        boxShadow: m.shadow,
                        borderTop: `1px solid ${m.border}`,
                        borderBottom: '1px solid rgba(0,0,0,0.4)',
                        textShadow: `0 1px 0 ${m.highlight}`,
                        position: 'relative',
                        overflow: 'hidden',
                        cursor: canChange ? 'pointer' : 'default',
                        opacity: checkoutLoading === loadingKey ? 0.6 : 1,
                      }}>
                      <span style={{ position: 'relative', zIndex: 1 }}>
                        {checkoutLoading === loadingKey ? 'Redirecting...' : label}
                      </span>
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

          {upgradeTarget && upgradeTarget.serviceId === service?.id && (
            <div style={{ marginTop: '24px', padding: '16px', border: '1px solid var(--zule-gold, #c4a882)', borderRadius: '6px', textAlign: 'center' }}>
              <p style={{ fontSize: '14px', marginBottom: '12px' }}>
                Switch to <strong>{upgradeTarget.tierName}</strong>{upgradeTarget.price ? ` (${upgradeTarget.price})` : ''}? Your card on file will be billed.
              </p>
              <button
                onClick={() => handleUpgrade(upgradeTarget.serviceId, upgradeTarget.priceId)}
                disabled={upgradeLoading}
                style={{ background: 'var(--zule-gold, #c4a882)', color: '#111', border: 'none', padding: '8px 24px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', fontWeight: 600, marginRight: '8px', opacity: upgradeLoading ? 0.6 : 1 }}
              >
                {upgradeLoading ? 'Switching...' : 'Confirm'}
              </button>
              <button
                onClick={() => setUpgradeTarget(null)}
                style={{ background: 'none', border: '1px solid #444', color: '#888', padding: '8px 24px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px' }}
              >
                Never Mind
              </button>
            </div>
          )}

          {service && service.id !== 'goals' && getActiveSubscription(service.id) && !cancelConfirm && (
            <div style={{ marginTop: '24px', textAlign: 'center' }}>
              <button
                onClick={() => setCancelConfirm(true)}
                style={{ background: 'none', border: '1px solid #ef4444', color: '#ef4444', padding: '8px 24px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px' }}
              >
                Cancel Subscription
              </button>
            </div>
          )}

          {service && service.id !== 'goals' && cancelConfirm && (
            <div style={{ marginTop: '24px', padding: '16px', border: '1px solid #ef4444', borderRadius: '6px', textAlign: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer', marginBottom: '12px' }}>
                <input
                  type="checkbox"
                  id="cancel-confirm-check"
                  style={{ cursor: 'pointer' }}
                />
                I want to cancel my {service.name} subscription
              </label>
              <button
                onClick={() => {
                  const checked = (document.getElementById('cancel-confirm-check') as HTMLInputElement)?.checked;
                  if (checked) handleCancel(service.id);
                }}
                disabled={cancelLoading}
                style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 24px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', marginRight: '8px', opacity: cancelLoading ? 0.6 : 1 }}
              >
                {cancelLoading ? 'Canceling...' : 'Confirm Cancellation'}
              </button>
              <button
                onClick={() => setCancelConfirm(false)}
                style={{ background: 'none', border: '1px solid #444', color: '#888', padding: '8px 24px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px' }}
              >
                Never Mind
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
