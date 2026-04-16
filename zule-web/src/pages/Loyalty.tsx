import React, { useState, useEffect, useRef } from 'react';
import { supabase } from '../lib/supabase';

const g = "'Cormorant Garamond', serif";

interface LoyaltyCard {
  id: string;
  program_name: string;
  member_number: string;
  barcode_format: string | null;
  created_at: string;
}

async function getFreshToken(): Promise<string | null> {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.access_token ?? null;
}

export default function Loyalty() {
  const [cards, setCards] = useState<LoyaltyCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [programName, setProgramName] = useState('');
  const [memberNumber, setMemberNumber] = useState('');
  const [adding, setAdding] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [removeLoadingId, setRemoveLoadingId] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  useEffect(() => {
    fetchCards();
    return () => stopScanner();
  }, []);

  const fetchCards = async () => {
    const token = await getFreshToken();
    if (!token) return;

    try {
      setLoading(true);
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/loyalty-cards`,
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
        setCards(await res.json());
      }
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  };

  const addCard = async () => {
    if (!programName || !memberNumber) return;
    const token = await getFreshToken();
    if (!token) return;

    setAdding(true);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/loyalty-cards`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({ program_name: programName, member_number: memberNumber }),
        }
      );
      if (res.ok) {
        setProgramName('');
        setMemberNumber('');
        await fetchCards();
      }
    } catch {
      // silent
    } finally {
      setAdding(false);
    }
  };

  const removeCard = async (id: string) => {
    const token = await getFreshToken();
    if (!token) return;

    setRemoveLoadingId(id);
    try {
      await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/loyalty-cards`,
        {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({ id }),
        }
      );
      await fetchCards();
    } catch {
      // silent
    } finally {
      setRemoveLoadingId(null);
    }
  };

  const startScanner = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      streamRef.current = stream;
      setScanning(true);

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }

      // Use BarcodeDetector API if available
      if ('BarcodeDetector' in window) {
        const detector = new (window as any).BarcodeDetector({
          formats: ['code_128', 'code_39', 'ean_13', 'ean_8', 'qr_code', 'upc_a', 'upc_e'],
        });

        const detect = async () => {
          if (!videoRef.current || !streamRef.current) return;
          try {
            const barcodes = await detector.detect(videoRef.current);
            if (barcodes.length > 0) {
              setMemberNumber(barcodes[0].rawValue);
              stopScanner();
              return;
            }
          } catch {
            // detection failed, retry
          }
          if (streamRef.current) {
            requestAnimationFrame(detect);
          }
        };
        // Wait for video to be ready
        videoRef.current?.addEventListener('loadeddata', () => detect(), { once: true });
      }
    } catch {
      setScanning(false);
    }
  };

  const stopScanner = () => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop());
      streamRef.current = null;
    }
    setScanning(false);
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <h2 className="metal-text" style={{ fontFamily: g, fontSize: '24px', fontWeight: 400, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '8px', display: 'inline-block' }}>Loyalty Programs</h2>
      <p style={{ opacity: 0.5, fontSize: '13px', marginBottom: '24px' }}>Enter your loyalty member numbers here for automated rewards tracking.</p>

      {/* Add Card */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '14px', marginBottom: '12px' }}>Add Loyalty Card</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <input
            type="text"
            placeholder="Program name (e.g. Starbucks Rewards)"
            value={programName}
            onChange={e => setProgramName(e.target.value)}
            style={{ background: '#111', border: '1px solid #333', borderRadius: '4px', padding: '10px 12px', color: '#fff', fontSize: '14px' }}
          />
          <div style={{ display: 'flex', gap: '8px' }}>
            <input
              type="text"
              placeholder="Member number"
              value={memberNumber}
              onChange={e => setMemberNumber(e.target.value)}
              style={{ flex: 1, background: '#111', border: '1px solid #333', borderRadius: '4px', padding: '10px 12px', color: '#fff', fontSize: '14px' }}
            />
            <button
              onClick={scanning ? stopScanner : startScanner}
              style={{ background: 'none', border: '1px solid #444', borderRadius: '4px', padding: '10px 14px', color: '#888', cursor: 'pointer', fontSize: '18px', lineHeight: 1 }}
              title={scanning ? 'Stop scanner' : 'Scan barcode'}
            >
              {scanning ? '✕' : '📷'}
            </button>
          </div>

          {scanning && (
            <div style={{ position: 'relative', borderRadius: '6px', overflow: 'hidden', border: '1px solid #333' }}>
              <video
                ref={videoRef}
                style={{ width: '100%', display: 'block' }}
                playsInline
                muted
              />
              {!('BarcodeDetector' in window) && (
                <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, background: 'rgba(0,0,0,0.8)', padding: '8px', textAlign: 'center', fontSize: '11px', color: '#f59e0b' }}>
                  Barcode detection not supported in this browser. Use Chrome on Android for auto-scan, or enter the number manually.
                </div>
              )}
            </div>
          )}

          <button
            className="btn-primary"
            onClick={addCard}
            disabled={adding || !programName || !memberNumber}
            style={{ marginTop: '4px' }}
          >
            {adding ? 'Adding...' : 'Add Card'}
          </button>
        </div>
      </div>

      {/* Card List */}
      {cards.length > 0 ? (
        cards.map(card => (
          <div key={card.id} className="card" style={{ marginBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '15px', fontWeight: 500 }}>{card.program_name}</div>
              <div style={{ fontSize: '13px', opacity: 0.5, fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{card.member_number}</div>
            </div>
            <button
              onClick={() => removeCard(card.id)}
              disabled={removeLoadingId === card.id}
              style={{ background: 'none', border: '1px solid #ef4444', color: '#ef4444', padding: '4px 12px', borderRadius: '3px', cursor: 'pointer', fontSize: '11px' }}
            >
              {removeLoadingId === card.id ? '...' : 'Remove'}
            </button>
          </div>
        ))
      ) : (
        <div className="info-note">
          <p>No loyalty cards added yet.</p>
        </div>
      )}
    </div>
  );
}
