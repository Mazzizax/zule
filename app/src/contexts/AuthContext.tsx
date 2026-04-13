import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { Session, User } from '@supabase/supabase-js';

/**
 * AuthContext for Zule Web App
 *
 * NOTE: Ghost ID functionality has been moved to Vinzrik.
 * This context handles pure authentication only.
 * Zule knows WHO you are (identity), Vinzrik handles
 * the ghost_id that apps see.
 *
 * Session Security:
 * - sessionStorage backend: each tab is isolated, new tab = login required
 * - 8 minute inactivity timeout (resets on user interaction)
 * - 25 minute hard timeout (no matter what)
 */

const INACTIVITY_TIMEOUT = 8 * 60 * 1000; // 8 minutes
const HARD_TIMEOUT = 25 * 60 * 1000; // 25 minutes
const ACTIVITY_EVENTS = ['mousedown', 'keydown', 'scroll', 'touchstart'] as const;

// Kill signal key — localStorage is cross-tab, used ONLY to signal displacement
const KILL_SIGNAL_KEY = 'zule_login_event';

interface AuthContextType {
  session: Session | null;
  user: User | null;
  loading: boolean;
  emailVerified: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  resendVerification: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const inactivityTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hardTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loginTimeRef = useRef<number | null>(null);

  const forceLogout = useCallback(async (reason: string) => {
    console.warn('[SESSION-SECURITY]', reason);

    // Clean up timers
    if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    inactivityTimerRef.current = null;
    hardTimeoutRef.current = null;
    loginTimeRef.current = null;

    // Local-only signout — don't broadcast to other tabs/server
    // This prevents the displaced tab from killing the new session
    await supabase.auth.signOut({ scope: 'local' });
    setSession(null);
    setUser(null);
  }, []);

  const resetInactivityTimer = useCallback(() => {
    if (!loginTimeRef.current) return;

    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }

    inactivityTimerRef.current = setTimeout(() => {
      forceLogout('Session expired due to inactivity (8 minutes)');
    }, INACTIVITY_TIMEOUT);
  }, [forceLogout]);

  const startSessionTimers = useCallback(() => {
    loginTimeRef.current = Date.now();

    // Start inactivity tracking
    resetInactivityTimer();

    // Start hard timeout — 25 minutes no matter what
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    hardTimeoutRef.current = setTimeout(() => {
      forceLogout('Session expired (25 minute limit reached)');
    }, HARD_TIMEOUT);

    // Listen for user activity
    ACTIVITY_EVENTS.forEach((event) => {
      document.addEventListener(event, resetInactivityTimer, { passive: true });
    });
  }, [resetInactivityTimer, forceLogout]);

  const stopSessionTimers = useCallback(() => {
    if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    inactivityTimerRef.current = null;
    hardTimeoutRef.current = null;
    loginTimeRef.current = null;

    ACTIVITY_EVENTS.forEach((event) => {
      document.removeEventListener(event, resetInactivityTimer);
    });
  }, [resetInactivityTimer]);

  // Stable refs for use inside the effect without causing re-runs
  const startTimersRef = useRef(startSessionTimers);
  const stopTimersRef = useRef(stopSessionTimers);
  startTimersRef.current = startSessionTimers;
  stopTimersRef.current = stopSessionTimers;

  const forceLogoutRef = useRef(forceLogout);
  forceLogoutRef.current = forceLogout;

  useEffect(() => {
    // Listen for kill signal from other tabs (new login displaces this one)
    const handleKillSignal = (e: StorageEvent) => {
      if (e.key === KILL_SIGNAL_KEY && e.newValue && loginTimeRef.current) {
        forceLogoutRef.current('Session ended: you logged in from another location');
      }
    };
    window.addEventListener('storage', handleKillSignal);

    let initialLoad = true;

    // Listen for auth changes FIRST so we don't miss events
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      // Skip cross-tab broadcasts: sessionStorage is per-tab,
      // so if we have no session locally, ignore propagated ones.
      // Check sessionStorage directly instead of calling getSession() to avoid deadlock.
      if (session && !initialLoad) {
        const storageKeys = Object.keys(sessionStorage);
        const hasLocalSession = storageKeys.some(k => k.startsWith('sb-') && k.endsWith('-auth-token'));
        if (!hasLocalSession) return;
      }

      setSession(session);
      setUser(session?.user ?? null);

      if (session) {
        if (!loginTimeRef.current) {
          startTimersRef.current();
        }
      } else {
        stopTimersRef.current();
      }

      if (initialLoad) {
        initialLoad = false;
        setLoading(false);
      }
    });

    // Trigger initial session check
    supabase.auth.getSession().then(({ data: { session } }) => {
      // onAuthStateChange may have already fired — only set if still loading
      if (initialLoad) {
        setSession(session);
        setUser(session?.user ?? null);
        if (session) startTimersRef.current();
        initialLoad = false;
        setLoading(false);
      }
    });

    return () => {
      subscription.unsubscribe();
      stopTimersRef.current();
      window.removeEventListener('storage', handleKillSignal);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const signIn = async (email: string, password: string) => {
    // Broadcast kill signal BEFORE signing in — other tabs logout first
    localStorage.setItem(KILL_SIGNAL_KEY, crypto.randomUUID());

    // Small delay to let other tabs process the kill signal
    await new Promise((r) => setTimeout(r, 100));

    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;
  };

  const signUp = async (email: string, password: string) => {
    const { error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) throw error;
  };

  const signOut = async () => {
    stopSessionTimers();
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
  };

  const resendVerification = async () => {
    if (!user?.email) throw new Error('No email available');
    const { error } = await supabase.auth.resend({
      type: 'signup',
      email: user.email,
    });
    if (error) throw error;
  };

  const emailVerified = !!user?.email_confirmed_at;

  const value = {
    session,
    user,
    loading,
    emailVerified,
    signIn,
    signUp,
    signOut,
    resendVerification,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
