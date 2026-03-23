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

interface AuthContextType {
  session: Session | null;
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
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

    await supabase.auth.signOut();
    alert(reason);
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

  useEffect(() => {
    // Check for existing session (within this tab's sessionStorage only)
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session) startTimersRef.current();
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);

      if (session) {
        if (!loginTimeRef.current) {
          startTimersRef.current();
        }
      } else {
        stopTimersRef.current();
      }
    });

    return () => {
      subscription.unsubscribe();
      stopTimersRef.current();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const signIn = async (email: string, password: string) => {
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

  const value = {
    session,
    user,
    loading,
    signIn,
    signUp,
    signOut,
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
