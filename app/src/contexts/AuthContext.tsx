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
 * - 15 minute inactivity timeout (resets on user interaction)
 * - 1 hour hard timeout (no matter what)
 * - Matches Goals session policy
 */

const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes
const HARD_TIMEOUT = 60 * 60 * 1000; // 1 hour
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

    // Sign out
    await supabase.auth.signOut();
    alert(reason);
  }, []);

  const resetInactivityTimer = useCallback(() => {
    if (!loginTimeRef.current) return; // Not logged in

    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }

    inactivityTimerRef.current = setTimeout(() => {
      forceLogout('Session expired due to inactivity (15 minutes)');
    }, INACTIVITY_TIMEOUT);
  }, [forceLogout]);

  const startSessionTimers = useCallback(() => {
    loginTimeRef.current = Date.now();

    // Start inactivity tracking
    resetInactivityTimer();

    // Start hard timeout — 1 hour no matter what
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    hardTimeoutRef.current = setTimeout(() => {
      forceLogout('Session expired (1 hour limit reached)');
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

  useEffect(() => {
    // Check for existing session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session) startSessionTimers();
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);

      if (session) {
        // New sign-in or token refresh — only start timers if not already running
        if (!loginTimeRef.current) {
          startSessionTimers();
        }
      } else {
        // Signed out
        stopSessionTimers();
      }
    });

    return () => {
      subscription.unsubscribe();
      stopSessionTimers();
    };
  }, [startSessionTimers, stopSessionTimers]);

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
