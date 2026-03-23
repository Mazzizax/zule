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
 * - 8 minute inactivity timeout (resets on user interaction)
 * - 25 minute hard timeout (no matter what)
 * - Single-session enforcement: login on another tab/device kills this one
 */

const INACTIVITY_TIMEOUT = 8 * 60 * 1000; // 8 minutes
const HARD_TIMEOUT = 25 * 60 * 1000; // 25 minutes
const SESSION_CHECK_INTERVAL = 5 * 1000; // Check for rival sessions every 5 seconds
const ACTIVITY_EVENTS = ['mousedown', 'keydown', 'scroll', 'touchstart'] as const;

// Session lock key in localStorage — stores the session ID that owns this browser
const SESSION_LOCK_KEY = 'zule_active_session';

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
  const sessionCheckRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const loginTimeRef = useRef<number | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  const isLoggingOutRef = useRef(false);
  const didInitiateLoginRef = useRef(false);

  const forceLogout = useCallback(async (reason: string) => {
    if (isLoggingOutRef.current) return; // Prevent re-entrant logout
    isLoggingOutRef.current = true;

    console.warn('[SESSION-SECURITY]', reason);

    // Clean up timers
    if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    if (sessionCheckRef.current) clearInterval(sessionCheckRef.current);
    inactivityTimerRef.current = null;
    hardTimeoutRef.current = null;
    sessionCheckRef.current = null;
    loginTimeRef.current = null;
    sessionIdRef.current = null;

    // Sign out
    await supabase.auth.signOut();
    isLoggingOutRef.current = false;
    alert(reason);
  }, []);

  const resetInactivityTimer = useCallback(() => {
    if (!loginTimeRef.current) return; // Not logged in

    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }

    inactivityTimerRef.current = setTimeout(() => {
      forceLogout('Session expired due to inactivity (8 minutes)');
    }, INACTIVITY_TIMEOUT);
  }, [forceLogout]);

  const startSessionTimers = useCallback((claimLock: boolean) => {
    loginTimeRef.current = Date.now();

    if (claimLock) {
      // This tab initiated the login — generate a new lock and displace others
      const thisSessionId = crypto.randomUUID();
      sessionIdRef.current = thisSessionId;
      localStorage.setItem(SESSION_LOCK_KEY, thisSessionId);
    } else {
      // This tab is passively picking up a session (e.g. from another tab's login)
      // Adopt the existing lock — do NOT write a new one
      sessionIdRef.current = localStorage.getItem(SESSION_LOCK_KEY);
    }

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

    // Poll for rival sessions (other tabs or devices that took over)
    if (sessionCheckRef.current) clearInterval(sessionCheckRef.current);
    sessionCheckRef.current = setInterval(() => {
      const currentLock = localStorage.getItem(SESSION_LOCK_KEY);
      if (currentLock && currentLock !== sessionIdRef.current) {
        // Another tab/session claimed the lock — we've been displaced
        forceLogout('Session ended: you logged in from another location');
      }
    }, SESSION_CHECK_INTERVAL);
  }, [resetInactivityTimer, forceLogout]);

  const stopSessionTimers = useCallback(() => {
    if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    if (hardTimeoutRef.current) clearTimeout(hardTimeoutRef.current);
    if (sessionCheckRef.current) clearInterval(sessionCheckRef.current);
    inactivityTimerRef.current = null;
    hardTimeoutRef.current = null;
    sessionCheckRef.current = null;
    loginTimeRef.current = null;
    sessionIdRef.current = null;

    ACTIVITY_EVENTS.forEach((event) => {
      document.removeEventListener(event, resetInactivityTimer);
    });
  }, [resetInactivityTimer]);

  useEffect(() => {
    // Listen for storage events from OTHER tabs (same browser)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === SESSION_LOCK_KEY && e.newValue && e.newValue !== sessionIdRef.current && sessionIdRef.current) {
        forceLogout('Session ended: you logged in from another tab');
      }
    };
    window.addEventListener('storage', handleStorageChange);

    // Check for existing session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session) startSessionTimers(false); // Passive pickup on page load
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);

      if (session) {
        // New sign-in or token refresh — only start timers if not already running
        if (!loginTimeRef.current) {
          // Only claim the lock if this tab initiated the login
          const shouldClaim = didInitiateLoginRef.current;
          didInitiateLoginRef.current = false;
          startSessionTimers(shouldClaim);
        }
      } else {
        // Signed out
        stopSessionTimers();
      }
    });

    return () => {
      subscription.unsubscribe();
      stopSessionTimers();
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [startSessionTimers, stopSessionTimers, forceLogout]);

  const signIn = async (email: string, password: string) => {
    didInitiateLoginRef.current = true;
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      didInitiateLoginRef.current = false;
      throw error;
    }
  };

  const signUp = async (email: string, password: string) => {
    const { error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) throw error;
  };

  const signOut = async () => {
    // Clear the session lock so other tabs don't get a false displacement alert
    localStorage.removeItem(SESSION_LOCK_KEY);
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
