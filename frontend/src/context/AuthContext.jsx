import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import auth from '../services/auth';
import api from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => auth.getUser());
  const [token, setToken] = useState(() => auth.getToken());
  const [isLoading, setIsLoading] = useState(true);

  // Validate session on mount if token is stored
  useEffect(() => {
    let isMounted = true;

    async function verifySession() {
      const storedToken = auth.getToken();
      if (!storedToken) {
        if (isMounted) {
          setUser(null);
          setToken(null);
          setIsLoading(false);
        }
        return;
      }

      try {
        const currentUser = await api.getMe();
        if (isMounted) {
          setUser(currentUser);
          setToken(storedToken);
          auth.setSession(storedToken, currentUser);
        }
      } catch {
        // Token expired or invalid
        if (isMounted) {
          auth.clearSession();
          setUser(null);
          setToken(null);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    verifySession();

    // Listen to background auth changes (e.g. 401 triggers)
    const unsub = auth.onAuthChange((state) => {
      if (isMounted) {
        setUser(state.user);
        setToken(state.token);
      }
    });

    return () => {
      isMounted = false;
      unsub();
    };
  }, []);

  const login = useCallback(async (username, password) => {
    const response = await api.login({ username, password });
    const { access_token, user: userData } = response;
    auth.setSession(access_token, userData);
    setToken(access_token);
    setUser(userData);
    return response;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Best-effort logout
    } finally {
      auth.clearSession();
      setUser(null);
      setToken(null);
    }
  }, []);

  const value = {
    user,
    token,
    role: user?.role || null,
    isAuthenticated: Boolean(token && user),
    isLoading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
