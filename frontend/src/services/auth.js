/**
 * Authentication service for NIDS Phase 9.
 * Handles token storage, session state, login/logout operations,
 * and dispatching authentication lifecycle events.
 */

const TOKEN_KEY = 'nids_access_token';
const USER_KEY = 'nids_user';

// Listeners for auth state changes
const authChangeListeners = new Set();

export const auth = {
  /**
   * Retrieve stored access token.
   * @returns {string|null}
   */
  getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },

  /**
   * Retrieve stored user profile.
   * @returns {Object|null}
   */
  getUser() {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },

  /**
   * Check if token exists in storage.
   * @returns {boolean}
   */
  isAuthenticated() {
    return Boolean(this.getToken());
  },

  /**
   * Get current user role (ADMIN, ANALYST, VIEWER).
   * @returns {string|null}
   */
  getUserRole() {
    const user = this.getUser();
    return user ? user.role : null;
  },

  /**
   * Save session data to local storage.
   * @param {string} token
   * @param {Object} user
   */
  setSession(token, user) {
    try {
      if (token) {
        localStorage.setItem(TOKEN_KEY, token);
      }
      if (user) {
        localStorage.setItem(USER_KEY, JSON.stringify(user));
      }
    } catch (err) {
      console.error('Failed to save auth session to storage:', err);
    }
    this._notifyListeners();
  },

  /**
   * Clear session data from storage.
   */
  clearSession() {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
    } catch (err) {
      console.error('Failed to clear auth session from storage:', err);
    }
    this._notifyListeners();
  },

  /**
   * Subscribe to auth status transitions (e.g. login, logout, session expiration).
   * @param {Function} callback
   * @returns {Function} Unsubscribe callback
   */
  onAuthChange(callback) {
    authChangeListeners.add(callback);
    return () => {
      authChangeListeners.delete(callback);
    };
  },

  _notifyListeners() {
    authChangeListeners.forEach((cb) => {
      try {
        cb({
          isAuthenticated: this.isAuthenticated(),
          user: this.getUser(),
          token: this.getToken(),
        });
      } catch (err) {
        console.error('Error in auth listener:', err);
      }
    });
  },
};

export default auth;
