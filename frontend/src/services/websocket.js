/**
 * WebSocket service for Phase 7 & Phase 9 Real-Time Security Monitoring.
 * Manages an authenticated application-level WebSocket connection, handles
 * controlled reconnection with exponential backoff, sends auth handshake frame,
 * and distributes parsed telemetry events to React subscribers.
 */

import { API_BASE_URL } from './api';
import auth from './auth';

export const WS_STATUS = {
  CONNECTING: 'CONNECTING',
  CONNECTED: 'CONNECTED',
  DISCONNECTED: 'DISCONNECTED',
  RECONNECTING: 'RECONNECTING',
  UNAUTHORIZED: 'UNAUTHORIZED',
};

// Reconnection backoff schedule: 1s, 2s, 4s, 8s (capped at 8s)
const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000];

/**
 * Dynamically resolves the WebSocket monitor endpoint URL from existing API configuration.
 * @param {string|null} token
 * @returns {string}
 */
export function getWebSocketUrl() {
  let base = API_BASE_URL;
  if (!base) {
    if (typeof window !== 'undefined' && window.location) {
      const loc = window.location;
      const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
      base = `${proto}//${loc.host}`;
    } else {
      base = 'ws://127.0.0.1:8000';
    }
  } else if (base.startsWith('https://')) {
    base = base.replace(/^https:\/\//, 'wss://');
  } else if (base.startsWith('http://')) {
    base = base.replace(/^http:\/\//, 'ws://');
  }

  return `${base.replace(/\/+$/, '')}/api/v1/ws/monitor`;
}

class WebSocketService {
  constructor() {
    this._socket = null;
    this._status = WS_STATUS.DISCONNECTED;
    this._listeners = new Set();
    this._statusListeners = new Set();
    this._reconnectAttempts = 0;
    this._reconnectTimer = null;
    this._explicitlyClosed = false;

    // Listen for auth state changes
    auth.onAuthChange(({ isAuthenticated }) => {
      if (!isAuthenticated) {
        this.disconnect();
      } else if (this._status === WS_STATUS.DISCONNECTED || this._status === WS_STATUS.UNAUTHORIZED) {
        this.connect();
      }
    });
  }

  get status() {
    return this._status;
  }

  get isConnected() {
    return this._status === WS_STATUS.CONNECTED && this._socket?.readyState === WebSocket.OPEN;
  }

  /**
   * Register a listener for incoming parsed WebSocket telemetry events.
   * @param {Function} callback - fn(event: Object)
   * @returns {Function} Unsubscribe cleanup function
   */
  subscribe(callback) {
    this._listeners.add(callback);
    return () => {
      this._listeners.delete(callback);
    };
  }

  /**
   * Register a listener for connection status changes.
   * @param {Function} callback - fn(status: string)
   * @returns {Function} Unsubscribe cleanup function
   */
  onStatusChange(callback) {
    this._statusListeners.add(callback);
    // Immediately invoke with current status
    callback(this._status);
    return () => {
      this._statusListeners.delete(callback);
    };
  }

  _setStatus(newStatus) {
    if (this._status !== newStatus) {
      this._status = newStatus;
      this._statusListeners.forEach((cb) => {
        try {
          cb(newStatus);
        } catch (err) {
          console.error('Error in WebSocket status listener:', err);
        }
      });
    }
  }

  /**
   * Establish authenticated WebSocket connection to backend monitoring endpoint.
   */
  connect() {
    const token = auth.getToken();
    if (!token) {
      // Unauthenticated users should not attempt connection
      this._setStatus(WS_STATUS.DISCONNECTED);
      return;
    }

    // Prevent duplicate connections if already open or connecting
    if (this._socket && (this._socket.readyState === WebSocket.OPEN || this._socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this._explicitlyClosed = false;
    this._clearReconnectTimer();

    const wsUrl = getWebSocketUrl();
    this._setStatus(this._reconnectAttempts > 0 ? WS_STATUS.RECONNECTING : WS_STATUS.CONNECTING);

    try {
      this._socket = new WebSocket(wsUrl);

      this._socket.onopen = () => {
        this._reconnectAttempts = 0;
        this._setStatus(WS_STATUS.CONNECTED);

        // Send explicit authentication frame handshake
        try {
          this._socket.send(JSON.stringify({ type: 'auth', token }));
        } catch (err) {
          console.warn('Failed to transmit auth frame on WebSocket:', err);
        }
      };

      this._socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed && typeof parsed === 'object') {
            this._listeners.forEach((listener) => {
              try {
                listener(parsed);
              } catch (listenerErr) {
                console.error('Error in WebSocket message listener:', listenerErr);
              }
            });
          }
        } catch {
          // Malformed JSON is ignored safely without crashing
        }
      };

      this._socket.onerror = () => {
        // Starlette WebSocket errors trigger onclose immediately after
        this._setStatus(WS_STATUS.DISCONNECTED);
      };

      this._socket.onclose = (event) => {
        this._socket = null;

        // If rejected due to 1008 Policy Violation (Unauthorized), stop reconnecting
        if (event.code === 1008) {
          this._setStatus(WS_STATUS.UNAUTHORIZED);
          return;
        }

        if (!this._explicitlyClosed && auth.isAuthenticated()) {
          this._scheduleReconnect();
        } else {
          this._setStatus(WS_STATUS.DISCONNECTED);
        }
      };
    } catch {
      this._setStatus(WS_STATUS.DISCONNECTED);
      if (!this._explicitlyClosed && auth.isAuthenticated()) {
        this._scheduleReconnect();
      }
    }
  }

  _scheduleReconnect() {
    this._clearReconnectTimer();

    if (!auth.isAuthenticated()) {
      this._setStatus(WS_STATUS.DISCONNECTED);
      return;
    }

    const delayIndex = Math.min(this._reconnectAttempts, RECONNECT_DELAYS_MS.length - 1);
    const delayMs = RECONNECT_DELAYS_MS[delayIndex];
    this._reconnectAttempts += 1;

    this._setStatus(WS_STATUS.RECONNECTING);

    this._reconnectTimer = setTimeout(() => {
      this.connect();
    }, delayMs);
  }

  _clearReconnectTimer() {
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
  }

  /**
   * Explicitly terminate WebSocket connection.
   */
  disconnect() {
    this._explicitlyClosed = true;
    this._clearReconnectTimer();
    this._reconnectAttempts = 0;

    if (this._socket) {
      try {
        this._socket.close(1000, 'Client disconnected');
      } catch {
        // Socket close error ignored
      }
      this._socket = null;
    }

    this._setStatus(WS_STATUS.DISCONNECTED);
  }

  /**
   * Send a client message (e.g. ping). Server is push-only for telemetry.
   * @param {Object|string} data
   */
  send(data) {
    if (this.isConnected) {
      try {
        const payload = typeof data === 'string' ? data : JSON.stringify(data);
        this._socket.send(payload);
      } catch (err) {
        console.warn('Failed to transmit message on WebSocket:', err);
      }
    }
  }
}

// Global application-level singleton
export const websocketService = new WebSocketService();
export default websocketService;
