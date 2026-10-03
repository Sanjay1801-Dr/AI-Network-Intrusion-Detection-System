/**
 * Centralized API service layer for AI-Based Network Intrusion Detection System.
 * Connects React frontend directly to FastAPI REST endpoints.
 * Handles request execution, configurable base URLs, automatic JWT authentication,
 * and defensive error sanitization.
 */

import auth from './auth';

// Configurable backend base URL from environment or fallback to standard local default
const RAW_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export const API_BASE_URL = RAW_BASE_URL.replace(/\/+$/, '');

/**
 * Standard sanitized error structure.
 */
export class ApiError extends Error {
  /**
   * @param {string} message - User-friendly error message
   * @param {number} status - HTTP status code
   * @param {string} [errorCode] - Machine-readable error code if provided by backend
   * @param {any} [details] - Sanitized details
   */
  constructor(message, status = 0, errorCode = 'API_ERROR', details = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errorCode = errorCode;
    this.details = details;
  }
}

/**
 * Sanitize an error to prevent leaking Python stack traces, file paths, or DB queries.
 * @param {any} err
 * @param {Response} [res]
 * @returns {ApiError}
 */
async function sanitizeResponseError(res) {
  const status = res ? res.status : 0;
  let parsedJson = null;

  try {
    parsedJson = await res.json();
  } catch {
    // Non-JSON or empty response
  }

  // Handle standard HTTP statuses
  if (status === 401) {
    // Token expired or invalid credentials
    const message = parsedJson?.message || 'Invalid credentials or session expired. Please log in again.';
    // Clear invalid session if present
    auth.clearSession();
    return new ApiError(message, 401, 'UNAUTHORIZED', parsedJson?.details);
  }

  if (status === 403) {
    // Insufficient permissions for role
    const message = parsedJson?.message || 'Access forbidden: Your role lacks permission for this action.';
    return new ApiError(message, 403, 'FORBIDDEN', parsedJson?.details);
  }

  if (status === 422) {
    // Validation error
    let message = 'Validation error: The submitted network telemetry contains invalid or missing attributes.';
    if (parsedJson && parsedJson.message) {
      message = parsedJson.message;
    } else if (parsedJson && Array.isArray(parsedJson.detail)) {
      message = parsedJson.detail.map((d) => d.msg || d.message).join('; ');
    } else if (parsedJson && typeof parsedJson.detail === 'string') {
      message = parsedJson.detail;
    }
    return new ApiError(message, 422, 'VALIDATION_ERROR', parsedJson?.details);
  }

  if (status === 503) {
    const message = parsedJson?.message || 'ML Inference Service unavailable. Models are initializing or not loaded.';
    return new ApiError(message, 503, 'SERVICE_UNAVAILABLE');
  }

  if (status === 500) {
    const message = parsedJson?.message || 'An internal server error occurred while processing the request.';
    return new ApiError(message, 500, 'INTERNAL_SERVER_ERROR');
  }

  if (status === 404) {
    return new ApiError('The requested endpoint was not found on the backend service.', 404, 'NOT_FOUND');
  }

  if (status === 409) {
    const message = parsedJson?.message || 'Lifecycle transition conflict: The requested state change is not permitted.';
    return new ApiError(message, 409, 'STATE_CONFLICT', parsedJson?.details);
  }

  if (status === 429) {
    const message = parsedJson?.detail || parsedJson?.message || 'Rate limit exceeded: Too many requests. Please wait a moment and try again.';
    return new ApiError(message, 429, 'RATE_LIMIT_EXCEEDED', parsedJson?.details);
  }

  // Generic status error
  const message = parsedJson?.message || parsedJson?.detail || `API request failed with status code ${status}.`;
  return new ApiError(message, status, parsedJson?.error_code || 'HTTP_ERROR');
}

/**
 * Perform a fetch request with JWT authentication, timeout, and error sanitization.
 * @param {string} path - Relative URL path starting with /
 * @param {RequestInit} [options]
 * @returns {Promise<any>}
 */
async function request(path, options = {}) {
  const fullUrl = `${API_BASE_URL}${path}`;

  // Build headers with optional Bearer JWT token
  const headers = {
    'Accept': 'application/json',
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...options.headers,
  };

  const token = auth.getToken();
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(fullUrl, {
      ...options,
      headers,
    });

    if (!response.ok) {
      throw await sanitizeResponseError(response);
    }

    return await response.json();
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }

    // Network level or unreachable host errors
    const isNetworkError =
      err.name === 'TypeError' ||
      err.message?.includes('Failed to fetch') ||
      err.message?.includes('NetworkError') ||
      err.message?.includes('network');

    if (isNetworkError) {
      throw new ApiError(
        'Backend service unreachable. Please ensure the FastAPI backend is running at ' + API_BASE_URL,
        0,
        'NETWORK_UNAVAILABLE'
      );
    }

    throw new ApiError(
      'An unexpected error occurred while communicating with the backend.',
      0,
      'UNKNOWN_CLIENT_ERROR'
    );
  }
}

/**
 * Backend API Client
 */
export const api = {
  /**
   * Health Check: GET /api/health
   */
  async checkHealth() {
    return request('/api/health');
  },

  /**
   * User Login: POST /api/v1/auth/login
   * @param {Object} credentials
   * @param {string} credentials.username
   * @param {string} credentials.password
   * @returns {Promise<{ access_token: string, token_type: string, user: Object }>}
   */
  async login(credentials) {
    return request('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  },

  /**
   * Current Authenticated User: GET /api/v1/auth/me
   * @returns {Promise<{ id: number, username: string, role: string, is_active: boolean, created_at: string }>}
   */
  async getMe() {
    return request('/api/v1/auth/me');
  },

  /**
   * Logout: POST /api/v1/auth/logout
   */
  async logout() {
    try {
      return await request('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      auth.clearSession();
    }
  },

  /**
   * Submit network flow telemetry for AI inference: POST /api/v1/predict
   * @param {Object} flowData - Flow telemetry dictionary
   * @returns {Promise<import('../types').PredictionResponse>}
   */
  async predictFlow(flowData) {
    return request('/api/v1/predict', {
      method: 'POST',
      body: JSON.stringify(flowData),
    });
  },

  /**
   * Query prediction audit history: GET /api/v1/predictions
   * @param {Object} params
   * @param {number} [params.limit=20]
   * @param {number} [params.offset=0]
   * @returns {Promise<import('../types').PredictionHistoryResponse>}
   */
  async getPredictions({ limit = 20, offset = 0 } = {}) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    return request(`/api/v1/predictions?${query.toString()}`);
  },

  /**
   * Query security alerts with filtering: GET /api/v1/alerts
   * @param {Object} params
   * @param {number} [params.limit=20]
   * @param {number} [params.offset=0]
   * @param {string} [params.severity] - 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
   * @param {string} [params.status] - 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE'
   * @returns {Promise<import('../types').AlertHistoryResponse>}
   */
  async getAlerts({ limit = 20, offset = 0, severity = null, status = null } = {}) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });

    if (severity && severity !== 'ALL') {
      query.set('severity', severity);
    }
    if (status && status !== 'ALL') {
      query.set('status', status);
    }

    return request(`/api/v1/alerts?${query.toString()}`);
  },

  /**
   * Fetch single alert details including linked prediction metadata: GET /api/v1/alerts/{alert_id}
   * @param {number|string} alertId
   * @returns {Promise<any>}
   */
  async getAlert(alertId) {
    return request(`/api/v1/alerts/${alertId}`);
  },

  /**
   * Acknowledge alert: PATCH /api/v1/alerts/{alert_id}/acknowledge
   * @param {number|string} alertId
   * @returns {Promise<any>}
   */
  async acknowledgeAlert(alertId) {
    return request(`/api/v1/alerts/${alertId}/acknowledge`, {
      method: 'PATCH',
    });
  },

  /**
   * Resolve alert: PATCH /api/v1/alerts/{alert_id}/resolve
   * @param {number|string} alertId
   * @returns {Promise<any>}
   */
  async resolveAlert(alertId) {
    return request(`/api/v1/alerts/${alertId}/resolve`, {
      method: 'PATCH',
    });
  },

  /**
   * Query security audit logs: GET /api/v1/audit-logs
   * @param {Object} params
   * @param {number} [params.limit=20]
   * @param {number} [params.offset=0]
   * @param {string} [params.username]
   * @param {string} [params.action]
   * @param {string} [params.outcome]
   * @param {string} [params.resource_type]
   * @returns {Promise<{ total: number, limit: number, offset: number, items: Array }>}
   */
  async getAuditLogs({ limit = 20, offset = 0, username = null, action = null, outcome = null, resource_type = null } = {}) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });

    if (username && username.trim()) {
      query.set('username', username.trim());
    }
    if (action && action !== 'ALL') {
      query.set('action', action);
    }
    if (outcome && outcome !== 'ALL') {
      query.set('outcome', outcome);
    }
    if (resource_type && resource_type !== 'ALL') {
      query.set('resource_type', resource_type);
    }

    return request(`/api/v1/audit-logs?${query.toString()}`);
  },

  /**
   * Fetch security monitoring summary counters: GET /api/v1/audit-logs/summary
   * @returns {Promise<{ total_events: number, failed_logins: number, access_denied: number, rate_limit_exceeded: number }>}
   */
  async getAuditSummary() {
    return request('/api/v1/audit-logs/summary');
  },

  /**
   * Security Operations Overview Analytics: GET /api/v1/analytics/overview
   */
  async getAnalyticsOverview() {
    return request('/api/v1/analytics/overview');
  },

  /**
   * Threat Category and Severity Distributions: GET /api/v1/analytics/threat-distribution
   */
  async getThreatDistribution() {
    return request('/api/v1/analytics/threat-distribution');
  },

  /**
   * Security Timeline Trend Telemetry: GET /api/v1/analytics/timeline
   * @param {Object} params
   * @param {string} [params.time_range='7d'] - '24h' | '7d' | '30d'
   * @param {number} [params.limit=50]
   */
  async getSecurityTimeline({ time_range = '7d', limit = 50 } = {}) {
    const query = new URLSearchParams({
      time_range,
      limit: String(limit),
    });
    return request(`/api/v1/analytics/timeline?${query.toString()}`);
  },

  /**
   * Top Threat Originating Sources: GET /api/v1/analytics/top-sources
   * @param {Object} params
   * @param {number} [params.limit=10]
   */
  async getTopThreatSources({ limit = 10 } = {}) {
    const query = new URLSearchParams({ limit: String(limit) });
    return request(`/api/v1/analytics/top-sources?${query.toString()}`);
  },

  /**
   * Deep Forensic Prediction Investigation: GET /api/v1/analytics/investigate/{prediction_id}
   * @param {number|string} predictionId
   */
  async investigatePrediction(predictionId) {
    return request(`/api/v1/analytics/investigate/${predictionId}`);
  },

  /**
   * Demonstration Threat Intelligence Reputation Lookup: GET /api/v1/threat-intelligence/ip/{ip}
   * @param {string} ipAddress
   */
  async lookupThreatIntel(ipAddress) {
    return request(`/api/v1/threat-intelligence/ip/${encodeURIComponent(ipAddress.trim())}`);
  },

  /**
   * Create Incident: POST /api/v1/incidents
   * @param {Object} data - { title, description, alert_id, prediction_id, severity, category, assigned_to }
   */
  async createIncident(data) {
    return request('/api/v1/incidents', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  /**
   * List Incidents: GET /api/v1/incidents
   */
  async getIncidents({ status = null, severity = null, category = null, assigned_to = null, limit = 20, offset = 0 } = {}) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    if (status) query.append('status', status);
    if (severity) query.append('severity', severity);
    if (category) query.append('category', category);
    if (assigned_to) query.append('assigned_to', assigned_to);
    return request(`/api/v1/incidents?${query.toString()}`);
  },

  /**
   * Incident Summary Metrics: GET /api/v1/incidents/summary
   */
  async getIncidentSummary() {
    return request('/api/v1/incidents/summary');
  },

  /**
   * Get Incident Detail: GET /api/v1/incidents/{incident_id}
   * @param {number|string} incidentId
   */
  async getIncidentById(incidentId) {
    return request(`/api/v1/incidents/${incidentId}`);
  },

  /**
   * Update Incident Status: PATCH /api/v1/incidents/{incident_id}/status
   * @param {number|string} incidentId
   * @param {Object} data - { new_status, resolution_summary }
   */
  async updateIncidentStatus(incidentId, data) {
    return request(`/api/v1/incidents/${incidentId}/status`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  /**
   * Assign Incident: PATCH /api/v1/incidents/{incident_id}/assign
   * @param {number|string} incidentId
   * @param {string} assignedTo
   */
  async assignIncident(incidentId, assignedTo) {
    return request(`/api/v1/incidents/${incidentId}/assign`, {
      method: 'PATCH',
      body: JSON.stringify({ assigned_to: assignedTo }),
    });
  },

  /**
   * Add Incident Note: POST /api/v1/incidents/{incident_id}/notes
   * @param {number|string} incidentId
   * @param {string} note
   */
  async addIncidentNote(incidentId, note) {
    return request(`/api/v1/incidents/${incidentId}/notes`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    });
  },

  /**
   * List Incident Notes: GET /api/v1/incidents/{incident_id}/notes
   * @param {number|string} incidentId
   */
  async getIncidentNotes(incidentId) {
    return request(`/api/v1/incidents/${incidentId}/notes`);
  },

  /**
   * Get Incident Timeline: GET /api/v1/incidents/{incident_id}/timeline
   * @param {number|string} incidentId
   */
  async getIncidentTimeline(incidentId) {
    return request(`/api/v1/incidents/${incidentId}/timeline`);
  },

  /**
   * Download binary or text file with authentication header
   * @param {string} endpoint
   * @param {string} fallbackFilename
   */
  async downloadFile(endpoint, fallbackFilename = 'download') {
    const url = `${API_BASE_URL}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const headers = {};
    const token = auth.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(url, { headers });
    if (!res.ok) {
      throw await sanitizeResponseError(res);
    }

    let filename = fallbackFilename;
    const disposition = res.headers.get('Content-Disposition');
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename=["']?([^"']+)["']?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }

    const blob = await res.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(blobUrl);
    return true;
  },

  /**
   * Fetch JSON security assessment report: GET /api/v1/reports/security
   * @param {Object} [params]
   */
  async getSecurityReport(params = {}) {
    const query = new URLSearchParams();
    if (params.time_range) query.set('time_range', params.time_range);
    if (params.format) query.set('format', params.format);
    if (params.start_date) query.set('start_date', params.start_date);
    if (params.end_date) query.set('end_date', params.end_date);
    if (params.severity && params.severity !== 'ALL') query.set('severity', params.severity);
    if (params.category) query.set('category', params.category);
    if (params.limit) query.set('limit', String(params.limit));

    return request(`/api/v1/reports/security?${query.toString()}`);
  },

  /**
   * Download security report file (PDF, CSV, or JSON)
   * @param {Object} [params]
   * @param {string} [format='pdf']
   */
  async downloadSecurityReport(params = {}, format = 'pdf') {
    const query = new URLSearchParams();
    query.set('format', format);
    if (params.time_range) query.set('time_range', params.time_range);
    if (params.start_date) query.set('start_date', params.start_date);
    if (params.end_date) query.set('end_date', params.end_date);
    if (params.severity && params.severity !== 'ALL') query.set('severity', params.severity);
    if (params.category) query.set('category', params.category);

    const ext = format === 'pdf' ? 'pdf' : (format === 'csv' ? 'csv' : 'json');
    return this.downloadFile(`/api/v1/reports/security?${query.toString()}`, `security-report.${ext}`);
  },

  /**
   * Download individual dataset CSV: GET /api/v1/reports/{dataset}
   * @param {string} dataset - 'predictions' | 'alerts' | 'incidents' | 'audit-logs'
   * @param {Object} [params]
   */
  async downloadDatasetCsv(dataset, params = {}) {
    const query = new URLSearchParams({ format: 'csv' });
    if (params.time_range) query.set('time_range', params.time_range);
    if (params.start_date) query.set('start_date', params.start_date);
    if (params.end_date) query.set('end_date', params.end_date);
    if (params.severity && params.severity !== 'ALL') query.set('severity', params.severity);
    if (params.category) query.set('category', params.category);
    if (params.limit) query.set('limit', String(params.limit));

    return this.downloadFile(`/api/v1/reports/${dataset}?${query.toString()}`, `nids-${dataset}.csv`);
  },

  /**
   * Export Incident Forensic Evidence: GET /api/v1/reports/incidents/{incident_id}/evidence
   * @param {number|string} incidentId
   * @param {string} [format='json'] - 'json' | 'zip'
   */
  async exportIncidentEvidence(incidentId, format = 'json') {
    const query = new URLSearchParams({ format });
    const ext = format === 'zip' ? 'zip' : 'json';
    return this.downloadFile(
      `/api/v1/reports/incidents/${incidentId}/evidence?${query.toString()}`,
      `evidence-${incidentId}.${ext}`
    );
  },

  /**
   * Phase 16: Execute Threat Hunt Search: POST /api/v1/hunting/search
   * @param {Object} payload - ThreatHuntSearchRequest
   */
  async huntSearch(payload) {
    return this.request('/api/v1/hunting/search', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Phase 16: Get Threat Hunting Workbench Summary: GET /api/v1/hunting/summary
   */
  async getHuntingSummary() {
    return this.request('/api/v1/hunting/summary');
  },

  /**
   * Phase 16: Source IP Forensic Investigation: GET /api/v1/hunting/source/{ip_address}
   * @param {string} ipAddress
   */
  async investigateSource(ipAddress) {
    return this.request(`/api/v1/hunting/source/${encodeURIComponent(ipAddress.trim())}`);
  },

  /**
   * Phase 16: Get Threat Hunt Query History: GET /api/v1/hunting/history
   * @param {number} [limit=20]
   */
  async getHuntingHistory(limit = 20) {
    return this.request(`/api/v1/hunting/history?limit=${limit}`);
  },
};

export const acknowledgeAlert = (alertId) => api.acknowledgeAlert(alertId);
export const resolveAlert = (alertId) => api.resolveAlert(alertId);
export const getAlert = (alertId) => api.getAlert(alertId);
export const getAuditLogs = (params) => api.getAuditLogs(params);
export const getAuditSummary = () => api.getAuditSummary();
export const getAnalyticsOverview = () => api.getAnalyticsOverview();
export const getThreatDistribution = () => api.getThreatDistribution();
export const getSecurityTimeline = (params) => api.getSecurityTimeline(params);
export const getTopThreatSources = (params) => api.getTopThreatSources(params);
export const investigatePrediction = (predictionId) => api.investigatePrediction(predictionId);
export const lookupThreatIntel = (ipAddress) => api.lookupThreatIntel(ipAddress);
export const createIncident = (data) => api.createIncident(data);
export const getIncidents = (params) => api.getIncidents(params);
export const getIncidentById = (id) => api.getIncidentById(id);
export const getIncidentSummary = () => api.getIncidentSummary();
export const updateIncidentStatus = (id, data) => api.updateIncidentStatus(id, data);
export const assignIncident = (id, assignedTo) => api.assignIncident(id, assignedTo);
export const addIncidentNote = (id, note) => api.addIncidentNote(id, note);
export const getIncidentNotes = (id) => api.getIncidentNotes(id);
export const getIncidentTimeline = (id) => api.getIncidentTimeline(id);
export const getSecurityReport = (params) => api.getSecurityReport(params);
export const downloadSecurityReport = (params, format) => api.downloadSecurityReport(params, format);
export const downloadDatasetCsv = (dataset, params) => api.downloadDatasetCsv(dataset, params);
export const exportIncidentEvidence = (incidentId, format) => api.exportIncidentEvidence(incidentId, format);
export const huntSearch = (payload) => api.huntSearch(payload);
export const getHuntingSummary = () => api.getHuntingSummary();
export const investigateSource = (ipAddress) => api.investigateSource(ipAddress);
export const getHuntingHistory = (limit) => api.getHuntingHistory(limit);

export default api;
