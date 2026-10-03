/**
 * Data contracts and type constants for AI-NIDS Frontend (Phase 6).
 * Aligned with backend schemas from backend/app/schemas/.
 */

/**
 * Risk levels defined in the ML composite risk assessment engine.
 */
export const RISK_LEVELS = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

/**
 * Alert severities defined in the backend AlertRepository.
 */
export const ALERT_SEVERITIES = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Alert lifecycle statuses defined in Phase 8 Alert Lifecycle State Machine.
 */
export const ALERT_STATUSES = ['ALL', 'NEW', 'ACKNOWLEDGED', 'RESOLVED'];

/**
 * Standard pagination page limits.
 */
export const PAGE_LIMIT_OPTIONS = [10, 20, 50];

/**
 * @typedef {Object} AnomalyResult
 * @property {boolean} is_anomaly
 * @property {string} anomaly_label - 'NORMAL' | 'ANOMALOUS'
 * @property {number} anomaly_score - Normalized outlier score [0.0, 1.0]
 * @property {number} raw_decision_score
 * @property {string} interpretation
 */

/**
 * @typedef {Object} ClassificationResult
 * @property {string} predicted_label - E.g. 'BENIGN', 'DoS', 'Port Scan'
 * @property {boolean} is_intrusion
 * @property {number} confidence - Estimated class probability [0.0, 1.0]
 * @property {string} confidence_type - 'estimated_class_probability'
 * @property {Object.<string, number>} class_probabilities
 */

/**
 * @typedef {Object} RiskAssessment
 * @property {string} risk_level - 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * @property {string} recommended_action
 * @property {string} summary
 */

/**
 * @typedef {Object} PredictionResponse
 * @property {AnomalyResult} anomaly
 * @property {ClassificationResult} classification
 * @property {RiskAssessment} risk_assessment
 */

/**
 * @typedef {Object} PredictionHistoryItem
 * @property {number} id
 * @property {string} timestamp
 * @property {string} predicted_threat
 * @property {boolean} intrusion_flag
 * @property {number} anomaly_score
 * @property {number} classification_confidence
 * @property {string} risk_level
 * @property {string} recommended_action
 * @property {string|null} source_ip
 * @property {string|null} destination_ip
 * @property {number|null} destination_port
 * @property {string|null} protocol
 * @property {string} created_at
 */

/**
 * @typedef {Object} PredictionHistoryResponse
 * @property {number} total
 * @property {number} limit
 * @property {number} offset
 * @property {Array<PredictionHistoryItem>} items
 */

/**
 * @typedef {Object} AlertItem
 * @property {number} id
 * @property {number|null} prediction_id
 * @property {string} timestamp
 * @property {string} alert_type
 * @property {string} severity
 * @property {string} threat_label
 * @property {number} anomaly_score
 * @property {number} confidence
 * @property {string|null} source_ip
 * @property {string|null} destination_ip
 * @property {string} status - 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED'
 * @property {string} recommended_action
 * @property {string} created_at
 * @property {string|null} acknowledged_at - Timestamp when acknowledged
 * @property {string|null} resolved_at - Timestamp when resolved
 */

/**
 * @typedef {Object} AlertHistoryResponse
 * @property {number} total
 * @property {number} limit
 * @property {number} offset
 * @property {Array<AlertItem>} items
 */
