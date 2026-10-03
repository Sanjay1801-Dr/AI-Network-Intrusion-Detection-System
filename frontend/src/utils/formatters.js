/**
 * Formatting and utility functions for NIDS data presentation.
 */

/**
 * Format ISO datetime string to localized readable representation.
 * @param {string|Date} dateStr
 * @returns {string}
 */
export function formatDateTime(dateStr) {
  if (!dateStr) return 'N/A';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return String(dateStr);
  }
}

/**
 * Format score [0.0, 1.0] as a percentage string.
 * @param {number} val
 * @param {number} decimals
 * @returns {string}
 */
export function formatPercentage(val, decimals = 1) {
  if (val === null || val === undefined || isNaN(val)) return '0.0%';
  return `${(Number(val) * 100).toFixed(decimals)}%`;
}

/**
 * Format numeric score with fixed decimals.
 * @param {number} val
 * @param {number} decimals
 * @returns {string}
 */
export function formatScore(val, decimals = 4) {
  if (val === null || val === undefined || isNaN(val)) return '0.0000';
  return Number(val).toFixed(decimals);
}

/**
 * Format integer or float with thousands separators.
 * @param {number} val
 * @returns {string}
 */
export function formatNumber(val) {
  if (val === null || val === undefined || isNaN(val)) return '0';
  return Number(val).toLocaleString();
}

/**
 * Resolve display protocol name from standard protocol code or string.
 * @param {number|string} proto
 * @returns {string}
 */
export function formatProtocol(proto) {
  if (proto === null || proto === undefined) return 'UNKNOWN';
  const str = String(proto).trim();
  if (str === '6' || str.toUpperCase() === 'TCP') return 'TCP (6)';
  if (str === '17' || str.toUpperCase() === 'UDP') return 'UDP (17)';
  if (str === '1' || str.toUpperCase() === 'ICMP') return 'ICMP (1)';
  return str;
}
