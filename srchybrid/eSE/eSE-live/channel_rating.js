/**
 * eSE Live — Channel Rating
 * Calculates a 0-100 rating score for live channels based on 6 KPIs.
 * Max ~200 lines.
 */
'use strict';

/**
 * @typedef {Object} ChannelMetrics
 * @property {number} viewers - Current viewer count
 * @property {number} bitrate - Stream bitrate in kbps
 * @property {number} uptimeMinutes - How long the stream has been live
 * @property {number} meshHealth - % of peers with good connectivity (0-100)
 * @property {number} reports - Number of fake/spam reports
 * @property {number} broadcasterReputation - Historical trust score (0-100)
 */

/**
 * KPI weights (total = 100).
 */
const WEIGHTS = {
  viewers:      15,  // More viewers = more confident in quality
  bitrate:      20,  // Higher bitrate = better quality
  uptime:       15,  // Longer uptime = more stable
  meshHealth:   20,  // Better mesh = more reliable
  reports:      15,  // Fewer reports = more trustworthy
  reputation:   15   // Historical trust
};

/**
 * Calculate overall rating (0-100) for a channel.
 * @param {ChannelMetrics} m - Channel metrics.
 * @returns {{score: number, breakdown: Object, experience: string, emoji: string}}
 */
function calculateRating(m) {
  const scores = {
    viewers:    scoreViewers(m.viewers || 0),
    bitrate:    scoreBitrate(m.bitrate || 0),
    uptime:     scoreUptime(m.uptimeMinutes || 0),
    meshHealth: clamp(m.meshHealth || 0, 0, 100),
    reports:    scoreReports(m.reports || 0, m.viewers || 1),
    reputation: clamp(m.broadcasterReputation || 50, 0, 100)
  };

  // Weighted average
  let total = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    total += (scores[key] / 100) * weight;
  }

  const score = Math.round(clamp(total, 0, 100));
  const exp = getExperience(score);

  return {
    score,
    breakdown: scores,
    experience: exp.label,
    emoji: exp.emoji,
    bars: exp.bars
  };
}

/**
 * Score viewer count (0-100).
 * 0 viewers = 0, 5 = 40, 20 = 70, 100 = 90, 500+ = 100
 */
function scoreViewers(v) {
  if (v <= 0) return 0;
  if (v <= 5) return 20 + (v / 5) * 20;
  if (v <= 20) return 40 + ((v - 5) / 15) * 30;
  if (v <= 100) return 70 + ((v - 20) / 80) * 20;
  return Math.min(100, 90 + ((v - 100) / 400) * 10);
}

/**
 * Score bitrate (0-100).
 * <500 = poor, 1500 = SD, 3000 = HD, 5000 = FHD, 8000+ = excellent
 */
function scoreBitrate(b) {
  if (b < 500) return Math.round((b / 500) * 30);
  if (b < 1500) return 30 + Math.round(((b - 500) / 1000) * 20);
  if (b < 3000) return 50 + Math.round(((b - 1500) / 1500) * 20);
  if (b < 5000) return 70 + Math.round(((b - 3000) / 2000) * 15);
  return Math.min(100, 85 + Math.round(((b - 5000) / 3000) * 15));
}

/**
 * Score uptime (0-100).
 * <1min = 10, 5min = 50, 30min = 80, 2h+ = 100
 */
function scoreUptime(minutes) {
  if (minutes < 1) return 10;
  if (minutes < 5) return 10 + Math.round((minutes / 5) * 40);
  if (minutes < 30) return 50 + Math.round(((minutes - 5) / 25) * 30);
  if (minutes < 120) return 80 + Math.round(((minutes - 30) / 90) * 20);
  return 100;
}

/**
 * Score reports (inverse — more reports = lower score).
 * Ratio of reports to viewers. >10% = bad.
 */
function scoreReports(reports, viewers) {
  if (reports === 0) return 100;
  const ratio = reports / Math.max(viewers, 1);
  if (ratio > 0.2) return 0;
  if (ratio > 0.1) return 30;
  if (ratio > 0.05) return 60;
  if (ratio > 0.01) return 80;
  return 90;
}

/**
 * Get experience label and emoji based on score.
 */
function getExperience(score) {
  if (score >= 85) return { label: 'Excelente', emoji: '\uD83D\uDCF6', bars: 5 };
  if (score >= 70) return { label: 'Buena', emoji: '\uD83D\uDCF6', bars: 4 };
  if (score >= 50) return { label: 'Aceptable', emoji: '\uD83D\uDCF6', bars: 3 };
  if (score >= 30) return { label: 'Regular', emoji: '\uD83D\uDCF6', bars: 2 };
  return { label: 'Mala', emoji: '\uD83D\uDCF6', bars: 1 };
}

/**
 * Get quality label from bitrate.
 */
function qualityLabel(bitrate) {
  if (bitrate >= 8000) return '4K';
  if (bitrate >= 5000) return '1080p';
  if (bitrate >= 3000) return '720p';
  if (bitrate >= 1500) return '480p';
  return 'SD';
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

module.exports = { calculateRating, qualityLabel, WEIGHTS };
