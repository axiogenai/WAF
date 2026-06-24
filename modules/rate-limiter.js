'use strict';

/**
 * ShieldWall WAF — IP-based Sliding-Window Rate Limiter
 *
 * Features:
 *  • Sliding window with configurable size and max requests
 *  • Automatic escalation: repeated violations → temp ban → permanent blacklist
 *  • Manual blacklist / whitelist management
 *  • Background cleanup of expired entries
 *
 * Exports: class RateLimiter
 */

class RateLimiter {
  /**
   * @param {Object} opts
   * @param {number} opts.windowMs       – sliding window size in ms (default 60 000)
   * @param {number} opts.maxRequests    – max requests per window (default 100)
   * @param {number} opts.banThreshold   – violations before temp ban (default 3)
   * @param {number} opts.banDurationMs  – temp-ban duration in ms (default 900 000 = 15 min)
   */
  constructor(opts = {}) {
    this.windowMs      = opts.windowMs      || 60_000;
    this.maxRequests   = opts.maxRequests    || 100;
    this.banThreshold  = opts.banThreshold   || 3;
    this.banDurationMs = opts.banDurationMs  || 900_000;

    // Escalation parameters
    this._violationWindowMs       = 5 * 60_000;  // 5 min window for counting violations
    this._tempBanEscalationCount  = 3;            // 3 temp bans → permanent blacklist

    // Internal stores
    /** @type {Map<string, number[]>} IP → array of request timestamps */
    this._requests = new Map();

    /** @type {Map<string, { violations: number[], tempBanCount: number }>} */
    this._violations = new Map();

    /** @type {Map<string, { expiresAt: number, reason: string }>} */
    this._tempBans = new Map();

    /** @type {Map<string, { reason: string, bannedAt: number }>} */
    this._blacklist = new Map();

    /** @type {Set<string>} */
    this._whitelist = new Set();

    // Start periodic cleanup every 30 s
    this._cleanupTimer = setInterval(() => this._cleanup(), 30_000);
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Check whether a request from `ip` is allowed.
   *
   * @param {string} ip
   * @returns {{ allowed: boolean, remaining?: number, retryAfter?: number,
   *             banned?: boolean, reason?: string }}
   */
  checkRequest(ip) {
    // 1. Whitelist always passes
    if (this._whitelist.has(ip)) {
      return { allowed: true, remaining: this.maxRequests };
    }

    // 2. Permanent blacklist
    if (this._blacklist.has(ip)) {
      const entry = this._blacklist.get(ip);
      return {
        allowed: false,
        banned: true,
        reason: `Blacklisted: ${entry.reason}`,
      };
    }

    // 3. Temp ban check
    if (this._tempBans.has(ip)) {
      const ban = this._tempBans.get(ip);
      if (Date.now() < ban.expiresAt) {
        const retryAfter = Math.ceil((ban.expiresAt - Date.now()) / 1000);
        return {
          allowed: false,
          banned: true,
          reason: ban.reason,
          retryAfter,
        };
      }
      // Ban expired — remove it
      this._tempBans.delete(ip);
    }

    // 4. Sliding window rate check
    const now = Date.now();
    const windowStart = now - this.windowMs;

    if (!this._requests.has(ip)) {
      this._requests.set(ip, []);
    }

    const timestamps = this._requests.get(ip);

    // Prune timestamps outside window
    while (timestamps.length > 0 && timestamps[0] <= windowStart) {
      timestamps.shift();
    }

    if (timestamps.length >= this.maxRequests) {
      // Rate exceeded — record violation and possibly escalate
      this._recordViolation(ip);

      const oldestInWindow = timestamps[0] || now;
      const retryAfter = Math.ceil((oldestInWindow + this.windowMs - now) / 1000);

      return {
        allowed: false,
        remaining: 0,
        retryAfter: Math.max(1, retryAfter),
      };
    }

    // Allowed — record timestamp
    timestamps.push(now);
    const remaining = this.maxRequests - timestamps.length;

    return { allowed: true, remaining };
  }

  /**
   * Return all currently temp-banned and blacklisted IPs.
   * @returns {Array<{ ip: string, type: string, expiresAt?: number, reason: string }>}
   */
  getBannedIPs() {
    const now = Date.now();
    const list = [];

    for (const [ip, ban] of this._tempBans.entries()) {
      if (ban.expiresAt > now) {
        list.push({
          ip,
          type: 'tempBan',
          expiresAt: ban.expiresAt,
          reason: ban.reason,
        });
      }
    }

    for (const [ip, entry] of this._blacklist.entries()) {
      list.push({
        ip,
        type: 'blacklist',
        reason: entry.reason,
        bannedAt: entry.bannedAt,
      });
    }

    return list;
  }

  /**
   * Aggregate stats.
   * @returns {{ totalTracked: number, bannedCount: number, topOffenders: Array }}
   */
  getStats() {
    const now = Date.now();
    const activeBans = [...this._tempBans.values()].filter((b) => b.expiresAt > now).length;
    const bannedCount = activeBans + this._blacklist.size;

    // Top offenders by request count in current window
    const windowStart = now - this.windowMs;
    const offenders = [];

    for (const [ip, timestamps] of this._requests.entries()) {
      const recentCount = timestamps.filter((t) => t > windowStart).length;
      if (recentCount > 0) {
        offenders.push({ ip, requestCount: recentCount });
      }
    }

    offenders.sort((a, b) => b.requestCount - a.requestCount);

    return {
      totalTracked: this._requests.size,
      bannedCount,
      blacklistedCount: this._blacklist.size,
      whitelistedCount: this._whitelist.size,
      topOffenders: offenders.slice(0, 10),
    };
  }

  /**
   * Permanently blacklist an IP.
   * @param {string} ip
   * @param {string} reason
   */
  blacklist(ip, reason) {
    this._blacklist.set(ip, {
      reason: reason || 'Manual blacklist',
      bannedAt: Date.now(),
    });
    // Remove from temp bans if present
    this._tempBans.delete(ip);
  }

  /**
   * Add an IP to the whitelist (always allowed).
   * @param {string} ip
   */
  whitelist(ip) {
    this._whitelist.add(ip);
    // Remove from bans if present
    this._tempBans.delete(ip);
    this._blacklist.delete(ip);
  }

  /**
   * Remove a temp ban or blacklist entry.
   * @param {string} ip
   */
  unban(ip) {
    this._tempBans.delete(ip);
    this._blacklist.delete(ip);
    this._violations.delete(ip);
  }

  /**
   * @param {string} ip
   * @returns {boolean}
   */
  isBlacklisted(ip) {
    return this._blacklist.has(ip);
  }

  /**
   * @param {string} ip
   * @returns {boolean}
   */
  isWhitelisted(ip) {
    return this._whitelist.has(ip);
  }

  /**
   * Graceful shutdown — clear the cleanup timer.
   */
  destroy() {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
  }

  // ─── Internal helpers ──────────────────────────────────────────────────────

  /**
   * Record a rate-limit violation and apply escalation logic.
   *
   * Escalation ladder:
   *   • 3 violations within 5 min  → 15 min temp ban
   *   • 3 temp bans (lifetime)     → permanent blacklist
   */
  _recordViolation(ip) {
    const now = Date.now();

    if (!this._violations.has(ip)) {
      this._violations.set(ip, { violations: [], tempBanCount: 0 });
    }

    const entry = this._violations.get(ip);
    entry.violations.push(now);

    // Prune violations outside the 5-minute window
    const windowStart = now - this._violationWindowMs;
    entry.violations = entry.violations.filter((t) => t > windowStart);

    if (entry.violations.length >= this.banThreshold) {
      // Reset violation window
      entry.violations = [];
      entry.tempBanCount++;

      if (entry.tempBanCount >= this._tempBanEscalationCount) {
        // Escalate to permanent blacklist
        this.blacklist(ip, 'Auto-escalation: repeated rate-limit violations');
        return;
      }

      // Temp ban
      this._tempBans.set(ip, {
        expiresAt: now + this.banDurationMs,
        reason: `Rate-limit temp ban #${entry.tempBanCount} (${this.banThreshold} violations in ${this._violationWindowMs / 1000}s)`,
      });
    }
  }

  /**
   * Periodic cleanup of stale data.
   */
  _cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Clean up request timestamp arrays
    for (const [ip, timestamps] of this._requests.entries()) {
      const fresh = timestamps.filter((t) => t > windowStart);
      if (fresh.length === 0) {
        this._requests.delete(ip);
      } else {
        this._requests.set(ip, fresh);
      }
    }

    // Remove expired temp bans
    for (const [ip, ban] of this._tempBans.entries()) {
      if (ban.expiresAt <= now) {
        this._tempBans.delete(ip);
      }
    }

    // Clean up stale violation entries (no violations in the last window)
    const violationCutoff = now - this._violationWindowMs;
    for (const [ip, entry] of this._violations.entries()) {
      entry.violations = entry.violations.filter((t) => t > violationCutoff);
      if (entry.violations.length === 0 && entry.tempBanCount === 0) {
        this._violations.delete(ip);
      }
    }
  }
}

module.exports = { RateLimiter };
