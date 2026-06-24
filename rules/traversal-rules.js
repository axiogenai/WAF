'use strict';

/**
 * ShieldWall WAF — Path Traversal Rule Signatures
 *
 * Each rule object:
 *   id          – unique rule identifier (TRAV-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp
 */

const traversalRules = [
  // ───────────────────────── Basic traversal ─────────────────────────
  {
    id: 'TRAV-0001',
    severity: 'high',
    description: 'Basic directory traversal: ../',
    pattern: /\.\.\//,
  },
  {
    id: 'TRAV-0002',
    severity: 'high',
    description: 'Basic directory traversal: ..\\',
    pattern: /\.\.\\/,
  },
  {
    id: 'TRAV-0003',
    severity: 'high',
    description: 'Repeated traversal: ../../ (depth ≥ 2)',
    pattern: /(\.\.(\/|\\)){2,}/,
  },

  // ───────────────────── URL-encoded traversal ─────────────────────
  {
    id: 'TRAV-0010',
    severity: 'high',
    description: 'URL-encoded traversal: %2e%2e%2f (../)',
    pattern: /%2e%2e(%2f|%5c)/i,
  },
  {
    id: 'TRAV-0011',
    severity: 'high',
    description: 'URL-encoded traversal: %2e%2e/ or ..%2f',
    pattern: /(%2e%2e\/|\.\.%2f|\.\.%5c)/i,
  },
  {
    id: 'TRAV-0012',
    severity: 'critical',
    description: 'Double URL-encoded traversal: %252e%252e%252f',
    pattern: /%252e%252e(%252f|%255c)/i,
  },
  {
    id: 'TRAV-0013',
    severity: 'critical',
    description: 'Double URL-encoded dot: %252e',
    pattern: /%252e/i,
  },

  // ──────────────────── Unicode / overlong UTF-8 ────────────────────
  {
    id: 'TRAV-0020',
    severity: 'critical',
    description: 'Unicode traversal: ..%c0%af (overlong /)',
    pattern: /\.\.%c0%af/i,
  },
  {
    id: 'TRAV-0021',
    severity: 'critical',
    description: 'Unicode traversal: ..%c1%9c (overlong \\)',
    pattern: /\.\.%c1%9c/i,
  },
  {
    id: 'TRAV-0022',
    severity: 'high',
    description: 'Overlong UTF-8 encoded dot: %c0%ae',
    pattern: /%c0%ae/i,
  },

  // ───────────────────────── Null byte ─────────────────────────
  {
    id: 'TRAV-0030',
    severity: 'critical',
    description: 'Null byte injection: %00',
    pattern: /%00/,
  },
  {
    id: 'TRAV-0031',
    severity: 'critical',
    description: 'Null byte injection: \\x00 or \\0',
    pattern: /(\\x00|\\0)/,
  },

  // ───────────────────── Sensitive files (Unix) ─────────────────────
  {
    id: 'TRAV-0040',
    severity: 'critical',
    description: 'Sensitive file access: /etc/passwd',
    pattern: /\/etc\/passwd/i,
  },
  {
    id: 'TRAV-0041',
    severity: 'critical',
    description: 'Sensitive file access: /etc/shadow',
    pattern: /\/etc\/shadow/i,
  },
  {
    id: 'TRAV-0042',
    severity: 'high',
    description: 'Sensitive file access: /etc/hosts or /etc/hostname',
    pattern: /\/etc\/(hosts|hostname)/i,
  },
  {
    id: 'TRAV-0043',
    severity: 'high',
    description: 'Sensitive file access: .env file',
    pattern: /\.env(\b|$)/i,
  },
  {
    id: 'TRAV-0044',
    severity: 'high',
    description: 'Sensitive file access: .htaccess / .htpasswd',
    pattern: /\.(htaccess|htpasswd)/i,
  },

  // ───────────────────── Sensitive files (Windows) ─────────────────────
  {
    id: 'TRAV-0050',
    severity: 'critical',
    description: 'Sensitive file access: win.ini',
    pattern: /win\.ini/i,
  },
  {
    id: 'TRAV-0051',
    severity: 'critical',
    description: 'Sensitive file access: boot.ini',
    pattern: /boot\.ini/i,
  },
  {
    id: 'TRAV-0052',
    severity: 'high',
    description: 'Sensitive file access: web.config (IIS)',
    pattern: /web\.config/i,
  },
  {
    id: 'TRAV-0053',
    severity: 'high',
    description: 'Sensitive file access: SAM / SYSTEM hive',
    pattern: /(\\|\/)(SAM|SYSTEM|SECURITY)$/i,
  },

  // ───────────────────── Sensitive directories ─────────────────────
  {
    id: 'TRAV-0060',
    severity: 'critical',
    description: 'Sensitive directory access: /proc/self',
    pattern: /\/proc\/self/i,
  },
  {
    id: 'TRAV-0061',
    severity: 'critical',
    description: 'Sensitive directory access: /proc/[0-9]',
    pattern: /\/proc\/\d/i,
  },
  {
    id: 'TRAV-0062',
    severity: 'high',
    description: 'Sensitive directory access: /windows/system32',
    pattern: /(\/|\\)windows(\/|\\)system32/i,
  },
  {
    id: 'TRAV-0063',
    severity: 'high',
    description: 'Sensitive directory access: /var/log',
    pattern: /\/var\/log\//i,
  },
  {
    id: 'TRAV-0064',
    severity: 'medium',
    description: 'Sensitive file access: id_rsa / authorized_keys',
    pattern: /(id_rsa|id_dsa|authorized_keys)/i,
  },
];

module.exports = traversalRules;
