'use strict';

/**
 * ShieldWall WAF — Remote / Local File Inclusion (RFI / LFI) Rule Signatures
 *
 * Each rule object:
 *   id          – unique rule identifier (RFILFI-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp
 */

const rfiLfiRules = [
  // ───────────────────────── PHP stream wrappers ─────────────────────────
  {
    id: 'RFILFI-0001',
    severity: 'critical',
    description: 'PHP wrapper: php://filter (source disclosure)',
    pattern: /php:\/\/filter/i,
  },
  {
    id: 'RFILFI-0002',
    severity: 'critical',
    description: 'PHP wrapper: php://input (RCE vector)',
    pattern: /php:\/\/input/i,
  },
  {
    id: 'RFILFI-0003',
    severity: 'critical',
    description: 'PHP wrapper: expect:// (command execution)',
    pattern: /expect:\/\//i,
  },
  {
    id: 'RFILFI-0004',
    severity: 'critical',
    description: 'PHP wrapper: zip:// (archive traversal)',
    pattern: /zip:\/\//i,
  },
  {
    id: 'RFILFI-0005',
    severity: 'high',
    description: 'PHP wrapper: phar:// (deserialization)',
    pattern: /phar:\/\//i,
  },
  {
    id: 'RFILFI-0006',
    severity: 'high',
    description: 'PHP wrapper: php://fd (file descriptor access)',
    pattern: /php:\/\/fd/i,
  },
  {
    id: 'RFILFI-0007',
    severity: 'high',
    description: 'PHP wrapper: glob:// (directory listing)',
    pattern: /glob:\/\//i,
  },
  {
    id: 'RFILFI-0008',
    severity: 'high',
    description: 'PHP wrapper: php://memory or php://temp',
    pattern: /php:\/\/(memory|temp)/i,
  },

  // ──────────────────── Remote file includes ────────────────────
  {
    id: 'RFILFI-0010',
    severity: 'critical',
    description: 'Remote include: HTTP(S) URL in parameter value',
    pattern: /[=&?](https?:\/\/)/i,
  },
  {
    id: 'RFILFI-0011',
    severity: 'critical',
    description: 'Remote include: FTP URL in parameter value',
    pattern: /[=&?]ftp:\/\//i,
  },
  {
    id: 'RFILFI-0012',
    severity: 'high',
    description: 'Remote include: URL-encoded http (%68%74%74%70)',
    pattern: /%68%74%74%70%3a%2f%2f/i,
  },

  // ──────────────────── Data URI includes ────────────────────
  {
    id: 'RFILFI-0020',
    severity: 'high',
    description: 'Data URI inclusion: data:// wrapper in parameter',
    pattern: /data:\/\//i,
  },
  {
    id: 'RFILFI-0021',
    severity: 'high',
    description: 'Data URI with base64: data:…;base64,',
    pattern: /data:[^;]*;base64,/i,
  },

  // ──────────────────── Log poisoning paths ────────────────────
  {
    id: 'RFILFI-0030',
    severity: 'critical',
    description: 'Log poisoning: Apache access / error log path',
    pattern: /\/var\/log\/(apache2?|httpd)\/(access|error)/i,
  },
  {
    id: 'RFILFI-0031',
    severity: 'critical',
    description: 'Log poisoning: Nginx access / error log path',
    pattern: /\/var\/log\/nginx\/(access|error)/i,
  },
  {
    id: 'RFILFI-0032',
    severity: 'high',
    description: 'Log poisoning: auth.log / syslog / mail.log',
    pattern: /\/var\/log\/(auth\.log|syslog|mail\.log|messages)/i,
  },
  {
    id: 'RFILFI-0033',
    severity: 'high',
    description: 'Log poisoning: PHP session file path',
    pattern: /\/tmp\/sess_[a-zA-Z0-9]/i,
  },
];

module.exports = rfiLfiRules;
