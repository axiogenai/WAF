'use strict';

/**
 * ShieldWall WAF — HTTP Protocol Violation Rule Signatures
 *
 * Unlike the other rule modules which export simple regex-pattern objects,
 * protocol rules are a mix of regex patterns and programmatic checks.
 * Each rule has:
 *   id          – unique rule identifier (PROTO-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp  (applied to raw request line / headers / body)
 *   checkFn     – optional function (req, bodyStr) → boolean
 *                 (used when a regex alone is insufficient)
 */

const protocolRules = [
  // ───────────────────────── Invalid HTTP methods ─────────────────────────
  {
    id: 'PROTO-0001',
    severity: 'medium',
    description: 'Unusual HTTP method: TRACE (cross-site tracing vector)',
    pattern: null,
    checkFn: (req) => req.method === 'TRACE',
  },
  {
    id: 'PROTO-0002',
    severity: 'medium',
    description: 'Unusual HTTP method: TRACK',
    pattern: null,
    checkFn: (req) => req.method === 'TRACK',
  },
  {
    id: 'PROTO-0003',
    severity: 'low',
    description: 'Unusual HTTP method: CONNECT (proxy tunneling)',
    pattern: null,
    checkFn: (req) => req.method === 'CONNECT',
  },
  {
    id: 'PROTO-0004',
    severity: 'low',
    description: 'Non-standard HTTP method detected',
    pattern: null,
    checkFn: (req) => {
      const standard = new Set([
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
      ]);
      return !standard.has(req.method);
    },
  },

  // ───────────────────────── Oversized headers ─────────────────────────
  {
    id: 'PROTO-0010',
    severity: 'high',
    description: 'Oversized Cookie header (> 8 KB)',
    pattern: null,
    checkFn: (req) => {
      const cookie = req.headers['cookie'] || '';
      return cookie.length > 8192;
    },
  },
  {
    id: 'PROTO-0011',
    severity: 'high',
    description: 'Oversized single header value (> 16 KB)',
    pattern: null,
    checkFn: (req) => {
      const headers = req.headers;
      for (const key of Object.keys(headers)) {
        const val = Array.isArray(headers[key])
          ? headers[key].join(', ')
          : String(headers[key]);
        if (val.length > 16384) return true;
      }
      return false;
    },
  },

  // ───────────────────────── Missing Host header ─────────────────────────
  {
    id: 'PROTO-0020',
    severity: 'high',
    description: 'Missing or empty Host header',
    pattern: null,
    checkFn: (req) => {
      const host = req.headers['host'];
      return !host || host.trim().length === 0;
    },
  },

  // ──────────────── HTTP Request Smuggling ────────────────
  {
    id: 'PROTO-0030',
    severity: 'critical',
    description: 'HTTP request smuggling: duplicate Content-Length headers',
    pattern: null,
    checkFn: (req) => {
      const raw = req.rawHeaders || [];
      let clCount = 0;
      for (let i = 0; i < raw.length; i += 2) {
        if (raw[i].toLowerCase() === 'content-length') clCount++;
      }
      return clCount > 1;
    },
  },
  {
    id: 'PROTO-0031',
    severity: 'critical',
    description: 'HTTP request smuggling: Transfer-Encoding + Content-Length conflict',
    pattern: null,
    checkFn: (req) => {
      const hasTE = !!req.headers['transfer-encoding'];
      const hasCL = !!req.headers['content-length'];
      return hasTE && hasCL;
    },
  },
  {
    id: 'PROTO-0032',
    severity: 'critical',
    description: 'HTTP request smuggling: obfuscated Transfer-Encoding header',
    pattern: null,
    checkFn: (req) => {
      const raw = req.rawHeaders || [];
      for (let i = 0; i < raw.length; i += 2) {
        const name = raw[i];
        if (/transfer[\s-]*encoding/i.test(name) && name.toLowerCase() !== 'transfer-encoding') {
          return true;
        }
      }
      return false;
    },
  },

  // ──────────────────── CRLF Injection ────────────────────
  {
    id: 'PROTO-0040',
    severity: 'critical',
    description: 'CRLF injection: %0d%0a in URL or header value',
    pattern: /%0[dD]%0[aA]/,
  },
  {
    id: 'PROTO-0041',
    severity: 'critical',
    description: 'CRLF injection: literal \\r\\n sequence in input',
    pattern: /\r\n/,
  },
];

module.exports = protocolRules;
