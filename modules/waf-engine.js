'use strict';

/**
 * ShieldWall WAF — Core WAF Engine
 *
 * Centralises all rule sets and exposes a unified inspection API.
 *
 * Exports:
 *   CATEGORIES          – enum-like object of category names
 *   getAllRules()        – all rules grouped by category
 *   inspectRequest()    – full request inspection pipeline
 *   checkBotSignature() – scanner / bot detection
 */

const sqliRules      = require('../rules/sqli-rules');
const xssRules       = require('../rules/xss-rules');
const traversalRules = require('../rules/traversal-rules');
const rfiLfiRules    = require('../rules/rfi-lfi-rules');
const cmdiRules      = require('../rules/cmdi-rules');
const protocolRules  = require('../rules/protocol-rules');
const botSignatures  = require('../rules/bot-signatures');

// ─── Category constants ──────────────────────────────────────────────────────
const CATEGORIES = Object.freeze({
  SQLI:               'sqli',
  XSS:                'xss',
  PATH_TRAVERSAL:     'pathTraversal',
  RFI_LFI:            'rfiLfi',
  COMMAND_INJECTION:  'commandInjection',
  PROTOCOL_VIOLATION: 'protocolViolation',
});

// ─── Category → rules mapping ────────────────────────────────────────────────
const RULE_MAP = {
  [CATEGORIES.SQLI]:               sqliRules,
  [CATEGORIES.XSS]:                xssRules,
  [CATEGORIES.PATH_TRAVERSAL]:     traversalRules,
  [CATEGORIES.RFI_LFI]:            rfiLfiRules,
  [CATEGORIES.COMMAND_INJECTION]:  cmdiRules,
  [CATEGORIES.PROTOCOL_VIOLATION]: protocolRules,
};

// ─── getAllRules ──────────────────────────────────────────────────────────────
/**
 * Returns every loaded rule grouped by category.
 * @returns {Object.<string, Array>}
 */
function getAllRules() {
  const grouped = {};
  for (const [cat, rules] of Object.entries(RULE_MAP)) {
    grouped[cat] = rules.map((r) => ({
      id: r.id,
      severity: r.severity,
      description: r.description,
      hasPattern: !!r.pattern,
      hasCheckFn: typeof r.checkFn === 'function',
    }));
  }
  return grouped;
}

// ─── Normalisation helpers ───────────────────────────────────────────────────

/**
 * Decode a string that may be URL-encoded, double-encoded, or contain +
 * signs as spaces. Safely handles malformed sequences.
 */
function deepDecode(str) {
  if (typeof str !== 'string') return '';
  let decoded = str;

  // Normalise + to space first (query-string convention)
  decoded = decoded.replace(/\+/g, ' ');

  // Up to 3 passes of URI decoding to defeat double/triple encoding
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break; // nothing more to decode
      decoded = next;
    } catch {
      break; // malformed sequence — stop
    }
  }

  return decoded;
}

/**
 * Build an array of input strings to test from the request.
 * Covers: URL path, decoded query string, headers, and body.
 */
function extractInputs(req, bodyStr) {
  const inputs = [];

  // 1. Full URL (raw + decoded)
  const rawUrl = req.url || '';
  inputs.push(rawUrl);
  inputs.push(deepDecode(rawUrl));

  // 2. Query-string parameters — split out individual values
  const qIdx = rawUrl.indexOf('?');
  if (qIdx !== -1) {
    const qs = rawUrl.slice(qIdx + 1);
    const pairs = qs.split('&');
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx !== -1) {
        const key = pair.slice(0, eqIdx);
        const val = pair.slice(eqIdx + 1);
        inputs.push(deepDecode(key));
        inputs.push(deepDecode(val));
      } else {
        inputs.push(deepDecode(pair));
      }
    }
  }

  // 3. Important headers
  const headerFields = [
    'user-agent',
    'cookie',
    'referer',
    'x-forwarded-for',
    'x-forwarded-host',
    'origin',
    'authorization',
    'content-type',
  ];
  for (const field of headerFields) {
    const val = req.headers[field];
    if (val) {
      const raw = Array.isArray(val) ? val.join('; ') : String(val);
      inputs.push(raw);
      inputs.push(deepDecode(raw));
    }
  }

  // 4. Request body
  if (bodyStr && bodyStr.length > 0) {
    inputs.push(bodyStr);
    inputs.push(deepDecode(bodyStr));

    // If body is form-encoded, split key-value pairs
    const ct = req.headers['content-type'] || '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const bodyPairs = bodyStr.split('&');
      for (const pair of bodyPairs) {
        const eqIdx = pair.indexOf('=');
        if (eqIdx !== -1) {
          inputs.push(deepDecode(pair.slice(0, eqIdx)));
          inputs.push(deepDecode(pair.slice(eqIdx + 1)));
        }
      }
    }

    // If body is JSON, walk string values
    if (ct.includes('application/json')) {
      try {
        const json = JSON.parse(bodyStr);
        walkJsonStrings(json, (s) => {
          inputs.push(s);
          inputs.push(deepDecode(s));
        });
      } catch {
        // Not valid JSON — already covered by raw body above
      }
    }
  }

  // Deduplicate & filter blanks
  return [...new Set(inputs)].filter(Boolean);
}

/**
 * Walk a JSON value and invoke `cb` on every string leaf.
 */
function walkJsonStrings(val, cb) {
  if (typeof val === 'string') {
    cb(val);
  } else if (Array.isArray(val)) {
    for (const item of val) walkJsonStrings(item, cb);
  } else if (val && typeof val === 'object') {
    for (const key of Object.keys(val)) {
      cb(key); // keys can also be attack vectors
      walkJsonStrings(val[key], cb);
    }
  }
}

// ─── inspectRequest ──────────────────────────────────────────────────────────
/**
 * Run all enabled rule categories against the request.
 *
 * @param {http.IncomingMessage} req
 * @param {string}              bodyStr          – raw request body
 * @param {string[]}            enabledCategories – subset of CATEGORIES values
 * @returns {{ blocked: boolean, ruleId?: string, severity?: string,
 *             category?: string, description?: string, payload?: string }}
 */
function inspectRequest(req, bodyStr, enabledCategories) {
  // Handle enabledCategories as either array of strings or object { sqli: true, xss: false, ... }
  let cats;
  if (Array.isArray(enabledCategories)) {
    cats = enabledCategories;
  } else if (enabledCategories && typeof enabledCategories === 'object') {
    cats = Object.entries(enabledCategories)
      .filter(([_, enabled]) => enabled)
      .map(([key]) => key);
  } else {
    cats = Object.values(CATEGORIES);
  }
  const inputs = extractInputs(req, bodyStr);

  // Severity priority for deterministic ordering: critical > high > medium > low
  const severityWeight = { critical: 4, high: 3, medium: 2, low: 1 };
  let worstMatch = null;

  for (const category of cats) {
    const rules = RULE_MAP[category];
    if (!rules) continue;

    for (const rule of rules) {
      // ── Protocol rules with programmatic checks ──
      if (typeof rule.checkFn === 'function') {
        if (rule.checkFn(req, bodyStr)) {
          const match = {
            blocked: true,
            ruleId: rule.id,
            severity: rule.severity,
            category,
            description: rule.description,
            payload: `[protocol check: ${rule.id}]`,
          };
          if (rule.severity === 'critical') return match;
          if (!worstMatch || severityWeight[rule.severity] > severityWeight[worstMatch.severity]) {
            worstMatch = match;
          }
        }
      }

      // ── Pattern-based rules ──
      if (rule.pattern) {
        for (const input of inputs) {
          if (rule.pattern.test(input)) {
            // Extract a snippet around the match (for logging / response)
            const execResult = rule.pattern.exec(input);
            const matchedStr = execResult ? execResult[0] : '';
            const ctxStart = Math.max(0, (execResult ? execResult.index : 0) - 30);
            const ctxEnd = Math.min(input.length, (execResult ? execResult.index + matchedStr.length : 0) + 30);
            const snippet = input.slice(ctxStart, ctxEnd);

            const match = {
              blocked: true,
              ruleId: rule.id,
              severity: rule.severity,
              category,
              description: rule.description,
              payload: snippet.length > 200 ? snippet.slice(0, 200) + '…' : snippet,
            };

            // Short-circuit on critical — no need to keep scanning
            if (rule.severity === 'critical') return match;

            if (!worstMatch || severityWeight[rule.severity] > severityWeight[worstMatch.severity]) {
              worstMatch = match;
            }

            break; // One match per rule is enough — move to next rule
          }
        }
      }
    }
  }

  if (worstMatch) return worstMatch;

  return { blocked: false };
}

// ─── checkBotSignature ───────────────────────────────────────────────────────
/**
 * Check whether a User-Agent string matches a known scanner or aggressive
 * crawler.
 *
 * @param {string} userAgent
 * @returns {{ isBot: boolean, botName?: string, botType?: string }}
 */
function checkBotSignature(userAgent) {
  const ua = (userAgent || '').trim();

  // Check security scanners first (higher priority)
  for (const sig of botSignatures.scannerPatterns) {
    if (sig.pattern.test(ua)) {
      return { isBot: true, botName: sig.name, botType: 'scanner' };
    }
  }

  // Then aggressive crawlers
  for (const sig of botSignatures.crawlerPatterns) {
    if (sig.pattern.test(ua)) {
      return { isBot: true, botName: sig.name, botType: 'crawler' };
    }
  }

  return { isBot: false };
}

// ─── Exports ─────────────────────────────────────────────────────────────────
module.exports = {
  CATEGORIES,
  getAllRules,
  inspectRequest,
  checkBotSignature,
};
