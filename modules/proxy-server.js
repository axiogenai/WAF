'use strict';

/**
 * ShieldWall WAF — Reverse Proxy Server
 *
 * Creates an HTTP server that:
 *   1. Buffers the full request body
 *   2. Runs the WAF engine inspection pipeline
 *   3. Checks the rate limiter
 *   4. Detects bot / scanner user-agents
 *   5. Blocks or forwards accordingly
 *   6. Injects security response headers
 *   7. Strips risky upstream headers
 *   8. Logs every request
 *
 * Exports: createProxyServer(config) → http.Server
 */

const http  = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');

const wafEngine = require('./waf-engine');

// ─── Styled error pages ─────────────────────────────────────────────────────

function html403(incident) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>403 — Blocked by ShieldWall WAF</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0f172a;color:#e2e8f0;display:flex;align-items:center;
      justify-content:center;min-height:100vh}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:40px 48px;max-width:560px;width:90%;text-align:center;
      box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
    .shield{font-size:64px;margin-bottom:16px}
    h1{font-size:28px;color:#f87171;margin-bottom:8px}
    .subtitle{color:#94a3b8;margin-bottom:24px;font-size:14px}
    .details{background:#0f172a;border-radius:8px;padding:16px;text-align:left;
      font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;
      line-height:1.8;color:#94a3b8;overflow-x:auto}
    .details span{color:#38bdf8}
    .footer{margin-top:24px;font-size:11px;color:#475569}
  </style>
</head>
<body>
  <div class="card">
    <div class="shield">🛡️</div>
    <h1>403 Forbidden</h1>
    <p class="subtitle">Your request has been blocked by ShieldWall WAF.</p>
    <div class="details">
      <div><span>Incident ID:</span>  ${escapeHtml(incident.id)}</div>
      <div><span>Timestamp:</span>    ${escapeHtml(incident.timestamp)}</div>
      <div><span>Rule:</span>         ${escapeHtml(incident.ruleId)} (${escapeHtml(incident.severity)})</div>
      <div><span>Category:</span>     ${escapeHtml(incident.category)}</div>
      <div><span>Description:</span>  ${escapeHtml(incident.description)}</div>
    </div>
    <p class="footer">If you believe this is an error, contact the site administrator with the Incident ID above.</p>
  </div>
</body>
</html>`;
}

function html429(retryAfter) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>429 — Too Many Requests</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0f172a;color:#e2e8f0;display:flex;align-items:center;
      justify-content:center;min-height:100vh}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:40px 48px;max-width:480px;width:90%;text-align:center;
      box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
    .icon{font-size:64px;margin-bottom:16px}
    h1{font-size:28px;color:#fbbf24;margin-bottom:8px}
    .subtitle{color:#94a3b8;margin-bottom:16px;font-size:14px}
    .retry{background:#0f172a;border-radius:8px;padding:12px 24px;display:inline-block;
      font-family:'Cascadia Code',monospace;font-size:14px;color:#38bdf8}
    .footer{margin-top:24px;font-size:11px;color:#475569}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⏱️</div>
    <h1>429 Too Many Requests</h1>
    <p class="subtitle">You have exceeded the rate limit. Please slow down.</p>
    <div class="retry">Retry after: <strong>${retryAfter}</strong> seconds</div>
    <p class="footer">ShieldWall WAF — Rate Limiter</p>
  </div>
</body>
</html>`;
}

function html429Banned(reason) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>403 — IP Banned</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0f172a;color:#e2e8f0;display:flex;align-items:center;
      justify-content:center;min-height:100vh}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:40px 48px;max-width:480px;width:90%;text-align:center;
      box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
    .icon{font-size:64px;margin-bottom:16px}
    h1{font-size:28px;color:#f87171;margin-bottom:8px}
    .subtitle{color:#94a3b8;margin-bottom:16px;font-size:14px}
    .footer{margin-top:24px;font-size:11px;color:#475569}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>403 Forbidden — IP Banned</h1>
    <p class="subtitle">${escapeHtml(reason)}</p>
    <p class="footer">ShieldWall WAF — Contact the site administrator if you believe this is an error.</p>
  </div>
</body>
</html>`;
}

function html502() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>502 — Bad Gateway</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0f172a;color:#e2e8f0;display:flex;align-items:center;
      justify-content:center;min-height:100vh}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:40px 48px;max-width:480px;width:90%;text-align:center;
      box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
    .icon{font-size:64px;margin-bottom:16px}
    h1{font-size:28px;color:#fb923c;margin-bottom:8px}
    .subtitle{color:#94a3b8;margin-bottom:16px;font-size:14px}
    .footer{margin-top:24px;font-size:11px;color:#475569}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>502 Bad Gateway</h1>
    <p class="subtitle">The upstream server is unreachable or returned an invalid response.</p>
    <p class="footer">ShieldWall WAF — Reverse Proxy</p>
  </div>
</body>
</html>`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ─── Security headers ───────────────────────────────────────────────────────

const SECURITY_HEADERS = {
  'X-Frame-Options':           'DENY',
  'X-Content-Type-Options':    'nosniff',
  'X-XSS-Protection':          '1; mode=block',
  'Referrer-Policy':           'strict-origin-when-cross-origin',
  'Permissions-Policy':        'camera=(), microphone=(), geolocation=(), payment=()',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'X-Download-Options':        'noopen',
};

/** Headers to strip from upstream responses */
const STRIP_HEADERS = [
  'x-powered-by',
  'server',
  'x-aspnet-version',
  'x-aspnetmvc-version',
];

// ─── createProxyServer ───────────────────────────────────────────────────────

/**
 * @param {Object} config
 * @param {string}        config.targetUrl          – upstream origin (e.g. 'http://localhost:3000')
 * @param {number}        config.port               – port the proxy listens on
 * @param {string[]}      [config.enabledCategories] – WAF categories to enforce
 * @param {RateLimiter}   config.rateLimiter        – RateLimiter instance
 * @param {Array}         config.logs               – shared array for request logs
 * @param {Object}        config.stats              – shared stats counter object
 * @param {Function}      [config.onBlock]          – callback(logEntry) on blocked requests
 * @param {number}        [config.maxBodyBytes]     – max request body size (default 1 MB)
 * @param {number}        [config.proxyTimeout]     – upstream timeout in ms (default 30 000)
 * @returns {http.Server}
 */
function createProxyServer(config) {
  const {
    targetUrl,
    port,
    enabledCategories,
    rateLimiter,
    logs,
    stats,
    onBlock,
    maxBodyBytes = 1_048_576,   // 1 MB
    proxyTimeout = 30_000,
  } = config;

  const target = new URL(targetUrl);
  const isTargetHttps = target.protocol === 'https:';
  const transport = isTargetHttps ? https : http;

  // Initialise shared stats if needed
  if (stats) {
    stats.totalRequests   = stats.totalRequests   || 0;
    stats.blockedRequests = stats.blockedRequests  || 0;
    stats.allowedRequests = stats.allowedRequests  || 0;
    stats.rateLimited     = stats.rateLimited      || 0;
    stats.botDetections   = stats.botDetections    || 0;
    stats.botsBlocked     = stats.botsBlocked      || 0;
    stats.proxyErrors     = stats.proxyErrors      || 0;
  }

  const server = http.createServer((clientReq, clientRes) => {
    const requestId = crypto.randomUUID();
    const requestStart = Date.now();
    const clientIp = extractClientIp(clientReq);

    // ── 1. Buffer request body ──────────────────────────────────────────
    const bodyChunks = [];
    let bodySize = 0;
    let bodyOverflow = false;

    clientReq.on('data', (chunk) => {
      bodySize += chunk.length;
      if (bodySize > maxBodyBytes) {
        bodyOverflow = true;
        return;
      }
      bodyChunks.push(chunk);
    });

    clientReq.on('end', () => {
      if (bodyOverflow) {
        sendResponse(clientRes, 413, 'text/plain', 'Request body too large');
        const logEntry = {
          id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
          method: clientReq.method, path: clientReq.url,
          blocked: true, ruleId: 'BODY-OVERFLOW', category: 'protocolViolation',
          severity: 'high', userAgent: clientReq.headers['user-agent'] || '',
          responseCode: 413, durationMs: Date.now() - requestStart,
        };
        logRequest(logs, logEntry);
        if (stats) {
          stats.totalRequests++;
          stats.blockedRequests++;
        }
        if (typeof onBlock === 'function') onBlock(logEntry);
        return;
      }

      const bodyStr = Buffer.concat(bodyChunks).toString('utf-8');

      // ── 2. Rate limiter ─────────────────────────────────────────────
      if (rateLimiter) {
        const rateResult = rateLimiter.checkRequest(clientIp);
        if (!rateResult.allowed) {
          const logEntry = {
            id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
            method: clientReq.method, path: clientReq.url,
            blocked: true, ruleId: 'RATE-LIMIT',
            category: rateResult.banned ? 'ipBanned' : 'rateLimit',
            severity: rateResult.banned ? 'critical' : 'high',
            userAgent: clientReq.headers['user-agent'] || '',
            responseCode: rateResult.banned ? 403 : 429,
            durationMs: Date.now() - requestStart,
          };
          logRequest(logs, logEntry);

          if (stats) {
            stats.totalRequests++;
            stats.blockedRequests++;
            stats.rateLimited++;
          }
          if (typeof onBlock === 'function') onBlock(logEntry);

          if (rateResult.banned) {
            const page = html429Banned(rateResult.reason || 'Your IP has been banned.');
            clientRes.writeHead(403, {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Length': Buffer.byteLength(page),
              ...SECURITY_HEADERS,
            });
            clientRes.end(page);
          } else {
            const retryAfter = rateResult.retryAfter || 60;
            const page = html429(retryAfter);
            clientRes.writeHead(429, {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Length': Buffer.byteLength(page),
              'Retry-After': String(retryAfter),
              ...SECURITY_HEADERS,
            });
            clientRes.end(page);
          }
          return;
        }
      }

      // ── 3. Bot / scanner detection ──────────────────────────────────
      const userAgent = clientReq.headers['user-agent'] || '';
      const botCheck = wafEngine.checkBotSignature(userAgent);
      if (botCheck.isBot && botCheck.botType === 'scanner') {
        const incident = {
          id: requestId,
          timestamp: new Date().toISOString(),
          ruleId: 'BOT-SCANNER',
          severity: 'critical',
          category: 'botDetection',
          description: `Known security scanner detected: ${botCheck.botName}`,
        };

        const logEntry = {
          ...incident, ip: clientIp, method: clientReq.method, path: clientReq.url,
          blocked: true, userAgent, responseCode: 403,
          durationMs: Date.now() - requestStart,
        };
        logRequest(logs, logEntry);

        if (stats) {
          stats.totalRequests++;
          stats.blockedRequests++;
          stats.botDetections = (stats.botDetections || 0) + 1;
          stats.botsBlocked = (stats.botsBlocked || 0) + 1;
        }
        if (typeof onBlock === 'function') onBlock(logEntry);

        // Auto-blacklist scanners
        if (rateLimiter) {
          rateLimiter.blacklist(clientIp, `Security scanner: ${botCheck.botName}`);
        }

        const page = html403(incident);
        clientRes.writeHead(403, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': Buffer.byteLength(page),
          ...SECURITY_HEADERS,
        });
        clientRes.end(page);
        return;
      }

      // ── 4. WAF engine inspection ────────────────────────────────────
      const inspection = wafEngine.inspectRequest(
        clientReq,
        bodyStr,
        enabledCategories || Object.values(wafEngine.CATEGORIES),
      );

      if (inspection.blocked) {
        const incident = {
          id: requestId,
          timestamp: new Date().toISOString(),
          ruleId: inspection.ruleId,
          severity: inspection.severity,
          category: inspection.category,
          description: inspection.description,
        };

        const logEntry = {
          ...incident, ip: clientIp, method: clientReq.method, path: clientReq.url,
          blocked: true, userAgent, responseCode: 403, payload: inspection.payload,
          durationMs: Date.now() - requestStart,
        };
        logRequest(logs, logEntry);

        if (stats) {
          stats.totalRequests++;
          stats.blockedRequests++;
        }
        if (typeof onBlock === 'function') onBlock(logEntry);

        const page = html403(incident);
        clientRes.writeHead(403, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': Buffer.byteLength(page),
          ...SECURITY_HEADERS,
        });
        clientRes.end(page);
        return;
      }

      // ── 5. Forward to upstream ──────────────────────────────────────
      if (stats) { stats.totalRequests++; stats.allowedRequests++; }

      const proxyHeaders = { ...clientReq.headers };

      // Set correct Host header for upstream
      proxyHeaders['host'] = target.host;

      // Append X-Forwarded-* headers
      proxyHeaders['x-forwarded-for'] = clientIp
        + (proxyHeaders['x-forwarded-for'] ? `, ${proxyHeaders['x-forwarded-for']}` : '');
      proxyHeaders['x-forwarded-proto'] = 'http';
      proxyHeaders['x-forwarded-host'] = clientReq.headers['host'] || '';
      proxyHeaders['x-real-ip'] = clientIp;

      const proxyOpts = {
        hostname: target.hostname,
        port: target.port || (isTargetHttps ? 443 : 80),
        path: clientReq.url,
        method: clientReq.method,
        headers: proxyHeaders,
        timeout: proxyTimeout,
      };

      const proxyReq = transport.request(proxyOpts, (proxyRes) => {
        // Strip risky upstream headers
        const upstreamHeaders = { ...proxyRes.headers };
        for (const h of STRIP_HEADERS) {
          delete upstreamHeaders[h];
        }

        // Inject security headers (overwrite upstream values)
        Object.assign(upstreamHeaders, SECURITY_HEADERS);

        // Add ShieldWall fingerprint
        upstreamHeaders['x-shieldwall'] = 'protected';

        clientRes.writeHead(proxyRes.statusCode, upstreamHeaders);
        proxyRes.pipe(clientRes, { end: true });

        // Log successful proxy
        proxyRes.on('end', () => {
          logRequest(logs, {
            id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
            method: clientReq.method, path: clientReq.url,
            blocked: false, ruleId: null, category: null, severity: null,
            userAgent, responseCode: proxyRes.statusCode,
            durationMs: Date.now() - requestStart,
          });
        });
      });

      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        if (stats) stats.proxyErrors++;

        logRequest(logs, {
          id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
          method: clientReq.method, path: clientReq.url,
          blocked: false, ruleId: 'PROXY-TIMEOUT', category: 'proxyError',
          severity: 'high', userAgent, responseCode: 502,
          durationMs: Date.now() - requestStart,
        });

        const page = html502();
        clientRes.writeHead(502, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': Buffer.byteLength(page),
          ...SECURITY_HEADERS,
        });
        clientRes.end(page);
      });

      proxyReq.on('error', (err) => {
        if (stats) stats.proxyErrors++;

        logRequest(logs, {
          id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
          method: clientReq.method, path: clientReq.url,
          blocked: false, ruleId: 'PROXY-ERROR', category: 'proxyError',
          severity: 'high', userAgent, responseCode: 502,
          error: err.message, durationMs: Date.now() - requestStart,
        });

        if (!clientRes.headersSent) {
          const page = html502();
          clientRes.writeHead(502, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': Buffer.byteLength(page),
            ...SECURITY_HEADERS,
          });
          clientRes.end(page);
        }
      });

      // Write buffered body to upstream
      if (bodyChunks.length > 0) {
        proxyReq.write(Buffer.concat(bodyChunks));
      }
      proxyReq.end();
    });

    // Handle client-side errors (aborted connections etc.)
    clientReq.on('error', (err) => {
      logRequest(logs, {
        id: requestId, timestamp: new Date().toISOString(), ip: clientIp,
        method: clientReq.method, path: clientReq.url,
        blocked: false, ruleId: 'CLIENT-ERROR', category: 'clientError',
        severity: 'low', userAgent: clientReq.headers['user-agent'] || '',
        responseCode: 0, error: err.message,
        durationMs: Date.now() - requestStart,
      });
    });
  });

  return server;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Extract the client's real IP, respecting X-Forwarded-For (first hop).
 */
function extractClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (first) return first;
  }
  // Node ≥ 18.x socket.remoteAddress
  return req.socket?.remoteAddress || req.connection?.remoteAddress || '0.0.0.0';
}

/**
 * Utility to send a simple text response.
 */
function sendResponse(res, status, contentType, body) {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    ...SECURITY_HEADERS,
  });
  res.end(body);
}

/**
 * Append an entry to the shared logs array, keeping it bounded.
 */
function logRequest(logs, entry) {
  if (!Array.isArray(logs)) return;
  logs.push(entry);
  // Keep only the last 10 000 entries in memory
  if (logs.length > 10_000) {
    logs.splice(0, logs.length - 10_000);
  }
}

// ─── Exports ─────────────────────────────────────────────────────────────────
module.exports = { createProxyServer };
