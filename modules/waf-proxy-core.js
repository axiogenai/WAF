'use strict';

const http  = require('http');
const https = require('https');
const { URL } = require('url');

const SECURITY_HEADERS = {
  'X-Frame-Options':        'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection':       '1; mode=block',
  'Referrer-Policy':        'strict-origin-when-cross-origin',
  'X-Protected-By':         'ShieldWall-WAF/2.0'
};

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || '0.0.0.0';
}

function readBody(req, maxBytes = 256 * 1024) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    req.on('data', c => { total += c.length; if (total < maxBytes) chunks.push(c); });
    req.on('end',  () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error',() => resolve(''));
  });
}

function createWafProxyHandler({ wafEngine, domainRegistry, rateLimiter, wafLogs = [], maxLogs = 2000, onLog }) {
  return async function handleProxy(req, res) {
    const host   = (req.headers.host || '').split(':')[0].toLowerCase();
    const entry  = domainRegistry.lookup(host);
    const ip     = getClientIp(req);

    if (!entry) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><html><head><title>Not Found</title></head><body style="font-family:sans-serif;padding:40px;background:#0d1117;color:#e6edf3"><h2>🛡️ ShieldWall WAF</h2><p style="color:#8b949e">Domain <strong>${host}</strong> is not registered with this WAF.</p><p style="color:#8b949e">Register it at the ShieldWall dashboard to enable protection.</p></body></html>`);
      return;
    }

    const logEntry = { id: Date.now() + Math.random().toString(36).slice(2), host, ip, method: req.method, path: req.url, timestamp: Date.now(), blocked: false, category: null };

    try {
      const bodyStr = await readBody(req);

      // ── Bot detection ──────────────────────────────────────────────────────
      if (entry.rules.botDetection && wafEngine?.checkBotSignature) {
        const ua = req.headers['user-agent'] || '';
        const bot = wafEngine.checkBotSignature(ua);
        if (bot.isBot) {
          logEntry.blocked  = true;
          logEntry.category = 'Bot/Scanner';
          logEntry.detail   = bot.botName;
          pushLog(wafLogs, logEntry, maxLogs, onLog);
          domainRegistry.incrementStat(host, 'blocked');
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Blocked by ShieldWall WAF', reason: 'Bot/Scanner detected', bot: bot.botName }));
          return;
        }
      }

      // ── WAF rule inspection ────────────────────────────────────────────────
      if (wafEngine?.inspectRequest) {
        const result = wafEngine.inspectRequest(req, bodyStr, entry.rules);
        if (result.blocked) {
          logEntry.blocked  = true;
          logEntry.category = result.category;
          logEntry.ruleId   = result.ruleId;
          logEntry.payload  = result.payload;
          pushLog(wafLogs, logEntry, maxLogs, onLog);
          domainRegistry.incrementStat(host, 'blocked');
          res.writeHead(403, {
            'Content-Type': 'application/json',
            'X-ShieldWall-Rule': result.ruleId || 'unknown',
            'X-ShieldWall-Category': result.category || 'unknown'
          });
          res.end(JSON.stringify({
            error:    'Request blocked by ShieldWall WAF',
            category: result.category,
            ruleId:   result.ruleId,
            ref:      'SW-' + Date.now()
          }));
          return;
        }
      }

      // ── Rate limiting ──────────────────────────────────────────────────────
      if (rateLimiter?.check) {
        const rl = rateLimiter.check(ip);
        if (rl?.blocked) {
          logEntry.blocked  = true;
          logEntry.category = 'Rate Limited';
          pushLog(wafLogs, logEntry, maxLogs, onLog);
          domainRegistry.incrementStat(host, 'blocked');
          res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
          res.end(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }));
          return;
        }
      }

      // ── Forward to origin ──────────────────────────────────────────────────
      const originUrl  = new URL(entry.origin);
      const transport  = originUrl.protocol === 'https:' ? https : http;
      const targetPort = originUrl.port ? parseInt(originUrl.port) : (originUrl.protocol === 'https:' ? 443 : 80);

      const proxyHeaders = {
        ...req.headers,
        host:                originUrl.hostname,
        'x-forwarded-for':   ip,
        'x-forwarded-host':  host,
        'x-forwarded-proto': req.socket?.encrypted ? 'https' : 'http',
        'x-real-ip':         ip,
        'x-shieldwall':      '1'
      };
      delete proxyHeaders['x-shieldwall-proxy'];

      const proxyReq = transport.request({
        hostname:          originUrl.hostname,
        port:              targetPort,
        path:              req.url,
        method:            req.method,
        headers:           proxyHeaders,
        rejectUnauthorized: false,
        timeout:           30000
      }, (proxyRes) => {
        const outHeaders = { ...proxyRes.headers, ...SECURITY_HEADERS };
        delete outHeaders['x-powered-by'];
        res.writeHead(proxyRes.statusCode, outHeaders);
        proxyRes.pipe(res, { end: true });

        logEntry.status = proxyRes.statusCode;
        pushLog(wafLogs, logEntry, maxLogs, onLog);
        domainRegistry.incrementStat(host, 'allowed');
      });

      proxyReq.on('error', (err) => {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Gateway — origin server unreachable', detail: err.message }));
        }
      });

      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        if (!res.headersSent) {
          res.writeHead(504, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Gateway Timeout' }));
        }
      });

      if (bodyStr) proxyReq.write(bodyStr);
      proxyReq.end();

    } catch (e) {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'WAF internal error', detail: e.message }));
      }
    }
  };
}

function pushLog(arr, entry, max, onLog) {
  arr.unshift(entry);
  if (arr.length > max) arr.pop();
  if (onLog) onLog(entry);
}

module.exports = { createWafProxyHandler };
