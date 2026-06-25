'use strict';

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const multer   = require('multer');
const { execSync } = require('child_process');

// ─── Module Imports ──────────────────────────────────────────────────────────
let wafEngine, proxyServer, rateLimiterMod, scanner, codeAnalyzer, codeHardener, reportGenerator;
let domainRegistry, wafProxyCore;
try { wafEngine      = require('./modules/waf-engine');       } catch(e) { console.warn('waf-engine not loaded:', e.message); }
try { proxyServer    = require('./modules/proxy-server');     } catch(e) { console.warn('proxy-server not loaded:', e.message); }
try { rateLimiterMod = require('./modules/rate-limiter');     } catch(e) { console.warn('rate-limiter not loaded:', e.message); }
try { scanner        = require('./modules/scanner');          } catch(e) { console.warn('scanner not loaded:', e.message); }
try { codeAnalyzer   = require('./modules/code-analyzer');   } catch(e) { console.warn('code-analyzer not loaded:', e.message); }
try { codeHardener   = require('./modules/code-hardener');   } catch(e) { console.warn('code-hardener not loaded:', e.message); }
try { reportGenerator = require('./modules/report-generator'); } catch(e) { console.warn('report-generator not loaded:', e.message); }
try { domainRegistry = require('./modules/domain-registry'); } catch(e) { console.warn('domain-registry not loaded:', e.message); }
try { wafProxyCore   = require('./modules/waf-proxy-core');  } catch(e) { console.warn('waf-proxy-core not loaded:', e.message); }
let configGenerator;
try { configGenerator = require('./modules/config-generator'); } catch(e) { console.warn('config-generator not loaded:', e.message); }

const app = express();
const DASHBOARD_PORT = parseInt(process.env.PORT || '3000', 10);

const DASHBOARD_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0']);

// ─── Uploads Directory ───────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename:    (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
  }),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ─── Application State ───────────────────────────────────────────────────────
const CONFIG_FILE = path.join(__dirname, 'waf-config.json');
const IPS_FILE = path.join(__dirname, 'waf-ips.json');

let config = {
  proxyTarget: '',
  proxyPort: 8080,
  rules: {
    sqli: true, xss: true, pathTraversal: true,
    rfiLfi: true, commandInjection: true, protocolViolation: true, botDetection: true
  },
  rateLimiter: { windowMs: 60000, maxRequests: 100, banThreshold: 3, banDurationMs: 900000 },
  proxyActive: false
};

let stats = {
  totalRequests: 0, allowedRequests: 0, blockedRequests: 0,
  rateLimited: 0, botsBlocked: 0,
  threatsBreakdown: {
    'SQL Injection': 0, 'Cross-Site Scripting': 0, 'Path Traversal': 0,
    'RFI/LFI': 0, 'Command Injection': 0, 'Protocol Violation': 0,
    'Bot/Scanner': 0, 'Rate Limited': 0, 'CSRF': 0
  },
  startTime: Date.now()
};

let logs = [];
const MAX_LOGS = 1000;

// ─── In-Memory IP Lists (single source of truth) ─────────────────────────────
const ipBlacklist = new Map();  // ip -> { reason, addedAt }
const ipWhitelist = new Set();  // Set of IPs

// ─── Persistence Helpers ──────────────────────────────────────────────────────
function loadState() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
      config = { ...config, ...data };
    }
  } catch (e) {
    console.error('Error loading config file:', e.message);
  }

  try {
    if (fs.existsSync(IPS_FILE)) {
      const data = JSON.parse(fs.readFileSync(IPS_FILE, 'utf-8'));
      if (data.blacklist && Array.isArray(data.blacklist)) {
        for (const item of data.blacklist) {
          if (item && item.ip) {
            ipBlacklist.set(item.ip, { reason: item.reason || 'Manual', addedAt: item.addedAt || Date.now() });
          }
        }
      }
      if (data.whitelist && Array.isArray(data.whitelist)) {
        for (const item of data.whitelist) {
          if (item && item.ip) {
            ipWhitelist.add(item.ip);
          }
        }
      }
    }
  } catch (e) {
    console.error('Error loading IPs file:', e.message);
  }
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  } catch (e) {
    console.error('Error saving config file:', e.message);
  }
}

function saveIps() {
  try {
    const data = {
      blacklist: [...ipBlacklist.entries()].map(([ip, info]) => ({ ip, reason: info.reason, addedAt: info.addedAt })),
      whitelist: [...ipWhitelist].map(ip => ({ ip }))
    };
    fs.writeFileSync(IPS_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Error saving IPs file:', e.message);
  }
}

// Load state before initializing rate limiter
loadState();

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
let rateLimiter = null;
if (rateLimiterMod && rateLimiterMod.RateLimiter) {
  rateLimiter = new rateLimiterMod.RateLimiter(config.rateLimiter);
  for (const [ip, info] of ipBlacklist.entries()) {
    rateLimiter.blacklist(ip, info.reason);
  }
  for (const ip of ipWhitelist) {
    rateLimiter.whitelist(ip);
  }
}

// ─── Proxy State ──────────────────────────────────────────────────────────────
let proxyServerInstance = null;

// ─── Scan State ───────────────────────────────────────────────────────────────
let currentScan = { status: 'idle', progress: 0, checks: [], result: null, error: null };
let lastCodeAnalysis = null;
let lastHardenResult = null;
let uploadedFiles    = [];
const wafProxyLogs   = [];

// ─── WAF Proxy handler (for non-dashboard hosts) ──────────────────────────────
let wafProxyHandler = null;
if (wafProxyCore && domainRegistry) {
  wafProxyHandler = wafProxyCore.createWafProxyHandler({
    wafEngine,
    domainRegistry,
    rateLimiter,
    wafLogs: wafProxyLogs,
    maxLogs: 2000,
    onLog: (entry) => { wafProxyLogs.unshift(entry); if (wafProxyLogs.length > 2000) wafProxyLogs.pop(); }
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  // If this host is a registered WAF domain, ALWAYS route to the WAF handler
  // (even on hf.space — the WAF must fire for protected domains)
  if (wafProxyHandler && domainRegistry && domainRegistry.lookup(host)) {
    return wafProxyHandler(req, res);
  }
  // Otherwise, serve the dashboard
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Helpers ─────────────────────────────────────────────────────────────────
function addLog(entry) {
  logs.unshift({ id: Date.now() + Math.random().toString(36).slice(2), ...entry });
  if (logs.length > MAX_LOGS) logs.pop();
}

function catStatKey(cat) {
  const m = {
    sqli: 'SQL Injection', xss: 'Cross-Site Scripting', pathTraversal: 'Path Traversal',
    rfiLfi: 'RFI/LFI', commandInjection: 'Command Injection',
    protocolViolation: 'Protocol Violation', botDetection: 'Bot/Scanner',
    rateLimited: 'Rate Limited',
    rateLimit: 'Rate Limited',
    ipBanned: 'Rate Limited'
  };
  return m[cat] || cat;
}

// ─── Proxy Management ─────────────────────────────────────────────────────────
function startProxy(cb) {
  if (proxyServerInstance) return cb(new Error('Proxy already running'));
  if (!config.proxyTarget) return cb(new Error('No target URL configured'));
  if (!proxyServer) return cb(new Error('Proxy server module not available'));

  try {
    proxyServerInstance = proxyServer.createProxyServer({
      targetUrl: config.proxyTarget,
      port: config.proxyPort,
      enabledCategories: config.rules,
      rateLimiter,
      wafEngine,
      logs,
      stats,
      maxLogs: MAX_LOGS,
      onLog: addLog,
      onRequest: () => { stats.totalRequests++; },
      onAllow:   () => { stats.allowedRequests++; },
      onBlock: (entry) => {
        const key = catStatKey(entry.category);
        if (stats.threatsBreakdown[key] !== undefined) stats.threatsBreakdown[key]++;
      }
    });

    proxyServerInstance.listen(config.proxyPort, () => {
      console.log(`🛡️  WAF Proxy → ${config.proxyTarget} on port ${config.proxyPort}`);
      cb(null);
    });

    proxyServerInstance.on('error', (err) => {
      proxyServerInstance = null;
      console.error('Proxy error:', err.message);
    });
  } catch (e) {
    cb(e);
  }
}

function stopProxy(cb) {
  if (!proxyServerInstance) return cb(null);
  proxyServerInstance.close((err) => {
    proxyServerInstance = null;
    console.log('🛡️  Proxy stopped');
    cb(err || null);
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// API: Status & Configuration
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/status', (req, res) => {
  const ruleInfo = {};
  if (wafEngine) {
    const allRules = wafEngine.getAllRules ? wafEngine.getAllRules() : {};
    for (const [cat, rules] of Object.entries(allRules)) {
      ruleInfo[cat] = { count: Array.isArray(rules) ? rules.length : 0, enabled: config.rules[cat] !== false };
    }
  }
  res.json({
    config,
    stats,
    proxyActive: proxyServerInstance !== null,
    ruleInfo,
    uptime: Date.now() - stats.startTime,
    rateLimiterStats: rateLimiter ? rateLimiter.getStats() : {}
  });
});

app.post('/api/config', (req, res) => {
  const { proxyTarget, proxyPort, rules } = req.body;

  if (proxyTarget !== undefined) {
    if (proxyTarget) {
      try { new URL(proxyTarget); config.proxyTarget = proxyTarget; }
      catch { return res.status(400).json({ error: 'Invalid URL — include http:// or https://' }); }
    } else {
      config.proxyTarget = '';
    }
  }

  if (proxyPort !== undefined) {
    const p = Number(proxyPort);
    if (p >= 1024 && p <= 65535) config.proxyPort = p;
    else return res.status(400).json({ error: 'Port must be 1024–65535' });
  }

  if (rules && typeof rules === 'object') {
    config.rules = { ...config.rules, ...rules };
  }

  saveConfig();
  res.json({ message: 'Configuration updated.', config });
});

// ═════════════════════════════════════════════════════════════════════════════
// API: Proxy Control
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/proxy/start', (req, res) => {
  if (proxyServerInstance) return res.status(400).json({ error: 'Proxy already running.' });
  if (!config.proxyTarget) return res.status(400).json({ error: 'Set a target URL first.' });
  startProxy((err) => {
    if (err) return res.status(500).json({ error: err.message });
    config.proxyActive = true;
    saveConfig();
    res.json({ message: `Proxy started on port ${config.proxyPort}`, proxyActive: true });
  });
});

app.post('/api/proxy/stop', (req, res) => {
  if (!proxyServerInstance) return res.status(400).json({ error: 'Proxy is not running.' });
  stopProxy((err) => {
    if (err) return res.status(500).json({ error: err.message });
    config.proxyActive = false;
    saveConfig();
    res.json({ message: 'Proxy stopped.', proxyActive: false });
  });
});

app.post('/api/proxy/toggle', (req, res) => {
  if (proxyServerInstance) {
    stopProxy((err) => {
      if (err) return res.status(500).json({ error: err.message });
      config.proxyActive = false;
      saveConfig();
      res.json({ message: 'Proxy stopped.', proxyActive: false });
    });
  } else {
    if (!config.proxyTarget) return res.status(400).json({ error: 'Set a target URL first.' });
    startProxy((err) => {
      if (err) return res.status(500).json({ error: err.message });
      config.proxyActive = true;
      saveConfig();
      res.json({ message: 'Proxy started.', proxyActive: true });
    });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// API: Logs & Stats
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/logs', (req, res) => {
  let result = [...logs];
  if (req.query.filter === 'blocked')  result = result.filter(l => l.blocked);
  if (req.query.filter === 'allowed')  result = result.filter(l => !l.blocked);
  if (req.query.limit)                 result = result.slice(0, parseInt(req.query.limit) || 100);
  res.json(result);
});

app.get('/api/top-ips', (req, res) => {
  const counts = {};
  logs.filter(l => l.blocked).forEach(l => { if (l.ip) counts[l.ip] = (counts[l.ip] || 0) + 1; });
  const sorted = Object.entries(counts)
    .sort(([,a],[,b]) => b - a)
    .slice(0, 20)
    .map(([ip, count]) => ({
      ip,
      count,
      blacklisted: ipBlacklist.has(ip),
      whitelisted: ipWhitelist.has(ip)
    }));
  res.json(sorted);
});

app.post('/api/stats/reset', (req, res) => {
  logs = [];
  stats = {
    totalRequests: 0, allowedRequests: 0, blockedRequests: 0,
    rateLimited: 0, botsBlocked: 0,
    threatsBreakdown: {
      'SQL Injection': 0, 'Cross-Site Scripting': 0, 'Path Traversal': 0,
      'RFI/LFI': 0, 'Command Injection': 0, 'Protocol Violation': 0,
      'Bot/Scanner': 0, 'Rate Limited': 0, 'CSRF': 0
    },
    startTime: Date.now()
  };
  res.json({ message: 'Stats and logs reset.' });
});

// ═════════════════════════════════════════════════════════════════════════════
// API: IP Management (blacklist / whitelist)
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/ip/lists', (req, res) => {
  res.json({
    blacklist: [...ipBlacklist.entries()].map(([ip, info]) => ({ ip, reason: info.reason, addedAt: info.addedAt })),
    whitelist: [...ipWhitelist].map(ip => ({ ip })),
    banned:    rateLimiter ? rateLimiter.getBannedIPs() : []
  });
});

app.post('/api/ip/blacklist', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  ipBlacklist.set(ip, { reason: 'Manual', addedAt: Date.now() });
  if (rateLimiter) rateLimiter.blacklist(ip, 'Manual');
  saveIps();
  res.json({ message: `${ip} added to blacklist.` });
});

app.delete('/api/ip/blacklist/:ip', (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  ipBlacklist.delete(ip);
  if (rateLimiter) rateLimiter.unban(ip);
  saveIps();
  res.json({ message: `${ip} removed from blacklist.` });
});

app.post('/api/ip/whitelist', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  ipWhitelist.add(ip);
  ipBlacklist.delete(ip);
  if (rateLimiter) rateLimiter.whitelist(ip);
  saveIps();
  res.json({ message: `${ip} added to whitelist.` });
});

app.delete('/api/ip/whitelist/:ip', (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  ipWhitelist.delete(ip);
  saveIps();
  res.json({ message: `${ip} removed from whitelist.` });
});

// ═════════════════════════════════════════════════════════════════════════════
// API: Vulnerability Scanner — URL
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/scan/url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required.' });
  if (!scanner) return res.status(500).json({ error: 'Scanner module not loaded.' });

  currentScan = { status: 'scanning', progress: 0, checks: [], result: null, error: null };
  res.json({ message: 'Scan started.', status: 'scanning' });

  // Run async in background
  setImmediate(async () => {
    try {
      const result = await scanner.scanUrl(url, {
        onProgress: (progress, checkName) => {
          currentScan.progress = progress;
          if (checkName) currentScan.checks.push({ name: checkName, done: true });
        }
      });
      currentScan.status   = 'complete';
      currentScan.progress = 100;
      currentScan.result   = result;
      lastCodeAnalysis     = result; // make reportable
    } catch (e) {
      currentScan.status = 'error';
      currentScan.error  = e.message;
    }
  });
});

app.get('/api/scan/status', (req, res) => res.json(currentScan));

// ═════════════════════════════════════════════════════════════════════════════
// API: Code Analysis (file upload)
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/scan/code', upload.array('files', 50), async (req, res) => {
  if (!codeAnalyzer) return res.status(500).json({ error: 'Code analyzer module not loaded.' });
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files uploaded.' });

  try {
    const files = req.files.map(f => {
      const content = fs.readFileSync(f.path, 'utf-8');
      try { fs.unlinkSync(f.path); } catch {}
      return { filename: f.originalname, content };
    });
    const result = codeAnalyzer.analyzeCode(files);
    lastCodeAnalysis = result;
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Analysis failed: ' + e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// API: Scan Report Download
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/scan/report', (req, res) => {
  if (!reportGenerator) return res.status(500).json({ error: 'Report generator not loaded.' });
  const data = currentScan.result || lastCodeAnalysis;
  if (!data) return res.status(400).json({ error: 'Run a scan first.' });
  try {
    const html = reportGenerator.generateReport(data, lastCodeAnalysis);
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', 'attachment; filename="shieldwall-report.html"');
    res.send(html);
  } catch (e) {
    res.status(500).json({ error: 'Report failed: ' + e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// API: GitHub Repository Scanner
// ═════════════════════════════════════════════════════════════════════════════

const SOURCE_EXT = new Set([
  '.js','.jsx','.ts','.tsx','.mjs','.cjs',
  '.py','.pyw','.php','.phtml',
  '.html','.htm','.ejs','.hbs','.pug',
  '.rb','.erb','.java','.kt','.scala',
  '.go','.rs','.c','.cpp','.h','.hpp','.cs',
  '.sql','.sh','.bash','.bat','.ps1',
  '.json','.yaml','.yml','.toml','.env','.ini','.cfg'
]);

const IGNORE_DIRS = new Set([
  'node_modules','.git','__pycache__','.venv','venv',
  'dist','build','.next','.nuxt','vendor','bower_components',
  '.cache','coverage','env','.eggs'
]);

function walkDir(dir, max = 400) {
  const results = [];
  (function walk(d) {
    if (results.length >= max) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (results.length >= max) return;
      if (e.isDirectory()) {
        if (!IGNORE_DIRS.has(e.name)) walk(path.join(d, e.name));
      } else if (e.isFile()) {
        const ext = path.extname(e.name).toLowerCase();
        if (SOURCE_EXT.has(ext)) {
          const fp = path.join(d, e.name);
          try {
            const st = fs.statSync(fp);
            if (st.size < 512 * 1024) {
              results.push({
                filename: path.relative(dir, fp).replace(/\\/g, '/'),
                content:  fs.readFileSync(fp, 'utf-8')
              });
            }
          } catch {}
        }
      }
    }
  })(dir);
  return results;
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

app.post('/api/scan/github', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'GitHub URL required.' });

  // Validate GitHub URL
  const githubRe = /^https?:\/\/(www\.)?github\.com\/[\w.\-]+\/[\w.\-]+(\.git)?\/?$/;
  if (!githubRe.test(url)) {
    return res.status(400).json({ error: 'Invalid GitHub URL. Example: https://github.com/user/repo' });
  }

  const repoName = url.replace(/\.git\/?$/, '').split('/').pop();
  const cloneDir = path.join(uploadsDir, `gh-${Date.now()}-${repoName}`);

  try {
    // Clone (shallow)
    const gitUrl = url.endsWith('.git') ? url : url + '.git';
    execSync(`git clone --depth 1 "${gitUrl}" "${cloneDir}"`, { timeout: 90000, stdio: 'pipe' });

    // Walk source files
    const files = walkDir(cloneDir);
    if (!files.length) {
      cleanup(cloneDir);
      return res.status(400).json({ error: 'No source files found in the repository.' });
    }

    // Code analysis
    let codeAnalysis = null;
    if (codeAnalyzer) {
      codeAnalysis = codeAnalyzer.analyzeCode(files);
      lastCodeAnalysis = codeAnalysis;
    }

    // Code hardening
    let hardenResult = null;
    if (codeHardener) {
      const detection = codeHardener.detectFramework(files);
      const patches   = codeHardener.generatePatches(files, detection.framework);
      hardenResult    = { detection, patches };
      lastHardenResult = { detection, patches, files };
      uploadedFiles    = files;
    }

    cleanup(cloneDir);

    res.json({
      repoName,
      filesScanned: files.length,
      codeAnalysis,
      hardenResult,
      status: 'complete'
    });
  } catch (e) {
    cleanup(cloneDir);
    const msg = e.message.includes('timeout')    ? 'Clone timed out — repo too large.' :
                e.message.includes('128')        ? 'Repository not found or is private.' :
                e.message.includes('not found')  ? 'Repository not found or is private.' :
                                                   'Clone failed: ' + e.message;
    res.status(500).json({ error: msg });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// API: Code Hardener
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/harden/upload', upload.array('files', 50), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files uploaded.' });
  uploadedFiles = req.files.map(f => {
    const content = fs.readFileSync(f.path, 'utf-8');
    try { fs.unlinkSync(f.path); } catch {}
    return { filename: f.originalname, content };
  });
  res.json({ message: `${uploadedFiles.length} file(s) uploaded.`, files: uploadedFiles.map(f => f.filename) });
});

app.post('/api/harden/analyze', (req, res) => {
  if (!codeHardener) return res.status(500).json({ error: 'Code hardener not loaded.' });
  if (!uploadedFiles.length) return res.status(400).json({ error: 'Upload files first.' });
  try {
    const files     = uploadedFiles.map(f => ({ filename: f.filename, content: f.content }));
    const detection = codeHardener.detectFramework(files);
    const patches   = codeHardener.generatePatches(files, detection.framework);
    lastHardenResult = { detection, patches, files };
    res.json({ detection, patches });
  } catch (e) {
    res.status(500).json({ error: 'Hardening failed: ' + e.message });
  }
});

function applyPatchesToMemory(selectedPatchIndices) {
  if (!lastHardenResult || !lastHardenResult.files) {
    const files = uploadedFiles.map(f => ({ filename: f.filename, content: f.content }));
    return { files, appliedFilesCount: 0 };
  }

  const files = lastHardenResult.files.map(f => ({ filename: f.filename, content: f.content }));
  const patches = lastHardenResult.patches || [];
  const appliedFiles = new Set();

  for (const idx of selectedPatchIndices) {
    const patch = patches[idx];
    if (!patch) continue;

    let file = files.find(f => f.filename === patch.filename);
    if (!file) {
      if (patch.type === 'create_file' || !patch.original) {
        files.push({ filename: patch.filename, content: patch.patched });
        appliedFiles.add(patch.filename);
      }
      continue;
    }

    if (patch.original && file.content.includes(patch.original)) {
      file.content = file.content.replace(patch.original, patch.patched);
      appliedFiles.add(patch.filename);
    } else {
      console.warn(`Patch ${idx} original content not found in file ${patch.filename}. Trying fallback...`);
      const ext = path.extname(patch.filename).toLowerCase();
      if (ext === '.js' || ext === '.py') {
        let newContent = patch.patched;
        if (patch.original) {
          newContent = newContent.replace(patch.original, '');
        }
        file.content = file.content.trimEnd() + '\n\n' + newContent.trim();
        appliedFiles.add(patch.filename);
      } else if (ext === '.html' || ext === '.htm') {
        if (file.content.includes('<html>')) {
          file.content = file.content.replace('<html>', '<html>\n' + patch.patched);
          appliedFiles.add(patch.filename);
        } else if (file.content.includes('<HTML>')) {
          file.content = file.content.replace('<HTML>', '<HTML>\n' + patch.patched);
          appliedFiles.add(patch.filename);
        } else {
          file.content = patch.patched + '\n' + file.content;
          appliedFiles.add(patch.filename);
        }
      } else {
        file.content = file.content.trimEnd() + '\n\n' + patch.patched.trim();
        appliedFiles.add(patch.filename);
      }
    }
  }

  return { files, appliedFilesCount: appliedFiles.size };
}

app.post('/api/harden/apply', (req, res) => {
  if (!uploadedFiles || !uploadedFiles.length) {
    return res.status(400).json({ error: 'No uploaded or scanned files available to patch.' });
  }
  if (!lastHardenResult) {
    return res.status(400).json({ error: 'Run hardening analysis first.' });
  }

  const { patches, localPath } = req.body;
  const selectedIndices = Array.isArray(patches) ? patches.map(Number) : [];

  const { files, appliedFilesCount } = applyPatchesToMemory(selectedIndices);

  if (localPath) {
    const resolvedPath = path.resolve(localPath);
    if (!fs.existsSync(resolvedPath)) {
      return res.status(400).json({ error: `Local directory does not exist: ${resolvedPath}` });
    }

    try {
      let writtenFilesCount = 0;
      for (const file of files) {
        const targetPath = path.join(resolvedPath, file.filename);
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        fs.writeFileSync(targetPath, file.content, 'utf-8');
        writtenFilesCount++;
      }
      return res.json({
        message: `Successfully wrote ${writtenFilesCount} files to disk under "${resolvedPath}" (${appliedFilesCount} security patches applied).`,
        writtenFilesCount,
        appliedFilesCount
      });
    } catch (err) {
      return res.status(500).json({ error: `Failed to write files to disk: ${err.message}` });
    }
  } else {
    try {
      const AdmZip = require('adm-zip');
      const zip = new AdmZip();
      for (const file of files) {
        zip.addFile(file.filename, Buffer.from(file.content, 'utf-8'));
      }
      const zipBuffer = zip.toBuffer();
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="hardened-code.zip"');
      res.send(zipBuffer);
    } catch (err) {
      return res.status(500).json({ error: `Failed to generate ZIP: ${err.message}` });
    }
  }
});

app.post('/api/harden/download', (req, res) => {
  if (!uploadedFiles || !uploadedFiles.length) {
    return res.status(400).json({ error: 'No files available.' });
  }
  const { patches } = req.body || {};
  const selectedIndices = Array.isArray(patches) ? patches.map(Number) : [];
  const { files } = applyPatchesToMemory(selectedIndices);
  try {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip();
    for (const file of files) {
      zip.addFile(file.filename, Buffer.from(file.content, 'utf-8'));
    }
    const zipBuffer = zip.toBuffer();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="hardened-code.zip"');
    res.send(zipBuffer);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create zip: ' + err.message });
  }
});

app.post('/api/harden/github/push', async (req, res) => {
  const { repoUrl, patches, token, branch, commitMessage } = req.body;
  if (!repoUrl) {
    return res.status(400).json({ error: 'Repository URL is required.' });
  }
  if (!lastHardenResult) {
    return res.status(400).json({ error: 'Run hardening analysis first.' });
  }

  const selectedIndices = Array.isArray(patches) ? patches.map(Number) : [];
  const targetBranch = branch || 'main';
  const msg = commitMessage || 'ShieldWall: Integrated Embedded WAF Firewall & Security Hardening';

  let authUrl = repoUrl;
  if (token && repoUrl.startsWith('https://')) {
    authUrl = repoUrl.replace('https://', `https://${encodeURIComponent(token)}@`);
  }

  const pushDir = path.join(uploadsDir, `gh-push-${Date.now()}`);
  try {
    let cloneCmd = `git clone --depth 1 "${authUrl}" "${pushDir}"`;
    if (branch) {
      cloneCmd = `git clone --depth 1 --branch "${branch}" "${authUrl}" "${pushDir}"`;
    }
    console.log(`Cloning repository for git push...`);
    execSync(cloneCmd, { timeout: 90000, stdio: 'pipe' });

    const { files, appliedFilesCount } = applyPatchesToMemory(selectedIndices);
    
    let writtenFilesCount = 0;
    for (const file of files) {
      const targetPath = path.join(pushDir, file.filename);
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.writeFileSync(targetPath, file.content, 'utf-8');
      writtenFilesCount++;
    }

    const opts = { cwd: pushDir, timeout: 60000, stdio: 'pipe' };
    execSync(`git config user.name "ShieldWall WAF"`, opts);
    execSync(`git config user.email "waf@shieldwall.security"`, opts);
    execSync(`git add .`, opts);

    const status = execSync(`git status --porcelain`, opts).toString().trim();
    if (!status) {
      cleanup(pushDir);
      return res.json({ message: 'No changes detected. Codebase is already hardened.' });
    }

    execSync(`git commit -m "${msg.replace(/"/g, '\\"')}"`, opts);
    execSync(`git push origin HEAD`, opts);

    cleanup(pushDir);
    res.json({
      message: `Successfully applied ${appliedFilesCount} security patches and committed/pushed to branch "${targetBranch}".`,
      appliedFilesCount,
      writtenFilesCount
    });
  } catch (e) {
    cleanup(pushDir);
    let errMsg = e.message;
    if (e.stderr) {
      errMsg += ' | ' + e.stderr.toString();
    }
    res.status(500).json({ error: 'GitHub push failed: ' + errMsg });
  }
});


// ═════════════════════════════════════════════════════════════════════════════
// API: Harden from Live URL (published website)
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/harden/url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required.' });
  let parsed;
  try { parsed = new (require('url').URL)(url); } catch {
    return res.status(400).json({ error: 'Invalid URL. Include http:// or https://' });
  }

  const http  = require('http');
  const https = require('https');
  const transport = parsed.protocol === 'https:' ? https : http;

  function probe(targetUrl, opts = {}) {
    return new Promise((resolve) => {
      let u;
      try { u = new (require('url').URL)(targetUrl); } catch { return resolve(null); }
      const req2 = transport.request({
        method: opts.method || 'GET',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: (u.pathname || '/') + (u.search || ''),
        headers: { 'User-Agent': 'ShieldWall/2.0', ...(opts.headers || {}) },
        timeout: 8000,
        rejectUnauthorized: false
      }, (r) => {
        const chunks = [];
        r.on('data', c => chunks.push(c));
        r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks).toString('utf-8').slice(0, 4000) }));
      });
      req2.on('error', () => resolve(null));
      req2.on('timeout', () => { req2.destroy(); resolve(null); });
      req2.end(opts.body || undefined);
    });
  }

  try {
    const base = `${parsed.protocol}//${parsed.host}`;
    const main = await probe(url, { followRedirects: true });
    if (!main) return res.status(502).json({ error: 'Could not reach the URL. Make sure it is publicly accessible.' });

    const h = main.headers;
    const isHttps = parsed.protocol === 'https:';

    // Detect stack from headers
    const powered = (h['x-powered-by'] || '').toLowerCase();
    const server  = (h['server'] || '').toLowerCase();
    const cookies = h['set-cookie'] || [];
    const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : String(cookies);

    let framework = 'Generic Web Server';
    let fwIcon = '🌐';
    let fwConf = 60;
    if (powered.includes('express'))    { framework = 'Node.js / Express'; fwIcon = '🟩'; fwConf = 95; }
    else if (powered.includes('php'))   { framework = 'PHP';               fwIcon = '🐘'; fwConf = 95; }
    else if (powered.includes('asp.net')){ framework = 'ASP.NET';          fwIcon = '💜'; fwConf = 95; }
    else if (server.includes('nginx'))  { framework = 'Nginx';             fwIcon = '🟢'; fwConf = 80; }
    else if (server.includes('apache')) { framework = 'Apache';            fwIcon = '🪶'; fwConf = 80; }
    else if (server.includes('cloudflare')) { framework = 'Cloudflare CDN'; fwIcon = '🟠'; fwConf = 85; }
    else if (cookieStr.toLowerCase().includes('phpsessid')) { framework = 'PHP'; fwIcon = '🐘'; fwConf = 90; }
    else if (cookieStr.toLowerCase().includes('laravel')) { framework = 'Laravel (PHP)'; fwIcon = '🔴'; fwConf = 90; }
    else if (cookieStr.toLowerCase().includes('django')) { framework = 'Django (Python)'; fwIcon = '🐍'; fwConf = 90; }
    else if (cookieStr.toLowerCase().includes('rails')) { framework = 'Ruby on Rails'; fwIcon = '💎'; fwConf = 90; }

    // Run probes in parallel
    const [envProbe, gitProbe, adminProbe, phpinfoProbe, corsProbe] = await Promise.all([
      probe(`${base}/.env`),
      probe(`${base}/.git/config`),
      probe(`${base}/admin`),
      probe(`${base}/phpinfo.php`),
      probe(url, { headers: { 'Origin': 'https://evil-attacker.com' } })
    ]);

    const patches = [];
    const missing  = (hname) => !h[hname];

    const addHeaderPatch = (title, header, value, severity, desc) => {
      patches.push({
        type: 'server_config',
        title,
        filename: 'server-config-remediation.md',
        severity,
        description: desc,
        original: '',
        patched: `# ${title}\n\nAdd the following header to your server configuration:\n\n\`\`\`\n${header}: ${value}\n\`\`\`\n\n**Nginx:** Add inside \`server {}\` block\n\`\`\`nginx\nadd_header ${header} "${value}" always;\n\`\`\`\n\n**Apache (.htaccess):**\n\`\`\`apache\nHeader always set ${header} "${value}"\n\`\`\`\n\n**Express.js:**\n\`\`\`js\napp.use((req, res, next) => { res.setHeader('${header}', '${value}'); next(); });\n\`\`\`\n`
      });
    };

    if (missing('content-security-policy'))
      addHeaderPatch('Add Content-Security-Policy', 'Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'", 'High',
        "No CSP header found. This leaves the site vulnerable to XSS and clickjacking.");
    if (missing('x-frame-options'))
      addHeaderPatch('Add X-Frame-Options', 'X-Frame-Options', 'DENY', 'Medium',
        "No X-Frame-Options header. The site can be embedded in iframes, enabling clickjacking.");
    if (missing('x-content-type-options'))
      addHeaderPatch('Add X-Content-Type-Options', 'X-Content-Type-Options', 'nosniff', 'Low',
        "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses.");
    if (missing('referrer-policy'))
      addHeaderPatch('Add Referrer-Policy', 'Referrer-Policy', 'strict-origin-when-cross-origin', 'Low',
        "No Referrer-Policy. Sensitive URL parameters may leak to third-party sites.");
    if (isHttps && missing('strict-transport-security'))
      addHeaderPatch('Add HSTS', 'Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload', 'High',
        "HTTPS site has no HSTS header. Users are vulnerable to SSL stripping attacks.");
    if (missing('permissions-policy'))
      addHeaderPatch('Add Permissions-Policy', 'Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()', 'Info',
        "No Permissions-Policy. Browser features like camera/mic/location are unrestricted.");

    // Server version disclosure
    if (h['server'] && /[\d.]/.test(h['server'])) {
      patches.push({
        type: 'server_config', title: 'Hide Server Version', filename: 'server-config-remediation.md',
        severity: 'Low',
        description: `Server header exposes version: "${h['server']}". Attackers can target known CVEs.`,
        original: '', patched: `# Hide Server Version\n\nYour Server header reveals: \`${h['server']}\`\n\n**Nginx:**\n\`\`\`nginx\nserver_tokens off;\n\`\`\`\n\n**Apache:**\n\`\`\`apache\nServerTokens Prod\nServerSignature Off\n\`\`\`\n`
      });
    }

    // Exposed .env
    if (envProbe && envProbe.status === 200 && envProbe.body.includes('=')) {
      patches.push({
        type: 'server_config', title: 'CRITICAL: .env File Exposed Publicly!', filename: 'urgent-security-fixes.md',
        severity: 'Critical',
        description: 'The .env file is publicly accessible. This exposes database credentials, API keys, and other secrets.',
        original: '', patched: `# URGENT: .env File Exposed\n\nYour .env file is publicly accessible at \`${base}/.env\`\n\n**Immediate steps:**\n1. Revoke and rotate ALL credentials in your .env\n2. Block access in Nginx:\n\`\`\`nginx\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}\n\`\`\`\n\n3. Apache (.htaccess):\n\`\`\`apache\n<Files ".env">\n    Order allow,deny\n    Deny from all\n</Files>\n\`\`\`\n`
      });
    }

    // Exposed .git
    if (gitProbe && gitProbe.status === 200 && gitProbe.body.includes('[core]')) {
      patches.push({
        type: 'server_config', title: 'CRITICAL: .git Directory Exposed!', filename: 'urgent-security-fixes.md',
        severity: 'Critical',
        description: 'The .git directory is publicly accessible. Attackers can download your entire source code.',
        original: '', patched: `# URGENT: .git Directory Exposed\n\nYour .git directory is accessible at \`${base}/.git/\`\n\n**Nginx:**\n\`\`\`nginx\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}\n\`\`\`\n\n**Apache (.htaccess):**\n\`\`\`apache\nRedirectMatch 404 /\\.git\n\`\`\`\n`
      });
    }

    // phpinfo
    if (phpinfoProbe && phpinfoProbe.status === 200 && phpinfoProbe.body.toLowerCase().includes('phpinfo')) {
      patches.push({
        type: 'server_config', title: 'phpinfo.php Exposed', filename: 'urgent-security-fixes.md',
        severity: 'High',
        description: 'phpinfo.php is publicly accessible, exposing your PHP configuration, installed modules, and environment variables.',
        original: '', patched: `# Remove phpinfo.php\n\nDelete the file from your server:\n\`\`\`bash\nrm /var/www/html/phpinfo.php\n\`\`\`\n\nOr block it via Nginx:\n\`\`\`nginx\nlocation = /phpinfo.php { deny all; return 404; }\n\`\`\`\n`
      });
    }

    // CORS
    if (corsProbe) {
      const acao = corsProbe.headers['access-control-allow-origin'];
      if (acao === '*' || acao === 'https://evil-attacker.com') {
        patches.push({
          type: 'server_config', title: 'CORS Misconfiguration', filename: 'server-config-remediation.md',
          severity: 'High',
          description: `CORS header is set to "${acao}". Cross-origin requests from any domain are permitted.`,
          original: '', patched: `# Fix CORS Misconfiguration\n\nReplace wildcard or reflected origin with a strict allowlist:\n\n**Nginx:**\n\`\`\`nginx\nif ($http_origin ~* "^https://(yourdomain\\.com|app\\.yourdomain\\.com)$") {\n    add_header Access-Control-Allow-Origin $http_origin;\n}\n\`\`\`\n\n**Express.js:**\n\`\`\`js\nconst cors = require('cors');\napp.use(cors({ origin: ['https://yourdomain.com'] }));\n\`\`\`\n`
        });
      }
    }

    // Cookie checks
    if (cookies.length) {
      const ckArr = Array.isArray(cookies) ? cookies : [cookies];
      for (const ck of ckArr) {
        const issues = [];
        if (!ck.toLowerCase().includes('httponly')) issues.push('HttpOnly is missing');
        if (!ck.toLowerCase().includes('secure') && isHttps) issues.push('Secure flag is missing');
        if (!ck.toLowerCase().includes('samesite')) issues.push('SameSite is missing');
        if (issues.length) {
          const name = ck.split('=')[0];
          patches.push({
            type: 'server_config', title: `Insecure Cookie: ${name}`, filename: 'server-config-remediation.md',
            severity: 'Medium',
            description: `Cookie "${name}" is missing: ${issues.join(', ')}.`,
            original: '', patched: `# Fix Cookie Security: ${name}\n\nIssues: ${issues.join(', ')}\n\n**Express.js:**\n\`\`\`js\nres.cookie('${name}', value, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'Strict'\n});\n\`\`\`\n\n**PHP:**\n\`\`\`php\nsetcookie('${name}', $value, [\n  'httponly' => true,\n  'secure'   => true,\n  'samesite' => 'Strict',\n]);\n\`\`\`\n`
          });
          break;
        }
      }
    }

    const detection = {
      framework,
      confidence: fwConf,
      serverHeader: h['server'] || null,
      poweredBy: h['x-powered-by'] || null,
      isHttps,
      icon: fwIcon
    };

    lastHardenResult = { detection, patches, files: [] };
    uploadedFiles = [];

    res.json({
      detection,
      patches,
      scannedUrl: url,
      status: 'complete'
    });
  } catch (e) {
    res.status(500).json({ error: 'URL hardening failed: ' + e.message });
  }
});



app.post('/api/rate-limiter/config', (req, res) => {
  const { windowMs, maxRequests, banThreshold, banDurationMs } = req.body;
  if (windowMs)      config.rateLimiter.windowMs      = Number(windowMs);
  if (maxRequests)   config.rateLimiter.maxRequests   = Number(maxRequests);
  if (banThreshold)  config.rateLimiter.banThreshold  = Number(banThreshold);
  if (banDurationMs) config.rateLimiter.banDurationMs = Number(banDurationMs);
  if (rateLimiterMod && rateLimiterMod.RateLimiter) {
    rateLimiter = new rateLimiterMod.RateLimiter(config.rateLimiter);
  }
  saveConfig();
  res.json({ message: 'Rate limiter updated.', config: config.rateLimiter });
});

// ═════════════════════════════════════════════════════════════════════════════
// API: WAF Domain Management
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/waf/domains', (req, res) => {
  if (!domainRegistry) return res.status(500).json({ error: 'Domain registry not loaded.' });
  res.json(domainRegistry.list());
});

app.post('/api/waf/domains', (req, res) => {
  if (!domainRegistry) return res.status(500).json({ error: 'Domain registry not loaded.' });
  const { domain, origin, rules } = req.body;
  if (!domain || !origin) return res.status(400).json({ error: 'domain and origin are required.' });
  try {
    const entry = domainRegistry.register(domain, origin, rules || {});
    if (wafProxyHandler === null && wafProxyCore && domainRegistry) {
      wafProxyHandler = wafProxyCore.createWafProxyHandler({
        wafEngine, domainRegistry, rateLimiter, wafLogs: wafProxyLogs, maxLogs: 2000
      });
    }
    res.json({ message: `${domain} registered. Point your DNS CNAME to this server.`, entry });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/waf/domains/:domain', (req, res) => {
  if (!domainRegistry) return res.status(500).json({ error: 'Domain registry not loaded.' });
  const domain = decodeURIComponent(req.params.domain);
  domainRegistry.remove(domain);
  res.json({ message: `${domain} removed from WAF.` });
});

app.get('/api/waf/logs', (req, res) => {
  let result = [...wafProxyLogs];
  if (req.query.domain) result = result.filter(l => l.host === req.query.domain);
  if (req.query.blocked === 'true') result = result.filter(l => l.blocked);
  res.json(result.slice(0, parseInt(req.query.limit || '200', 10)));
});

// ─── WAF Firewall Test ─────────────────────────────────────────────────────
app.post('/api/waf/test/:domain', (req, res) => {
  if (!domainRegistry) return res.status(500).json({ error: 'Domain registry not loaded.' });
  if (!wafEngine)      return res.status(500).json({ error: 'WAF engine not loaded.' });

  const domain = decodeURIComponent(req.params.domain);
  const entry  = domainRegistry.lookup(domain);
  if (!entry) return res.status(404).json({ error: `Domain "${domain}" is not registered.` });

  const tests = [
    {
      name: 'Clean Request',
      expectBlock: false,
      req: { url: '/', method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'SQL Injection',
      expectBlock: true,
      req: { url: "/search?q=1' OR '1'='1", method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'Cross-Site Scripting (XSS)',
      expectBlock: true,
      req: { url: '/comment?text=<script>alert(document.cookie)</script>', method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'Path Traversal',
      expectBlock: true,
      req: { url: '/files?path=../../../etc/passwd', method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'Command Injection',
      expectBlock: true,
      req: { url: '/api?cmd=; cat /etc/passwd', method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'Remote File Inclusion',
      expectBlock: true,
      req: { url: '/page?file=http://evil.com/shell.php', method: 'GET', headers: { host: domain, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' } },
      body: ''
    },
    {
      name: 'Bot / Scanner Detection',
      expectBlock: true,
      req: { url: '/', method: 'GET', headers: { host: domain, 'user-agent': 'sqlmap/1.6' } },
      body: ''
    }
  ];

  const results = tests.map(t => {
    let blocked = false;
    let ruleId  = null;
    let category = null;

    // Check bot detection first
    if (t.req.headers['user-agent'] && entry.rules.botDetection && wafEngine.checkBotSignature) {
      const bot = wafEngine.checkBotSignature(t.req.headers['user-agent']);
      if (bot.isBot) {
        blocked  = true;
        category = 'Bot/Scanner';
        ruleId   = bot.botName;
      }
    }

    // Check WAF rules
    if (!blocked && wafEngine.inspectRequest) {
      const result = wafEngine.inspectRequest(t.req, t.body, entry.rules);
      if (result.blocked) {
        blocked  = true;
        ruleId   = result.ruleId;
        category = result.category;
      }
    }

    const pass = t.expectBlock ? blocked : !blocked;

    return {
      name: t.name,
      expectBlock: t.expectBlock,
      blocked,
      ruleId,
      category,
      pass
    };
  });

  const passCount = results.filter(r => r.pass).length;

  res.json({
    domain,
    total: tests.length,
    passed: passCount,
    failed: tests.length - passCount,
    grade: passCount === tests.length ? 'A+' : passCount >= tests.length - 1 ? 'A' : passCount >= tests.length - 2 ? 'B' : 'F',
    results
  });
});

app.get('/api/waf/stats', (req, res) => {
  if (!domainRegistry) return res.json([]);
  res.json(domainRegistry.list());
});

app.post('/api/scan/configs', (req, res) => {
  if (!configGenerator) return res.status(500).json({ error: 'Config generator not loaded.' });
  const { url, findings } = req.body;
  if (!findings || !Array.isArray(findings)) return res.status(400).json({ error: 'findings array required.' });
  let domain = 'yourdomain.com';
  try { domain = new URL(url || 'https://yourdomain.com').hostname; } catch {}
  res.json({
    nginx:       configGenerator.generateNginxConfig(domain, findings),
    apache:      configGenerator.generateApacheConfig(domain, findings),
    cloudflare:  configGenerator.generateCloudflareHeaders(domain, findings),
    html:        configGenerator.generateHtmlMetaTags(domain, findings),
    modsecurity: configGenerator.generateModSecurityRules(domain, findings),
  });
});

app.post('/api/waf/domains/:domain/rules', (req, res) => {
  if (!domainRegistry) return res.status(500).json({ error: 'Domain registry not loaded.' });
  const domain = decodeURIComponent(req.params.domain);
  const entry  = domainRegistry.lookup(domain);
  if (!entry) return res.status(404).json({ error: 'Domain not found.' });
  domainRegistry.register(domain, entry.origin, { ...entry.rules, ...req.body });
  res.json({ message: 'Rules updated.', entry: domainRegistry.lookup(domain) });
});

// ═════════════════════════════════════════════════════════════════════════════
// SHIELD — One-Line Middleware Protection API
// ═════════════════════════════════════════════════════════════════════════════

// ── Shield: check a request ──────────────────────────────────────────────────
// Any server can POST request metadata here and get a block/allow decision.
app.post('/api/shield/check', (req, res) => {
  // Allow cross-origin calls from any protected site
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-Shield-Key');

  if (!wafEngine) return res.status(500).json({ error: 'WAF engine not loaded.' });

  const { domain, url, method, headers, body, ip } = req.body;
  if (!domain || !url) return res.status(400).json({ error: 'domain and url are required.' });

  // Verify domain is registered
  if (domainRegistry) {
    const entry = domainRegistry.lookup(domain);
    if (!entry) return res.status(403).json({ error: `Domain "${domain}" is not registered. Register it first at the ShieldWall dashboard.` });
  }

  // Build a mock request object for the WAF engine
  const mockReq = {
    url:     url || '/',
    method:  method || 'GET',
    headers: headers || {}
  };

  const entry = domainRegistry ? domainRegistry.lookup(domain) : null;
  const rules = entry?.rules || { sqli: true, xss: true, pathTraversal: true, rfiLfi: true, commandInjection: true, protocolViolation: true, botDetection: true };

  let blocked  = false;
  let category = null;
  let ruleId   = null;
  let detail   = null;

  // Bot detection
  const ua = (headers && headers['user-agent']) || '';
  if (rules.botDetection && wafEngine.checkBotSignature) {
    const bot = wafEngine.checkBotSignature(ua);
    if (bot.isBot) {
      blocked  = true;
      category = 'Bot/Scanner';
      ruleId   = bot.botName;
      detail   = `Detected scanner: ${bot.botName}`;
    }
  }

  // WAF rule inspection
  if (!blocked && wafEngine.inspectRequest) {
    const result = wafEngine.inspectRequest(mockReq, body || '', rules);
    if (result.blocked) {
      blocked  = true;
      category = result.category;
      ruleId   = result.ruleId;
      detail   = result.payload;
    }
  }

  // Rate limiting by IP
  if (!blocked && rateLimiter?.check && ip) {
    const rl = rateLimiter.check(ip);
    if (rl?.blocked) {
      blocked  = true;
      category = 'Rate Limited';
      detail   = 'Too many requests from this IP';
    }
  }

  // Log the check
  if (entry && domainRegistry) {
    domainRegistry.incrementStat(domain, blocked ? 'blocked' : 'allowed');
  }
  const logEntry = {
    id: Date.now() + Math.random().toString(36).slice(2),
    host: domain, ip: ip || req.ip, method: method || 'GET',
    path: url, timestamp: Date.now(), blocked, category
  };
  wafProxyLogs.unshift(logEntry);
  if (wafProxyLogs.length > 2000) wafProxyLogs.pop();

  res.json({
    action:   blocked ? 'BLOCK' : 'ALLOW',
    blocked,
    category: category || null,
    ruleId:   ruleId || null,
    detail:   detail || null,
    ref:      'SW-' + Date.now()
  });
});

// CORS preflight for shield check
app.options('/api/shield/check', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-Shield-Key');
  res.status(204).end();
});

// ── Shield: get middleware code for a domain ─────────────────────────────────
app.get('/api/shield/middleware/:domain', (req, res) => {
  const domain = decodeURIComponent(req.params.domain);
  const shieldUrl = `https://adityax26-waf.hf.space/api/shield/check`;

  const code = {
    nodejs: `// ShieldWall WAF Protection — Add this BEFORE your routes
const http = require('https');

function shieldWall(req, res, next) {
  const data = JSON.stringify({
    domain: '${domain}',
    url: req.url,
    method: req.method,
    headers: { 'user-agent': req.headers['user-agent'] || '' },
    body: '',
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
  });
  const r = http.request('${shieldUrl}', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
  }, (resp) => {
    let body = '';
    resp.on('data', c => body += c);
    resp.on('end', () => {
      try {
        const result = JSON.parse(body);
        if (result.blocked) {
          res.status(403).json({ error: 'Blocked by ShieldWall WAF', category: result.category, ruleId: result.ruleId });
        } else {
          next();
        }
      } catch { next(); }
    });
  });
  r.on('error', () => next()); // fail-open: if ShieldWall is unreachable, allow the request
  r.write(data);
  r.end();
}

// Usage: app.use(shieldWall);`,

    python: `# ShieldWall WAF Protection — Add this to your Flask/Django app
import requests, functools
from flask import request, jsonify, abort

SHIELD_URL = '${shieldUrl}'
SHIELD_DOMAIN = '${domain}'

def shieldwall_protect(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            r = requests.post(SHIELD_URL, json={
                'domain': SHIELD_DOMAIN,
                'url': request.path + ('?' + request.query_string.decode() if request.query_string else ''),
                'method': request.method,
                'headers': {'user-agent': request.headers.get('User-Agent', '')},
                'body': request.get_data(as_text=True),
                'ip': request.remote_addr
            }, timeout=2)
            result = r.json()
            if result.get('blocked'):
                return jsonify(error='Blocked by ShieldWall WAF', category=result.get('category')), 403
        except:
            pass  # fail-open
        return f(*args, **kwargs)
    return wrapper

# Usage: @app.before_request followed by shieldwall_protect
# Or decorate individual routes: @shieldwall_protect`,

    php: `<?php
// ShieldWall WAF Protection — Add this at the top of your PHP entry point
function shieldwall_check() {
    $data = json_encode([
        'domain' => '${domain}',
        'url'    => $_SERVER['REQUEST_URI'],
        'method' => $_SERVER['REQUEST_METHOD'],
        'headers'=> ['user-agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''],
        'body'   => file_get_contents('php://input'),
        'ip'     => $_SERVER['REMOTE_ADDR']
    ]);
    $ch = curl_init('${shieldUrl}');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $data,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 2
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);
    if ($resp) {
        $result = json_decode($resp, true);
        if (!empty($result['blocked'])) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Blocked by ShieldWall WAF', 'category' => $result['category']]);
            exit;
        }
    }
}
shieldwall_check();
?>`,

    script_tag: `<!-- ShieldWall WAF Protection — Add this to your HTML <head> -->
<script src="https://adityax26-waf.hf.space/shield.js?domain=${encodeURIComponent(domain)}"></script>`
  };

  res.json(code);
});

// ── Shield: embeddable client-side protection script ─────────────────────────
app.get('/shield.js', (req, res) => {
  const domain = req.query.domain || '';
  res.set('Content-Type', 'application/javascript');
  res.set('Cache-Control', 'public, max-age=3600');
  res.set('Access-Control-Allow-Origin', '*');

  res.send(`(function(){
  'use strict';
  var SHIELD_URL = '${req.protocol}://${req.get('host')}/api/shield/check';
  var DOMAIN = '${domain.replace(/'/g, "\\'")}';
  if (!DOMAIN) return;

  // ── Block inline XSS attempts ──
  var meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = "script-src 'self' 'unsafe-inline' https://adityax26-waf.hf.space; object-src 'none';";
  document.head.appendChild(meta);

  // ── Check current page load ──
  var data = JSON.stringify({
    domain: DOMAIN,
    url: location.pathname + location.search,
    method: 'GET',
    headers: { 'user-agent': navigator.userAgent },
    body: '',
    ip: ''
  });

  var xhr = new XMLHttpRequest();
  xhr.open('POST', SHIELD_URL, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onload = function() {
    try {
      var r = JSON.parse(xhr.responseText);
      if (r.blocked) {
        document.title = 'Blocked by ShieldWall WAF';
        document.body.innerHTML = '<div style="font-family:Inter,sans-serif;text-align:center;padding:60px;background:#0d1117;color:#e6edf3;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center">'
          + '<div style="font-size:64px;margin-bottom:16px">\\u{1F6E1}\\uFE0F</div>'
          + '<h1 style="margin:0 0 8px;font-size:1.5rem">Blocked by ShieldWall WAF</h1>'
          + '<p style="color:#8b949e;margin:0">Category: ' + (r.category||'unknown') + '</p>'
          + '<p style="color:#656d76;margin-top:8px;font-size:0.8rem">Ref: ' + (r.ref||'') + '</p></div>';
      }
    } catch(e) {}
  };
  xhr.send(data);

  // ── Intercept form submissions ──
  document.addEventListener('submit', function(e) {
    var form = e.target;
    var formData = new FormData(form);
    var body = '';
    formData.forEach(function(v, k) { body += k + '=' + encodeURIComponent(v) + '&'; });

    var check = new XMLHttpRequest();
    check.open('POST', SHIELD_URL, false); // synchronous to block submission
    check.setRequestHeader('Content-Type', 'application/json');
    try {
      check.send(JSON.stringify({
        domain: DOMAIN,
        url: form.action || location.pathname,
        method: form.method || 'POST',
        headers: { 'user-agent': navigator.userAgent },
        body: body,
        ip: ''
      }));
      var r = JSON.parse(check.responseText);
      if (r.blocked) {
        e.preventDefault();
        alert('ShieldWall WAF blocked this submission:\\n' + (r.category||'Threat detected'));
      }
    } catch(ex) {}
  }, true);

  // ── Monitor URL for injection attempts ──
  if (location.search) {
    var checkUrl = new XMLHttpRequest();
    checkUrl.open('POST', SHIELD_URL, true);
    checkUrl.setRequestHeader('Content-Type', 'application/json');
    checkUrl.onload = function() {
      try {
        var r = JSON.parse(checkUrl.responseText);
        if (r.blocked) {
          document.title = 'Blocked by ShieldWall WAF';
          document.body.innerHTML = '<div style="font-family:Inter,sans-serif;text-align:center;padding:60px;background:#0d1117;color:#e6edf3;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center">'
            + '<div style="font-size:64px;margin-bottom:16px">\\u{1F6E1}\\uFE0F</div>'
            + '<h1 style="margin:0 0 8px;font-size:1.5rem">Blocked by ShieldWall WAF</h1>'
            + '<p style="color:#8b949e;margin:0">Malicious URL parameter detected</p>'
            + '<p style="color:#8b949e;margin:4px 0">Category: ' + (r.category||'unknown') + '</p>'
            + '<p style="color:#656d76;margin-top:8px;font-size:0.8rem">Ref: ' + (r.ref||'') + '</p></div>';
        }
      } catch(e) {}
    };
    checkUrl.send(JSON.stringify({
      domain: DOMAIN,
      url: location.pathname + location.search,
      method: 'GET',
      headers: { 'user-agent': navigator.userAgent },
      body: '',
      ip: ''
    }));
  }

  console.log('%c\\u{1F6E1}\\uFE0F ShieldWall WAF Protection Active', 'color:#3fb950;font-weight:bold;font-size:14px');
})();
`);
});

// ═════════════════════════════════════════════════════════════════════════════
// Start Server
// ═════════════════════════════════════════════════════════════════════════════

app.listen(DASHBOARD_PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║        🛡️  SHIELDWALL SECURITY PLATFORM  🛡️          ║');
  console.log('║                                                      ║');
  console.log(`║  Dashboard : http://localhost:${DASHBOARD_PORT}                   ║`);
  console.log(`║  WAF Proxy : Port ${config.proxyPort} (set target URL first)      ║`);
  console.log('║                                                      ║');
  console.log('║  Modules:                                            ║');
  console.log(`║    WAF Engine      ${wafEngine       ? '✅' : '❌'}                              ║`);
  console.log(`║    Proxy Server    ${proxyServer     ? '✅' : '❌'}                              ║`);
  console.log(`║    Rate Limiter    ${rateLimiter     ? '✅' : '❌'}                              ║`);
  console.log(`║    URL Scanner     ${scanner         ? '✅' : '❌'}                              ║`);
  console.log(`║    Code Analyzer   ${codeAnalyzer    ? '✅' : '❌'}                              ║`);
  console.log(`║    Code Hardener   ${codeHardener    ? '✅' : '❌'}                              ║`);
  console.log(`║    Report Generator${reportGenerator ? '✅' : '❌'}                              ║`);
  console.log(`║    Domain Registry ${domainRegistry  ? '✅' : '❌'}                              ║`);
  console.log(`║    WAF Proxy Core  ${wafProxyCore    ? '✅' : '❌'}                              ║`);
  console.log('╚══════════════════════════════════════════════════════╝');
  if (domainRegistry) {
    const domains = domainRegistry.list();
    if (domains.length) {
      console.log(`\n🌐 Protected domains (${domains.length}):`);
      domains.forEach(d => console.log(`   • ${d.domain} → ${d.origin}`));
    }
  }
  console.log('');
});
