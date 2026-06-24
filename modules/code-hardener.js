/**
 * ShieldWall Code Hardener Module
 * Detects frameworks and generates security patches
 */

const FRAMEWORK_INDICATORS = {
  express: {
    files: ['package.json', 'app.js', 'server.js', 'index.js'],
    patterns: [
      /require\s*\(\s*['"]express['"]\s*\)/,
      /from\s+['"]express['"]/,
      /express\(\)/,
      /app\.listen\s*\(/,
      /app\.(get|post|put|delete|use)\s*\(/
    ],
    deps: ['express']
  },
  flask: {
    files: ['app.py', 'wsgi.py', 'requirements.txt', 'config.py'],
    patterns: [
      /from\s+flask\s+import/,
      /import\s+flask/i,
      /Flask\s*\(\s*__name__\s*\)/,
      /@app\.route\s*\(/,
      /app\.run\s*\(/
    ],
    deps: ['flask', 'Flask']
  },
  django: {
    files: ['manage.py', 'settings.py', 'urls.py', 'wsgi.py', 'asgi.py'],
    patterns: [
      /django\.conf/,
      /INSTALLED_APPS/,
      /MIDDLEWARE/,
      /urlpatterns/,
      /from\s+django/
    ],
    deps: ['django', 'Django']
  },
  html: {
    files: ['index.html', 'main.html', 'home.html'],
    patterns: [
      /<!DOCTYPE\s+html>/i,
      /<html[\s>]/i,
      /<head[\s>]/i,
      /<body[\s>]/i
    ],
    deps: []
  },
  nextjs: {
    files: ['next.config.js', 'next.config.mjs', 'next.config.ts', 'tsconfig.json'],
    patterns: [
      /next\/router/,
      /next\/link/,
      /next\/head/,
      /next\/image/,
      /from\s+['"]next['"]/,
      /import\s+\w+\s+from\s+['"]next/,
      /require\s*\(\s*['"]next['"]\s*\)/
    ],
    deps: ['next']
  }
};

function detectFramework(files) {
  const scores = { express: 0, flask: 0, django: 0, html: 0, nextjs: 0 };
  const indicators = { express: [], flask: [], django: [], html: [], nextjs: [] };

  for (const file of files) {
    const fname = file.filename.toLowerCase();
    const content = file.content || '';

    for (const [fw, config] of Object.entries(FRAMEWORK_INDICATORS)) {
      // Check filenames
      for (const expectedFile of config.files) {
        if (fname === expectedFile || fname.endsWith('/' + expectedFile)) {
          scores[fw] += 2;
          indicators[fw].push(`Found file: ${file.filename}`);
        }
      }

      // Check content patterns
      for (const pattern of config.patterns) {
        if (pattern.test(content)) {
          scores[fw] += 3;
          indicators[fw].push(`Pattern match in ${file.filename}: ${pattern.source.substring(0, 50)}`);
        }
      }

      // Check dependencies
      if (fname === 'package.json' || fname.endsWith('/package.json')) {
        try {
          const pkg = JSON.parse(content);
          const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
          for (const dep of config.deps) {
            if (allDeps[dep]) {
              scores[fw] += 5;
              indicators[fw].push(`Found dependency: ${dep} in package.json`);
            }
          }
        } catch (e) { /* ignore parse errors */ }
      }

      if (fname === 'requirements.txt' || fname.endsWith('/requirements.txt')) {
        for (const dep of config.deps) {
          if (content.toLowerCase().includes(dep.toLowerCase())) {
            scores[fw] += 5;
            indicators[fw].push(`Found dependency: ${dep} in requirements.txt`);
          }
        }
      }
    }
  }

  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const topFw = sorted[0];

  if (topFw[1] === 0) {
    return { framework: 'unknown', confidence: 0, indicators: ['No framework indicators found'] };
  }

  const maxPossible = Math.max(...Object.values(scores)) || 1;
  const confidence = Math.min(Math.round((topFw[1] / (maxPossible + 10)) * 100), 99);

  return {
    framework: topFw[0],
    confidence,
    indicators: indicators[topFw[0]]
  };
}

function generatePatches(files, framework) {
  const patches = [];

  switch (framework) {
    case 'express':
      patches.push(...generateExpressPatches(files));
      break;
    case 'flask':
      patches.push(...generateFlaskPatches(files));
      break;
    case 'django':
      patches.push(...generateDjangoPatches(files));
      break;
    case 'html':
      patches.push(...generateHtmlPatches(files));
      break;
    case 'nextjs':
      patches.push(...generateNextJsPatches(files));
      break;
    default:
      patches.push({
        filename: 'N/A',
        description: 'Unknown framework — unable to generate automatic patches. Manual security review recommended.',
        severity: 'Info',
        original: '',
        patched: '',
        type: 'add_config'
      });
  }

  return patches;
}

function generateExpressPatches(files) {
  const patches = [];
  const hasFile = (name) => files.some(f => f.filename.toLowerCase().includes(name));
  const getFile = (name) => files.find(f => f.filename.toLowerCase().includes(name));
  const contentIncludes = (content, str) => content && content.includes(str);

  // Find main server file
  const serverFile = getFile('server.js') || getFile('app.js') || getFile('index.js');
  const pkgFile = getFile('package.json');
  const serverContent = serverFile ? serverFile.content : '';

  // 0. Embedded WAF Firewall Middleware
  if (!contentIncludes(serverContent, 'shieldwall-waf')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Embed ShieldWall WAF reverse firewall middleware directly into your Express application to inspect query params, bodies, and User-Agents without needing an external proxy.',
      severity: 'Critical',
      original: `const app = express();`,
      patched: `const app = express();\nconst shieldwallWaf = require('./shieldwall-waf');\napp.use(shieldwallWaf);`,
      type: 'modify_code'
    });

    patches.push({
      filename: 'shieldwall-waf.js',
      description: 'Create ShieldWall self-contained request firewall middleware.',
      severity: 'Critical',
      original: '',
      patched: `const RULES = {
  sqli: [
    /[\\'\"][ \\t]*or[ \\t]+/i,
    /union[ \\t]+select/i,
    /select[ \\t]+.*[ \\t]+from/i,
    /insert[ \\t]+into/i,
    /update[ \\t]+.*[ \\t]+set/i,
    /delete[ \\t]+from/i,
    /drop[ \\t]+table/i,
    /exec\\([^\\)]*\\)/i
  ],
  xss: [
    /<script[^>]*>/i,
    /javascript:/i,
    /onmouseover=/i,
    /onerror=/i,
    /onload=/i,
    /alert\\([^\\)]*\\)/i,
    /<iframe[^>]*>/i
  ],
  traversal: [
    /\\.\\.\\//,
    /\\/etc\\/passwd/i,
    /\\/win\\.ini/i,
    /boot\\.ini/i
  ],
  cmdi: [
    /[;&|][ \\t]*(\\/bin\\/)?(sh|bash|cmd|powershell)/i,
    /exec\\s*\\([^\\)]*\\)/i,
    /system\\s*\\([^\\)]*\\)/i
  ],
  bots: [
    /sqlmap/i,
    /nikto/i,
    /burpsuite/i,
    /nmap/i,
    /w3af/i
  ]
};

module.exports = function(req, res, next) {
  const inspectString = (str) => {
    if (!str) return false;
    for (const [category, patterns] of Object.entries(RULES)) {
      for (const pattern of patterns) {
        if (pattern.test(str)) {
          console.warn('[ShieldWall Embedded WAF] Blocked request matching category: ' + category);
          return true;
        }
      }
    }
    return false;
  };

  if (inspectString(req.url) || inspectString(decodeURIComponent(req.originalUrl || ''))) {
    return res.status(403).send('<h1>Blocked by ShieldWall Embedded WAF</h1>');
  }

  if (req.body) {
    const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    if (inspectString(bodyStr)) {
      return res.status(403).send('<h1>Blocked by ShieldWall Embedded WAF</h1>');
    }
  }

  const ua = req.headers['user-agent'] || '';
  for (const pattern of RULES.bots) {
    if (pattern.test(ua)) {
      console.warn('[ShieldWall Embedded WAF] Blocked bot User-Agent: ' + ua);
      return res.status(403).send('<h1>Blocked by ShieldWall Embedded WAF</h1>');
    }
  }

  next();
};`,
      type: 'create_file'
    });
  }


  // 1. Helmet middleware
  if (!contentIncludes(serverContent, 'helmet')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Add Helmet middleware for comprehensive HTTP security headers (X-Frame-Options, CSP, HSTS, XSS Protection, etc.)',
      severity: 'High',
      original: `const express = require('express');\nconst app = express();`,
      patched: `const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\n\napp.use(helmet());`,
      type: 'modify_code'
    });

    if (pkgFile) {
      const pkg = safeParse(pkgFile.content);
      if (pkg && !(pkg.dependencies || {})['helmet']) {
        patches.push({
          filename: 'package.json',
          description: 'Add helmet dependency',
          severity: 'High',
          original: `"dependencies": {`,
          patched: `"dependencies": {\n    "helmet": "^7.1.0",`,
          type: 'add_dependency'
        });
      }
    }
  }

  // 2. Rate limiting
  if (!contentIncludes(serverContent, 'rate-limit') && !contentIncludes(serverContent, 'rateLimit')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Add express-rate-limit to prevent brute force and DDoS attacks. Limits each IP to 100 requests per 15 minutes.',
      severity: 'High',
      original: `const app = express();`,
      patched: `const rateLimit = require('express-rate-limit');\nconst app = express();\n\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  standardHeaders: true,\n  legacyHeaders: false,\n  message: { error: 'Too many requests, please try again later.' }\n});\napp.use(limiter);`,
      type: 'modify_code'
    });
  }

  // 3. CSRF protection
  if (!contentIncludes(serverContent, 'csrf') && !contentIncludes(serverContent, 'csurf')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Add CSRF protection for state-changing requests (POST, PUT, DELETE). Generates and validates CSRF tokens.',
      severity: 'High',
      original: `// Middleware`,
      patched: `const crypto = require('crypto');\nfunction generateCsrfToken(req, res, next) {\n  if (!req.session) req.session = {};\n  if (!req.session.csrfToken) {\n    req.session.csrfToken = crypto.randomBytes(32).toString('hex');\n  }\n  res.locals.csrfToken = req.session.csrfToken;\n  next();\n}\nfunction validateCsrfToken(req, res, next) {\n  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {\n    const token = req.body._csrf || req.headers['x-csrf-token'];\n    if (!token || token !== req.session.csrfToken) {\n      return res.status(403).json({ error: 'Invalid CSRF token' });\n    }\n  }\n  next();\n}`,
      type: 'modify_code'
    });
  }

  // 4. Disable X-Powered-By
  if (!contentIncludes(serverContent, 'x-powered-by') && !contentIncludes(serverContent, 'disable') && !contentIncludes(serverContent, 'helmet')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Disable X-Powered-By header to prevent server technology fingerprinting.',
      severity: 'Medium',
      original: `const app = express();`,
      patched: `const app = express();\napp.disable('x-powered-by');`,
      type: 'modify_code'
    });
  }

  // 5. Request size limits
  if (!contentIncludes(serverContent, 'limit')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Add request body size limits to prevent large payload attacks and memory exhaustion.',
      severity: 'Medium',
      original: `app.use(express.json());`,
      patched: `app.use(express.json({ limit: '1mb' }));\napp.use(express.urlencoded({ extended: true, limit: '1mb' }));`,
      type: 'modify_code'
    });
  }

  // 6. Secure cookie settings
  if (contentIncludes(serverContent, 'cookie') && !contentIncludes(serverContent, 'httpOnly')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Set secure cookie options: httpOnly prevents JavaScript access, secure ensures HTTPS-only, sameSite prevents CSRF.',
      severity: 'Medium',
      original: `cookie: {`,
      patched: `cookie: {\n    httpOnly: true,\n    secure: process.env.NODE_ENV === 'production',\n    sameSite: 'strict',\n    maxAge: 24 * 60 * 60 * 1000,`,
      type: 'modify_code'
    });
  }

  // 7. CORS hardening
  if (contentIncludes(serverContent, "origin: '*'") || contentIncludes(serverContent, 'origin: "*"')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'CORS wildcard origin detected. Restrict to specific trusted domains to prevent cross-origin attacks.',
      severity: 'High',
      original: `origin: '*'`,
      patched: `origin: ['https://yourdomain.com', 'https://app.yourdomain.com']`,
      type: 'modify_code'
    });
  }

  // 8. Input validation
  if (!contentIncludes(serverContent, 'validator') && !contentIncludes(serverContent, 'sanitize')) {
    patches.push({
      filename: serverFile ? serverFile.filename : 'server.js',
      description: 'Add input validation utility function to sanitize user inputs across all routes.',
      severity: 'Medium',
      original: `// Routes`,
      patched: `function sanitizeInput(str) {\n  if (typeof str !== 'string') return str;\n  return str\n    .replace(/&/g, '&amp;')\n    .replace(/</g, '&lt;')\n    .replace(/>/g, '&gt;')\n    .replace(/"/g, '&quot;')\n    .replace(/'/g, '&#x27;')\n    .replace(/\\//g, '&#x2F;');\n}\n\n// Routes`,
      type: 'modify_code'
    });
  }

  return patches;
}

function generateFlaskPatches(files) {
  const patches = [];
  const getFile = (name) => files.find(f => f.filename.toLowerCase().includes(name));
  const appFile = getFile('app.py') || getFile('main.py') || getFile('__init__.py');
  const reqFile = getFile('requirements.txt');
  const content = appFile ? appFile.content : '';

  // 0. Embedded WAF Firewall Middleware
  if (!content.includes('shieldwall_waf')) {
    patches.push({
      filename: appFile ? appFile.filename : 'app.py',
      description: 'Embed ShieldWall WAF request inspector directly into Flask using a before_request handler to protect your app in any hosting environment.',
      severity: 'Critical',
      original: `app = Flask(__name__)`,
      patched: `app = Flask(__name__)\nfrom shieldwall_waf import shieldwall_waf\nshieldwall_waf(app)`,
      type: 'modify_code'
    });

    patches.push({
      filename: 'shieldwall_waf.py',
      description: 'Create ShieldWall Python request firewall module.',
      severity: 'Critical',
      original: '',
      patched: `import re
import urllib.parse
import json

RULES = {
    'sqli': [
        re.compile(r"['\\\"][ \\t]*or[ \\t]+", re.IGNORECASE),
        re.compile(r"union[ \\t]+select", re.IGNORECASE),
        re.compile(r"select[ \\t]+.*[ \\t]+from", re.IGNORECASE),
        re.compile(r"insert[ \\t]+into", re.IGNORECASE),
        re.compile(r"update[ \\t]+.*[ \\t]+set", re.IGNORECASE),
        re.compile(r"delete[ \\t]+from", re.IGNORECASE),
        re.compile(r"drop[ \\t]+table", re.IGNORECASE)
    ],
    'xss': [
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"onmouseover=", re.IGNORECASE),
        re.compile(r"onerror=", re.IGNORECASE),
        re.compile(r"onload=", re.IGNORECASE),
        re.compile(r"alert\\(", re.IGNORECASE),
        re.compile(r"<iframe[^>]*>", re.IGNORECASE)
    ],
    'traversal': [
        re.compile(r"\\.\\./"),
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"/win\\.ini", re.IGNORECASE)
    ],
    'cmdi': [
        re.compile(r"[;&|][ \\t]*(/bin/)?(sh|bash|cmd|powershell)", re.IGNORECASE)
    ],
    'bots': [
        re.compile(r"(sqlmap|nikto|burpsuite|nmap|w3af)", re.IGNORECASE)
    ]
}

def inspect_string(val):
    if not val:
        return False
    val_str = str(val)
    for category, patterns in RULES.items():
        for pattern in patterns:
            if pattern.search(val_str):
                return True
    return False

def shieldwall_waf(app):
    from flask import request, abort
    @app.before_request
    def inspect_request():
        full_path = request.full_path
        decoded_path = urllib.parse.unquote(full_path)
        if inspect_string(full_path) or inspect_string(decoded_path):
            abort(403, description="Blocked by ShieldWall Embedded WAF")
            
        ua = request.headers.get('User-Agent', '')
        for pattern in RULES['bots']:
            if pattern.search(ua):
                abort(403, description="Blocked by ShieldWall Embedded WAF")
                
        if request.is_json:
            try:
                body_str = json.dumps(request.get_json())
                if inspect_string(body_str):
                    abort(403, description="Blocked by ShieldWall Embedded WAF")
            except:
                pass
        elif request.data:
            if inspect_string(request.data.decode('utf-8', errors='ignore')):
                abort(403, description="Blocked by ShieldWall Embedded WAF")

class ShieldWallWafMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        from django.http import HttpResponseForbidden
        full_path = request.get_full_path()
        decoded_path = urllib.parse.unquote(full_path)
        if inspect_string(full_path) or inspect_string(decoded_path):
            return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
            
        ua = request.META.get('HTTP_USER_AGENT', '')
        for pattern in RULES['bots']:
            if pattern.search(ua):
                return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
                
        if request.body:
            if inspect_string(request.body.decode('utf-8', errors='ignore')):
                return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
                
        return self.get_response(request)
`,
      type: 'create_file'
    });
  }

  if (!content.includes('Talisman') && !content.includes('talisman')) {
    patches.push({
      filename: appFile ? appFile.filename : 'app.py',
      description: 'Add Flask-Talisman for HTTPS enforcement, Content Security Policy, and security headers.',
      severity: 'High',
      original: `from flask import Flask\napp = Flask(__name__)`,
      patched: `from flask import Flask\nfrom flask_talisman import Talisman\n\napp = Flask(__name__)\nTalisman(app, content_security_policy={\n    'default-src': "'self'",\n    'script-src': "'self'",\n    'style-src': "'self' 'unsafe-inline'"\n})`,
      type: 'modify_code'
    });
  }

  if (!content.includes('CSRFProtect') && !content.includes('csrf')) {
    patches.push({
      filename: appFile ? appFile.filename : 'app.py',
      description: 'Add Flask-WTF CSRF protection for all POST/PUT/DELETE requests.',
      severity: 'High',
      original: `app = Flask(__name__)`,
      patched: `from flask_wtf.csrf import CSRFProtect\n\napp = Flask(__name__)\napp.config['SECRET_KEY'] = os.urandom(32).hex()\ncsrf = CSRFProtect(app)`,
      type: 'modify_code'
    });
  }

  if (!content.includes('Limiter') && !content.includes('limiter')) {
    patches.push({
      filename: appFile ? appFile.filename : 'app.py',
      description: 'Add Flask-Limiter for rate limiting to prevent brute-force and DDoS attacks.',
      severity: 'High',
      original: `app = Flask(__name__)`,
      patched: `from flask_limiter import Limiter\nfrom flask_limiter.util import get_remote_address\n\napp = Flask(__name__)\nlimiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])`,
      type: 'modify_code'
    });
  }

  if (!content.includes('SESSION_COOKIE_SECURE')) {
    patches.push({
      filename: appFile ? appFile.filename : 'config.py',
      description: 'Set secure session cookie configuration to prevent session hijacking.',
      severity: 'Medium',
      original: `# Configuration`,
      patched: `app.config['SESSION_COOKIE_SECURE'] = True\napp.config['SESSION_COOKIE_HTTPONLY'] = True\napp.config['SESSION_COOKIE_SAMESITE'] = 'Lax'\napp.config['PERMANENT_SESSION_LIFETIME'] = 3600`,
      type: 'add_config'
    });
  }

  if (reqFile) {
    const reqContent = reqFile.content || '';
    const missing = [];
    if (!reqContent.includes('flask-talisman')) missing.push('flask-talisman>=1.0.0');
    if (!reqContent.includes('flask-wtf')) missing.push('Flask-WTF>=1.2.0');
    if (!reqContent.includes('flask-limiter')) missing.push('Flask-Limiter>=3.5.0');
    if (!reqContent.includes('bleach')) missing.push('bleach>=6.0.0');
    if (missing.length > 0) {
      patches.push({
        filename: 'requirements.txt',
        description: `Add missing security dependencies: ${missing.join(', ')}`,
        severity: 'High',
        original: reqContent.split('\n').slice(0, 3).join('\n'),
        patched: reqContent.split('\n').slice(0, 3).join('\n') + '\n' + missing.join('\n'),
        type: 'add_dependency'
      });
    }
  }

  return patches;
}

function generateDjangoPatches(files) {
  const patches = [];
  const settingsFile = files.find(f => f.filename.toLowerCase().includes('settings.py'));
  const content = settingsFile ? settingsFile.content : '';

  // 0. Embedded WAF Firewall Middleware
  if (!content.includes('ShieldWallWafMiddleware')) {
    patches.push({
      filename: settingsFile ? settingsFile.filename : 'settings.py',
      description: 'Embed ShieldWall WAF as a Django middleware class to inspect incoming requests and protect your app in any environment.',
      severity: 'Critical',
      original: `MIDDLEWARE = [`,
      patched: `MIDDLEWARE = [\n    'shieldwall_waf.ShieldWallWafMiddleware',`,
      type: 'modify_code'
    });

    patches.push({
      filename: 'shieldwall_waf.py',
      description: 'Create ShieldWall Python request firewall module.',
      severity: 'Critical',
      original: '',
      patched: `import re
import urllib.parse
import json

RULES = {
    'sqli': [
        re.compile(r"['\\\"][ \\t]*or[ \\t]+", re.IGNORECASE),
        re.compile(r"union[ \\t]+select", re.IGNORECASE),
        re.compile(r"select[ \\t]+.*[ \\t]+from", re.IGNORECASE),
        re.compile(r"insert[ \\t]+into", re.IGNORECASE),
        re.compile(r"update[ \\t]+.*[ \\t]+set", re.IGNORECASE),
        re.compile(r"delete[ \\t]+from", re.IGNORECASE),
        re.compile(r"drop[ \\t]+table", re.IGNORECASE)
    ],
    'xss': [
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"onmouseover=", re.IGNORECASE),
        re.compile(r"onerror=", re.IGNORECASE),
        re.compile(r"onload=", re.IGNORECASE),
        re.compile(r"alert\\(", re.IGNORECASE),
        re.compile(r"<iframe[^>]*>", re.IGNORECASE)
    ],
    'traversal': [
        re.compile(r"\\.\\./"),
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"/win\\.ini", re.IGNORECASE)
    ],
    'cmdi': [
        re.compile(r"[;&|][ \\t]*(/bin/)?(sh|bash|cmd|powershell)", re.IGNORECASE)
    ],
    'bots': [
        re.compile(r"(sqlmap|nikto|burpsuite|nmap|w3af)", re.IGNORECASE)
    ]
}

def inspect_string(val):
    if not val:
        return False
    val_str = str(val)
    for category, patterns in RULES.items():
        for pattern in patterns:
            if pattern.search(val_str):
                return True
    return False

def shieldwall_waf(app):
    from flask import request, abort
    @app.before_request
    def inspect_request():
        full_path = request.full_path
        decoded_path = urllib.parse.unquote(full_path)
        if inspect_string(full_path) or inspect_string(decoded_path):
            abort(403, description="Blocked by ShieldWall Embedded WAF")
            
        ua = request.headers.get('User-Agent', '')
        for pattern in RULES['bots']:
            if pattern.search(ua):
                abort(403, description="Blocked by ShieldWall Embedded WAF")
                
        if request.is_json:
            try:
                body_str = json.dumps(request.get_json())
                if inspect_string(body_str):
                    abort(403, description="Blocked by ShieldWall Embedded WAF")
            except:
                pass
        elif request.data:
            if inspect_string(request.data.decode('utf-8', errors='ignore')):
                abort(403, description="Blocked by ShieldWall Embedded WAF")

class ShieldWallWafMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        from django.http import HttpResponseForbidden
        full_path = request.get_full_path()
        decoded_path = urllib.parse.unquote(full_path)
        if inspect_string(full_path) or inspect_string(decoded_path):
            return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
            
        ua = request.META.get('HTTP_USER_AGENT', '')
        for pattern in RULES['bots']:
            if pattern.search(ua):
                return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
                
        if request.body:
            if inspect_string(request.body.decode('utf-8', errors='ignore')):
                return HttpResponseForbidden("<h1>Blocked by ShieldWall Embedded WAF</h1>")
                
        return self.get_response(request)
`,
      type: 'create_file'
    });
  }

  const checks = [
    { key: 'CSRF_COOKIE_SECURE', value: 'True', desc: 'Enable CSRF cookie security (HTTPS only)', sev: 'High' },
    { key: 'SESSION_COOKIE_SECURE', value: 'True', desc: 'Enable session cookie security (HTTPS only)', sev: 'High' },
    { key: 'SECURE_HSTS_SECONDS', value: '31536000', desc: 'Enable HTTP Strict Transport Security (1 year)', sev: 'High' },
    { key: 'SECURE_HSTS_INCLUDE_SUBDOMAINS', value: 'True', desc: 'Apply HSTS to all subdomains', sev: 'Medium' },
    { key: 'SECURE_HSTS_PRELOAD', value: 'True', desc: 'Allow HSTS preload list inclusion', sev: 'Medium' },
    { key: 'X_FRAME_OPTIONS', value: "'DENY'", desc: 'Prevent clickjacking by denying iframe embedding', sev: 'Medium' },
    { key: 'SECURE_CONTENT_TYPE_NOSNIFF', value: 'True', desc: 'Prevent MIME type sniffing', sev: 'Low' },
    { key: 'SECURE_BROWSER_XSS_FILTER', value: 'True', desc: 'Enable browser XSS filter', sev: 'Low' },
    { key: 'SECURE_SSL_REDIRECT', value: 'True', desc: 'Force HTTPS redirect', sev: 'High' }
  ];

  for (const check of checks) {
    if (!content.includes(check.key)) {
      patches.push({
        filename: settingsFile ? settingsFile.filename : 'settings.py',
        description: check.desc,
        severity: check.sev,
        original: `# Security settings`,
        patched: `${check.key} = ${check.value}`,
        type: 'add_config'
      });
    } else if (content.includes(`${check.key} = False`)) {
      patches.push({
        filename: settingsFile ? settingsFile.filename : 'settings.py',
        description: `${check.desc} (currently disabled, should be enabled)`,
        severity: check.sev,
        original: `${check.key} = False`,
        patched: `${check.key} = ${check.value}`,
        type: 'modify_code'
      });
    }
  }

  // Check DEBUG
  if (content.includes('DEBUG = True')) {
    patches.push({
      filename: settingsFile ? settingsFile.filename : 'settings.py',
      description: 'DEBUG mode is enabled. This must be False in production to prevent information leakage.',
      severity: 'Critical',
      original: `DEBUG = True`,
      patched: `DEBUG = False`,
      type: 'modify_code'
    });
  }

  // Check ALLOWED_HOSTS
  if (content.includes("ALLOWED_HOSTS = ['*']") || content.includes('ALLOWED_HOSTS = ["*"]')) {
    patches.push({
      filename: settingsFile ? settingsFile.filename : 'settings.py',
      description: 'ALLOWED_HOSTS wildcard allows any domain. Restrict to your actual domains.',
      severity: 'High',
      original: `ALLOWED_HOSTS = ['*']`,
      patched: `ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']`,
      type: 'modify_code'
    });
  }

  return patches;
}

function isClientSideJs(content) {
  if (!content) return false;
  const browserIndicators = [
    'document', 'window', 'innerHTML', 'textContent',
    'querySelector', 'getElementById', 'getElementsBy',
    'addEventListener', 'alert(', 'prompt(', 'location.'
  ];
  const hasBrowser = browserIndicators.some(ind => content.includes(ind));
  
  const backendIndicators = [
    "require('fs')", 'require("fs")',
    "require('path')", 'require("path")',
    "require('child_process')", 'require("child_process")',
    "require('os')", 'require("os")'
  ];
  const hasBackend = backendIndicators.some(ind => content.includes(ind));

  return hasBrowser && !hasBackend;
}

function generateHtmlPatches(files) {
  const patches = [];
  const htmlFile = files.find(f => /\.(html|htm)$/i.test(f.filename));
  const content = htmlFile ? htmlFile.content : '';

  // 1. CSP meta tag
  if (htmlFile && !content.includes('Content-Security-Policy')) {
    let original = '';
    let patched = '';
    if (content.includes('<head>')) {
      original = '<head>';
      patched = `<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">`;
    } else if (content.includes('<HEAD>')) {
      original = '<HEAD>';
      patched = `<HEAD>\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">`;
    } else if (content.includes('<html>')) {
      original = '<html>';
      patched = `<html>\n<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">\n</head>`;
    } else if (content.includes('<HTML>')) {
      original = '<HTML>';
      patched = `<HTML>\n<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">\n</head>`;
    } else {
      original = content;
      patched = `<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">\n</head>\n` + content;
    }

    patches.push({
      filename: htmlFile.filename,
      description: 'Add Content Security Policy meta tag to prevent XSS and data injection attacks.',
      severity: 'High',
      original,
      patched,
      type: 'modify_code'
    });
  }

  // 2. Input sanitization function
  const jsFile = files.find(f => /\.(js)$/i.test(f.filename) && !f.filename.includes('min.') && isClientSideJs(f.content));
  if (jsFile && !jsFile.content.includes('sanitizeHTML')) {
    patches.push({
      filename: jsFile.filename,
      description: 'Add input sanitization utility to prevent XSS when inserting user content into the DOM.',
      severity: 'High',
      original: jsFile.content,
      patched: `function sanitizeHTML(str) {\n  const div = document.createElement('div');\n  div.appendChild(document.createTextNode(str));\n  return div.innerHTML;\n}\n\n` + jsFile.content,
      type: 'modify_code'
    });
  }

  // 3. Check for innerHTML usage
  for (const file of files) {
    if (/\.js$/i.test(file.filename) && file.content) {
      const lines = file.content.split('\n');
      lines.forEach((line, lineIdx) => {
        const match = line.match(/([a-zA-Z0-9_$]+)\.innerHTML\s*=\s*([^;\n\r]+);?/);
        if (match) {
          const fullLine = match[0];
          const elementVar = match[1];
          const valueVar = match[2];
          patches.push({
            filename: file.filename,
            description: `Line ${lineIdx + 1}: Unsanitized innerHTML usage detected: "${fullLine}". Use textContent for plain text or sanitize HTML before insertion.`,
            severity: 'Medium',
            original: line,
            patched: line.replace(fullLine, `${elementVar}.textContent = ${valueVar};`),
            type: 'modify_code'
          });
        }
      });
    }
  }

  return patches;
}

function safeParse(str) {
  try { return JSON.parse(str); } catch (e) { return null; }
}

function generateNextJsPatches(files) {
  const patches = [];
  const getFile = (name) => files.find(f => f.filename.toLowerCase().includes(name));
  
  const nextConfigJs = getFile('next.config.js');
  const nextConfigMjs = getFile('next.config.mjs');
  const nextConfig = nextConfigJs || nextConfigMjs;
  
  const hasSrcDir = files.some(f => f.filename.startsWith('src/'));
  const middlewareFilename = hasSrcDir ? 'src/middleware.js' : 'middleware.js';
  const hasMiddleware = files.some(f => f.filename.includes('middleware.js') || f.filename.includes('middleware.ts'));

  if (!hasMiddleware) {
    patches.push({
      filename: middlewareFilename,
      description: 'Embed ShieldWall WAF middleware for global, cloud-native request filtering inside Next.js.',
      severity: 'Critical',
      original: '',
      patched: `import { NextResponse } from 'next/server';

const RULES = {
  sqli: [
    /[\\'\"][ \\t]*or[ \\t]+/i,
    /union[ \\t]+select/i,
    /select[ \\t]+.*[ \\t]+from/i,
    /insert[ \\t]+into/i,
    /update[ \\t]+.*[ \\t]+set/i,
    /delete[ \\t]+from/i,
    /drop[ \\t]+table/i
  ],
  xss: [
    /<script[^>]*>/i,
    /javascript:/i,
    /onmouseover=/i,
    /onerror=/i,
    /onload=/i,
    /alert\\([^\\)]*\\)/i
  ],
  traversal: [
    /\\.\\.\\//,
    /\\/etc\\/passwd/i,
    /boot\\.ini/i
  ],
  bots: [
    /sqlmap/i,
    /nikto/i,
    /burpsuite/i,
    /nmap/i
  ]
};

function inspectString(str) {
  if (!str) return false;
  for (const [category, patterns] of Object.entries(RULES)) {
    for (const pattern of patterns) {
      if (pattern.test(str)) {
        console.warn('[ShieldWall WAF] Blocked request matching category: ' + category);
        return true;
      }
    }
  }
  return false;
}

export function middleware(request) {
  const url = request.nextUrl;
  const userAgent = request.headers.get('user-agent') || '';

  if (inspectString(url.pathname) || inspectString(url.search)) {
    return new NextResponse(
      '<h1>Blocked by ShieldWall Embedded WAF</h1>',
      { status: 403, headers: { 'content-type': 'text/html' } }
    );
  }

  for (const pattern of RULES.bots) {
    if (pattern.test(userAgent)) {
      return new NextResponse(
        '<h1>Blocked by ShieldWall Embedded WAF</h1>',
        { status: 403, headers: { 'content-type': 'text/html' } }
      );
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/:path*',
};`,
      type: 'create_file'
    });
  }

  // 2. Next.js Config Security Headers
  if (nextConfig) {
    const configContent = nextConfig.content || '';
    if (!configContent.includes('headers')) {
      let original = '';
      let patched = '';
      if (configContent.includes('module.exports = nextConfig')) {
        original = 'module.exports = nextConfig';
        patched = `nextConfig.headers = async () => {
  return [
    {
      source: '/:path*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-XSS-Protection', value: '1; mode=block' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
      ]
    }
  ];
};

module.exports = nextConfig;`;
      } else if (configContent.includes('export default nextConfig')) {
        original = 'export default nextConfig';
        patched = `nextConfig.headers = async () => {
  return [
    {
      source: '/:path*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-XSS-Protection', value: '1; mode=block' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
      ]
    }
  ];
};

export default nextConfig;`;
      } else {
        original = configContent;
        patched = configContent + `\n\nconst shieldwallHeaders = async () => {
  return [
    {
      source: '/:path*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-XSS-Protection', value: '1; mode=block' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
      ]
    }
  ];
};
if (typeof module !== 'undefined') {
  if (module.exports && module.exports.headers === undefined) {
    module.exports.headers = shieldwallHeaders;
  }
}`;
      }

      patches.push({
        filename: nextConfig.filename,
        description: 'Configure comprehensive HTTP security headers (X-Frame-Options, CSP, etc.) in Next.js config.',
        severity: 'High',
        original,
        patched,
        type: 'modify_code'
      });
    }
  } else {
    // Create new next.config.js
    patches.push({
      filename: 'next.config.js',
      description: 'Create next.config.js with security headers configured.',
      severity: 'High',
      original: '',
      patched: `const nextConfig = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
        ]
      }
    ];
  }
};

module.exports = nextConfig;`,
      type: 'create_file'
    });
  }

  return patches;
}

module.exports = { detectFramework, generatePatches };
