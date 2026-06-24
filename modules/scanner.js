'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// HTTP helper – works with built-in http / https only
// ---------------------------------------------------------------------------

/**
 * Make an HTTP/HTTPS request and return { statusCode, headers, body }.
 * Follows up to `maxRedirects` redirects (default 5).
 * @param {string} targetUrl
 * @param {object} [opts]
 * @param {string} [opts.method]        - HTTP method (default GET)
 * @param {number} [opts.timeout]       - ms (default 10 000)
 * @param {number} [opts.maxRedirects]  - redirect limit (default 5)
 * @param {boolean} [opts.followRedirects] - whether to follow (default false)
 * @param {object}  [opts.headers]      - extra request headers
 * @returns {Promise<{statusCode:number, headers:object, body:string, finalUrl:string}>}
 */
function makeRequest(targetUrl, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const timeout = opts.timeout || 10000;
  const maxRedirects = opts.maxRedirects || 5;
  const followRedirects = opts.followRedirects || false;
  const extraHeaders = opts.headers || {};

  return new Promise((resolve, reject) => {
    let redirectCount = 0;

    function doRequest(currentUrl) {
      let parsed;
      try {
        parsed = new URL(currentUrl);
      } catch (e) {
        return reject(new Error(`Invalid URL: ${currentUrl}`));
      }

      const transport = parsed.protocol === 'https:' ? https : http;

      const reqOpts = {
        method,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: {
          'User-Agent': 'ShieldWall-Scanner/1.0',
          Accept: '*/*',
          ...extraHeaders,
        },
        timeout,
        rejectUnauthorized: false, // accept self-signed certs during scan
      };

      const req = transport.request(reqOpts, (res) => {
        // Handle redirects
        if (
          followRedirects &&
          [301, 302, 303, 307, 308].includes(res.statusCode) &&
          res.headers.location &&
          redirectCount < maxRedirects
        ) {
          redirectCount++;
          let next = res.headers.location;
          if (next.startsWith('/')) {
            next = `${parsed.protocol}//${parsed.host}${next}`;
          }
          res.resume(); // drain
          return doRequest(next);
        }

        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
            finalUrl: currentUrl,
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timed out: ${currentUrl}`));
      });
      req.on('error', (err) => reject(err));
      req.end();
    }

    doRequest(targetUrl);
  });
}

// ---------------------------------------------------------------------------
// Individual check modules
// ---------------------------------------------------------------------------

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SCAN-${String(findingCounter).padStart(4, '0')}`;
}

// 1. Security Headers ---------------------------------------------------------

function checkSecurityHeaders(headers, targetUrl) {
  const findings = [];
  const isHttps = targetUrl.startsWith('https');

  const headerChecks = [
    {
      header: 'x-frame-options',
      title: 'Missing X-Frame-Options Header',
      severity: 'Medium',
      category: 'Security Headers',
      description:
        'The X-Frame-Options header is not set. This allows the page to be embedded in iframes, potentially enabling clickjacking attacks.',
      remediation:
        'Set the X-Frame-Options header to DENY or SAMEORIGIN. Example: X-Frame-Options: DENY',
    },
    {
      header: 'content-security-policy',
      title: 'Missing Content-Security-Policy Header',
      severity: 'High',
      category: 'Security Headers',
      description:
        'No Content-Security-Policy header is set. CSP mitigates cross-site scripting (XSS), clickjacking, and other code injection attacks by specifying which dynamic resources are allowed to load.',
      remediation:
        "Implement a strict Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'",
    },
    {
      header: 'x-content-type-options',
      title: 'Missing X-Content-Type-Options Header',
      severity: 'Low',
      category: 'Security Headers',
      description:
        'The X-Content-Type-Options header is not set. This makes the application vulnerable to MIME-sniffing attacks where the browser may interpret files as a different content type.',
      remediation: 'Set the X-Content-Type-Options header to nosniff. Example: X-Content-Type-Options: nosniff',
    },
    {
      header: 'x-xss-protection',
      title: 'Missing X-XSS-Protection Header',
      severity: 'Low',
      category: 'Security Headers',
      description:
        'The X-XSS-Protection header is not set. Although deprecated in modern browsers in favour of CSP, it still provides a layer of protection in older browsers.',
      remediation:
        'Set X-XSS-Protection: 1; mode=block. Note: CSP is the preferred modern mitigation.',
    },
    {
      header: 'referrer-policy',
      title: 'Missing Referrer-Policy Header',
      severity: 'Low',
      category: 'Security Headers',
      description:
        'No Referrer-Policy header is set. This can lead to leakage of sensitive URL parameters to third-party sites via the Referer header.',
      remediation:
        'Set the Referrer-Policy header. Recommended: Referrer-Policy: strict-origin-when-cross-origin',
    },
    {
      header: 'permissions-policy',
      title: 'Missing Permissions-Policy Header',
      severity: 'Info',
      category: 'Security Headers',
      description:
        'The Permissions-Policy (formerly Feature-Policy) header is not set. This header controls which browser features and APIs the page is allowed to use.',
      remediation:
        'Set a restrictive Permissions-Policy header. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
  ];

  // HSTS only relevant for HTTPS
  if (isHttps) {
    headerChecks.push({
      header: 'strict-transport-security',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'High',
      category: 'Security Headers',
      description:
        'The site is served over HTTPS but does not set a Strict-Transport-Security (HSTS) header. This means the browser will not enforce HTTPS-only connections, making users vulnerable to SSL stripping attacks.',
      remediation:
        'Set the Strict-Transport-Security header with a minimum max-age of 31536000 (1 year). Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });
  }

  for (const check of headerChecks) {
    const value = headers[check.header];
    if (!value) {
      findings.push({
        id: nextId(),
        title: check.title,
        severity: check.severity,
        category: check.category,
        description: check.description,
        evidence: `Header "${check.header}" is absent from the response.`,
        remediation: check.remediation,
      });
    }
  }

  // Check weak CSP
  const csp = headers['content-security-policy'];
  if (csp) {
    if (csp.includes("'unsafe-inline'")) {
      findings.push({
        id: nextId(),
        title: 'Content-Security-Policy Allows unsafe-inline',
        severity: 'Medium',
        category: 'Security Headers',
        description:
          "The CSP header includes 'unsafe-inline', which significantly weakens XSS protection by allowing inline scripts and styles.",
        evidence: `CSP value: ${csp}`,
        remediation:
          "Remove 'unsafe-inline' from your CSP and use nonce-based or hash-based policies instead.",
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        id: nextId(),
        title: 'Content-Security-Policy Allows unsafe-eval',
        severity: 'Medium',
        category: 'Security Headers',
        description:
          "The CSP header includes 'unsafe-eval', which allows dynamic code execution via eval() and similar functions, weakening XSS protections.",
        evidence: `CSP value: ${csp}`,
        remediation:
          "Remove 'unsafe-eval' from your CSP. Refactor code to avoid eval(), new Function(), and similar constructs.",
      });
    }
    if (csp.includes('*') && !csp.includes('*.')) {
      findings.push({
        id: nextId(),
        title: 'Content-Security-Policy Uses Wildcard Source',
        severity: 'High',
        category: 'Security Headers',
        description:
          "The CSP header uses a wildcard '*' source, which effectively disables the protection CSP is meant to provide.",
        evidence: `CSP value: ${csp}`,
        remediation:
          "Replace wildcard '*' sources with explicit, trusted domain names.",
      });
    }
  }

  // Check weak HSTS
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) {
        findings.push({
          id: nextId(),
          title: 'Strict-Transport-Security max-age Too Short',
          severity: 'Medium',
          category: 'Security Headers',
          description: `The HSTS max-age is set to ${maxAge} seconds, which is less than the recommended minimum of 31536000 (1 year).`,
          evidence: `HSTS value: ${hsts}`,
          remediation:
            'Increase the HSTS max-age to at least 31536000 seconds (1 year). Consider adding includeSubDomains and preload directives.',
        });
      }
    }
  }

  return findings;
}

// 2. Cookie Security ----------------------------------------------------------

function checkCookieSecurity(headers) {
  const findings = [];
  const setCookieHeaders = headers['set-cookie'];
  if (!setCookieHeaders) return findings;

  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

  for (const raw of cookies) {
    const parts = raw.split(';').map((p) => p.trim());
    const nameValue = parts[0] || '';
    const cookieName = nameValue.split('=')[0] || 'unknown';
    const lower = raw.toLowerCase();

    if (!lower.includes('httponly')) {
      findings.push({
        id: nextId(),
        title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
        severity: 'Medium',
        category: 'Cookie Security',
        description: `The cookie "${cookieName}" does not have the HttpOnly flag set. This means it can be accessed via JavaScript, making it vulnerable to XSS-based session theft.`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Add the HttpOnly flag to the "${cookieName}" cookie to prevent client-side JavaScript access.`,
      });
    }

    if (!lower.includes('secure')) {
      findings.push({
        id: nextId(),
        title: `Cookie "${cookieName}" Missing Secure Flag`,
        severity: 'Medium',
        category: 'Cookie Security',
        description: `The cookie "${cookieName}" does not have the Secure flag set. This means it can be transmitted over unencrypted HTTP connections, exposing it to interception.`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Add the Secure flag to the "${cookieName}" cookie to ensure it is only sent over HTTPS.`,
      });
    }

    if (!lower.includes('samesite')) {
      findings.push({
        id: nextId(),
        title: `Cookie "${cookieName}" Missing SameSite Attribute`,
        severity: 'Low',
        category: 'Cookie Security',
        description: `The cookie "${cookieName}" does not have the SameSite attribute set. This can make the application vulnerable to cross-site request forgery (CSRF) attacks.`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Add SameSite=Strict or SameSite=Lax to the "${cookieName}" cookie.`,
      });
    }

    if (lower.includes('samesite=none') && !lower.includes('secure')) {
      findings.push({
        id: nextId(),
        title: `Cookie "${cookieName}" SameSite=None Without Secure`,
        severity: 'High',
        category: 'Cookie Security',
        description: `The cookie "${cookieName}" has SameSite=None but is missing the Secure flag. Modern browsers will reject this cookie.`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `When using SameSite=None, the Secure flag is mandatory. Add the Secure flag or change SameSite to Lax/Strict.`,
      });
    }
  }

  return findings;
}

// 3. Server Information Disclosure --------------------------------------------

function checkServerDisclosure(headers) {
  const findings = [];

  const serverHeader = headers['server'];
  if (serverHeader) {
    const hasVersion = /\/[\d.]+/.test(serverHeader);
    if (hasVersion) {
      findings.push({
        id: nextId(),
        title: 'Server Version Disclosed in Server Header',
        severity: 'Medium',
        category: 'Information Disclosure',
        description: `The Server header reveals the software name and version: "${serverHeader}". This information helps attackers identify known vulnerabilities for that specific version.`,
        evidence: `Server: ${serverHeader}`,
        remediation:
          'Configure your web server to suppress or genericize the Server header. For Nginx: server_tokens off; For Apache: ServerTokens Prod',
      });
    } else {
      findings.push({
        id: nextId(),
        title: 'Server Software Disclosed',
        severity: 'Low',
        category: 'Information Disclosure',
        description: `The Server header reveals the software name: "${serverHeader}". While no version is disclosed, this still provides information to potential attackers.`,
        evidence: `Server: ${serverHeader}`,
        remediation:
          'Consider removing or masking the Server header entirely to reduce the attack surface.',
      });
    }
  }

  const poweredBy = headers['x-powered-by'];
  if (poweredBy) {
    findings.push({
      id: nextId(),
      title: 'X-Powered-By Header Discloses Technology Stack',
      severity: 'Medium',
      category: 'Information Disclosure',
      description: `The X-Powered-By header reveals the backend technology: "${poweredBy}". Attackers can use this to target framework-specific vulnerabilities.`,
      evidence: `X-Powered-By: ${poweredBy}`,
      remediation:
        'Remove the X-Powered-By header. For Express.js: app.disable("x-powered-by") or use Helmet. For PHP: expose_php = Off in php.ini',
    });
  }

  // Check other informational headers
  const infoHeaders = [
    'x-aspnet-version',
    'x-aspnetmvc-version',
    'x-generator',
    'x-drupal-cache',
    'x-varnish',
    'x-backend-server',
    'via',
  ];

  for (const hdr of infoHeaders) {
    if (headers[hdr]) {
      findings.push({
        id: nextId(),
        title: `Information Disclosure via ${hdr} Header`,
        severity: 'Low',
        category: 'Information Disclosure',
        description: `The header "${hdr}" leaks infrastructure or technology information: "${headers[hdr]}".`,
        evidence: `${hdr}: ${headers[hdr]}`,
        remediation: `Remove or suppress the "${hdr}" header in your server configuration.`,
      });
    }
  }

  return findings;
}

// 4. Sensitive Path Probing ---------------------------------------------------

const SENSITIVE_PATHS = [
  // Version control
  { path: '/.git/HEAD', description: 'Git repository HEAD file', severity: 'Critical' },
  { path: '/.git/config', description: 'Git repository configuration', severity: 'Critical' },
  { path: '/.svn/entries', description: 'SVN repository entries', severity: 'Critical' },
  // Environment files
  { path: '/.env', description: 'Environment configuration file', severity: 'Critical' },
  { path: '/.env.local', description: 'Local environment config', severity: 'Critical' },
  { path: '/.env.production', description: 'Production environment config', severity: 'Critical' },
  { path: '/.env.backup', description: 'Backup environment config', severity: 'Critical' },
  // Web server config
  { path: '/.htaccess', description: 'Apache configuration file', severity: 'High' },
  { path: '/web.config', description: 'IIS configuration file', severity: 'High' },
  { path: '/.htpasswd', description: 'Apache password file', severity: 'Critical' },
  // Info files
  { path: '/robots.txt', description: 'Robots exclusion file', severity: 'Info' },
  { path: '/sitemap.xml', description: 'Sitemap file', severity: 'Info' },
  { path: '/crossdomain.xml', description: 'Flash cross-domain policy', severity: 'Low' },
  // Admin panels
  { path: '/admin', description: 'Admin panel', severity: 'Medium' },
  { path: '/wp-admin', description: 'WordPress admin panel', severity: 'Medium' },
  { path: '/wp-login.php', description: 'WordPress login page', severity: 'Medium' },
  { path: '/administrator', description: 'Joomla admin panel', severity: 'Medium' },
  // Database tools
  { path: '/phpmyadmin', description: 'phpMyAdmin database manager', severity: 'High' },
  { path: '/adminer.php', description: 'Adminer database manager', severity: 'High' },
  { path: '/phpinfo.php', description: 'PHP info page', severity: 'High' },
  // Server status
  { path: '/server-status', description: 'Apache server status', severity: 'High' },
  { path: '/server-info', description: 'Apache server info', severity: 'High' },
  // API documentation
  { path: '/api/docs', description: 'API documentation', severity: 'Medium' },
  { path: '/swagger.json', description: 'Swagger/OpenAPI specification', severity: 'Medium' },
  { path: '/swagger-ui.html', description: 'Swagger UI', severity: 'Medium' },
  { path: '/graphql', description: 'GraphQL endpoint', severity: 'Medium' },
  { path: '/api/graphql', description: 'GraphQL API endpoint', severity: 'Medium' },
  // Backup files
  { path: '/backup.zip', description: 'Backup archive', severity: 'Critical' },
  { path: '/backup.tar.gz', description: 'Backup archive (tar)', severity: 'Critical' },
  { path: '/dump.sql', description: 'Database dump file', severity: 'Critical' },
  { path: '/database.sql', description: 'Database SQL file', severity: 'Critical' },
  { path: '/db.sql', description: 'Database SQL file', severity: 'Critical' },
  // Config/debug
  { path: '/config.json', description: 'JSON config file', severity: 'High' },
  { path: '/config.yml', description: 'YAML config file', severity: 'High' },
  { path: '/debug', description: 'Debug endpoint', severity: 'Medium' },
  { path: '/trace', description: 'Trace endpoint', severity: 'Medium' },
  { path: '/elmah.axd', description: '.NET error log', severity: 'High' },
  { path: '/wp-config.php.bak', description: 'WordPress config backup', severity: 'Critical' },
  { path: '/.DS_Store', description: 'macOS directory metadata', severity: 'Low' },
  { path: '/Thumbs.db', description: 'Windows thumbnail cache', severity: 'Low' },
  { path: '/.dockerenv', description: 'Docker environment indicator', severity: 'Info' },
  { path: '/docker-compose.yml', description: 'Docker Compose config', severity: 'High' },
  { path: '/Dockerfile', description: 'Dockerfile', severity: 'Medium' },
];

async function probeSensitivePaths(baseUrl, options = {}) {
  const findings = [];
  const concurrency = options.concurrency || 5;
  const timeout = options.timeout || 8000;

  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return findings;
  }
  const origin = `${parsed.protocol}//${parsed.host}`;

  // Process paths in batches
  for (let i = 0; i < SENSITIVE_PATHS.length; i += concurrency) {
    const batch = SENSITIVE_PATHS.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (entry) => {
        try {
          const res = await makeRequest(`${origin}${entry.path}`, {
            method: 'HEAD',
            timeout,
          });

          if (res.statusCode === 200 || res.statusCode === 301 || res.statusCode === 302) {
            // For 200 responses, do a GET to confirm body content for critical items
            let bodySnippet = '';
            if (res.statusCode === 200 && entry.severity === 'Critical') {
              try {
                const getRes = await makeRequest(`${origin}${entry.path}`, {
                  method: 'GET',
                  timeout,
                });
                bodySnippet = getRes.body ? getRes.body.substring(0, 200) : '';
              } catch {
                // ignore
              }
            }

            return {
              id: nextId(),
              title: `Sensitive Path Accessible: ${entry.path}`,
              severity: entry.severity,
              category: 'Sensitive Path Exposure',
              description: `The path "${entry.path}" (${entry.description}) returned HTTP ${res.statusCode}. This resource should not be publicly accessible.`,
              evidence: `${entry.path} → HTTP ${res.statusCode}${bodySnippet ? ` | Body preview: ${bodySnippet.replace(/\n/g, ' ').substring(0, 120)}` : ''}`,
              remediation: `Block public access to "${entry.path}" via your web server configuration or remove the file from the public directory.`,
            };
          }
          return null;
        } catch {
          return null; // timeout or connection error – not a finding
        }
      })
    );

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        findings.push(r.value);
      }
    }
  }

  return findings;
}

// 5. Directory Listing Detection ----------------------------------------------

const DIRECTORY_LISTING_INDICATORS = [
  'Index of /',
  'Index of .',
  '<title>Index of',
  'Directory listing for',
  'Directory Listing',
  'Parent Directory',
  '[To Parent Directory]',
  '<h1>Index of',
  'mod_autoindex',
];

async function checkDirectoryListing(baseUrl, options = {}) {
  const findings = [];
  const timeout = options.timeout || 8000;

  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return findings;
  }
  const origin = `${parsed.protocol}//${parsed.host}`;

  const testPaths = ['/', '/images/', '/assets/', '/uploads/', '/static/', '/media/', '/css/', '/js/', '/files/', '/public/'];

  for (const testPath of testPaths) {
    try {
      const res = await makeRequest(`${origin}${testPath}`, {
        method: 'GET',
        timeout,
      });

      if (res.statusCode === 200 && res.body) {
        for (const indicator of DIRECTORY_LISTING_INDICATORS) {
          if (res.body.includes(indicator)) {
            findings.push({
              id: nextId(),
              title: `Directory Listing Enabled: ${testPath}`,
              severity: 'Medium',
              category: 'Directory Listing',
              description: `The path "${testPath}" exposes a directory listing. This allows attackers to enumerate files and discover sensitive resources that may not be linked from the application.`,
              evidence: `Found indicator "${indicator}" in response body at ${testPath}`,
              remediation:
                'Disable directory listing in your web server configuration. For Apache: Options -Indexes. For Nginx: autoindex off;',
            });
            break; // one finding per path
          }
        }
      }
    } catch {
      // ignore
    }
  }

  return findings;
}

// 6. Open Redirect Check ------------------------------------------------------

const REDIRECT_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '/\\evil.com',
  'https:evil.com',
  '////evil.com',
  'https://evil.com%23',
  'https://evil.com%2F%2F',
  '/%0d/evil.com',
  '/evil.com',
];

const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_url', 'redirect_uri', 'next', 'return', 'returnUrl', 'return_url', 'continue', 'dest', 'destination', 'goto', 'target', 'link', 'out', 'rurl', 'redir'];

async function checkOpenRedirects(targetUrl, options = {}) {
  const findings = [];
  const timeout = options.timeout || 8000;

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return findings;
  }

  // Gather parameters from the original URL plus common redirect params
  const paramsToTest = new Set();
  for (const key of parsed.searchParams.keys()) {
    paramsToTest.add(key);
  }
  // Also test common redirect parameter names even if not in original URL
  for (const rp of REDIRECT_PARAMS) {
    paramsToTest.add(rp);
  }

  const origin = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;

  for (const param of paramsToTest) {
    // Only test a subset of payloads per param for efficiency
    for (const payload of REDIRECT_PAYLOADS.slice(0, 3)) {
      try {
        const testUrl = `${origin}?${param}=${encodeURIComponent(payload)}`;
        const res = await makeRequest(testUrl, {
          method: 'GET',
          timeout,
          followRedirects: false,
        });

        if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
          const location = res.headers.location || '';
          if (
            location.includes('evil.com') ||
            location.startsWith('//evil') ||
            location.startsWith('https://evil')
          ) {
            findings.push({
              id: nextId(),
              title: `Open Redirect via "${param}" Parameter`,
              severity: 'Medium',
              category: 'Open Redirect',
              description: `The application redirects to an attacker-controlled domain when the "${param}" parameter is manipulated. This can be used for phishing attacks by redirecting users from the trusted domain to a malicious site.`,
              evidence: `Request: ${testUrl} → ${res.statusCode} Location: ${location}`,
              remediation: `Validate redirect targets against a whitelist of allowed domains. Never redirect to user-supplied URLs without validation. Use relative paths instead of absolute URLs where possible.`,
            });
            break; // one finding per param is enough
          }
        }
      } catch {
        // ignore
      }
    }
  }

  return findings;
}

// 7. HTML Form Analysis -------------------------------------------------------

function analyzeHtmlForms(body, targetUrl) {
  const findings = [];
  if (!body) return findings;

  // Naive but effective form parser — no external deps
  const formRegex = /<form[\s\S]*?<\/form>/gi;
  const forms = body.match(formRegex) || [];

  if (forms.length === 0) {
    return findings;
  }

  // Report total forms found
  findings.push({
    id: nextId(),
    title: `${forms.length} HTML Form(s) Detected`,
    severity: 'Info',
    category: 'HTML Form Analysis',
    description: `The page contains ${forms.length} HTML form(s). Each form is analysed for CSRF protection and secure attributes.`,
    evidence: `Found ${forms.length} <form> element(s) on ${targetUrl}`,
    remediation: 'Ensure all forms include anti-CSRF tokens and use POST method for state-changing operations.',
  });

  const csrfTokenNames = [
    'csrf',
    '_csrf',
    'csrfmiddlewaretoken',
    'csrf_token',
    '__requestverificationtoken',
    'authenticity_token',
    '_token',
    'antiforgery',
    'xsrf',
    '_xsrf',
  ];

  let formIndex = 0;
  for (const formHtml of forms) {
    formIndex++;
    const methodMatch = formHtml.match(/method\s*=\s*["']?(\w+)["']?/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
    const actionMatch = formHtml.match(/action\s*=\s*["']([^"']*)["']/i);
    const action = actionMatch ? actionMatch[1] : '(none)';

    if (method === 'POST') {
      // Check for CSRF token
      const lowerForm = formHtml.toLowerCase();
      const hasToken = csrfTokenNames.some(
        (name) =>
          lowerForm.includes(`name="${name}"`) ||
          lowerForm.includes(`name='${name}'`) ||
          lowerForm.includes(`name=${name}`) ||
          lowerForm.includes(`id="${name}"`) ||
          lowerForm.includes(`id='${name}'`)
      );

      // Also check for hidden inputs that might be tokens
      const hiddenInputs = formHtml.match(/<input[^>]*type\s*=\s*["']hidden["'][^>]*>/gi) || [];
      const hasHiddenToken = hiddenInputs.some((input) => {
        const namePart = input.match(/name\s*=\s*["']([^"']+)["']/i);
        if (namePart) {
          const n = namePart[1].toLowerCase();
          return csrfTokenNames.some((t) => n.includes(t));
        }
        return false;
      });

      if (!hasToken && !hasHiddenToken) {
        findings.push({
          id: nextId(),
          title: `POST Form #${formIndex} Missing CSRF Token`,
          severity: 'High',
          category: 'CSRF Protection',
          description: `A form with method="POST" (action="${action}") does not appear to contain an anti-CSRF token. This makes it vulnerable to Cross-Site Request Forgery attacks.`,
          evidence: `Form #${formIndex}: method=POST, action="${action}", no CSRF token input found.`,
          remediation:
            'Add a unique, unpredictable CSRF token to every form that performs state-changing operations. Use framework-provided CSRF middleware (e.g., csurf for Express, Django CSRF middleware, Flask-WTF).',
        });
      }
    }

    // Check for autocomplete on password fields
    if (/type\s*=\s*["']password["']/i.test(formHtml)) {
      if (!/autocomplete\s*=\s*["']off["']/i.test(formHtml) && !/autocomplete\s*=\s*["']new-password["']/i.test(formHtml)) {
        findings.push({
          id: nextId(),
          title: `Form #${formIndex} Password Field Without autocomplete=off`,
          severity: 'Low',
          category: 'HTML Form Analysis',
          description: `Form #${formIndex} contains a password field without autocomplete="off" or autocomplete="new-password". Browsers may cache passwords in their autofill database.`,
          evidence: `Form #${formIndex} contains a password input without autocomplete restriction.`,
          remediation:
            'Add autocomplete="off" or autocomplete="new-password" to password input fields to prevent browser caching.',
        });
      }
    }

    // Check for action targeting HTTP on an HTTPS page
    if (targetUrl.startsWith('https') && action.startsWith('http://')) {
      findings.push({
        id: nextId(),
        title: `Form #${formIndex} Submits to Insecure HTTP`,
        severity: 'High',
        category: 'Mixed Content',
        description: `Form #${formIndex} on an HTTPS page submits to an HTTP URL ("${action}"). This causes a mixed-content situation where form data, potentially including credentials, is sent in cleartext.`,
        evidence: `Form action: ${action} (HTTP) on HTTPS page.`,
        remediation: 'Change the form action to use HTTPS or a relative URL.',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Grade Calculation
// ---------------------------------------------------------------------------

function calculateGrade(summary) {
  const { critical, high } = summary;
  if (critical === 0 && high === 0) return 'A';
  if (critical === 0 && high <= 2) return 'B';
  if (critical === 0 && high <= 5) return 'C';
  if (critical <= 1) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Main Scanner Function
// ---------------------------------------------------------------------------

/**
 * Scan a URL for security vulnerabilities.
 *
 * @param {string} targetUrl  - The URL to scan
 * @param {object} [options]  - Scan options
 * @param {number} [options.timeout]       - Per-request timeout in ms (default 10000)
 * @param {number} [options.concurrency]   - Max concurrent path probes (default 5)
 * @param {boolean} [options.skipPathScan] - Skip sensitive path probing
 * @param {boolean} [options.skipRedirectCheck] - Skip open redirect checks
 * @param {boolean} [options.skipFormAnalysis]  - Skip HTML form analysis
 * @param {boolean} [options.skipDirectoryListing] - Skip directory listing detection
 * @returns {Promise<object>} Scan report
 */
async function scanUrl(targetUrl, options = {}) {
  const startTime = Date.now();
  findingCounter = 0; // reset per scan

  // Validate URL
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new Error(`Invalid URL: ${targetUrl}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol: ${parsed.protocol}. Only http and https are supported.`);
  }

  const allFindings = [];

  // Step 1: Fetch the main page
  let mainResponse;
  try {
    mainResponse = await makeRequest(targetUrl, {
      method: 'GET',
      timeout: options.timeout || 10000,
      followRedirects: true,
    });
  } catch (err) {
    throw new Error(`Failed to connect to ${targetUrl}: ${err.message}`);
  }

  // 1. Security Headers
  const headerFindings = checkSecurityHeaders(mainResponse.headers, targetUrl);
  allFindings.push(...headerFindings);

  // 2. Cookie Security
  const cookieFindings = checkCookieSecurity(mainResponse.headers);
  allFindings.push(...cookieFindings);

  // 3. Server Information Disclosure
  const serverFindings = checkServerDisclosure(mainResponse.headers);
  allFindings.push(...serverFindings);

  // 4. Sensitive Path Probing
  if (!options.skipPathScan) {
    const pathFindings = await probeSensitivePaths(targetUrl, options);
    allFindings.push(...pathFindings);
  }

  // 5. Directory Listing Detection
  if (!options.skipDirectoryListing) {
    const dirFindings = await checkDirectoryListing(targetUrl, options);
    allFindings.push(...dirFindings);
  }

  // 6. Open Redirect Check
  if (!options.skipRedirectCheck) {
    const redirectFindings = await checkOpenRedirects(targetUrl, options);
    allFindings.push(...redirectFindings);
  }

  // 7. HTML Form Analysis
  if (!options.skipFormAnalysis) {
    const formFindings = analyzeHtmlForms(mainResponse.body, targetUrl);
    allFindings.push(...formFindings);
  }

  // Build summary
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    grade: 'A',
  };

  for (const f of allFindings) {
    switch (f.severity) {
      case 'Critical':
        summary.critical++;
        break;
      case 'High':
        summary.high++;
        break;
      case 'Medium':
        summary.medium++;
        break;
      case 'Low':
        summary.low++;
        break;
      case 'Info':
        summary.info++;
        break;
    }
  }

  summary.grade = calculateGrade(summary);

  const duration = Date.now() - startTime;

  return {
    url: targetUrl,
    scanDate: new Date().toISOString(),
    duration,
    findings: allFindings,
    summary,
  };
}

module.exports = { scanUrl, makeRequest };
