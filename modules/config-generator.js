'use strict';

function generateNginxConfig(domain, findings) {
  const missingHeaders = getMissingHeaders(findings);
  const hasXSS          = hasVuln(findings, 'xss');
  const hasSQLi         = hasVuln(findings, 'sql');
  const hasTraversal    = hasVuln(findings, 'traversal');

  return `# ─── ShieldWall Security Config for ${domain} ───
# Drop this inside your nginx server {} block

server {
    listen 80;
    listen 443 ssl;
    server_name ${domain};

    # ── Security Headers ──────────────────────────────────
    ${missingHeaders.csp      ? `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none';" always;` : '# Content-Security-Policy: already set'}
    ${missingHeaders.hsts     ? `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;` : '# HSTS: already set'}
    ${missingHeaders.frame    ? `add_header X-Frame-Options "SAMEORIGIN" always;` : '# X-Frame-Options: already set'}
    ${missingHeaders.xss      ? `add_header X-XSS-Protection "1; mode=block" always;` : '# X-XSS-Protection: already set'}
    ${missingHeaders.nosniff  ? `add_header X-Content-Type-Options "nosniff" always;` : '# X-Content-Type-Options: already set'}
    ${missingHeaders.referrer ? `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` : '# Referrer-Policy: already set'}
    ${missingHeaders.perms    ? `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;` : '# Permissions-Policy: already set'}
    add_header X-Protected-By "ShieldWall-WAF" always;

    # ── Hide server info ──────────────────────────────────
    server_tokens off;
    more_clear_headers Server;
    more_clear_headers X-Powered-By;

    # ── Rate Limiting ─────────────────────────────────────
    limit_req_zone $binary_remote_addr zone=shieldwall:10m rate=30r/s;
    limit_req zone=shieldwall burst=60 nodelay;
    limit_conn_zone $binary_remote_addr zone=sw_conn:10m;
    limit_conn sw_conn 20;

    # ── Block Bad Bots & Scanners ─────────────────────────
    if ($http_user_agent ~* "(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|nuclei|acunetix|nessus)") {
        return 403;
    }

    # ── Block Common Attack Patterns ──────────────────────
    ${hasXSS ? `
    # Block XSS patterns
    if ($query_string ~* "(<script|javascript:|vbscript:|onload=|onerror=|onclick=|eval\\()") {
        return 403;
    }` : ''}
    ${hasSQLi ? `
    # Block SQL Injection patterns
    if ($query_string ~* "(union.*select|select.*from|drop.*table|insert.*into|delete.*from|or 1=1|or '1'='1'|benchmark\\(|sleep\\()") {
        return 403;
    }` : ''}
    ${hasTraversal ? `
    # Block Path Traversal
    if ($request_uri ~* "(\\.\\./|%2e%2e%2f|%252e%252e%252f)") {
        return 403;
    }` : ''}

    # ── Block Sensitive File Access ───────────────────────
    location ~* "(\\.env|\\.git|wp-config\\.php|\\.htpasswd|composer\\.lock|package\\.json|\\.DS_Store)" {
        return 404;
    }

    # ── Request Size Limits ───────────────────────────────
    client_max_body_size 10m;
    client_body_timeout 12s;
    client_header_timeout 12s;
}`;
}

function generateApacheConfig(domain, findings) {
  const missingHeaders = getMissingHeaders(findings);
  const hasXSS         = hasVuln(findings, 'xss');
  const hasSQLi        = hasVuln(findings, 'sql');

  return `# ─── ShieldWall .htaccess for ${domain} ───
# Place this in your document root

Options -Indexes -ExecCGI
ServerSignature Off

# ── Security Headers ──────────────────────────────────
<IfModule mod_headers.c>
    ${missingHeaders.csp      ? `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"` : '# CSP already set'}
    ${missingHeaders.hsts     ? `Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"` : '# HSTS already set'}
    ${missingHeaders.frame    ? `Header always set X-Frame-Options "SAMEORIGIN"` : '# X-Frame-Options already set'}
    ${missingHeaders.xss      ? `Header always set X-XSS-Protection "1; mode=block"` : '# X-XSS-Protection already set'}
    ${missingHeaders.nosniff  ? `Header always set X-Content-Type-Options "nosniff"` : '# X-Content-Type-Options already set'}
    ${missingHeaders.referrer ? `Header always set Referrer-Policy "strict-origin-when-cross-origin"` : '# Referrer-Policy already set'}
    Header always set X-Protected-By "ShieldWall-WAF"
    Header unset Server
    Header unset X-Powered-By
</IfModule>

# ── Block Sensitive Files ────────────────────────────
<FilesMatch "(\\.env|\\.git|wp-config\\.php|\\.htpasswd|composer\\.lock|\\.DS_Store)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# ── Block Attack Patterns ─────────────────────────────
<IfModule mod_rewrite.c>
    RewriteEngine On

    # Bad bots
    RewriteCond %{HTTP_USER_AGENT} (nikto|sqlmap|nmap|masscan|acunetix|nessus) [NC]
    RewriteRule .* - [F,L]

    # Path traversal
    RewriteCond %{THE_REQUEST} \\.\\./  [NC,OR]
    RewriteCond %{QUERY_STRING} (\\.\\./|%2e%2e%2f) [NC]
    RewriteRule .* - [F,L]
    ${hasSQLi ? `
    # SQL Injection
    RewriteCond %{QUERY_STRING} (union.*select|select.*from|drop.*table|or 1=1) [NC]
    RewriteRule .* - [F,L]` : ''}
    ${hasXSS ? `
    # XSS
    RewriteCond %{QUERY_STRING} (<script|javascript:|onerror=|onload=) [NC]
    RewriteRule .* - [F,L]` : ''}
</IfModule>`;
}

function generateCloudflareHeaders(domain, findings) {
  const m = getMissingHeaders(findings);
  return `# ─── Cloudflare Pages _headers for ${domain} ───
# Place this file in your project root

/*
  X-Protected-By: ShieldWall-WAF
  ${m.frame    ? 'X-Frame-Options: SAMEORIGIN' : ''}
  ${m.nosniff  ? 'X-Content-Type-Options: nosniff' : ''}
  ${m.xss      ? 'X-XSS-Protection: 1; mode=block' : ''}
  ${m.referrer ? 'Referrer-Policy: strict-origin-when-cross-origin' : ''}
  ${m.perms    ? 'Permissions-Policy: camera=(), microphone=(), geolocation=()' : ''}
  ${m.csp      ? "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';" : ''}
  ${m.hsts     ? 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' : ''}`.replace(/^\s*\n/gm, '');
}

function generateHtmlMetaTags(domain, findings) {
  const m = getMissingHeaders(findings);
  return `<!-- ShieldWall Security Meta Tags for ${domain} -->
<!-- Paste inside your <head> tag -->

${m.csp     ? `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none';">` : '<!-- CSP: set via server header (recommended) -->'}
${m.referrer ? `<meta name="referrer" content="strict-origin-when-cross-origin">` : ''}
<meta http-equiv="X-UA-Compatible" content="IE=edge">

<!-- Note: HSTS, X-Frame-Options, X-Content-Type-Options must be set via server headers.
     Meta tags cannot replace HTTP response headers for these. -->`;
}

function generateModSecurityRules(domain, findings) {
  const hasXSS      = hasVuln(findings, 'xss');
  const hasSQLi     = hasVuln(findings, 'sql');
  const hasTraversal = hasVuln(findings, 'traversal');

  return `# ─── ShieldWall ModSecurity Rules for ${domain} ───
# Add to your modsecurity.conf

SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 10485760

# ── Bad Bot Blocking ──────────────────────────────────
SecRule REQUEST_HEADERS:User-Agent "@rx (nikto|sqlmap|nmap|masscan|acunetix|nessus)" \\
    "id:1001,phase:1,deny,status:403,msg:'Blocked scanner bot'"

# ── Path Traversal ────────────────────────────────────
${hasTraversal ? `SecRule REQUEST_URI "@rx (\\.\\./|%2e%2e%2f|%252e%252e)" \\
    "id:1002,phase:1,deny,status:403,msg:'Path traversal attempt'"` : '# No traversal vulnerabilities detected'}

# ── SQL Injection ─────────────────────────────────────
${hasSQLi ? `SecRule ARGS "@rx (union.*select|select.*from|drop.*table|benchmark\\(|sleep\\()" \\
    "id:1003,phase:2,deny,status:403,msg:'SQL injection attempt'"` : '# No SQLi vulnerabilities detected'}

# ── XSS ──────────────────────────────────────────────
${hasXSS ? `SecRule ARGS "@rx (<script|javascript:|vbscript:|onerror=|onload=)" \\
    "id:1004,phase:2,deny,status:403,msg:'XSS attempt'"` : '# No XSS vulnerabilities detected'}

# ── Block Sensitive File Access ───────────────────────
SecRule REQUEST_URI "@rx (\\.env|\\.git/|wp-config\\.php|\\.htpasswd)" \\
    "id:1005,phase:1,deny,status:404,msg:'Sensitive file access blocked'"`;
}

function getMissingHeaders(findings) {
  const ids = findings.map(f => (f.id || f.check || '').toLowerCase());
  return {
    csp:      ids.some(i => i.includes('csp') || i.includes('content-security')),
    hsts:     ids.some(i => i.includes('hsts') || i.includes('strict-transport')),
    frame:    ids.some(i => i.includes('frame') || i.includes('clickjack')),
    xss:      ids.some(i => i.includes('xss') || i.includes('x-xss')),
    nosniff:  ids.some(i => i.includes('nosniff') || i.includes('content-type')),
    referrer: ids.some(i => i.includes('referrer')),
    perms:    ids.some(i => i.includes('permission')),
  };
}

function hasVuln(findings, type) {
  return findings.some(f => {
    const txt = ((f.id || '') + (f.title || '') + (f.description || '')).toLowerCase();
    return txt.includes(type);
  });
}

module.exports = {
  generateNginxConfig,
  generateApacheConfig,
  generateCloudflareHeaders,
  generateHtmlMetaTags,
  generateModSecurityRules,
};
