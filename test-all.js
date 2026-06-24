const http = require('http');
const https = require('https');

function req(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const opts = {
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method,
      headers: body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(JSON.stringify(body)) } : {}
    };
    const rq = mod.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch { resolve({ status: res.statusCode, body: d }); }
      });
    });
    rq.on('error', reject);
    if (body) rq.write(JSON.stringify(body));
    rq.end();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('\n=== SHIELDWALL FULL SYSTEM TEST ===\n');

  // 1. Status check
  let r = await req('GET', 'http://localhost:3000/api/status');
  console.log('[' + r.status + '] GET /api/status - proxyActive:', r.body.proxyActive);

  // 2. Save config
  r = await req('POST', 'http://localhost:3000/api/config', { proxyTarget: 'https://jsonplaceholder.typicode.com', proxyPort: 8080 });
  console.log('[' + r.status + '] POST /api/config:', r.body.message || r.body.error);

  // 3. Start proxy
  r = await req('POST', 'http://localhost:3000/api/proxy/start', {});
  console.log('[' + r.status + '] POST /api/proxy/start:', r.body.message || r.body.error);

  await sleep(1500);

  // 4. Test clean passthrough
  try {
    r = await req('GET', 'http://localhost:8080/posts/1');
    console.log('[' + r.status + '] PROXY GET /posts/1 -', r.status === 200 ? 'PASS ✓' : 'FAIL ✗');
  } catch(e) { console.log('[ERR] PROXY passthrough:', e.message); }

  // 5. Test SQL injection block
  try {
    r = await req('GET', "http://localhost:8080/search?q=' OR 1=1--");
    console.log('[' + r.status + '] SQL injection -', r.status === 403 ? 'BLOCKED ✓' : 'NOT BLOCKED ✗');
  } catch(e) { console.log('[ERR] SQL test:', e.message); }

  // 6. Test XSS block
  try {
    r = await req('GET', 'http://localhost:8080/search?q=<script>alert(1)</script>');
    console.log('[' + r.status + '] XSS -', r.status === 403 ? 'BLOCKED ✓' : 'NOT BLOCKED ✗');
  } catch(e) { console.log('[ERR] XSS test:', e.message); }

  // 7. Test path traversal
  try {
    r = await req('GET', 'http://localhost:8080/../../etc/passwd');
    console.log('[' + r.status + '] Path traversal -', r.status === 403 ? 'BLOCKED ✓' : 'NOT BLOCKED ✗');
  } catch(e) { console.log('[ERR] Path traversal:', e.message); }

  // 8. Check stats
  r = await req('GET', 'http://localhost:3000/api/status');
  const stats = r.body.stats || {};
  console.log('\nStats after tests:');
  console.log('  Total requests:', stats.totalRequests);
  console.log('  Blocked:', stats.blockedRequests);
  console.log('  Allowed:', stats.allowedRequests);

  // 9. Test IP blacklist
  r = await req('POST', 'http://localhost:3000/api/ip/blacklist', { ip: '1.2.3.4' });
  console.log('[' + r.status + '] Blacklist IP:', r.body.message || r.body.error);
  r = await req('GET', 'http://localhost:3000/api/ip/lists');
  console.log('IP lists - blacklist:', r.body.blacklist);

  // 10. URL scanner test
  r = await req('POST', 'http://localhost:3000/api/scan/url', { url: 'https://example.com' });
  console.log('[' + r.status + '] POST /api/scan/url:', r.body.message || r.body.error);
  
  await sleep(2000);
  r = await req('GET', 'http://localhost:3000/api/scan/status');
  console.log('Scan status:', r.body.status, '- progress:', r.body.progress);

  // 11. Code analysis test
  const { FormData, Blob } = require('buffer');
  // Simple test without file upload - just check endpoint responds

  // 12. Stop proxy
  r = await req('POST', 'http://localhost:3000/api/proxy/stop', {});
  console.log('[' + r.status + '] POST /api/proxy/stop:', r.body.message || r.body.error);

  console.log('\n=== TEST COMPLETE ===\n');
}

run().catch(e => console.error('FATAL:', e.message, e.stack));
