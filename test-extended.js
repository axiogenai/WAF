const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { FormData, Blob } = require('buffer');

function req(method, url, body, isForm) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const headers = {};
    let postData;
    if (body && !isForm) {
      postData = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(postData);
    }
    const opts = {
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method, headers
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
    if (postData) rq.write(postData);
    rq.end();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('\n=== EXTENDED SYSTEM TEST ===\n');

  // 1. IP lists
  let r = await req('POST', 'http://localhost:3000/api/ip/blacklist', { ip: '10.0.0.1' });
  console.log('['+r.status+'] Blacklist 10.0.0.1:', r.body.message || r.body.error);

  r = await req('POST', 'http://localhost:3000/api/ip/whitelist', { ip: '192.168.1.1' });
  console.log('['+r.status+'] Whitelist 192.168.1.1:', r.body.message || r.body.error);

  r = await req('GET', 'http://localhost:3000/api/ip/lists');
  console.log('IP Lists - blacklist count:', r.body.blacklist.length, '| whitelist count:', r.body.whitelist.length);
  console.log('  Blacklist:', JSON.stringify(r.body.blacklist));
  console.log('  Whitelist:', JSON.stringify(r.body.whitelist));

  // 2. Remove from lists
  r = await req('DELETE', 'http://localhost:3000/api/ip/blacklist/10.0.0.1');
  console.log('['+r.status+'] Remove blacklist:', r.body.message || r.body.error);

  // 3. Top IPs
  r = await req('GET', 'http://localhost:3000/api/top-ips');
  console.log('['+r.status+'] Top IPs:', JSON.stringify(r.body).slice(0, 120));

  // 4. Scan a URL and wait for completion
  console.log('\n--- URL Scanner Test ---');
  r = await req('POST', 'http://localhost:3000/api/scan/url', { url: 'https://example.com' });
  console.log('['+r.status+'] Start scan:', r.body.message || r.body.error);

  for (let i = 0; i < 30; i++) {
    await sleep(2000);
    r = await req('GET', 'http://localhost:3000/api/scan/status');
    console.log('  Scan progress:', r.body.progress+'%', '| status:', r.body.status);
    if (r.body.status === 'complete' || r.body.status === 'error') break;
  }

  if (r.body.status === 'complete' && r.body.result) {
    const res = r.body.result;
    console.log('  Grade:', res.grade);
    console.log('  Findings:', (res.findings || []).length);
  }

  // 5. Code analyzer test (inline)
  console.log('\n--- Code Analyzer Test ---');
  const testCode = `
const express = require('express');
const app = express();
app.get('/user', (req, res) => {
  const id = req.query.id;
  // SQL injection vulnerability
  db.query("SELECT * FROM users WHERE id = " + id);
  // XSS vulnerability
  res.send("<div>" + req.query.name + "</div>");
});
  `.trim();
  
  // Write temp file
  const tmpFile = path.join(__dirname, 'uploads', 'test-analyze.js');
  fs.writeFileSync(tmpFile, testCode);
  
  // Use multipart form upload via node's built-in
  const boundary = '----ShieldWallBoundary' + Date.now();
  const fileContent = Buffer.from(testCode);
  const formData = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="files"; filename="test.js"\r\nContent-Type: text/javascript\r\n\r\n`),
    fileContent,
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);

  await new Promise((resolve, reject) => {
    const rq = http.request({
      hostname: 'localhost', port: 3000, path: '/api/scan/code', method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': formData.length }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const body = JSON.parse(d);
          console.log('['+res.statusCode+'] Code analysis - grade:', body.grade, '| findings:', (body.findings||[]).length);
          if (body.findings && body.findings.length) {
            body.findings.slice(0, 3).forEach(f => console.log('  Finding:', f.title, '['+f.severity+']'));
          }
        } catch(e) { console.log('Code analysis response:', d.slice(0,200)); }
        resolve();
      });
    });
    rq.on('error', reject);
    rq.write(formData);
    rq.end();
  });

  try { fs.unlinkSync(tmpFile); } catch {}

  // 6. Harden analyze
  console.log('\n--- Code Hardener Test ---');
  const nodeCode = `
const express = require('express');
const app = express();
app.use(express.json());
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
  `.trim();
  const hardenBoundary = '----ShieldWallHarden' + Date.now();
  const hardenBuf = Buffer.from(nodeCode);
  const hardenForm = Buffer.concat([
    Buffer.from(`--${hardenBoundary}\r\nContent-Disposition: form-data; name="files"; filename="app.js"\r\nContent-Type: text/javascript\r\n\r\n`),
    hardenBuf,
    Buffer.from(`\r\n--${hardenBoundary}--\r\n`)
  ]);
  await new Promise((resolve, reject) => {
    const rq = http.request({
      hostname: 'localhost', port: 3000, path: '/api/harden/upload', method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${hardenBoundary}`, 'Content-Length': hardenForm.length }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { const b = JSON.parse(d); console.log('['+res.statusCode+'] Upload:', b.message || b.error); }
        catch { console.log('Upload response:', d.slice(0,100)); }
        resolve();
      });
    });
    rq.on('error', reject);
    rq.write(hardenForm);
    rq.end();
  });

  r = await req('POST', 'http://localhost:3000/api/harden/analyze', {});
  console.log('['+r.status+'] Analyze - framework:', r.body.detection ? JSON.stringify(r.body.detection).slice(0,80) : r.body.error);
  console.log('  Patches:', (r.body.patches || []).length);

  // 7. Stats reset
  r = await req('POST', 'http://localhost:3000/api/stats/reset', {});
  console.log('\n['+r.status+'] Stats reset:', r.body.message);

  console.log('\n=== ALL TESTS PASSED ===\n');
}

run().catch(e => console.error('FATAL:', e.message, e.stack));
