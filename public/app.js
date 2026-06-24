'use strict';

// ═══════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function fmtTime(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function toast(type, title, msg = '') {
  const icons = {
    success: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    error:   '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info:    '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  };
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `${icons[type] || icons.info}<div class="toast-content"><div class="toast-title">${esc(title)}</div>${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}</div>`;
  t.addEventListener('click', () => dismissToast(t));
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => dismissToast(t), 5000);
}

function dismissToast(el) {
  el.classList.add('out');
  setTimeout(() => el.remove(), 200);
}

function sevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high')     return 'sev-high';
  if (s === 'medium')   return 'sev-medium';
  if (s === 'low')      return 'sev-low';
  return 'sev-info';
}

// ═══════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════

function initNav() {
  document.querySelectorAll('.nav-btn[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;
      document.querySelectorAll('.nav-btn').forEach(b => { b.classList.remove('active'); b.removeAttribute('aria-current'); });
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      btn.setAttribute('aria-current', 'page');
      document.getElementById(tabId).classList.add('active');
    });
  });
}

// ═══════════════════════════════════════════════════════
// SCAN MODE TABS (URL / GitHub / Files)
// ═══════════════════════════════════════════════════════

function initScanModeTabs() {
  document.querySelectorAll('.scan-mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const panelId = tab.dataset.panel;
      const parent  = tab.closest('.card');
      parent.querySelectorAll('.scan-mode-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      parent.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      parent.querySelector('#' + panelId).classList.add('active');
    });
  });
}

// ═══════════════════════════════════════════════════════
// FILE DROP ZONE
// ═══════════════════════════════════════════════════════

function initDropZone(dropzoneId, inputId, listId, onFilesReady) {
  const zone  = document.getElementById(dropzoneId);
  const input = document.getElementById(inputId);
  const list  = document.getElementById(listId);
  let files   = [];

  function render() {
    list.innerHTML = files.map((f, i) => `
      <div class="file-item">
        <div class="file-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
        </div>
        <span class="file-item-name">${esc(f.name)}</span>
        <span class="file-item-size">${fmtSize(f.size)}</span>
        <button class="file-remove" data-i="${i}" aria-label="Remove ${esc(f.name)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>`).join('');
    list.querySelectorAll('.file-remove').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        files.splice(Number(btn.dataset.i), 1);
        render();
        onFilesReady(files);
      });
    });
    onFilesReady(files);
  }

  function add(newFiles) {
    files = [...files, ...Array.from(newFiles)].slice(0, 50);
    render();
  }

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('over'); add(e.dataTransfer.files); });
  input.addEventListener('change', () => { add(input.files); input.value = ''; });

  return () => files;
}

// ═══════════════════════════════════════════════════════
// SCAN RESULTS RENDERING
// ═══════════════════════════════════════════════════════

function computeGrade(findings) {
  if (!findings || !findings.length) return { letter: 'A+', pct: 100 };
  const weights = { critical: 40, high: 20, medium: 8, low: 2, info: 0 };
  let penalty = 0;
  for (const f of findings) penalty += weights[(f.severity || '').toLowerCase()] || 0;
  const score = Math.max(0, 100 - penalty);
  let letter = 'A+';
  if (score < 10)  letter = 'F';
  else if (score < 25)  letter = 'D';
  else if (score < 45)  letter = 'C';
  else if (score < 65)  letter = 'C+';
  else if (score < 75)  letter = 'B';
  else if (score < 85)  letter = 'B+';
  else if (score < 92)  letter = 'A';
  else if (score < 98)  letter = 'A+';
  return { letter, pct: score };
}

function gradeColor(letter) {
  if (letter === 'F')  return '#f85149';
  if (letter === 'D')  return '#d29922';
  if (letter.startsWith('C')) return '#e3b341';
  if (letter.startsWith('B')) return '#2f81f7';
  return '#3fb950';
}

function renderGrade(findings) {
  const { letter, pct } = computeGrade(findings);
  const ring = document.getElementById('grade-ring-fill');
  const gradeEl = document.getElementById('result-grade');
  const circ = 100.5;
  const offset = circ - (circ * pct / 100);
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = gradeColor(letter);
  gradeEl.textContent = letter;
  gradeEl.style.color = gradeColor(letter);
}

function renderSummaryGrid(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of (findings || [])) {
    const s = (f.severity || 'info').toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
    counts.total++;
  }
  const el = document.getElementById('result-summary');
  el.innerHTML = [
    { key: 'total',    label: 'Total',    cls: 'total'    },
    { key: 'critical', label: 'Critical', cls: 'critical' },
    { key: 'high',     label: 'High',     cls: 'high'     },
    { key: 'medium',   label: 'Medium',   cls: 'medium'   },
    { key: 'low',      label: 'Low',      cls: 'low'      },
  ].map(({ key, label, cls }) => `
    <div class="summary-card ${cls}">
      <div class="summary-card-value">${counts[key] || 0}</div>
      <div class="summary-card-label">${label}</div>
    </div>`).join('');
}

function renderFindings(findings, sourceLabel) {
  const list = document.getElementById('findings-list');
  const countEl = document.getElementById('findings-count');
  countEl.textContent = `${(findings || []).length} issues`;

  if (!findings || !findings.length) {
    list.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
      <h4>No issues found</h4>
      <p>This ${sourceLabel || 'target'} has no detectable vulnerabilities</p>
    </div>`;
    return;
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => (order[(a.severity||'').toLowerCase()]||4) - (order[(b.severity||'').toLowerCase()]||4));

  list.innerHTML = sorted.map((f, i) => `
    <div class="finding-item" data-i="${i}">
      <div class="finding-header">
        <span class="sev ${sevClass(f.severity)}">${esc(f.severity || 'Info')}</span>
        <span class="finding-title">${esc(f.title || f.check || 'Finding')}</span>
        ${f.filename || f.file ? `<span class="finding-file">${esc(f.filename || f.file)}</span>` : ''}
        <svg class="finding-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </div>
      <div class="finding-body">
        <div class="finding-body-inner">
          ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
          ${f.evidence ? `<div class="finding-label">Evidence</div><div class="finding-evidence">${esc(f.evidence)}</div>` : ''}
          ${(f.remediation || f.fix) ? `<div class="finding-label">Remediation</div><div class="finding-fix">${esc(f.remediation || f.fix)}</div>` : ''}
        </div>
      </div>
    </div>`).join('');

  list.querySelectorAll('.finding-item').forEach(item => {
    item.querySelector('.finding-header').addEventListener('click', () => {
      const body = item.querySelector('.finding-body');
      const isOpen = item.classList.toggle('open');
      body.classList.toggle('open', isOpen);
      body.style.maxHeight = isOpen ? body.scrollHeight + 'px' : '0';
    });
  });
}

function showScanResults(data, sourceLabel) {
  document.getElementById('scan-results').classList.remove('hidden');

  const findings = data.findings || data.vulnerabilities || [];

  renderGrade(findings);
  renderSummaryGrid(findings);
  renderFindings(findings, sourceLabel);

  const scanUrl = data.url || data.target || '';
  const scanned = data.filesScanned ? `${data.filesScanned} files scanned` : (scanUrl ? scanUrl : sourceLabel || 'scan');
  document.getElementById('result-headline').textContent = `${findings.length} issue${findings.length === 1 ? '' : 's'} found`;
  document.getElementById('result-sub').textContent = scanned;

  const headers = data.headers || {};
  const hasWaf  = !!(headers['x-protected-by'] || headers['cf-ray'] || headers['x-sucuri-id'] || headers['x-cdn']);
  if (window._showProtectBanner && scanUrl) window._showProtectBanner(scanUrl, hasWaf);

  if (findings.length > 0) loadDeployConfigs(scanUrl, findings);
}

let _deployConfigs = {};
let _activeConfigTab = 'nginx';

async function loadDeployConfigs(url, findings) {
  const panel = document.getElementById('deploy-fix-panel');
  if (!panel) return;
  panel.classList.remove('hidden');
  document.getElementById('config-code-content').textContent = 'Generating configs...';

  try {
    const r = await fetch('/api/scan/configs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, findings })
    });
    _deployConfigs = await r.json();
    renderConfigTab(_activeConfigTab);
  } catch {
    document.getElementById('config-code-content').textContent = '# Error generating config. Try again.';
  }
}

function renderConfigTab(tab) {
  _activeConfigTab = tab;
  const el = document.getElementById('config-code-content');
  if (el) el.textContent = _deployConfigs[tab] || '# Not available';
  document.querySelectorAll('.config-tab').forEach(b => b.classList.toggle('active', b.dataset.cfg === tab));
}

function initConfigPanel() {
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('config-tab')) renderConfigTab(e.target.dataset.cfg);
  });

  document.getElementById('btn-copy-config')?.addEventListener('click', async () => {
    const code = document.getElementById('config-code-content')?.textContent || '';
    try {
      await navigator.clipboard.writeText(code);
      const btn = document.getElementById('btn-copy-config');
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    } catch { toast('error', 'Copy failed — select text manually'); }
  });
}


// ═══════════════════════════════════════════════════════
// SCANNER TAB
// ═══════════════════════════════════════════════════════

function initScanner() {
  let pollInterval = null;

  function setProgress(fillId, pctId, statusId, wrapId, pct, status) {
    document.getElementById(wrapId).classList.remove('hidden');
    document.getElementById(fillId).style.width = pct + '%';
    document.getElementById(pctId).textContent  = pct + '%';
    document.getElementById(statusId).textContent = status;
  }

  // ── URL scan ──────────────────────────────────────────
  document.getElementById('btn-scan-url').addEventListener('click', async () => {
    const url = document.getElementById('url-scan-input').value.trim();
    if (!url) { toast('warning', 'Enter a URL first'); return; }
    if (!url.startsWith('http')) { toast('warning', 'URL must start with http:// or https://'); return; }

    const btn = document.getElementById('btn-scan-url');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    setProgress('url-progress-fill', 'url-progress-pct', 'url-progress-status', 'url-progress', 5, 'Starting scan...');

    try {
      const r = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const startData = await r.json();
      if (!r.ok) throw new Error(startData.error || 'Failed to start scan');

      clearInterval(pollInterval);
      let prev = 0;
      pollInterval = setInterval(async () => {
        try {
          const sr = await fetch('/api/scan/status');
          const status = await sr.json();
          const pct = Math.max(prev, status.progress || 0);
          prev = pct;
          const checkName = status.checks && status.checks.length ? status.checks[status.checks.length - 1].name : 'Scanning...';
          setProgress('url-progress-fill', 'url-progress-pct', 'url-progress-status', 'url-progress', pct, checkName);
          if (status.status === 'complete') {
            clearInterval(pollInterval);
            setProgress('url-progress-fill', 'url-progress-pct', 'url-progress-status', 'url-progress', 100, 'Done');
            showScanResults(status.result, url);
            toast('success', 'Scan complete', `${(status.result?.findings || []).length} issues found`);
            btn.disabled = false; btn.textContent = 'Scan';
          } else if (status.status === 'error') {
            clearInterval(pollInterval);
            toast('error', 'Scan failed', status.error);
            btn.disabled = false; btn.textContent = 'Scan';
          }
        } catch {}
      }, 1000);
    } catch (e) {
      toast('error', 'Scan error', e.message);
      btn.disabled = false; btn.textContent = 'Scan';
    }
  });

  // ── GitHub scan ───────────────────────────────────────
  document.getElementById('btn-scan-github').addEventListener('click', async () => {
    const url = document.getElementById('github-scan-input').value.trim();
    if (!url) { toast('warning', 'Enter a GitHub URL'); return; }

    const btn = document.getElementById('btn-scan-github');
    btn.disabled = true; btn.textContent = 'Cloning...';
    setProgress('github-progress-fill', 'github-progress-pct', 'github-progress-status', 'github-progress', 5, 'Cloning repository...');

    try {
      const r = await fetch('/api/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Clone failed');

      setProgress('github-progress-fill', 'github-progress-pct', 'github-progress-status', 'github-progress', 100, 'Done');
      showScanResults(data.codeAnalysis || data, `${data.repoName} (${data.filesScanned} files)`);
      toast('success', 'Repo scan complete', `${data.filesScanned} files analyzed`);
    } catch (e) {
      toast('error', 'GitHub scan failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Clone & Scan';
    }
  });

  // ── File upload scan ──────────────────────────────────
  let scannerGetFiles = initDropZone('scanner-dropzone', 'scanner-file-input', 'scanner-file-list', files => {
    document.getElementById('btn-analyze-code').disabled = files.length === 0;
  });

  document.getElementById('btn-analyze-code').addEventListener('click', async () => {
    const files = scannerGetFiles();
    if (!files.length) { toast('warning', 'Upload some files first'); return; }

    const btn = document.getElementById('btn-analyze-code');
    btn.disabled = true; btn.textContent = 'Analyzing...';

    try {
      const fd = new FormData();
      files.forEach(f => fd.append('files', f));
      const r = await fetch('/api/scan/code', { method: 'POST', body: fd });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Analysis failed');
      showScanResults(data, 'uploaded files');
      toast('success', 'Analysis complete', `${(data.findings || data.vulnerabilities || []).length} issues found`);
    } catch (e) {
      toast('error', 'Analysis failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Analyze Code';
    }
  });

  // ── Export report ─────────────────────────────────────
  document.getElementById('btn-download-report').addEventListener('click', async () => {
    try {
      const r = await fetch('/api/scan/report');
      if (!r.ok) { const d = await r.json(); throw new Error(d.error); }
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'shieldwall-report.html';
      a.click();
    } catch (e) {
      toast('error', 'Export failed', e.message);
    }
  });
}

// ═══════════════════════════════════════════════════════
// HARDENER TAB
// ═══════════════════════════════════════════════════════

function initHardener() {
  let hardenGetFiles = initDropZone('hardener-dropzone', 'hardener-file-input', 'hardener-file-list', files => {
    document.getElementById('btn-harden').disabled = files.length === 0;
  });

  let lastPatches = [];
  let lastFiles   = [];
  let lastGithubUrl = '';

  function showHardenResults(data) {
    const det  = data.detection || {};
    const patches = data.patches || [];
    lastPatches = patches;
    lastFiles   = data.files || [];
    lastGithubUrl = data.repoUrl || '';

    document.getElementById('harden-results').classList.remove('hidden');

    document.getElementById('fw-icon').textContent  = det.icon || '⚙️';
    document.getElementById('fw-name').textContent  = det.framework || 'Unknown';
    document.getElementById('fw-sub').textContent   = det.version ? `v${det.version}` : (det.serverHeader ? `Server: ${det.serverHeader}` : 'Detected from project files');
    const conf = Math.round(det.confidence || 0);
    document.getElementById('conf-fill').style.width  = conf + '%';
    document.getElementById('conf-label').textContent = conf + '% confidence';

    const badge = document.getElementById('patches-badge');
    badge.textContent = `${patches.length} patch${patches.length === 1 ? '' : 'es'}`;

    renderPatches(patches);
    document.getElementById('patch-actions-footer').style.display = patches.length ? '' : 'none';
    document.getElementById('select-all-row').style.display = patches.length ? '' : 'none';
  }

  function renderPatches(patches) {
    const container = document.getElementById('patches-container');
    if (!patches.length) {
      container.innerHTML = `<div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        <h4>No patches generated</h4>
        <p>No security issues were found that require patching</p>
      </div>`;
      return;
    }

    container.innerHTML = patches.map((p, i) => {
      const isNewFile = p.type === 'create_file' || p.type === 'server_config';
      return `
        <div class="patch-card checked-card" data-i="${i}" data-checked="true">
          <div class="patch-header">
            <div class="patch-check checked" data-i="${i}">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            </div>
            <span class="sev ${sevClass(p.severity || 'medium')}">${esc(p.severity || 'Medium')}</span>
            <span class="patch-title">${esc(p.title || p.description || 'Security Patch')}</span>
            <span class="patch-file">${esc(p.filename || '')}</span>
            <button class="patch-expand-btn" data-i="${i}" aria-label="Expand patch">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
            </button>
          </div>
          <div class="patch-body">
            <div class="patch-body-inner">
              ${p.description ? `<div class="patch-desc">${esc(p.description)}</div>` : ''}
              ${isNewFile ? `
                <div class="patch-newfile">
                  <div class="patch-newfile-header">
                    <span class="badge-new">${p.type === 'server_config' ? 'Config' : 'New'}</span>
                    <span class="patch-newfile-name">${esc(p.filename || 'config')}</span>
                  </div>
                  <details class="patch-details">
                    <summary class="patch-summary">View remediation guide</summary>
                    <pre class="patch-pre">${esc(p.patched || '')}</pre>
                  </details>
                </div>` : (p.original !== undefined && p.patched !== undefined ? `
                <div class="diff-grid">
                  <div class="diff-pane diff-before">
                    <div class="diff-label">Before</div>
                    <div class="diff-pane-scroll"><pre>${esc(p.original || '(empty)')}</pre></div>
                  </div>
                  <div class="diff-pane diff-after">
                    <div class="diff-label">After</div>
                    <div class="diff-pane-scroll"><pre>${esc(p.patched || '(empty)')}</pre></div>
                  </div>
                </div>` : '')}
            </div>
          </div>
        </div>`;
    }).join('');

    // Expand/collapse
    container.querySelectorAll('.patch-expand-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const card = btn.closest('.patch-card');
        const body = card.querySelector('.patch-body');
        const isExp = card.classList.toggle('expanded');
        body.style.maxHeight = isExp ? body.scrollHeight + 'px' : '0';
      });
    });

    // Checkbox toggle
    container.querySelectorAll('.patch-check').forEach(chk => {
      chk.addEventListener('click', e => {
        e.stopPropagation();
        const card = chk.closest('.patch-card');
        const checked = card.dataset.checked !== 'true';
        card.dataset.checked = String(checked);
        chk.classList.toggle('checked', checked);
        updateSelectAllState();
      });
    });

    updateSelectAllState();
  }

  function updateSelectAllState() {
    const cards = document.querySelectorAll('#patches-container .patch-card');
    const checkedCount = [...cards].filter(c => c.dataset.checked === 'true').length;
    document.getElementById('selected-count-badge').textContent = `${checkedCount} selected`;
    const allChk = document.getElementById('chk-select-all');
    allChk.indeterminate = checkedCount > 0 && checkedCount < cards.length;
    allChk.checked = checkedCount === cards.length;
  }

  document.getElementById('chk-select-all').addEventListener('change', e => {
    const checked = e.target.checked;
    document.querySelectorAll('#patches-container .patch-card').forEach(card => {
      card.dataset.checked = String(checked);
      card.querySelector('.patch-check').classList.toggle('checked', checked);
    });
    updateSelectAllState();
  });

  function getSelectedIndices() {
    return [...document.querySelectorAll('#patches-container .patch-card')]
      .map((c, i) => c.dataset.checked === 'true' ? i : null)
      .filter(i => i !== null);
  }

  // ── File upload harden ────────────────────────────────
  document.getElementById('btn-harden').addEventListener('click', async () => {
    const files = hardenGetFiles();
    if (!files.length) { toast('warning', 'Upload project files first'); return; }

    const btn = document.getElementById('btn-harden');
    btn.disabled = true; btn.textContent = 'Analyzing...';
    try {
      const fd = new FormData();
      files.forEach(f => fd.append('files', f));
      const r = await fetch('/api/harden/upload', { method: 'POST', body: fd });
      const uploadData = await r.json();
      if (!r.ok) throw new Error(uploadData.error);

      const r2 = await fetch('/api/harden/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const data = await r2.json();
      if (!r2.ok) throw new Error(data.error);

      showHardenResults(data);
      toast('success', 'Hardening complete', `${data.patches?.length || 0} patches generated`);
    } catch (e) {
      toast('error', 'Hardening failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Detect & Harden';
    }
  });

  // ── GitHub harden ─────────────────────────────────────
  document.getElementById('btn-harden-github').addEventListener('click', async () => {
    const url = document.getElementById('harden-github-input').value.trim();
    if (!url) { toast('warning', 'Enter a GitHub URL'); return; }

    const btn = document.getElementById('btn-harden-github');
    const prog = document.getElementById('harden-github-progress');
    btn.disabled = true; btn.textContent = 'Cloning...';
    prog.classList.remove('hidden');

    function setP(pct, status) {
      document.getElementById('harden-github-progress-fill').style.width = pct + '%';
      document.getElementById('harden-github-progress-pct').textContent = pct + '%';
      document.getElementById('harden-github-progress-status').textContent = status;
    }
    setP(10, 'Cloning repository...');

    try {
      const r = await fetch('/api/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      setP(80, 'Generating patches...');
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);

      setP(100, 'Done');
      lastGithubUrl = url;
      showHardenResults({ ...data.hardenResult, repoUrl: url });
      toast('success', 'Repo hardened', `${data.hardenResult?.patches?.length || 0} patches generated`);
    } catch (e) {
      toast('error', 'GitHub hardening failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Harden Repo';
    }
  });

  // ── URL harden ────────────────────────────────────────
  document.getElementById('btn-harden-url').addEventListener('click', async () => {
    const url = document.getElementById('harden-url-input').value.trim();
    if (!url) { toast('warning', 'Enter a URL first'); return; }
    if (!url.startsWith('http')) { toast('warning', 'URL must start with http:// or https://'); return; }

    const btn = document.getElementById('btn-harden-url');
    btn.disabled = true; btn.textContent = 'Probing...';

    try {
      const r = await fetch('/api/harden/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);

      showHardenResults(data);
      toast('success', 'Analysis complete', `${data.patches?.length || 0} recommendations generated`);
    } catch (e) {
      toast('error', 'URL hardening failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Generate Patches';
    }
  });

  // ── Patch actions ─────────────────────────────────────
  document.getElementById('btn-download-patched').addEventListener('click', async () => {
    const indices = getSelectedIndices();
    if (!indices.length) { toast('warning', 'Select at least one patch'); return; }
    try {
      const r = await fetch('/api/harden/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ patches: indices })
      });
      if (!r.ok) { const d = await r.json(); throw new Error(d.error); }
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'hardened-code.zip';
      a.click();
      toast('success', 'Download started');
    } catch (e) {
      toast('error', 'Download failed', e.message);
    }
  });

  document.getElementById('btn-show-local-apply').addEventListener('click', () => {
    const s = document.getElementById('local-apply-section');
    const g = document.getElementById('github-push-container');
    g.classList.add('hidden');
    s.classList.toggle('hidden');
  });

  document.getElementById('btn-show-github-push').addEventListener('click', () => {
    const s = document.getElementById('local-apply-section');
    const g = document.getElementById('github-push-container');
    s.classList.add('hidden');
    g.classList.toggle('hidden');
  });

  document.getElementById('btn-write-local').addEventListener('click', async () => {
    const localPath = document.getElementById('local-project-path').value.trim();
    if (!localPath) { toast('warning', 'Enter a directory path'); return; }
    const indices = getSelectedIndices();
    const btn = document.getElementById('btn-write-local');
    btn.disabled = true; btn.textContent = 'Writing...';
    try {
      const r = await fetch('/api/harden/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ patches: indices, localPath })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);
      toast('success', 'Applied to disk', data.message);
    } catch (e) {
      toast('error', 'Failed to apply', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Apply';
    }
  });

  document.getElementById('btn-github-push').addEventListener('click', async () => {
    const token   = document.getElementById('github-pat').value.trim();
    const branch  = document.getElementById('github-branch').value.trim();
    const msg     = document.getElementById('github-commit-msg').value.trim();
    if (!token) { toast('warning', 'Enter a GitHub PAT token'); return; }
    if (!lastGithubUrl) { toast('warning', 'Run GitHub hardening first to set the repo URL'); return; }
    const indices = getSelectedIndices();
    const btn = document.getElementById('btn-github-push');
    btn.disabled = true; btn.textContent = 'Pushing...';
    try {
      const r = await fetch('/api/harden/github/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: lastGithubUrl, patches: indices, token, branch, commitMessage: msg })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);
      toast('success', 'Pushed to GitHub', data.message);

      // Auto-trigger a re-scan to show the clean/updated state
      setTimeout(() => {
        toast('info', 'Re-scanning repository to verify patches...');
        document.getElementById('btn-harden-github')?.click();
      }, 1000);
    } catch (e) {
      toast('error', 'Push failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Commit & Push Changes';
    }
  });
}

// ═══════════════════════════════════════════════════════
// PROTECT TAB — WAF PROXY
// ═══════════════════════════════════════════════════════



// ═══════════════════════════════════════════════════════
// PROTECT SITES / DOMAINS TAB
// ═══════════════════════════════════════════════════════

function initDomains() {
  let domainsLogInterval = null;
  let lastScanUrl = '';

  const serverHost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'adityax26-waf.hf.space'
    : window.location.host;

  const hostEl = document.getElementById('this-server-host');
  if (hostEl) hostEl.textContent = serverHost;

  const dnsValEl = document.getElementById('dns-record-value');
  if (dnsValEl) dnsValEl.textContent = serverHost;

  const navBadge = document.getElementById('domains-nav-badge');

  async function loadDomains() {
    try {
      const r = await fetch('/api/waf/domains');
      const domains = await r.json();
      renderDomainList(Array.isArray(domains) ? domains : Object.values(domains));
      if (navBadge) navBadge.textContent = Array.isArray(domains) ? domains.length : Object.keys(domains).length;
    } catch {}
  }

  function renderDomainList(domains) {
    const listEl = document.getElementById('domains-list');
    const cntBadge = document.getElementById('domains-count-badge');
    if (cntBadge) cntBadge.textContent = `${domains.length} site${domains.length === 1 ? '' : 's'}`;

    const filterSel = document.getElementById('waf-domain-filter');
    if (filterSel) {
      const current = filterSel.value;
      filterSel.innerHTML = '<option value="">All domains</option>' +
        domains.map(d => `<option value="${esc(d.domain)}" ${d.domain === current ? 'selected' : ''}>${esc(d.domain)}</option>`).join('');
    }

    if (!domains.length) {
      listEl.innerHTML = `<div class="empty-state" id="domains-empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        <h4>No sites registered yet</h4>
        <p>Register a domain above to start protecting it</p>
      </div>`;
      return;
    }

    listEl.innerHTML = domains.map(d => `
      <div class="domain-card">
        <div class="domain-card-header">
          <div class="domain-info">
            <div class="domain-active-dot"></div>
            <div>
              <div class="domain-name">${esc(d.domain)}</div>
              <div class="domain-origin">${esc(d.origin)}</div>
            </div>
          </div>
          <div class="domain-stats">
            <div class="domain-stat">
              <span class="domain-stat-value">${(d.stats?.total || 0).toLocaleString()}</span>
              <span class="domain-stat-label">Total</span>
            </div>
            <div class="domain-stat">
              <span class="domain-stat-value" style="color:var(--green)">${(d.stats?.allowed || 0).toLocaleString()}</span>
              <span class="domain-stat-label">Allowed</span>
            </div>
            <div class="domain-stat">
              <span class="domain-stat-value" style="color:var(--red)">${(d.stats?.blocked || 0).toLocaleString()}</span>
              <span class="domain-stat-label">Blocked</span>
            </div>
          </div>
          <div class="domain-actions">
            <button class="btn btn-ghost btn-sm domain-dns-btn" data-domain="${esc(d.domain)}">DNS Setup</button>
            <button class="btn btn-danger btn-sm domain-remove-btn" data-domain="${esc(d.domain)}">Remove</button>
          </div>
        </div>
        <div class="domain-dns-panel hidden" id="dns-panel-${esc(d.domain).replace(/\./g, '-')}">
          <div class="dns-record-card">
            <div class="dns-row"><span class="dns-col-label">Type</span><span class="dns-col-value">CNAME</span></div>
            <div class="dns-row"><span class="dns-col-label">Name</span><span class="dns-col-value">${esc(d.domain)}</span></div>
            <div class="dns-row"><span class="dns-col-label">Value</span><span class="dns-col-value">${esc(serverHost)}</span></div>
            <div class="dns-row"><span class="dns-col-label">TTL</span><span class="dns-col-value">Auto</span></div>
          </div>
        </div>
      </div>`).join('');

    listEl.querySelectorAll('.domain-remove-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm(`Remove ${btn.dataset.domain} from WAF protection?`)) return;
        await fetch(`/api/waf/domains/${encodeURIComponent(btn.dataset.domain)}`, { method: 'DELETE' });
        toast('info', `${btn.dataset.domain} removed`);
        loadDomains();
      });
    });

    listEl.querySelectorAll('.domain-dns-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const panelId = 'dns-panel-' + btn.dataset.domain.replace(/\./g, '-');
        const panel = document.getElementById(panelId);
        if (panel) panel.classList.toggle('hidden');
      });
    });
  }

  async function fetchWafLogs() {
    try {
      const domain = document.getElementById('waf-domain-filter')?.value || '';
      const blocked = document.getElementById('chk-waf-blocked-only')?.checked;
      let url = `/api/waf/logs?limit=100`;
      if (domain) url += `&domain=${encodeURIComponent(domain)}`;
      if (blocked) url += `&blocked=true`;
      const r = await fetch(url);
      const logs = await r.json();
      const tbody = document.getElementById('waf-log-tbody');
      if (!tbody) return;
      if (!logs.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:20px">${blocked ? 'No blocked requests' : 'No traffic yet'}</td></tr>`;
        return;
      }
      tbody.innerHTML = logs.map(l => `
        <tr class="${l.blocked ? 'blocked' : ''}">
          <td>${fmtTime(l.timestamp)}</td>
          <td>${esc(l.host || '-')}</td>
          <td>${esc(l.method || 'GET')}</td>
          <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l.path || '/')}</td>
          <td>${esc(l.ip || '-')}</td>
          <td><span class="log-blocked-badge ${l.blocked ? 'yes' : 'no'}">${l.blocked ? 'Blocked' : 'Allowed'}</span></td>
          <td>${esc(l.category || '-')}</td>
        </tr>`).join('');
    } catch {}
  }

  document.getElementById('chk-waf-blocked-only')?.addEventListener('change', fetchWafLogs);
  document.getElementById('waf-domain-filter')?.addEventListener('change', fetchWafLogs);

  document.querySelector('[data-tab="tab-domains"]')?.addEventListener('click', () => {
    loadDomains();
    fetchWafLogs();
    clearInterval(domainsLogInterval);
    domainsLogInterval = setInterval(fetchWafLogs, 3000);
  });

  loadDomains();

  // ── Protect-site banner ────────────────────────────────
  const banner     = document.getElementById('protect-site-banner');
  const btnProtect = document.getElementById('btn-protect-this-site');

  window._showProtectBanner = function(url, hasWaf) {
    lastScanUrl = url;
    if (!hasWaf && banner) banner.classList.remove('hidden');
    else if (banner)       banner.classList.add('hidden');
  };

  btnProtect?.addEventListener('click', async () => {
    if (!lastScanUrl) return;

    let domain, origin;
    try {
      const u = new URL(lastScanUrl);
      domain = u.hostname.startsWith('www.') ? u.hostname : 'www.' + u.hostname;
      origin = lastScanUrl;
    } catch { toast('error', 'Invalid scanned URL'); return; }

    btnProtect.disabled = true;
    btnProtect.textContent = 'Enabling...';

    try {
      const r = await fetch('/api/waf/domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, origin })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);

      document.getElementById('dns-record-name').textContent  = domain;
      document.getElementById('dns-record-value').textContent = serverHost;
      document.getElementById('modal-step-1').classList.add('hidden');
      document.getElementById('modal-step-2').classList.remove('hidden');
      document.getElementById('protect-modal').classList.remove('hidden');
      loadDomains();
      toast('success', `${domain} is now protected`);
    } catch (e) {
      toast('error', 'Registration failed', e.message);
    } finally {
      btnProtect.disabled = false;
      btnProtect.textContent = 'Enable WAF Protection';
    }
  });

  document.getElementById('btn-modal-close')?.addEventListener('click', () => {
    document.getElementById('protect-modal')?.classList.add('hidden');
  });
  document.getElementById('protect-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
  });

  document.getElementById('btn-register-domain')?.addEventListener('click', async () => {
    const domain = document.getElementById('protect-domain').value.trim();
    const origin = document.getElementById('protect-origin').value.trim();
    if (!domain || !origin) { toast('warning', 'Fill in both fields'); return; }
    const btn = document.getElementById('btn-register-domain');
    btn.disabled = true; btn.textContent = 'Registering...';
    try {
      const r = await fetch('/api/waf/domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, origin })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error);
      document.getElementById('dns-record-name').textContent = domain;
      document.getElementById('dns-record-value').textContent = serverHost;
      document.getElementById('modal-step-1').classList.add('hidden');
      document.getElementById('modal-step-2').classList.remove('hidden');
      loadDomains();
      toast('success', `${domain} is now protected`);
    } catch (e) {
      toast('error', 'Registration failed', e.message);
    } finally {
      btn.disabled = false; btn.textContent = 'Register & Get DNS Instructions';
    }
  });

  document.getElementById('btn-go-to-domains')?.addEventListener('click', () => {
    document.getElementById('protect-modal')?.classList.add('hidden');
    document.querySelector('[data-tab="tab-domains"]')?.click();
  });
}



document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initScanModeTabs();
  initScanner();
  initHardener();
  initDomains();
  initConfigPanel();
});

