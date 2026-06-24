'use strict';

// ---------------------------------------------------------------------------
// ShieldWall — HTML Security Report Generator
// ---------------------------------------------------------------------------

const SEVERITY_COLORS = {
  Critical: '#e74c3c',
  High: '#e67e22',
  Medium: '#f1c40f',
  Low: '#3498db',
  Info: '#95a5a6',
};

const GRADE_COLORS = {
  A: '#27ae60',
  B: '#2ecc71',
  C: '#f1c40f',
  D: '#e67e22',
  F: '#e74c3c',
};

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function formatDate(isoString) {
  try {
    const d = new Date(isoString);
    return d.toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return isoString;
  }
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  const s = (ms / 1000).toFixed(1);
  return `${s}s`;
}

function buildSeverityBadge(severity) {
  const color = SEVERITY_COLORS[severity] || '#95a5a6';
  return `<span class="severity-badge" style="background:${color}">${escapeHtml(severity)}</span>`;
}

function buildGradeBadge(grade) {
  const color = GRADE_COLORS[grade] || '#95a5a6';
  return `<div class="grade-badge" style="background:${color}"><span class="grade-letter">${escapeHtml(grade)}</span><span class="grade-label">Security Grade</span></div>`;
}

function buildSeverityBar(summary) {
  const total = summary.critical + summary.high + summary.medium + summary.low + summary.info;
  if (total === 0) {
    return '<div class="severity-bar"><div class="bar-segment" style="width:100%;background:#27ae60;color:#fff;text-align:center;padding:8px 0">No findings</div></div>';
  }

  const segments = [
    { label: 'Critical', count: summary.critical, color: SEVERITY_COLORS.Critical },
    { label: 'High', count: summary.high, color: SEVERITY_COLORS.High },
    { label: 'Medium', count: summary.medium, color: SEVERITY_COLORS.Medium },
    { label: 'Low', count: summary.low, color: SEVERITY_COLORS.Low },
    { label: 'Info', count: summary.info, color: SEVERITY_COLORS.Info },
  ];

  let html = '<div class="severity-bar">';
  for (const seg of segments) {
    if (seg.count === 0) continue;
    const pct = ((seg.count / total) * 100).toFixed(1);
    html += `<div class="bar-segment" style="width:${pct}%;background:${seg.color}" title="${seg.label}: ${seg.count}">${seg.count > 0 ? seg.count : ''}</div>`;
  }
  html += '</div>';

  // Legend
  html += '<div class="severity-legend">';
  for (const seg of segments) {
    html += `<span class="legend-item"><span class="legend-dot" style="background:${seg.color}"></span>${seg.label}: ${seg.count}</span>`;
  }
  html += '</div>';

  return html;
}

function buildFindingsTable(findings, sectionTitle) {
  if (!findings || findings.length === 0) {
    return `<div class="section"><h2>${escapeHtml(sectionTitle)}</h2><p class="no-findings">No findings in this category.</p></div>`;
  }

  // Group by severity
  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const sorted = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  let html = `<div class="section"><h2>${escapeHtml(sectionTitle)}</h2>`;
  html += '<div class="findings-list">';

  for (const f of sorted) {
    html += `<div class="finding-card">`;
    html += `<div class="finding-header">`;
    html += buildSeverityBadge(f.severity);
    html += `<span class="finding-id">${escapeHtml(f.id || '')}</span>`;
    html += `<h3 class="finding-title">${escapeHtml(f.title)}</h3>`;
    html += `</div>`;

    if (f.category) {
      html += `<div class="finding-meta"><strong>Category:</strong> ${escapeHtml(f.category)}</div>`;
    }
    if (f.file) {
      html += `<div class="finding-meta"><strong>File:</strong> ${escapeHtml(f.file)}${f.line ? ` (line ${f.line})` : ''}</div>`;
    }

    html += `<div class="finding-body">`;
    html += `<div class="finding-field"><strong>Description</strong><p>${escapeHtml(f.description)}</p></div>`;

    if (f.evidence) {
      html += `<div class="finding-field"><strong>Evidence</strong><pre class="evidence">${escapeHtml(f.evidence)}</pre></div>`;
    }
    if (f.code) {
      html += `<div class="finding-field"><strong>Code</strong><pre class="code-snippet">${escapeHtml(f.code)}</pre></div>`;
    }
    if (f.remediation) {
      html += `<div class="finding-field remediation"><strong>Remediation</strong><p>${escapeHtml(f.remediation)}</p></div>`;
    }

    html += `</div></div>`;
  }

  html += '</div></div>';
  return html;
}

function buildStyles() {
  return `
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      
      :root {
        --bg-primary: #0f1117;
        --bg-secondary: #1a1d27;
        --bg-card: #1e2130;
        --bg-code: #151822;
        --border: #2a2d3e;
        --text-primary: #e1e4ed;
        --text-secondary: #8b8fa3;
        --text-muted: #5e6278;
        --accent: #6366f1;
        --accent-light: #818cf8;
        --success: #27ae60;
        --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        --font-mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, 'Courier New', monospace;
      }

      body {
        font-family: var(--font-sans);
        background: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        font-size: 14px;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }

      .container {
        max-width: 1100px;
        margin: 0 auto;
        padding: 0 24px;
      }

      /* Header */
      .report-header {
        background: linear-gradient(135deg, #1a1d27 0%, #0f1117 100%);
        border-bottom: 1px solid var(--border);
        padding: 40px 0;
      }
      .header-inner {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 24px;
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: linear-gradient(135deg, var(--accent) 0%, #4f46e5 100%);
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 28px;
        box-shadow: 0 4px 16px rgba(99, 102, 241, 0.3);
      }
      .brand-text h1 {
        font-size: 26px;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: #fff;
      }
      .brand-text .subtitle {
        font-size: 13px;
        color: var(--text-secondary);
        margin-top: 2px;
      }
      .scan-meta {
        text-align: right;
        font-size: 13px;
        color: var(--text-secondary);
        line-height: 1.8;
      }
      .scan-meta strong {
        color: var(--text-primary);
      }

      /* Executive Summary */
      .exec-summary {
        padding: 40px 0;
        border-bottom: 1px solid var(--border);
      }
      .exec-summary h2 {
        font-size: 20px;
        font-weight: 600;
        margin-bottom: 24px;
        color: var(--text-primary);
      }
      .summary-grid {
        display: grid;
        grid-template-columns: auto 1fr;
        gap: 32px;
        align-items: start;
      }
      .grade-badge {
        width: 140px;
        height: 140px;
        border-radius: 20px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        transition: transform 0.2s;
      }
      .grade-badge:hover { transform: scale(1.05); }
      .grade-letter {
        font-size: 64px;
        font-weight: 800;
        color: #fff;
        line-height: 1;
        text-shadow: 0 2px 4px rgba(0,0,0,0.3);
      }
      .grade-label {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: rgba(255,255,255,0.85);
        margin-top: 6px;
      }
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 12px;
      }
      .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px;
        text-align: center;
      }
      .stat-number {
        font-size: 32px;
        font-weight: 700;
        line-height: 1.1;
      }
      .stat-label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-secondary);
        margin-top: 4px;
      }

      /* Severity Bar */
      .severity-bar {
        display: flex;
        height: 32px;
        border-radius: 8px;
        overflow: hidden;
        margin: 16px 0 8px;
        border: 1px solid var(--border);
      }
      .bar-segment {
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: 700;
        color: #fff;
        min-width: 28px;
        transition: opacity 0.2s;
      }
      .bar-segment:hover { opacity: 0.85; }
      .severity-legend {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        margin-top: 8px;
      }
      .legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        color: var(--text-secondary);
      }
      .legend-dot {
        width: 10px;
        height: 10px;
        border-radius: 3px;
        display: inline-block;
      }

      /* Sections */
      .section {
        padding: 32px 0;
        border-bottom: 1px solid var(--border);
      }
      .section:last-child { border-bottom: none; }
      .section h2 {
        font-size: 20px;
        font-weight: 600;
        margin-bottom: 20px;
        padding-bottom: 12px;
        border-bottom: 2px solid var(--accent);
        display: inline-block;
      }

      /* Finding Cards */
      .findings-list {
        display: flex;
        flex-direction: column;
        gap: 16px;
      }
      .finding-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
        transition: border-color 0.2s;
      }
      .finding-card:hover { border-color: var(--accent); }
      .finding-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px 20px;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        flex-wrap: wrap;
      }
      .finding-id {
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-muted);
        background: var(--bg-primary);
        padding: 2px 8px;
        border-radius: 4px;
      }
      .finding-title {
        font-size: 15px;
        font-weight: 600;
        color: var(--text-primary);
        flex: 1;
        min-width: 200px;
      }
      .finding-meta {
        padding: 6px 20px;
        font-size: 12px;
        color: var(--text-secondary);
        border-bottom: 1px solid rgba(42, 45, 62, 0.5);
      }
      .finding-body {
        padding: 16px 20px;
      }
      .finding-field {
        margin-bottom: 14px;
      }
      .finding-field:last-child { margin-bottom: 0; }
      .finding-field strong {
        display: block;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-secondary);
        margin-bottom: 6px;
      }
      .finding-field p {
        color: var(--text-primary);
        line-height: 1.65;
        font-size: 13px;
      }
      .remediation {
        background: rgba(39, 174, 96, 0.08);
        border: 1px solid rgba(39, 174, 96, 0.2);
        border-radius: 8px;
        padding: 12px 16px;
      }
      .remediation strong { color: var(--success); }
      pre.evidence, pre.code-snippet {
        background: var(--bg-code);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px 16px;
        font-family: var(--font-mono);
        font-size: 12px;
        line-height: 1.5;
        overflow-x: auto;
        color: #c8ccd8;
        white-space: pre-wrap;
        word-break: break-all;
      }

      /* Severity Badge */
      .severity-badge {
        display: inline-flex;
        align-items: center;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #fff;
        white-space: nowrap;
      }

      .no-findings {
        color: var(--text-secondary);
        font-style: italic;
        padding: 24px;
        text-align: center;
        background: var(--bg-card);
        border-radius: 12px;
        border: 1px dashed var(--border);
      }

      /* Footer */
      .report-footer {
        padding: 32px 0;
        text-align: center;
        border-top: 1px solid var(--border);
        margin-top: 40px;
      }
      .footer-brand {
        font-size: 14px;
        font-weight: 600;
        color: var(--text-secondary);
      }
      .footer-brand span { color: var(--accent-light); }
      .footer-meta {
        font-size: 11px;
        color: var(--text-muted);
        margin-top: 8px;
      }
      .footer-disclaimer {
        font-size: 11px;
        color: var(--text-muted);
        margin-top: 16px;
        max-width: 600px;
        margin-left: auto;
        margin-right: auto;
        line-height: 1.6;
      }

      /* Table of Contents */
      .toc {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px 24px;
        margin: 24px 0;
      }
      .toc h3 {
        font-size: 14px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-secondary);
        margin-bottom: 12px;
      }
      .toc ul {
        list-style: none;
        padding: 0;
      }
      .toc li {
        padding: 6px 0;
        font-size: 13px;
      }
      .toc a {
        color: var(--accent-light);
        text-decoration: none;
      }
      .toc a:hover { text-decoration: underline; }
      .toc .toc-count {
        color: var(--text-muted);
        font-size: 12px;
        margin-left: 8px;
      }

      /* Responsive */
      @media (max-width: 768px) {
        .summary-grid { grid-template-columns: 1fr; justify-items: center; }
        .header-inner { flex-direction: column; }
        .scan-meta { text-align: left; }
        .stats-grid { grid-template-columns: repeat(3, 1fr); }
        .finding-header { flex-direction: column; align-items: flex-start; }
      }

      @media print {
        body { background: #fff; color: #000; }
        .container { max-width: 100%; }
        .finding-card { break-inside: avoid; border: 1px solid #ccc; }
        .report-header { background: #f5f5f5; }
        .severity-bar .bar-segment { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .grade-badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .severity-badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      }
    </style>
  `;
}

/**
 * Generate a complete, self-contained HTML security audit report.
 *
 * @param {object|null} scanResult       - Output from scanUrl() (URL scan findings)
 * @param {object|null} codeAnalysisResult - Output from analyzeCode() (static analysis findings)
 * @returns {string} Complete HTML document string
 */
function generateReport(scanResult, codeAnalysisResult) {
  const now = new Date().toISOString();

  // Merge summaries
  const scanSummary = scanResult
    ? scanResult.summary
    : { critical: 0, high: 0, medium: 0, low: 0, info: 0, grade: 'A' };
  const codeSummary = codeAnalysisResult
    ? codeAnalysisResult.summary
    : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const combinedSummary = {
    critical: scanSummary.critical + codeSummary.critical,
    high: scanSummary.high + codeSummary.high,
    medium: scanSummary.medium + codeSummary.medium,
    low: scanSummary.low + codeSummary.low,
    info: scanSummary.info + codeSummary.info,
  };
  const totalFindings =
    combinedSummary.critical +
    combinedSummary.high +
    combinedSummary.medium +
    combinedSummary.low +
    combinedSummary.info;

  // Grade based on combined totals
  let grade;
  if (combinedSummary.critical === 0 && combinedSummary.high === 0) grade = 'A';
  else if (combinedSummary.critical === 0 && combinedSummary.high <= 2) grade = 'B';
  else if (combinedSummary.critical === 0 && combinedSummary.high <= 5) grade = 'C';
  else if (combinedSummary.critical <= 1) grade = 'D';
  else grade = 'F';

  const targetUrl = scanResult ? scanResult.url : 'N/A';
  const scanDate = scanResult ? scanResult.scanDate : now;
  const duration = scanResult ? scanResult.duration : 0;

  // Build HTML
  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldWall Security Report — ${escapeHtml(targetUrl)}</title>
  ${buildStyles()}
</head>
<body>

  <!-- Header -->
  <header class="report-header">
    <div class="container">
      <div class="header-inner">
        <div class="brand">
          <div class="brand-icon">&#x1F6E1;</div>
          <div class="brand-text">
            <h1>ShieldWall</h1>
            <div class="subtitle">Security Assessment Report</div>
          </div>
        </div>
        <div class="scan-meta">
          <div><strong>Target:</strong> ${escapeHtml(targetUrl)}</div>
          <div><strong>Scan Date:</strong> ${escapeHtml(formatDate(scanDate))}</div>
          <div><strong>Duration:</strong> ${escapeHtml(formatDuration(duration))}</div>
          <div><strong>Total Findings:</strong> ${totalFindings}</div>
        </div>
      </div>
    </div>
  </header>

  <main class="container">

    <!-- Executive Summary -->
    <div class="exec-summary">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        ${buildGradeBadge(grade)}
        <div>
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-number" style="color:${SEVERITY_COLORS.Critical}">${combinedSummary.critical}</div>
              <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
              <div class="stat-number" style="color:${SEVERITY_COLORS.High}">${combinedSummary.high}</div>
              <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
              <div class="stat-number" style="color:${SEVERITY_COLORS.Medium}">${combinedSummary.medium}</div>
              <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
              <div class="stat-number" style="color:${SEVERITY_COLORS.Low}">${combinedSummary.low}</div>
              <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
              <div class="stat-number" style="color:${SEVERITY_COLORS.Info}">${combinedSummary.info}</div>
              <div class="stat-label">Info</div>
            </div>
          </div>
          ${buildSeverityBar(combinedSummary)}
        </div>
      </div>
    </div>

    <!-- Table of Contents -->
    <div class="toc">
      <h3>Contents</h3>
      <ul>`;

  if (scanResult && scanResult.findings && scanResult.findings.length > 0) {
    html += `<li><a href="#url-scan">URL Scan Findings</a><span class="toc-count">${scanResult.findings.length} finding(s)</span></li>`;
  }
  if (codeAnalysisResult && codeAnalysisResult.findings && codeAnalysisResult.findings.length > 0) {
    html += `<li><a href="#code-analysis">Code Analysis Findings</a><span class="toc-count">${codeAnalysisResult.findings.length} finding(s)</span></li>`;

    // Subcategories for code analysis
    const codeCategories = {};
    for (const f of codeAnalysisResult.findings) {
      const cat = f.title.split(':')[0] || 'Other';
      codeCategories[cat] = (codeCategories[cat] || 0) + 1;
    }
    for (const [cat, count] of Object.entries(codeCategories)) {
      html += `<li style="padding-left:20px"><a href="#code-analysis">${escapeHtml(cat)}</a><span class="toc-count">${count}</span></li>`;
    }
  }

  html += `
      </ul>
    </div>`;

  // URL Scan Findings
  if (scanResult && scanResult.findings && scanResult.findings.length > 0) {
    html += `<div id="url-scan">`;
    html += buildFindingsTable(scanResult.findings, `URL Scan Findings — ${escapeHtml(targetUrl)}`);
    html += `</div>`;
  } else if (scanResult) {
    html += `<div id="url-scan" class="section"><h2>URL Scan Findings</h2><p class="no-findings">&#x2705; No vulnerabilities detected in the URL scan. Well done!</p></div>`;
  }

  // Code Analysis Findings
  if (codeAnalysisResult && codeAnalysisResult.findings && codeAnalysisResult.findings.length > 0) {
    html += `<div id="code-analysis">`;
    html += buildFindingsTable(
      codeAnalysisResult.findings,
      `Code Analysis Findings (${codeAnalysisResult.summary.totalFiles} file(s) scanned)`
    );
    html += `</div>`;

    // File breakdown table
    if (codeAnalysisResult.summary.fileBreakdown && Object.keys(codeAnalysisResult.summary.fileBreakdown).length > 0) {
      html += `<div class="section"><h2>File Breakdown</h2>`;
      html += `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">`;
      html += `<thead><tr style="border-bottom:2px solid var(--border)">`;
      html += `<th style="text-align:left;padding:10px;color:var(--text-secondary)">File</th>`;
      html += `<th style="text-align:center;padding:10px;color:${SEVERITY_COLORS.Critical}">Critical</th>`;
      html += `<th style="text-align:center;padding:10px;color:${SEVERITY_COLORS.High}">High</th>`;
      html += `<th style="text-align:center;padding:10px;color:${SEVERITY_COLORS.Medium}">Medium</th>`;
      html += `<th style="text-align:center;padding:10px;color:${SEVERITY_COLORS.Low}">Low</th>`;
      html += `<th style="text-align:center;padding:10px;color:${SEVERITY_COLORS.Info}">Info</th>`;
      html += `</tr></thead><tbody>`;

      for (const [file, counts] of Object.entries(codeAnalysisResult.summary.fileBreakdown)) {
        html += `<tr style="border-bottom:1px solid var(--border)">`;
        html += `<td style="padding:8px 10px;font-family:var(--font-mono);font-size:12px">${escapeHtml(file)}</td>`;
        html += `<td style="text-align:center;padding:8px">${counts.critical || 0}</td>`;
        html += `<td style="text-align:center;padding:8px">${counts.high || 0}</td>`;
        html += `<td style="text-align:center;padding:8px">${counts.medium || 0}</td>`;
        html += `<td style="text-align:center;padding:8px">${counts.low || 0}</td>`;
        html += `<td style="text-align:center;padding:8px">${counts.info || 0}</td>`;
        html += `</tr>`;
      }

      html += `</tbody></table></div></div>`;
    }
  } else if (codeAnalysisResult) {
    html += `<div id="code-analysis" class="section"><h2>Code Analysis Findings</h2><p class="no-findings">&#x2705; No vulnerabilities detected in the code analysis. Well done!</p></div>`;
  }

  // Footer
  html += `
    <!-- Footer -->
    <footer class="report-footer">
      <div class="footer-brand">Generated by <span>ShieldWall</span> Security Platform</div>
      <div class="footer-meta">${escapeHtml(formatDate(now))}</div>
      <div class="footer-disclaimer">
        This report is generated by automated security scanning tools and should be reviewed by a qualified
        security professional. False positives may occur. The findings in this report are based on the data
        available at the time of scanning and do not constitute a comprehensive penetration test. ShieldWall
        provides this report for informational purposes to assist in improving application security posture.
      </div>
    </footer>

  </main>
</body>
</html>`;

  return html;
}

module.exports = { generateReport };
