'use strict';

/**
 * ShieldWall WAF — Bot & Scanner Signature Database
 *
 * Exports:
 *   scannerPatterns  – regex patterns matching known security scanner / attack-tool User-Agents
 *   crawlerPatterns  – regex patterns matching aggressive or abusive crawlers
 *
 * Each entry is { name, pattern } so we can report *which* tool was detected.
 */

const scannerPatterns = [
  // ──── Vulnerability scanners ────
  { name: 'sqlmap',       pattern: /sqlmap/i },
  { name: 'Nikto',        pattern: /nikto/i },
  { name: 'Nmap',         pattern: /nmap/i },
  { name: 'Burp Suite',   pattern: /burp\s*(suite)?|burpcollaborator/i },
  { name: 'Masscan',      pattern: /masscan/i },
  { name: 'DirBuster',    pattern: /dirbuster/i },
  { name: 'GoBuster',     pattern: /gobuster/i },
  { name: 'wfuzz',        pattern: /wfuzz/i },
  { name: 'Hydra',        pattern: /hydra/i },
  { name: 'Acunetix',     pattern: /acunetix/i },
  { name: 'Nessus',       pattern: /nessus/i },
  { name: 'Qualys',       pattern: /qualys/i },
  { name: 'Arachni',      pattern: /arachni/i },
  { name: 'w3af',         pattern: /w3af/i },
  { name: 'OWASP ZAP',    pattern: /zap|owasp/i },
  { name: 'Skipfish',     pattern: /skipfish/i },
  { name: 'Wapiti',       pattern: /wapiti/i },
  { name: 'Vega',         pattern: /vega\/\d/i },
  { name: 'OpenVAS',      pattern: /openvas/i },
  { name: 'Nuclei',       pattern: /nuclei/i },
  { name: 'Jaeles',       pattern: /jaeles/i },
  { name: 'Commix',       pattern: /commix/i },
  { name: 'XSSer',        pattern: /xsser/i },
  { name: 'Havij',        pattern: /havij/i },
  { name: 'Pangolin',     pattern: /pangolin/i },
  { name: 'AppScan',      pattern: /appscan/i },
  { name: 'WebInspect',   pattern: /webinspect/i },
  { name: 'Paros',        pattern: /paros/i },
  { name: 'Grabber',      pattern: /grabber/i },
  { name: 'Fierce',       pattern: /fierce/i },
  { name: 'Whatweb',      pattern: /whatweb/i },
  { name: 'Httprint',     pattern: /httprint/i },
  { name: 'Dalfox',       pattern: /dalfox/i },
  { name: 'Ffuf',         pattern: /\bffuf\b/i },
  { name: 'Feroxbuster',  pattern: /feroxbuster/i },
  { name: 'Httpx',        pattern: /\bhttpx\b/i },
  { name: 'Subfinder',    pattern: /subfinder/i },
  { name: 'Amass',        pattern: /\bamass\b/i },
];

const crawlerPatterns = [
  { name: 'Scrapy',            pattern: /scrapy/i },
  { name: 'Python-Requests',   pattern: /python-requests/i },
  { name: 'Python-urllib',     pattern: /python-urllib/i },
  { name: 'Java Http Client',  pattern: /java\/\d|apache-httpclient|okhttp/i },
  { name: 'Go-http-client',    pattern: /go-http-client/i },
  { name: 'libwww-perl',       pattern: /libwww-perl/i },
  { name: 'Wget',              pattern: /\bwget\b/i },
  { name: 'Curl Bot',          pattern: /\bcurl\b/i },
  { name: 'Mechanize',         pattern: /mechanize/i },
  { name: 'Phantomjs',         pattern: /phantomjs/i },
  { name: 'HeadlessChrome',    pattern: /headlesschrome/i },
  { name: 'SlimerJS',          pattern: /slimerjs/i },
  { name: 'CasperJS',          pattern: /casperjs/i },
  { name: 'HTTrack',           pattern: /httrack/i },
  { name: 'Offline Explorer',  pattern: /offline\s*explorer/i },
  { name: 'LinkChecker',       pattern: /linkchecker/i },
  { name: 'WebCopier',         pattern: /webcopier/i },
  { name: 'Teleport',          pattern: /teleport/i },
  { name: 'SiteSucker',        pattern: /sitesucker/i },
  { name: 'Empty User-Agent',  pattern: /^$/  },
];

module.exports = { scannerPatterns, crawlerPatterns };
