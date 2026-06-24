'use strict';

/**
 * ShieldWall WAF — Command Injection (OS Cmd-i) Rule Signatures
 *
 * Each rule object:
 *   id          – unique rule identifier (CMDI-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp
 */

const cmdiRules = [
  // ──────────────────── Shell metacharacters ────────────────────
  {
    id: 'CMDI-0001',
    severity: 'critical',
    description: 'Shell command separator: semicolon (;)',
    pattern: /;\s*(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|chmod|chown|rm|mv|cp|bash|sh|python|perl|ruby|php|node)\b/i,
  },
  {
    id: 'CMDI-0002',
    severity: 'critical',
    description: 'Shell pipe operator: | command',
    pattern: /\|\s*(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/i,
  },
  {
    id: 'CMDI-0003',
    severity: 'critical',
    description: 'Shell OR operator: || command',
    pattern: /\|\|\s*(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|bash|sh|python|perl)\b/i,
  },
  {
    id: 'CMDI-0004',
    severity: 'critical',
    description: 'Shell AND operator: && command',
    pattern: /&&\s*(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|bash|sh|python|perl)\b/i,
  },
  {
    id: 'CMDI-0005',
    severity: 'critical',
    description: 'Backtick command substitution: `command`',
    pattern: /`[^`]*\b(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|bash|sh|python|perl)\b[^`]*`/i,
  },
  {
    id: 'CMDI-0006',
    severity: 'critical',
    description: 'Dollar-paren command substitution: $(command)',
    pattern: /\$\(\s*(cat|ls|dir|id|whoami|uname|ifconfig|ipconfig|ping|wget|curl|nc|netcat|bash|sh|python|perl)\b/i,
  },
  {
    id: 'CMDI-0007',
    severity: 'high',
    description: 'Output redirection: > or >> to file',
    pattern: /\b(echo|printf|cat)\b.*>\s*\//i,
  },
  {
    id: 'CMDI-0008',
    severity: 'high',
    description: 'Input redirection: < from file',
    pattern: /<\s*\/\w/i,
  },

  // ──────────────────── Common recon / info-gathering ────────────────────
  {
    id: 'CMDI-0010',
    severity: 'high',
    description: 'Recon command: whoami',
    pattern: /\bwhoami\b/i,
  },
  {
    id: 'CMDI-0011',
    severity: 'high',
    description: 'Recon command: id (Unix user ID)',
    pattern: /[;|&`]\s*\bid\b/i,
  },
  {
    id: 'CMDI-0012',
    severity: 'high',
    description: 'Recon command: uname -a',
    pattern: /\buname\s+-[a-z]/i,
  },
  {
    id: 'CMDI-0013',
    severity: 'high',
    description: 'Recon command: cat /etc/passwd',
    pattern: /\bcat\s+\/etc\/passwd/i,
  },
  {
    id: 'CMDI-0014',
    severity: 'high',
    description: 'Network recon: ifconfig / ipconfig / ip addr',
    pattern: /\b(ifconfig|ipconfig|ip\s+addr)\b/i,
  },
  {
    id: 'CMDI-0015',
    severity: 'medium',
    description: 'DNS recon: nslookup / dig / host',
    pattern: /\b(nslookup|dig|host)\s+/i,
  },
  {
    id: 'CMDI-0016',
    severity: 'high',
    description: 'Download payload: wget / curl to remote URL',
    pattern: /\b(wget|curl)\s+https?:\/\//i,
  },
  {
    id: 'CMDI-0017',
    severity: 'high',
    description: 'Netcat listener / reverse connect: nc / netcat',
    pattern: /\b(nc|netcat|ncat)\s+(-[a-z]+\s+)*(-l|-e)/i,
  },

  // ──────────────────── Reverse shell patterns ────────────────────
  {
    id: 'CMDI-0020',
    severity: 'critical',
    description: 'Reverse shell: /dev/tcp/ (bash)',
    pattern: /\/dev\/tcp\//i,
  },
  {
    id: 'CMDI-0021',
    severity: 'critical',
    description: 'Reverse shell: bash -i >& /dev/tcp',
    pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp/i,
  },
  {
    id: 'CMDI-0022',
    severity: 'critical',
    description: 'Reverse shell: python -c (socket/pty)',
    pattern: /python[23]?\s+-c\s+['"]import\s+(socket|os|subprocess)/i,
  },
  {
    id: 'CMDI-0023',
    severity: 'critical',
    description: 'Reverse shell: perl -e (socket)',
    pattern: /perl\s+-e\s+['"].*socket/i,
  },
  {
    id: 'CMDI-0024',
    severity: 'critical',
    description: 'Reverse shell: ruby -rsocket or php -r fsockopen',
    pattern: /(ruby\s+-rsocket|php\s+-r\s+.*fsockopen)/i,
  },
  {
    id: 'CMDI-0025',
    severity: 'critical',
    description: 'Reverse shell: mkfifo pipe pattern',
    pattern: /mkfifo\s+/i,
  },

  // ──────────────────── Windows-specific ────────────────────
  {
    id: 'CMDI-0030',
    severity: 'critical',
    description: 'Windows command execution: cmd /c or cmd.exe',
    pattern: /cmd\s*(\.exe)?\s*\/[ck]\s/i,
  },
  {
    id: 'CMDI-0031',
    severity: 'critical',
    description: 'Windows command execution: powershell.exe / pwsh',
    pattern: /\b(powershell|pwsh)(\.exe)?\b/i,
  },
  {
    id: 'CMDI-0032',
    severity: 'high',
    description: 'Windows file read: type command',
    pattern: /\btype\s+[a-zA-Z]:\\|type\s+\S+\.\w{2,4}/i,
  },
  {
    id: 'CMDI-0033',
    severity: 'high',
    description: 'Windows user enumeration: net user / net localgroup',
    pattern: /\bnet\s+(user|localgroup|group)\b/i,
  },
  {
    id: 'CMDI-0034',
    severity: 'high',
    description: 'Windows process list: tasklist / wmic process',
    pattern: /\b(tasklist|wmic\s+process)\b/i,
  },
];

module.exports = cmdiRules;
