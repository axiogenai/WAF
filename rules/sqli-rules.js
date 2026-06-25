'use strict';

/**
 * ShieldWall WAF — SQL Injection Rule Signatures
 *
 * Each rule object:
 *   id          – unique rule identifier (SQLI-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp executed with the 'i' flag (case-insensitive)
 *
 * Patterns are intentionally broad enough to catch evasion attempts while
 * narrow enough to avoid common false-positives on normal text.
 */

const sqliRules = [
  // ───────────────────────── Tautologies ─────────────────────────
  {
    id: 'SQLI-0001',
    severity: 'critical',
    description: 'Tautology: OR 1=1 variant',
    pattern: /[^a-z0-9]\s*OR\s+1\s*=\s*1/i,
  },
  {
    id: 'SQLI-0002',
    severity: 'critical',
    description: "Tautology: OR 'x'='x' quoted-string equality",
    pattern: /[^a-z0-9]\s*OR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/i,
  },
  {
    id: 'SQLI-0003',
    severity: 'critical',
    description: 'Tautology: OR true / OR 1',
    pattern: /[^a-z0-9]\s*OR\s+(true|1)\b/i,
  },
  {
    id: 'SQLI-0004',
    severity: 'high',
    description: 'Tautology: numeric equality bypass (e.g. 1=1, 2=2)',
    pattern: /[^a-z0-9]\s*OR\s+\d+\s*=\s*\d+/i,
  },
  {
    id: 'SQLI-0005',
    severity: 'high',
    description: "Tautology: OR ''='' variant",
    pattern: /[^a-z0-9]\s*OR\s+['"]{2}\s*=\s*['"]{2}/i,
  },
  {
    id: 'SQLI-0006',
    severity: 'high',
    description: 'Tautology: AND 1=1 always-true probe',
    pattern: /[^a-z0-9]\s*AND\s+\d+\s*=\s*\d+/i,
  },
  {
    id: 'SQLI-0007',
    severity: 'critical',
    description: 'Tautology: OR with identical quoted values',
    pattern: /OR\s+(['"])([^'"]+)\1\s*=\s*\1\2\1/i,
  },
  {
    id: 'SQLI-0008',
    severity: 'critical',
    description: 'Tautology: quote-break OR with equality (broad catch-all)',
    pattern: /['"]\s*OR\s+.{1,30}=.{1,30}/i,
  },

  // ───────────────────────── Union-based ─────────────────────────
  {
    id: 'SQLI-0010',
    severity: 'critical',
    description: 'Union-based injection: UNION SELECT',
    pattern: /UNION\s+(ALL\s+)?SELECT\b/i,
  },
  {
    id: 'SQLI-0011',
    severity: 'critical',
    description: 'Union-based injection: UNION SELECT with column enumeration',
    pattern: /UNION\s+(ALL\s+)?SELECT\s+NULL/i,
  },
  {
    id: 'SQLI-0012',
    severity: 'high',
    description: 'Union-based injection: ORDER BY enumeration probe',
    pattern: /ORDER\s+BY\s+\d{2,}/i,
  },

  // ───────────────────── Stacked queries ─────────────────────
  {
    id: 'SQLI-0020',
    severity: 'critical',
    description: 'Stacked query: DROP TABLE / DROP DATABASE',
    pattern: /;\s*DROP\s+(TABLE|DATABASE|SCHEMA)\b/i,
  },
  {
    id: 'SQLI-0021',
    severity: 'critical',
    description: 'Stacked query: INSERT INTO',
    pattern: /;\s*INSERT\s+INTO\b/i,
  },
  {
    id: 'SQLI-0022',
    severity: 'critical',
    description: 'Stacked query: UPDATE … SET',
    pattern: /;\s*UPDATE\s+\S+\s+SET\b/i,
  },
  {
    id: 'SQLI-0023',
    severity: 'critical',
    description: 'Stacked query: DELETE FROM',
    pattern: /;\s*DELETE\s+FROM\b/i,
  },
  {
    id: 'SQLI-0024',
    severity: 'critical',
    description: 'Stacked query: ALTER TABLE',
    pattern: /;\s*ALTER\s+TABLE\b/i,
  },
  {
    id: 'SQLI-0025',
    severity: 'critical',
    description: 'Stacked query: CREATE TABLE',
    pattern: /;\s*CREATE\s+(TABLE|DATABASE)\b/i,
  },
  {
    id: 'SQLI-0026',
    severity: 'critical',
    description: 'Stacked query: EXEC / EXECUTE statement',
    pattern: /;\s*EXEC(UTE)?\s/i,
  },

  // ──────────────────── Comment injection ────────────────────
  {
    id: 'SQLI-0030',
    severity: 'medium',
    description: 'SQL comment sequence: double-dash (--)',
    pattern: /['"].*--/i,
  },
  {
    id: 'SQLI-0031',
    severity: 'medium',
    description: 'SQL block comment: /* … */',
    pattern: /\/\*[\s\S]*?\*\//,
  },
  {
    id: 'SQLI-0032',
    severity: 'medium',
    description: 'MySQL comment injection: # end-of-line comment',
    pattern: /['"].*#/i,
  },
  {
    id: 'SQLI-0033',
    severity: 'medium',
    description: 'URL-encoded hash comment (%23)',
    pattern: /['"].*%23/i,
  },
  {
    id: 'SQLI-0034',
    severity: 'medium',
    description: 'MySQL version comment: /*!',
    pattern: /\/\*!/,
  },

  // ──────────────────── Blind SQL injection ────────────────────
  {
    id: 'SQLI-0040',
    severity: 'critical',
    description: 'Blind SQLi: SLEEP() time-based',
    pattern: /SLEEP\s*\(\s*\d+/i,
  },
  {
    id: 'SQLI-0041',
    severity: 'critical',
    description: 'Blind SQLi: BENCHMARK() time-based',
    pattern: /BENCHMARK\s*\(\s*\d+/i,
  },
  {
    id: 'SQLI-0042',
    severity: 'critical',
    description: 'Blind SQLi: WAITFOR DELAY (MSSQL)',
    pattern: /WAITFOR\s+DELAY\s+'/i,
  },
  {
    id: 'SQLI-0043',
    severity: 'high',
    description: 'Blind SQLi: pg_sleep() (PostgreSQL)',
    pattern: /pg_sleep\s*\(/i,
  },
  {
    id: 'SQLI-0044',
    severity: 'high',
    description: 'Blind SQLi: IF() conditional probe',
    pattern: /IF\s*\(.*SELECT/i,
  },
  {
    id: 'SQLI-0045',
    severity: 'high',
    description: 'Blind SQLi: CASE WHEN conditional probe',
    pattern: /CASE\s+WHEN\s+.*THEN/i,
  },

  // ──────────────────── Error-based injection ────────────────────
  {
    id: 'SQLI-0050',
    severity: 'critical',
    description: 'Error-based: EXTRACTVALUE()',
    pattern: /EXTRACTVALUE\s*\(/i,
  },
  {
    id: 'SQLI-0051',
    severity: 'critical',
    description: 'Error-based: UPDATEXML()',
    pattern: /UPDATEXML\s*\(/i,
  },
  {
    id: 'SQLI-0052',
    severity: 'high',
    description: 'Error-based: CONVERT() type coercion',
    pattern: /CONVERT\s*\(.*USING/i,
  },
  {
    id: 'SQLI-0053',
    severity: 'high',
    description: 'Error-based: EXP() overflow probe',
    pattern: /EXP\s*\(\s*~\s*\(/i,
  },
  {
    id: 'SQLI-0054',
    severity: 'high',
    description: 'Error-based: GTID_SUBSET() (MySQL ≥5.6)',
    pattern: /GTID_SUBSET\s*\(/i,
  },

  // ──────────────────── Common tool signatures ────────────────────
  {
    id: 'SQLI-0060',
    severity: 'critical',
    description: 'sqlmap payload marker',
    pattern: /sqlmap/i,
  },
  {
    id: 'SQLI-0061',
    severity: 'high',
    description: 'sqlmap boundary string probe',
    pattern: /q[a-z]{3}[A-Z]{3}[a-z]{3}/,
  },

  // ──────────────────── Encoded variants ────────────────────
  {
    id: 'SQLI-0070',
    severity: 'high',
    description: 'Hex-encoded SELECT (0x53454C454354)',
    pattern: /0x5[34]454[Cc]454[Cc]54/i,
  },
  {
    id: 'SQLI-0071',
    severity: 'high',
    description: 'URL-encoded single quote (%27)',
    pattern: /%27\s*(OR|AND|UNION|SELECT)/i,
  },
  {
    id: 'SQLI-0072',
    severity: 'high',
    description: 'Double URL-encoded single quote (%2527)',
    pattern: /%2527/i,
  },
  {
    id: 'SQLI-0073',
    severity: 'medium',
    description: 'Char() / CHR() string construction',
    pattern: /CHAR\s*\(\s*\d+(\s*,\s*\d+){2,}/i,
  },
  {
    id: 'SQLI-0074',
    severity: 'medium',
    description: 'CONCAT() string assembly',
    pattern: /CONCAT\s*\(.*SELECT/i,
  },

  // ──────────────── Suspicious SQL keywords in payloads ───────────────
  {
    id: 'SQLI-0080',
    severity: 'high',
    description: 'SELECT … FROM pattern in user input',
    pattern: /SELECT\s+.{1,200}\s+FROM\s+/i,
  },
  {
    id: 'SQLI-0081',
    severity: 'high',
    description: 'INSERT INTO … VALUES pattern',
    pattern: /INSERT\s+INTO\s+\S+\s*\(.*\)\s*VALUES/i,
  },
  {
    id: 'SQLI-0082',
    severity: 'high',
    description: 'UPDATE … SET pattern',
    pattern: /UPDATE\s+\S+\s+SET\s+\S+\s*=/i,
  },
  {
    id: 'SQLI-0083',
    severity: 'high',
    description: 'DELETE FROM pattern',
    pattern: /DELETE\s+FROM\s+\S+/i,
  },
  {
    id: 'SQLI-0084',
    severity: 'critical',
    description: 'DROP TABLE / DROP DATABASE keyword',
    pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)\s+/i,
  },
  {
    id: 'SQLI-0085',
    severity: 'high',
    description: 'INFORMATION_SCHEMA access probe',
    pattern: /INFORMATION_SCHEMA\.(TABLES|COLUMNS|SCHEMATA)/i,
  },
  {
    id: 'SQLI-0086',
    severity: 'high',
    description: 'MySQL system table probe: mysql.user',
    pattern: /mysql\s*\.\s*user/i,
  },
  {
    id: 'SQLI-0087',
    severity: 'high',
    description: 'LOAD_FILE() or INTO OUTFILE / DUMPFILE',
    pattern: /(LOAD_FILE|INTO\s+(OUT|DUMP)FILE)\s*\(/i,
  },

  // ──────────────────── Auth bypass patterns ────────────────────
  {
    id: 'SQLI-0090',
    severity: 'critical',
    description: "Auth bypass: admin'-- pattern",
    pattern: /admin\s*['"]--/i,
  },
  {
    id: 'SQLI-0091',
    severity: 'critical',
    description: "Auth bypass: ' OR ''=' tautology",
    pattern: /['"]\s*OR\s*['"]{2}\s*=\s*['"/]/i,
  },
  {
    id: 'SQLI-0092',
    severity: 'critical',
    description: "Auth bypass: ') OR ('1'='1",
    pattern: /['"]\s*\)\s*OR\s*\(\s*['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  },
  {
    id: 'SQLI-0093',
    severity: 'high',
    description: 'Auth bypass: HAVING / GROUP BY enumeration',
    pattern: /'\s*(HAVING|GROUP\s+BY)\s+/i,
  },
];

module.exports = sqliRules;
