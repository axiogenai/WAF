'use strict';

// ---------------------------------------------------------------------------
// ShieldWall — Static Source Code Analyzer
// ---------------------------------------------------------------------------

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `CODE-${String(findingCounter).padStart(4, '0')}`;
}

/**
 * Determine the language of a file from its filename.
 */
function detectLanguage(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const map = {
    js: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    jsx: 'javascript',
    ts: 'javascript',
    tsx: 'javascript',
    py: 'python',
    php: 'php',
    json: 'json',
    yml: 'yaml',
    yaml: 'yaml',
    html: 'html',
    htm: 'html',
    env: 'env',
    cfg: 'config',
    ini: 'config',
    conf: 'config',
    rb: 'ruby',
    java: 'java',
    go: 'go',
  };
  return map[ext] || 'unknown';
}

/**
 * Return a context snippet around a given line number.
 */
function snippet(lines, lineIndex, contextSize = 0) {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length - 1, lineIndex + contextSize);
  return lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join('\n');
}

// ===================================================================
// 1. Hardcoded Secrets Detection
// ===================================================================

const SECRET_PATTERNS = [
  // AWS Access Key
  {
    regex: /AKIA[0-9A-Z]{16}/g,
    title: 'AWS Access Key ID Detected',
    description:
      'An AWS Access Key ID was found hardcoded in the source code. This key grants programmatic access to AWS services and should never be stored in code repositories.',
    remediation:
      'Remove the key from source code immediately. Rotate the compromised key in the AWS IAM console. Use environment variables or AWS Secrets Manager to manage credentials.',
  },
  // AWS Secret Key (generic high-entropy base64 near aws/secret context)
  {
    regex: /(?:aws_secret_access_key|aws_secret|AWS_SECRET)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    title: 'AWS Secret Access Key Detected',
    description:
      'An AWS Secret Access Key was found hardcoded. This, combined with an Access Key ID, grants full API access to AWS resources.',
    remediation:
      'Immediately rotate the key in the AWS IAM console. Store secrets using AWS Secrets Manager, environment variables, or a vault solution.',
  },
  // Google API Key
  {
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    title: 'Google API Key Detected',
    description:
      'A Google API key was found in the source code. Exposed API keys can be used to consume API quotas, access restricted services, or incur billing charges.',
    remediation:
      'Restrict the API key in the Google Cloud Console by IP, referrer, or API. Rotate the key and use environment variables instead of hardcoding.',
  },
  // OpenAI / Stripe secret key
  {
    regex: /sk-[a-zA-Z0-9]{32,}/g,
    title: 'Secret Key (OpenAI/Stripe Pattern) Detected',
    description:
      'A secret key matching the OpenAI or Stripe format (sk-...) was found in source code. These keys grant full API access and can result in data breaches or financial loss.',
    remediation:
      'Rotate the key immediately. Store API keys in environment variables or a secrets manager. Never commit secret keys to version control.',
  },
  // GitHub Token
  {
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    title: 'GitHub Token Detected',
    description:
      'A GitHub personal access token or OAuth token was found in source code. These tokens can be used to access private repositories, modify code, or manage organisation settings.',
    remediation:
      'Revoke the token in GitHub Settings → Developer Settings → Personal Access Tokens. Use environment variables or GitHub Actions secrets.',
  },
  // Slack Token
  {
    regex: /xox[bposa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/g,
    title: 'Slack Token Detected',
    description:
      'A Slack bot or user token was found. These tokens can be used to read messages, post content, and access workspace data.',
    remediation:
      'Revoke the token in Slack API settings. Regenerate and store the new token in a secrets manager.',
  },
  // Generic password assignment
  {
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"](?!\s*\))/gi,
    title: 'Hardcoded Password Detected',
    description:
      'A hardcoded password was found in the source code. Hardcoded credentials are easily discoverable and cannot be rotated without code changes.',
    remediation:
      'Remove the hardcoded password. Use environment variables, a .env file excluded from version control, or a secrets management service.',
  },
  // Generic secret assignment
  {
    regex: /(?:secret|client_secret|app_secret)\s*[=:]\s*['"]([^'"]{4,})['"](?!\s*\))/gi,
    title: 'Hardcoded Secret Value Detected',
    description:
      'A hardcoded secret value was found in the source code. Secrets in source code can be extracted by anyone with repository access.',
    remediation:
      'Move the secret to environment variables or a secrets manager. Ensure the value is not present in version control history.',
  },
  // Generic API key assignment
  {
    regex: /(?:api_key|apikey|api_secret|access_token)\s*[=:]\s*['"]([^'"]{8,})['"](?!\s*\))/gi,
    title: 'Hardcoded API Key or Token Detected',
    description:
      'A hardcoded API key or access token was found. Exposed tokens can lead to unauthorized access, data breaches, and financial liability.',
    remediation:
      'Rotate the exposed key/token. Use environment variables or a secrets vault. Add patterns to .gitignore and use pre-commit hooks to prevent future leaks.',
  },
  // Generic token assignment
  {
    regex: /(?<![\w.])token\s*[=:]\s*['"]([A-Za-z0-9_\-.]{16,})['"](?!\s*\))/gi,
    title: 'Hardcoded Token Detected',
    description: 'A hardcoded authentication or session token was found in the source code.',
    remediation:
      'Remove the token from source code. Use runtime configuration (environment variables or a vault) to supply tokens.',
  },
  // Private key
  {
    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----/g,
    title: 'Private Key Embedded in Source Code',
    description:
      'A PEM-encoded private key was found in the source code. Private keys should never be stored in repositories as they can be used for impersonation, decryption, or signing.',
    remediation:
      'Remove the private key from source code immediately. Store keys in a secure key management system (e.g., AWS KMS, HashiCorp Vault). Regenerate the keypair if the key has been committed to a public repository.',
  },
  // Connection strings with credentials
  {
    regex: /(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql):\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    title: 'Database Connection String with Credentials',
    description:
      'A database connection string containing embedded credentials was found. This exposes the database host, username, and password to anyone with access to the source code.',
    remediation:
      'Move connection strings to environment variables. Use IAM-based authentication or a secrets manager instead of embedding credentials in connection URIs.',
  },
  // JWT tokens (3 base64 segments)
  {
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    title: 'JWT Token Found in Source Code',
    description:
      'A JSON Web Token was found hardcoded in the source. If this is a long-lived or privileged token, it may grant unauthorized access to protected resources.',
    remediation:
      'Remove the JWT from source code. Tokens should be generated at runtime and stored in secure, short-lived storage.',
  },
];

function checkSecrets(filename, content, lines) {
  const findings = [];
  const language = detectLanguage(filename);

  // Skip binary-looking files and minified JS
  if (lines.length === 1 && content.length > 10000) return findings;
  // Skip test fixtures/mocks that commonly have fake keys
  const isTestFile = /\.(test|spec|mock|fixture)\./i.test(filename) || /__(tests|mocks)__/i.test(filename);

  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      // Determine line number
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;

      // Skip comments
      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();
      if (
        trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('*') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('"""') ||
        trimmed.startsWith("'''")
      ) {
        continue;
      }

      // Skip known placeholder/example values
      const matchStr = match[0];
      if (
        /example|placeholder|your[-_]?key|change[-_]?me|xxx|test|dummy|fake|sample|TODO|FIXME/i.test(matchStr) ||
        /example|placeholder|your[-_]?key|change[-_]?me|xxx{3,}|test|dummy|fake|sample/i.test(line)
      ) {
        continue;
      }

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: 'Critical',
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: `${pattern.description}${isTestFile ? ' (Note: found in a test file — verify whether this is a real credential or a test fixture.)' : ''}`,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// 2. Unsafe Function Usage
// ===================================================================

const UNSAFE_PATTERNS = {
  javascript: [
    {
      regex: /\beval\s*\(/g,
      title: 'Use of eval()',
      description:
        'eval() executes arbitrary code strings at runtime. If any user-controlled input reaches eval(), it enables Remote Code Execution (RCE).',
      remediation:
        'Replace eval() with safer alternatives like JSON.parse() for data, or use a sandboxed interpreter. If dynamic code execution is absolutely required, use the vm2 module with strict sandboxing.',
    },
    {
      regex: /\bnew\s+Function\s*\(/g,
      title: 'Use of new Function() Constructor',
      description:
        'The Function constructor is equivalent to eval() — it compiles and executes arbitrary code strings, enabling code injection.',
      remediation:
        'Avoid new Function(). Use predefined functions, closures, or a lookup table instead of dynamically constructing functions from strings.',
    },
    {
      regex: /\bsetTimeout\s*\(\s*['"`]/g,
      title: 'setTimeout() Called with String Argument',
      description:
        'Passing a string to setTimeout() causes it to be eval\'d, enabling code injection if the string contains user input.',
      remediation:
        'Pass a function reference to setTimeout() instead of a string: setTimeout(myFunction, delay) or setTimeout(() => { ... }, delay).',
    },
    {
      regex: /\bsetInterval\s*\(\s*['"`]/g,
      title: 'setInterval() Called with String Argument',
      description:
        'Passing a string to setInterval() causes it to be eval\'d, enabling code injection similar to eval().',
      remediation:
        'Pass a function reference to setInterval() instead of a string.',
    },
    {
      regex: /\bdocument\.write\s*\(/g,
      title: 'Use of document.write()',
      description:
        'document.write() injects raw HTML into the page. If user input flows into it, it enables DOM-based XSS attacks.',
      remediation:
        'Use DOM manipulation methods like textContent, createElement, or a templating library that auto-escapes output.',
    },
    {
      regex: /\.innerHTML\s*=/g,
      title: 'Direct innerHTML Assignment',
      description:
        'Setting innerHTML with unsanitized data allows attackers to inject malicious HTML and JavaScript, leading to Cross-Site Scripting (XSS).',
      remediation:
        'Use textContent for plain text, or sanitize HTML with DOMPurify before assigning to innerHTML. Consider using a framework with auto-escaping (React, Vue).',
    },
    {
      regex: /\.outerHTML\s*=/g,
      title: 'Direct outerHTML Assignment',
      description:
        'Setting outerHTML with unsanitized data can lead to XSS attacks similar to innerHTML.',
      remediation:
        'Use safe DOM manipulation methods or sanitize content with DOMPurify before assignment.',
    },
    {
      regex: /\.insertAdjacentHTML\s*\(/g,
      title: 'Use of insertAdjacentHTML()',
      description:
        'insertAdjacentHTML() parses and inserts raw HTML. If the content is user-controlled, it enables XSS.',
      remediation:
        'Sanitize the HTML string with DOMPurify before using insertAdjacentHTML(), or use insertAdjacentText() for plain text.',
    },
    {
      regex: /child_process\s*\.\s*exec\s*\(/g,
      title: 'Use of child_process.exec()',
      description:
        'child_process.exec() runs shell commands with a shell interpreter, making it vulnerable to command injection if user input is included.',
      remediation:
        'Use child_process.execFile() or child_process.spawn() with an arguments array instead. Never concatenate user input into shell commands.',
    },
    {
      regex: /child_process\s*\.\s*execSync\s*\(/g,
      title: 'Use of child_process.execSync()',
      description:
        'execSync() runs shell commands synchronously with a shell interpreter. Like exec(), it is vulnerable to command injection.',
      remediation:
        'Use child_process.execFileSync() or child_process.spawnSync() with an arguments array.',
    },
  ],
  python: [
    {
      regex: /\beval\s*\(/g,
      title: 'Use of eval()',
      description:
        'Python eval() evaluates arbitrary expressions. If user input reaches eval(), an attacker can execute arbitrary Python code.',
      remediation:
        'Use ast.literal_eval() for safely evaluating data literals. For mathematical expressions, use a dedicated expression parser.',
    },
    {
      regex: /\bexec\s*\(/g,
      title: 'Use of exec()',
      description:
        'Python exec() executes arbitrary Python code from a string. This is one of the most dangerous functions if user input is involved.',
      remediation:
        'Eliminate exec() usage. Use importlib for dynamic imports, or define allowed operations in a dispatch table.',
    },
    {
      regex: /\bos\.system\s*\(/g,
      title: 'Use of os.system()',
      description:
        'os.system() passes commands to the OS shell, making it vulnerable to command injection if user input is included.',
      remediation:
        'Use subprocess.run() with a list of arguments and shell=False (the default). Never construct shell commands from user input.',
    },
    {
      regex: /subprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
      title: 'subprocess with shell=True',
      description:
        'Using shell=True in subprocess functions passes the command through the system shell, enabling command injection.',
      remediation:
        'Set shell=False (the default) and pass arguments as a list: subprocess.run(["cmd", "arg1", "arg2"]).',
    },
    {
      regex: /\bpickle\.loads?\s*\(/g,
      title: 'Use of pickle.load(s)()',
      description:
        'Python pickle deserialisation can execute arbitrary code. If an attacker can control the pickled data, they achieve Remote Code Execution.',
      remediation:
        'Never unpickle data from untrusted sources. Use JSON, MessagePack, or Protocol Buffers for data serialisation. If pickle is required, use hmac to verify data integrity before deserialising.',
    },
    {
      regex: /\byaml\.load\s*\([^)]*(?!Loader)/g,
      title: 'Unsafe YAML Loading',
      description:
        'yaml.load() without a safe Loader can execute arbitrary Python code embedded in YAML documents.',
      remediation:
        'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
    },
    {
      regex: /\b__import__\s*\(/g,
      title: 'Use of __import__()',
      description:
        '__import__() dynamically imports modules. If the module name comes from user input, it can be used to load malicious modules.',
      remediation:
        'Use importlib.import_module() with a whitelist of allowed module names.',
    },
  ],
  php: [
    {
      regex: /\beval\s*\(/g,
      title: 'Use of eval()',
      description:
        'PHP eval() executes arbitrary PHP code from a string. This is the most common vector for PHP webshell backdoors.',
      remediation:
        'Eliminate eval() usage entirely. Use dedicated parsers, template engines, or refactor logic to avoid dynamic code execution.',
    },
    {
      regex: /\bexec\s*\(/g,
      title: 'Use of exec()',
      description:
        'PHP exec() executes system commands. If user input is included, it enables command injection and full server compromise.',
      remediation:
        'Use escapeshellarg() and escapeshellcmd() to sanitize inputs. Better yet, avoid shell commands and use PHP native functions.',
    },
    {
      regex: /\bsystem\s*\(/g,
      title: 'Use of system()',
      description:
        'PHP system() passes commands to the OS shell and displays output. It is vulnerable to command injection.',
      remediation:
        'Replace with escapeshellarg()/escapeshellcmd() wrappers or use PHP native alternatives.',
    },
    {
      regex: /\bpassthru\s*\(/g,
      title: 'Use of passthru()',
      description:
        'PHP passthru() executes shell commands and returns raw output. Like exec() and system(), it is vulnerable to command injection.',
      remediation: 'Avoid passthru(). Use PHP native functions or properly sanitize all inputs with escapeshellarg().',
    },
    {
      regex: /\bshell_exec\s*\(|`[^`]*\$/g,
      title: 'Use of shell_exec() or Backtick Operator',
      description:
        'shell_exec() and backtick operators (`) execute shell commands. Any user input in the command string enables command injection.',
      remediation:
        'Avoid shell_exec() and backtick operators. Use PHP native functions where possible.',
    },
    {
      regex: /\bpreg_replace\s*\(\s*['"][^'"]*\/e/g,
      title: 'preg_replace() with /e Modifier',
      description:
        'The /e modifier in preg_replace() evaluates the replacement string as PHP code, enabling code injection through crafted regex input.',
      remediation:
        'Use preg_replace_callback() instead. The /e modifier was deprecated in PHP 5.5 and removed in PHP 7.0.',
    },
    {
      regex: /\bunserialize\s*\(/g,
      title: 'Use of unserialize()',
      description:
        'PHP unserialize() can trigger object injection attacks. Attackers can instantiate arbitrary classes and chain destructors/wakeup methods for RCE.',
      remediation:
        'Use json_decode() for data exchange. If unserialize() is required, use the allowed_classes option: unserialize($data, ["allowed_classes" => false]).',
    },
    {
      regex: /\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/g,
      title: 'extract() on Superglobal Input',
      description:
        'Using extract() on user input ($_GET, $_POST, etc.) allows attackers to overwrite any variable in the current scope, potentially bypassing security checks.',
      remediation:
        'Never use extract() on user input. Access superglobal values directly: $_POST["key"].',
    },
  ],
};

function checkUnsafeFunctions(filename, content, lines) {
  const findings = [];
  const language = detectLanguage(filename);
  const patterns = UNSAFE_PATTERNS[language];
  if (!patterns) return findings;

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();

      // Skip comments
      if (
        trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('*') ||
        trimmed.startsWith('/*')
      ) {
        continue;
      }

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: 'High',
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: pattern.description,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// 3. SQL Injection Vulnerabilities
// ===================================================================

const SQL_INJECTION_PATTERNS = [
  // JS: string concatenation in query
  {
    regex: /(?:query|execute|raw|sequelize\.query)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^'"]*['"]\s*\+/gi,
    title: 'SQL Injection: String Concatenation in Query',
    description:
      'SQL queries are constructed using string concatenation with potentially user-controlled variables. This is the classic SQL injection vector.',
    remediation:
      'Use parameterized queries or prepared statements. For Node.js: db.query("SELECT * FROM users WHERE id = ?", [userId]). For ORMs, use built-in query builders.',
    languages: ['javascript'],
  },
  // JS: template literal in query
  {
    regex: /(?:query|execute|raw|sequelize\.query)\s*\(\s*`[^`]*\$\{/gi,
    title: 'SQL Injection: Template Literal in Query',
    description:
      'SQL queries are constructed using JavaScript template literals with interpolated expressions. Variables injected via ${} are not parameterized.',
    remediation:
      'Replace template literals with parameterized queries. Use db.query("SELECT * FROM users WHERE id = ?", [id]) instead of db.query(`SELECT * FROM users WHERE id = ${id}`).',
    languages: ['javascript'],
  },
  // Python: f-string in SQL
  {
    regex: /(?:execute|cursor\.execute|session\.execute|db\.execute)\s*\(\s*f['"`]/gi,
    title: 'SQL Injection: f-string in SQL Query',
    description:
      'SQL queries are constructed using Python f-strings, which directly interpolate variables into the query string without parameterization.',
    remediation:
      'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)). Never use f-strings, .format(), or % formatting in SQL queries.',
    languages: ['python'],
  },
  // Python: .format() in SQL
  {
    regex: /(?:execute|cursor\.execute|session\.execute|db\.execute)\s*\(\s*['"][^'"]*['"]\.format\s*\(/gi,
    title: 'SQL Injection: .format() in SQL Query',
    description:
      'SQL queries are constructed using Python str.format(), which directly interpolates variables into the query string.',
    remediation:
      'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)).',
    languages: ['python'],
  },
  // Python: % formatting in SQL
  {
    regex: /(?:execute|cursor\.execute|session\.execute|db\.execute)\s*\(\s*['"][^'"]*%s[^'"]*['"]\s*%/gi,
    title: 'SQL Injection: % String Formatting in SQL Query',
    description:
      'SQL queries use the Python % operator for string formatting, which bypasses parameterization and enables SQL injection.',
    remediation:
      'Use the parameterized form: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)). Note: the %s inside the query string is the DB-API placeholder, not Python string formatting.',
    languages: ['python'],
  },
  // PHP: variable in SQL string
  {
    regex: /(?:mysql_query|mysqli_query|pg_query|\$\w+->query|\$pdo->query)\s*\(\s*['"][^'"]*\$\w+/gi,
    title: 'SQL Injection: PHP Variable in Query String',
    description:
      'PHP variables are directly embedded in SQL query strings, creating a SQL injection vulnerability.',
    remediation:
      'Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
    languages: ['php'],
  },
  // Generic: concatenation with common SQL keywords
  {
    regex: /['"](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?['"]\s*\+\s*(?:req\.|request\.|params\.|args\.|input)/gi,
    title: 'SQL Injection: User Input Concatenated into SQL',
    description:
      'User-supplied input (from request parameters) is directly concatenated into a SQL query string.',
    remediation:
      'Always use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
    languages: ['javascript', 'python', 'php'],
  },
];

function checkSqlInjection(filename, content, lines) {
  const findings = [];
  const language = detectLanguage(filename);

  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.languages && !pattern.languages.includes(language)) continue;

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();

      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: 'Critical',
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: pattern.description,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// 4. Missing Input Validation
// ===================================================================

const INPUT_VALIDATION_PATTERNS = {
  javascript: [
    {
      regex: /req\.body\[?\.?\w+/g,
      title: 'Unvalidated req.body Usage',
      description:
        'Request body data (req.body) is used directly without validation or sanitization. This can lead to injection attacks, type confusion, or unexpected behaviour.',
      remediation:
        'Validate and sanitize all req.body fields using express-validator, joi, or zod before processing. Define explicit schemas for expected input.',
    },
    {
      regex: /req\.query\[?\.?\w+/g,
      title: 'Unvalidated req.query Usage',
      description:
        'Query string parameters (req.query) are used directly without validation. Query parameters are user-controlled and should never be trusted.',
      remediation:
        'Validate and type-check all req.query values. Use express-validator or a schema validation library.',
    },
    {
      regex: /req\.params\[?\.?\w+/g,
      title: 'Unvalidated req.params Usage',
      description:
        'URL parameters (req.params) are used directly without validation. These values come from the URL path and are user-controlled.',
      remediation:
        'Validate req.params values — especially IDs — to ensure they match expected formats (e.g., UUID, integer).',
    },
  ],
  python: [
    {
      regex: /request\.form\[?\.?(?:get\s*\()?\s*['"]?\w+/g,
      title: 'Unvalidated request.form Usage',
      description:
        'Flask request.form data is used without validation or sanitization.',
      remediation:
        'Validate all form inputs using WTForms validators or marshmallow schemas.',
    },
    {
      regex: /request\.args\[?\.?(?:get\s*\()?\s*['"]?\w+/g,
      title: 'Unvalidated request.args Usage',
      description:
        'Flask query parameters (request.args) are used without validation.',
      remediation:
        'Validate all query parameters. Use type coercion: request.args.get("page", 1, type=int).',
    },
    {
      regex: /request\.json\[?\.?(?:get\s*\()?\s*['"]?\w+/g,
      title: 'Unvalidated request.json Usage',
      description:
        'Flask request.json data is used directly without schema validation.',
      remediation: 'Use marshmallow or pydantic to validate JSON request bodies.',
    },
  ],
};

function checkInputValidation(filename, content, lines) {
  const findings = [];
  const language = detectLanguage(filename);
  const patterns = INPUT_VALIDATION_PATTERNS[language];
  if (!patterns) return findings;

  // Check if validation middleware/decorators are present
  const hasValidation =
    content.includes('express-validator') ||
    content.includes('joi.') ||
    content.includes('Joi.') ||
    content.includes('zod.') ||
    content.includes('yup.') ||
    content.includes('@validate') ||
    content.includes('WTForms') ||
    content.includes('marshmallow') ||
    content.includes('pydantic') ||
    content.includes('class.*Form(') ||
    content.includes('Schema(');

  if (hasValidation) return findings; // file already uses validation

  // Track unique lines to avoid reporting the same line multiple times
  const reportedLines = new Set();

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;

      if (reportedLines.has(lineNum)) continue;
      reportedLines.add(lineNum);

      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: 'Medium',
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: pattern.description,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// 5. Insecure Configuration
// ===================================================================

const INSECURE_CONFIG_PATTERNS = [
  // Debug mode in production
  {
    regex: /\bDEBUG\s*=\s*True\b/g,
    title: 'Debug Mode Enabled',
    severity: 'High',
    description:
      'DEBUG mode is enabled. In production, debug mode exposes stack traces, internal paths, environment variables, and database queries to end users.',
    remediation:
      'Set DEBUG = False in production settings. Use environment variables to control: DEBUG = os.environ.get("DEBUG", "False") == "True".',
    filePatterns: ['settings.py', 'config.py', '.env', 'app.py'],
  },
  {
    regex: /\bDEBUG\s*[:=]\s*true\b/gi,
    title: 'Debug Mode Enabled',
    severity: 'High',
    description:
      'Debug mode is enabled in configuration. This may expose sensitive information, stack traces, and internal application details.',
    remediation:
      'Disable debug mode in production environments. Use environment-specific configuration.',
    filePatterns: null,
  },
  // CORS wildcard
  {
    regex: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"][*]['"]|cors\(\s*\)/g,
    title: 'CORS Configured with Wildcard Origin',
    severity: 'Medium',
    description:
      'CORS is configured to allow all origins (*). This permits any website to make authenticated requests to your API, potentially leading to data theft.',
    remediation:
      'Restrict CORS to specific trusted domains: cors({ origin: ["https://yourdomain.com"] }). Never use wildcard in production.',
    filePatterns: null,
  },
  {
    regex: /CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True/g,
    title: 'Django CORS Allows All Origins',
    severity: 'Medium',
    description:
      'Django CORS is configured to allow all origins, permitting any website to make cross-origin requests.',
    remediation:
      'Set CORS_ALLOW_ALL_ORIGINS = False and define CORS_ALLOWED_ORIGINS with specific trusted domains.',
    filePatterns: ['settings.py'],
  },
  // Disabled CSRF
  {
    regex: /csrf\s*[:=]\s*false|csurf\s*[:=]\s*false/gi,
    title: 'CSRF Protection Disabled',
    severity: 'High',
    description:
      'CSRF (Cross-Site Request Forgery) protection is explicitly disabled. This allows attackers to forge requests on behalf of authenticated users.',
    remediation:
      'Enable CSRF protection. For Express, use the csurf middleware. For Django/Flask, ensure CSRF middleware is active.',
    filePatterns: null,
  },
  {
    regex: /WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False/g,
    title: 'Flask CSRF Protection Disabled',
    severity: 'High',
    description:
      'Flask-WTF CSRF protection is disabled. All forms are vulnerable to cross-site request forgery.',
    remediation: 'Set WTF_CSRF_ENABLED = True and ensure Flask-WTF is properly initialized.',
    filePatterns: null,
  },
  // Insecure secret key
  {
    regex: /SECRET_KEY\s*=\s*['"](?:secret|changeme|password|default|12345|abcdef|django-insecure)[^'"]*['"]/gi,
    title: 'Insecure SECRET_KEY Value',
    severity: 'Critical',
    description:
      'The application SECRET_KEY is set to a weak, default, or well-known value. This compromises session security, CSRF tokens, and any cryptographic operations that use the key.',
    remediation:
      'Generate a strong random secret key (at least 50 characters). Store it in environment variables: SECRET_KEY = os.environ["SECRET_KEY"].',
    filePatterns: null,
  },
  // Insecure SSL/TLS
  {
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|rejectUnauthorized\s*:\s*false/g,
    title: 'TLS Certificate Verification Disabled',
    severity: 'High',
    description:
      'TLS certificate verification is disabled. This makes the application vulnerable to man-in-the-middle attacks by accepting any certificate, including self-signed and expired ones.',
    remediation:
      'Enable certificate verification (this is the default). If using self-signed certs in development, use a proper CA or restrict the bypass to development environments only.',
    filePatterns: null,
  },
  // ALLOWED_HOSTS wildcard
  {
    regex: /ALLOWED_HOSTS\s*=\s*\[\s*['"][*]['"]\s*\]/g,
    title: 'Django ALLOWED_HOSTS Set to Wildcard',
    severity: 'High',
    description:
      'ALLOWED_HOSTS is set to ["*"], which accepts requests for any hostname. This can facilitate cache poisoning and host header injection attacks.',
    remediation:
      'Set ALLOWED_HOSTS to a list of specific, valid hostnames for your application.',
    filePatterns: ['settings.py'],
  },
  // Hardcoded SMTP credentials
  {
    regex: /(?:EMAIL_HOST_PASSWORD|SMTP_PASSWORD|MAIL_PASSWORD)\s*=\s*['"][^'"]+['"]/g,
    title: 'Hardcoded Email/SMTP Password',
    severity: 'High',
    description: 'An email or SMTP password is hardcoded in a configuration file.',
    remediation:
      'Move the SMTP password to environment variables or a secrets manager.',
    filePatterns: null,
  },
  // Session not secure
  {
    regex: /SESSION_COOKIE_SECURE\s*=\s*False/g,
    title: 'Session Cookie Not Marked Secure',
    severity: 'Medium',
    description:
      'Session cookies can be transmitted over unencrypted HTTP, allowing session hijacking via network sniffing.',
    remediation: 'Set SESSION_COOKIE_SECURE = True in production.',
    filePatterns: ['settings.py'],
  },
  {
    regex: /SESSION_COOKIE_HTTPONLY\s*=\s*False/g,
    title: 'Session Cookie Accessible via JavaScript',
    severity: 'Medium',
    description:
      'Session cookies can be accessed by client-side JavaScript, enabling session theft via XSS.',
    remediation: 'Set SESSION_COOKIE_HTTPONLY = True.',
    filePatterns: ['settings.py'],
  },
];

function checkInsecureConfig(filename, content, lines) {
  const findings = [];

  for (const pattern of INSECURE_CONFIG_PATTERNS) {
    // If filePatterns is specified, only check matching filenames
    if (pattern.filePatterns) {
      const basename = filename.split('/').pop().split('\\').pop();
      const matches = pattern.filePatterns.some(
        (fp) => basename === fp || filename.endsWith(fp)
      );
      if (!matches) continue;
    }

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: pattern.severity,
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: pattern.description,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// 6. Dependency Vulnerabilities
// ===================================================================

// Map of packages with known vulnerable version ranges
const KNOWN_VULNERABLE_PACKAGES = {
  // npm packages
  'lodash': {
    vulnerableBelow: '4.17.21',
    severity: 'High',
    cve: 'CVE-2021-23337',
    description: 'Lodash versions before 4.17.21 are vulnerable to Command Injection via the template function.',
  },
  'express': {
    vulnerableBelow: '4.19.2',
    severity: 'Medium',
    cve: 'CVE-2024-29041',
    description: 'Express versions before 4.19.2 are vulnerable to open redirect via URL manipulation.',
  },
  'axios': {
    vulnerableBelow: '1.6.0',
    severity: 'High',
    cve: 'CVE-2023-45857',
    description: 'Axios versions before 1.6.0 are vulnerable to CSRF due to cookie exposure.',
  },
  'jsonwebtoken': {
    vulnerableBelow: '9.0.0',
    severity: 'Critical',
    cve: 'CVE-2022-23529',
    description: 'jsonwebtoken versions before 9.0.0 are vulnerable to Remote Code Execution.',
  },
  'minimist': {
    vulnerableBelow: '1.2.6',
    severity: 'Critical',
    cve: 'CVE-2021-44906',
    description: 'minimist before 1.2.6 is vulnerable to Prototype Pollution.',
  },
  'node-fetch': {
    vulnerableBelow: '2.6.7',
    severity: 'High',
    cve: 'CVE-2022-0235',
    description: 'node-fetch before 2.6.7 is vulnerable to information exposure via headers.',
  },
  'qs': {
    vulnerableBelow: '6.10.3',
    severity: 'High',
    cve: 'CVE-2022-24999',
    description: 'qs before 6.10.3 is vulnerable to Prototype Pollution.',
  },
  'moment': {
    vulnerableBelow: '2.29.4',
    severity: 'High',
    cve: 'CVE-2022-31129',
    description: 'moment before 2.29.4 is vulnerable to ReDoS (Regular Expression Denial of Service).',
  },
  'handlebars': {
    vulnerableBelow: '4.7.7',
    severity: 'Critical',
    cve: 'CVE-2021-23369',
    description: 'Handlebars before 4.7.7 is vulnerable to Remote Code Execution via template compilation.',
  },
  'underscore': {
    vulnerableBelow: '1.13.6',
    severity: 'Critical',
    cve: 'CVE-2021-23358',
    description: 'Underscore before 1.13.6 is vulnerable to Arbitrary Code Execution via the template function.',
  },
  'helmet': {
    vulnerableBelow: '4.0.0',
    severity: 'Medium',
    cve: 'N/A',
    description: 'Older helmet versions have limited security header support. Upgrade for comprehensive protection.',
  },
  'body-parser': {
    vulnerableBelow: '1.20.3',
    severity: 'Medium',
    cve: 'CVE-2024-45590',
    description: 'body-parser before 1.20.3 is vulnerable to Denial of Service.',
  },
  'tar': {
    vulnerableBelow: '6.1.9',
    severity: 'High',
    cve: 'CVE-2021-37713',
    description: 'tar before 6.1.9 is vulnerable to Arbitrary File Overwrite.',
  },
  'glob-parent': {
    vulnerableBelow: '5.1.2',
    severity: 'High',
    cve: 'CVE-2020-28469',
    description: 'glob-parent before 5.1.2 is vulnerable to Regular Expression Denial of Service.',
  },
  'path-parse': {
    vulnerableBelow: '1.0.7',
    severity: 'High',
    cve: 'CVE-2021-23343',
    description: 'path-parse before 1.0.7 is vulnerable to ReDoS.',
  },
};

/**
 * Compare semver strings loosely (major.minor.patch).
 * Returns true if version is below the threshold.
 */
function isVersionBelow(version, threshold) {
  if (!version || !threshold) return false;

  // Strip leading ^ ~ >= etc.
  const clean = (v) =>
    v
      .replace(/^[~^>=<!\s]+/, '')
      .replace(/-.*$/, '')
      .split('.')
      .map((n) => parseInt(n, 10) || 0);

  const vParts = clean(version);
  const tParts = clean(threshold);

  for (let i = 0; i < 3; i++) {
    const v = vParts[i] || 0;
    const t = tParts[i] || 0;
    if (v < t) return true;
    if (v > t) return false;
  }
  return false; // equal = not below
}

function checkDependencies(filename, content) {
  const findings = [];
  const basename = filename.split('/').pop().split('\\').pop();
  if (basename !== 'package.json') return findings;

  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    findings.push({
      id: nextId(),
      title: 'Malformed package.json',
      severity: 'Info',
      file: filename,
      line: 1,
      code: 'Unable to parse package.json',
      description: 'The package.json file could not be parsed as valid JSON.',
      remediation: 'Fix the JSON syntax errors in package.json.',
    });
    return findings;
  }

  const allDeps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const known = KNOWN_VULNERABLE_PACKAGES[name];
    if (known && isVersionBelow(version, known.vulnerableBelow)) {
      findings.push({
        id: nextId(),
        title: `Vulnerable Dependency: ${name}@${version}`,
        severity: known.severity,
        file: filename,
        line: 1,
        code: `"${name}": "${version}"`,
        description: `${known.description} (${known.cve}). Installed version ${version} is below the patched version ${known.vulnerableBelow}.`,
        remediation: `Update ${name} to version ${known.vulnerableBelow} or later: npm install ${name}@latest`,
      });
    }
  }

  // Check for missing security-critical packages
  const deps = pkg.dependencies || {};
  const securityPackages = [
    {
      name: 'helmet',
      description: 'helmet middleware provides essential security headers for Express applications.',
    },
    {
      name: 'express-rate-limit',
      description: 'Rate limiting prevents brute-force and DoS attacks.',
    },
  ];

  // Only check if this appears to be an Express project
  if (deps['express']) {
    for (const secPkg of securityPackages) {
      if (!deps[secPkg.name] && !allDeps[secPkg.name]) {
        findings.push({
          id: nextId(),
          title: `Missing Security Package: ${secPkg.name}`,
          severity: 'Medium',
          file: filename,
          line: 1,
          code: `"dependencies": { "express": "${deps['express']}" }`,
          description: `The Express project is missing the ${secPkg.name} package. ${secPkg.description}`,
          remediation: `Install ${secPkg.name}: npm install ${secPkg.name}`,
        });
      }
    }
  }

  return findings;
}

// ===================================================================
// XSS Detection (bonus)
// ===================================================================

function checkXss(filename, content, lines) {
  const findings = [];
  const language = detectLanguage(filename);

  const patterns = [];
  if (language === 'javascript' || language === 'html') {
    patterns.push(
      {
        regex: /\.html\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\$\()/g,
        title: 'Potential XSS via .html() Method',
        description:
          'User-controlled data may be passed to jQuery .html() which renders raw HTML, enabling XSS.',
        remediation: 'Use .text() for plain text, or sanitize with DOMPurify before calling .html().',
      },
      {
        regex: /res\.send\s*\(\s*(?:req\.|request\.)/g,
        title: 'Reflected XSS: User Input in res.send()',
        description:
          'User input is directly included in the HTTP response via res.send(), enabling reflected XSS.',
        remediation:
          'HTML-encode all user input before including it in responses. Use a templating engine with auto-escaping.',
      }
    );
  }

  if (language === 'python') {
    patterns.push(
      {
        regex: /\bMarkup\s*\(\s*f['"]/g,
        title: 'Potential XSS via Markup() with f-string',
        description:
          'User input may be included in a Jinja2 Markup() object via f-string, bypassing auto-escaping.',
        remediation: 'Use Markup.escape() on user input before wrapping in Markup().',
      },
      {
        regex: /\|\s*safe\b/g,
        title: 'Jinja2 |safe Filter Usage',
        description:
          'The |safe filter disables Jinja2 auto-escaping. If applied to user-controlled data, it enables XSS.',
        remediation: 'Avoid using |safe with user input. Sanitize data server-side before marking as safe.',
      }
    );
  }

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      findings.push({
        id: nextId(),
        title: pattern.title,
        severity: 'High',
        file: filename,
        line: lineNum,
        code: snippet(lines, lineNum - 1, 1),
        description: pattern.description,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}

// ===================================================================
// Main Analyzer
// ===================================================================

/**
 * Analyze an array of source files for security vulnerabilities.
 *
 * @param {Array<{filename:string, content:string}>} files
 * @returns {{findings:Array, summary:object}}
 */
function analyzeCode(files) {
  findingCounter = 0;
  const allFindings = [];

  for (const file of files) {
    if (!file || !file.filename || typeof file.content !== 'string') continue;

    const { filename, content } = file;

    // Skip empty files and very large binary-looking files
    if (!content || content.length === 0) continue;
    if (content.length > 2 * 1024 * 1024) continue; // skip files > 2MB

    const lines = content.split('\n');

    // 1. Hardcoded Secrets
    allFindings.push(...checkSecrets(filename, content, lines));

    // 2. Unsafe Functions
    allFindings.push(...checkUnsafeFunctions(filename, content, lines));

    // 3. SQL Injection
    allFindings.push(...checkSqlInjection(filename, content, lines));

    // 4. Missing Input Validation
    allFindings.push(...checkInputValidation(filename, content, lines));

    // 5. Insecure Configuration
    allFindings.push(...checkInsecureConfig(filename, content, lines));

    // 6. Dependency Vulnerabilities
    allFindings.push(...checkDependencies(filename, content));

    // Bonus: XSS patterns
    allFindings.push(...checkXss(filename, content, lines));
  }

  // Build summary
  const summary = {
    totalFiles: files.length,
    totalFindings: allFindings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    byCategory: {},
    fileBreakdown: {},
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

    // Category breakdown
    const cat = f.title.split(':')[0] || f.title;
    summary.byCategory[cat] = (summary.byCategory[cat] || 0) + 1;

    // File breakdown
    if (f.file) {
      if (!summary.fileBreakdown[f.file]) {
        summary.fileBreakdown[f.file] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      }
      const sev = f.severity.toLowerCase();
      if (summary.fileBreakdown[f.file][sev] !== undefined) {
        summary.fileBreakdown[f.file][sev]++;
      }
    }
  }

  return { findings: allFindings, summary };
}

module.exports = { analyzeCode };
