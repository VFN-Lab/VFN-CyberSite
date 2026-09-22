/**
 * VFN-CyberSite — Static Code Analyzer
 * Comprehensive source code vulnerability scanner supporting 8+ languages
 * Detects 40+ vulnerability types with severity classification
 */

// ============ VULNERABILITY RULES ============

const VULNERABILITY_RULES = [
  // ==================== INJECTION ====================
  // SQL Injection
  {
    id: 'SQLI-001',
    title: 'SQL Injection — String Concatenation in Query',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021 - Injection',
    languages: ['php', 'python', 'java', 'javascript', 'csharp', 'ruby', 'go'],
    patterns: [
      /["']SELECT\s.+\+\s*\w+/gi,
      /["']INSERT\s+INTO.+\+\s*\w+/gi,
      /["']UPDATE\s.+\+\s*\w+/gi,
      /["']DELETE\s+FROM.+\+\s*\w+/gi,
      /query\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE).+\$\{/gi,
      /query\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE).+\+/gi,
      /execute\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).+%/gi,
      /cursor\.execute\s*\(\s*f["']/gi,
      /cursor\.execute\s*\(\s*["'].*%s/gi,
      /\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
    ],
    recommendation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL. Use ORM methods.',
    fix: '// Instead of:\ndb.query("SELECT * FROM users WHERE id = " + userId)\n// Use:\ndb.query("SELECT * FROM users WHERE id = ?", [userId])'
  },
  {
    id: 'SQLI-002',
    title: 'SQL Injection — Raw Query with Variables',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      /mysql_query\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
      /mysqli_query\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
      /\$(?:pdo|db|conn|mysqli)\s*->\s*query\s*\(.*\$_(?:GET|POST|REQUEST)/gi,
    ],
    recommendation: 'Use PDO with prepared statements and bound parameters.',
    fix: '// Instead of:\n$db->query("SELECT * FROM users WHERE id = " . $_GET["id"])\n// Use:\n$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$_GET["id"]]);'
  },

  // NoSQL Injection
  {
    id: 'NOSQLI-001',
    title: 'NoSQL Injection',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-943',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'python'],
    patterns: [
      /\.find\s*\(\s*\{.*req\.(body|query|params)/gi,
      /\.findOne\s*\(\s*\{.*req\.(body|query|params)/gi,
      /\.deleteMany\s*\(\s*\{.*req\.(body|query|params)/gi,
      /\.updateOne\s*\(\s*\{.*req\.(body|query|params)/gi,
      /\$where\s*:.*req\./gi,
      /collection\.find\s*\(\s*\{.*request\./gi,
    ],
    recommendation: 'Validate and sanitize NoSQL query parameters. Use mongoose schema validation. Never pass raw user input to MongoDB queries.',
    fix: '// Validate input before using in query\nconst id = sanitize(req.params.id);\nconst user = await User.findById(id);'
  },

  // Command Injection
  {
    id: 'CMDI-001',
    title: 'OS Command Injection',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-78',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'python', 'php', 'ruby', 'java'],
    patterns: [
      /child_process.*exec\s*\(.*req\./gi,
      /child_process.*exec\s*\(.*\$\{/gi,
      /exec\s*\(\s*['"`].*\+\s*(?:req\.|input|user|param|arg)/gi,
      /execSync\s*\(.*\+/gi,
      /os\.system\s*\(.*\+/gi,
      /os\.system\s*\(.*f["']/gi,
      /os\.popen\s*\(.*\+/gi,
      /subprocess\.call\s*\(.*shell\s*=\s*True/gi,
      /subprocess\.Popen\s*\(.*shell\s*=\s*True/gi,
      /Runtime\.getRuntime\(\)\.exec\s*\(.*\+/gi,
      /ProcessBuilder.*\+/gi,
      /system\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /passthru\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /`.*\$\{.*req\./gi,
      /Kernel\.system\s*\(.*\+/gi,
    ],
    recommendation: 'Never pass user input to shell commands. Use language-specific APIs instead. If shell execution is necessary, use strict allowlists.',
    fix: '// Instead of:\nchild_process.exec("ping " + userInput)\n// Use:\nchild_process.execFile("ping", ["-c", "1", validatedHost])'
  },

  // ==================== XSS ====================
  {
    id: 'XSS-001',
    title: 'DOM-based XSS — innerHTML',
    severity: 'high',
    category: 'Cross-Site Scripting',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'html'],
    patterns: [
      /\.innerHTML\s*=\s*(?!['"`]<)/gi,
      /\.innerHTML\s*\+=\s*/gi,
      /\.outerHTML\s*=\s*/gi,
      /\.insertAdjacentHTML\s*\(/gi,
    ],
    recommendation: 'Use textContent or createElement/appendChild instead of innerHTML. Use DOMPurify to sanitize HTML.',
    fix: '// Instead of:\nelement.innerHTML = userInput\n// Use:\nelement.textContent = userInput\n// Or sanitize:\nelement.innerHTML = DOMPurify.sanitize(userInput)'
  },
  {
    id: 'XSS-002',
    title: 'DOM-based XSS — document.write',
    severity: 'high',
    category: 'Cross-Site Scripting',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'html'],
    patterns: [
      /document\.write\s*\(/gi,
      /document\.writeln\s*\(/gi,
    ],
    recommendation: 'Avoid document.write entirely. Use DOM manipulation methods.',
    fix: '// Instead of:\ndocument.write("<div>" + data + "</div>")\n// Use:\nconst div = document.createElement("div");\ndiv.textContent = data;\ndocument.body.appendChild(div);'
  },
  {
    id: 'XSS-003',
    title: 'React dangerouslySetInnerHTML',
    severity: 'high',
    category: 'Cross-Site Scripting',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript'],
    patterns: [
      /dangerouslySetInnerHTML/gi,
    ],
    recommendation: 'Avoid dangerouslySetInnerHTML. If absolutely necessary, sanitize with DOMPurify first.',
    fix: '// Instead of:\n<div dangerouslySetInnerHTML={{__html: userInput}} />\n// Use:\nimport DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />'
  },
  {
    id: 'XSS-004',
    title: 'XSS — Unescaped Output in PHP',
    severity: 'high',
    category: 'Cross-Site Scripting',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      /echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\[/gi,
      /print\s+\$_(?:GET|POST|REQUEST|COOKIE)\[/gi,
      /<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/gi,
    ],
    recommendation: 'Always use htmlspecialchars() or htmlentities() when outputting user input.',
    fix: '// Instead of:\necho $_GET["name"];\n// Use:\necho htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");'
  },
  {
    id: 'XSS-005',
    title: 'Vue.js v-html Directive',
    severity: 'high',
    category: 'Cross-Site Scripting',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    languages: ['html', 'javascript'],
    patterns: [
      /v-html\s*=/gi,
    ],
    recommendation: 'Avoid v-html with user input. Sanitize HTML before rendering.',
  },

  // ==================== AUTHENTICATION ====================
  {
    id: 'AUTH-001',
    title: 'Hardcoded Password / Secret',
    severity: 'critical',
    category: 'Authentication',
    cwe: 'CWE-798',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    languages: ['all'],
    patterns: [
      /(?:password|passwd|pwd|pass)\s*[:=]\s*["'][^"']{4,}/gi,
      /(?:secret|secret_key|secretkey)\s*[:=]\s*["'][^"']{4,}/gi,
      /(?:api_key|apikey|api_secret)\s*[:=]\s*["'][^"']{8,}/gi,
      /(?:access_token|auth_token|token)\s*[:=]\s*["'][^"']{8,}/gi,
      /(?:private_key|privatekey)\s*[:=]\s*["'][^"']{8,}/gi,
      /(?:database_url|db_url|db_password|db_pass)\s*[:=]\s*["'][^"']{4,}/gi,
      /(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*[:=]\s*["'][^"']{8,}/gi,
      /AKIA[0-9A-Z]{16}/g,  // AWS Access Key
      /(?:sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{20,}/g,  // Stripe keys
      /ghp_[a-zA-Z0-9]{36}/g,  // GitHub personal token
      /glpat-[a-zA-Z0-9\-_]{20,}/g,  // GitLab personal token
      /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,  // JWT token
      /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
      /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/gi,
    ],
    recommendation: 'Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit secrets to source code.',
    fix: '// Instead of:\nconst API_KEY = "sk_live_abc123...";\n// Use:\nconst API_KEY = process.env.API_KEY;'
  },
  {
    id: 'AUTH-002',
    title: 'Weak Hashing Algorithm (MD5/SHA1)',
    severity: 'high',
    category: 'Cryptography',
    cwe: 'CWE-328',
    owasp: 'A02:2021 - Cryptographic Failures',
    languages: ['all'],
    patterns: [
      /md5\s*\(/gi,
      /sha1\s*\(/gi,
      /hashlib\.md5/gi,
      /hashlib\.sha1/gi,
      /MessageDigest\.getInstance\s*\(\s*["']MD5["']\)/gi,
      /MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\)/gi,
      /createHash\s*\(\s*["']md5["']\)/gi,
      /createHash\s*\(\s*["']sha1["']\)/gi,
      /MD5\.Create\(\)/gi,
      /SHA1\.Create\(\)/gi,
      /Digest::MD5/gi,
      /Digest::SHA1/gi,
    ],
    recommendation: 'Use bcrypt, scrypt, or Argon2 for password hashing. Use SHA-256 or SHA-3 for general hashing.',
    fix: '// Instead of:\nconst hash = crypto.createHash("md5").update(password).digest("hex");\n// Use:\nconst bcrypt = require("bcrypt");\nconst hash = await bcrypt.hash(password, 12);'
  },
  {
    id: 'AUTH-003',
    title: 'JWT Misconfiguration — No Algorithm Verification',
    severity: 'critical',
    category: 'Authentication',
    cwe: 'CWE-347',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    languages: ['javascript', 'python', 'java'],
    patterns: [
      /jwt\.verify\s*\(.*\{\s*algorithms\s*:\s*\[["']none["']\]/gi,
      /jwt\.decode\s*\(/gi,
      /algorithms\s*=\s*\[["']none["']\]/gi,
      /verify\s*=\s*False/gi,
    ],
    recommendation: 'Always verify JWT signatures. Never allow the "none" algorithm. Specify allowed algorithms explicitly.',
    fix: '// Always verify with specific algorithm:\njwt.verify(token, secret, { algorithms: ["HS256"] });'
  },

  // ==================== CRYPTOGRAPHY ====================
  {
    id: 'CRYPTO-001',
    title: 'Insecure Random Number Generation',
    severity: 'high',
    category: 'Cryptography',
    cwe: 'CWE-330',
    owasp: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'python', 'java', 'php'],
    patterns: [
      /Math\.random\s*\(\s*\)/g,
      /random\.random\s*\(\s*\)/g,
      /random\.randint\s*\(/g,
      /java\.util\.Random\b/g,
      /rand\s*\(\s*\)/g,
      /mt_rand\s*\(/g,
    ],
    recommendation: 'Use cryptographically secure random generators: crypto.randomBytes (Node.js), secrets module (Python), SecureRandom (Java).',
    fix: '// Instead of:\nconst token = Math.random().toString(36);\n// Use:\nconst crypto = require("crypto");\nconst token = crypto.randomBytes(32).toString("hex");'
  },
  {
    id: 'CRYPTO-002',
    title: 'ECB Mode Encryption',
    severity: 'high',
    category: 'Cryptography',
    cwe: 'CWE-327',
    owasp: 'A02:2021 - Cryptographic Failures',
    languages: ['all'],
    patterns: [
      /AES\/ECB/gi,
      /mode\s*[:=]\s*["']ECB["']/gi,
      /MODE_ECB/gi,
      /ECB_Mode/gi,
      /createCipheriv\s*\(\s*["']aes-\d+-ecb["']/gi,
    ],
    recommendation: 'Use AES-GCM or AES-CBC with proper IV. ECB mode leaks patterns in encrypted data.',
    fix: '// Instead of:\ncrypto.createCipher("aes-256-ecb", key)\n// Use:\ncrypto.createCipheriv("aes-256-gcm", key, iv)'
  },
  {
    id: 'CRYPTO-003',
    title: 'Disabled SSL/TLS Certificate Verification',
    severity: 'high',
    category: 'Cryptography',
    cwe: 'CWE-295',
    owasp: 'A02:2021 - Cryptographic Failures',
    languages: ['all'],
    patterns: [
      /rejectUnauthorized\s*:\s*false/gi,
      /verify\s*=\s*False/gi,
      /VERIFY_NONE/gi,
      /InsecureSkipVerify\s*:\s*true/gi,
      /ssl_verify\s*[:=]\s*false/gi,
      /NODE_TLS_REJECT_UNAUTHORIZED.*["']0["']/gi,
      /CURLOPT_SSL_VERIFYPEER\s*,\s*false/gi,
      /CURLOPT_SSL_VERIFYHOST\s*,\s*(?:0|false)/gi,
    ],
    recommendation: 'Never disable SSL certificate verification in production. Fix the root cause (proper certificates).',
  },

  // ==================== DATA EXPOSURE ====================
  {
    id: 'DATA-001',
    title: 'Debug Mode Enabled in Production',
    severity: 'high',
    category: 'Security Misconfiguration',
    cwe: 'CWE-215',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['python', 'php', 'java', 'javascript'],
    patterns: [
      /DEBUG\s*[:=]\s*True/gi,
      /debug\s*[:=]\s*true/gi,
      /display_errors\s*=\s*(?:On|1|true)/gi,
      /error_reporting\s*\(\s*E_ALL\s*\)/gi,
      /\.setLevel\s*\(\s*(?:Level\.)?ALL\s*\)/gi,
    ],
    recommendation: 'Disable debug mode in production. Use environment-specific configuration.',
  },
  {
    id: 'DATA-002',
    title: 'Sensitive Data in Logs',
    severity: 'medium',
    category: 'Data Exposure',
    cwe: 'CWE-532',
    owasp: 'A09:2021 - Security Logging and Monitoring Failures',
    languages: ['all'],
    patterns: [
      /console\.log\s*\(.*(?:password|token|secret|key|credential|ssn|credit.?card)/gi,
      /logger?\.\w+\s*\(.*(?:password|token|secret|key|credential)/gi,
      /print\s*\(.*(?:password|token|secret|key|credential)/gi,
      /Log\.\w+\s*\(.*(?:password|token|secret|key|credential)/gi,
    ],
    recommendation: 'Never log sensitive data. Implement log scrubbing. Use structured logging.',
  },
  {
    id: 'DATA-003',
    title: 'Exposed .env or Config File Pattern',
    severity: 'high',
    category: 'Data Exposure',
    cwe: 'CWE-538',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['all'],
    patterns: [
      /dotenv\.config\s*\(\s*\{\s*path\s*:\s*["']\.env\.production["']/gi,
      /config\.read\s*\(\s*["'].*\.ini["']\s*\)/gi,
    ],
    recommendation: 'Ensure .env files are in .gitignore and not accessible via web server.',
  },

  // ==================== SECURITY MISCONFIGURATION ====================
  {
    id: 'MISC-001',
    title: 'CORS Wildcard Configuration',
    severity: 'medium',
    category: 'Security Misconfiguration',
    cwe: 'CWE-942',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript', 'python', 'java', 'php'],
    patterns: [
      /Access-Control-Allow-Origin.*\*/gi,
      /cors\s*\(\s*\{?\s*origin\s*:\s*(?:true|["']\*["'])/gi,
      /CORS_ALLOW_ALL_ORIGINS\s*=\s*True/gi,
      /CORS_ORIGIN_ALLOW_ALL\s*=\s*True/gi,
      /header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*["']\)/gi,
    ],
    recommendation: 'Use a whitelist of specific allowed origins instead of wildcard (*).',
  },
  {
    id: 'MISC-002',
    title: 'Eval Usage — Code Injection Risk',
    severity: 'high',
    category: 'Code Quality',
    cwe: 'CWE-95',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'python', 'php', 'ruby'],
    patterns: [
      /\beval\s*\(/g,
      /new\s+Function\s*\(/g,
      /setTimeout\s*\(\s*["']/g,
      /setInterval\s*\(\s*["']/g,
      /exec\s*\(\s*["']/g,
    ],
    recommendation: 'Avoid eval() entirely. Use JSON.parse for JSON, use proper parsers for other data.',
  },
  {
    id: 'MISC-003',
    title: 'Insecure Deserialization',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-502',
    owasp: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['python', 'java', 'php', 'ruby', 'javascript'],
    patterns: [
      /pickle\.loads?\s*\(/gi,
      /yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)/gi,
      /yaml\.unsafe_load/gi,
      /ObjectInputStream/gi,
      /unserialize\s*\(\s*\$_/gi,
      /Marshal\.load/gi,
      /node-serialize/gi,
      /serialize-javascript/gi,
    ],
    recommendation: 'Never deserialize untrusted data. Use safe loaders (yaml.safe_load). Validate and sanitize before deserialization.',
  },
  {
    id: 'MISC-004',
    title: 'Path Traversal Vulnerability',
    severity: 'high',
    category: 'Access Control',
    cwe: 'CWE-22',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /fs\.readFile\s*\(.*req\.(body|query|params)/gi,
      /fs\.readFileSync\s*\(.*req\./gi,
      /fs\.createReadStream\s*\(.*req\./gi,
      /open\s*\(.*request\.(GET|POST|args)/gi,
      /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /include\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /require\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /fopen\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /new\s+File\s*\(.*request\.getParameter/gi,
      /path\.join\s*\(.*req\.(body|query|params)/gi,
    ],
    recommendation: 'Validate file paths against an allowlist. Use path.resolve and verify the resolved path starts with the expected directory.',
    fix: '// Safe file access:\nconst safePath = path.resolve(baseDir, userInput);\nif (!safePath.startsWith(path.resolve(baseDir))) {\n  throw new Error("Path traversal detected");\n}'
  },
  {
    id: 'MISC-005',
    title: 'Open Redirect',
    severity: 'medium',
    category: 'Access Control',
    cwe: 'CWE-601',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /res\.redirect\s*\(\s*req\.(body|query|params)/gi,
      /redirect\s*\(\s*request\.(GET|POST|args)/gi,
      /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
      /response\.sendRedirect\s*\(\s*request\.getParameter/gi,
      /window\.location\s*=\s*(?:params|query|search|hash)/gi,
      /window\.location\.href\s*=\s*(?:params|query|search)/gi,
      /location\.assign\s*\(.*(?:params|query|search|getParameter)/gi,
    ],
    recommendation: 'Validate redirect URLs against a whitelist of allowed domains. Use relative URLs only.',
  },
  {
    id: 'MISC-006',
    title: 'Prototype Pollution',
    severity: 'high',
    category: 'Code Quality',
    cwe: 'CWE-1321',
    owasp: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['javascript'],
    patterns: [
      /\[["']__proto__["']\]/g,
      /\.\s*__proto__\s*[=.]/g,
      /Object\.assign\s*\(\s*\{\}/g,
      /lodash\.merge\s*\(/gi,
      /lodash\.defaultsDeep\s*\(/gi,
      /jQuery\.extend\s*\(\s*true/gi,
      /\$\.extend\s*\(\s*true/gi,
    ],
    recommendation: 'Freeze prototypes, validate input keys, use Map instead of plain objects for untrusted data.',
  },
  {
    id: 'MISC-007',
    title: 'Missing Rate Limiting',
    severity: 'medium',
    category: 'Security Misconfiguration',
    cwe: 'CWE-307',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    languages: ['javascript'],
    patterns: [
      /app\.post\s*\(\s*["']\/(?:login|signin|auth|register|signup|forgot|reset)/gi,
    ],
    antiPatterns: [/rateLimit|rateLimiter|rate_limit|throttle|brute/gi],
    recommendation: 'Implement rate limiting on authentication endpoints (express-rate-limit, rate-limiter-flexible).',
  },
  {
    id: 'MISC-008',
    title: 'Server-Side Request Forgery (SSRF)',
    severity: 'high',
    category: 'Injection',
    cwe: 'CWE-918',
    owasp: 'A10:2021 - Server-Side Request Forgery',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /fetch\s*\(\s*req\.(body|query|params)/gi,
      /axios\.\w+\s*\(\s*req\.(body|query|params)/gi,
      /http\.get\s*\(\s*req\.(body|query|params)/gi,
      /requests\.get\s*\(\s*request\./gi,
      /urllib\.request\.urlopen\s*\(\s*request\./gi,
      /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /curl_setopt.*CURLOPT_URL.*\$_(?:GET|POST|REQUEST)/gi,
      /HttpURLConnection.*request\.getParameter/gi,
    ],
    recommendation: 'Validate and sanitize URLs. Use allowlists for domains. Block internal/private IP ranges.',
  },
  {
    id: 'MISC-009',
    title: 'Unrestricted File Upload',
    severity: 'high',
    category: 'Access Control',
    cwe: 'CWE-434',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /multer\s*\(\s*\{[^}]*\}\s*\)/gi,
      /move_uploaded_file\s*\(/gi,
      /file\.save\s*\(/gi,
    ],
    antiPatterns: [/fileFilter|allowedTypes|mimetype|extension.*check|whitelist|accept/gi],
    recommendation: 'Validate file type, size, and extension. Store uploads outside webroot. Rename uploaded files.',
  },
  {
    id: 'MISC-010',
    title: 'Regex Denial of Service (ReDoS)',
    severity: 'medium',
    category: 'Code Quality',
    cwe: 'CWE-1333',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript', 'python', 'java'],
    patterns: [
      /new RegExp\s*\(.*\+/gi,
      /RegExp\s*\(.*req\./gi,
      /re\.compile\s*\(.*request\./gi,
    ],
    recommendation: 'Never construct regex from user input. Use fixed regex patterns. Consider using RE2 for safe regex.',
  },
  {
    id: 'MISC-011',
    title: 'Header Injection / CRLF Injection',
    severity: 'high',
    category: 'Injection',
    cwe: 'CWE-113',
    owasp: 'A03:2021 - Injection',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /res\.setHeader\s*\(.*req\.(body|query|params)/gi,
      /res\.set\s*\(.*req\.(body|query|params)/gi,
      /header\s*\(\s*["'].*["']\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
      /response\.addHeader\s*\(.*request\.getParameter/gi,
    ],
    recommendation: 'Validate and sanitize any user input used in HTTP headers. Strip CRLF characters.',
  },
  {
    id: 'MISC-012',
    title: 'XML External Entity (XXE)',
    severity: 'critical',
    category: 'Injection',
    cwe: 'CWE-611',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['java', 'php', 'python', 'javascript'],
    patterns: [
      /DocumentBuilderFactory/gi,
      /SAXParserFactory/gi,
      /XMLReader/gi,
      /simplexml_load_string\s*\(\s*\$_/gi,
      /DOMDocument.*loadXML\s*\(\s*\$_/gi,
      /etree\.parse\s*\(/gi,
      /etree\.fromstring\s*\(/gi,
      /xml2js\.parseString/gi,
    ],
    antiPatterns: [/FEATURE_SECURE_PROCESSING|disallow-doctype-decl|SUPPORT_DTD.*false/gi],
    recommendation: 'Disable DTD processing and external entities in XML parsers. Use JSON instead of XML where possible.',
  },
  {
    id: 'MISC-013',
    title: 'Missing CSRF Protection',
    severity: 'medium',
    category: 'Access Control',
    cwe: 'CWE-352',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'php'],
    patterns: [
      /app\.post\s*\(\s*["']\/(?:api|user|account|profile|settings|admin|delete|update|transfer|pay)/gi,
    ],
    antiPatterns: [/csrf|csurf|csrfProtection|csrf_protect|@csrf/gi],
    recommendation: 'Implement CSRF tokens on all state-changing endpoints. Use framework-provided CSRF middleware.',
  },

  // ==================== DEPENDENCY ISSUES ====================
  {
    id: 'DEP-001',
    title: 'Known Vulnerable Package Pattern',
    severity: 'high',
    category: 'Dependency',
    cwe: 'CWE-1035',
    owasp: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['json'],
    patterns: [
      /"lodash"\s*:\s*"[<^~]?[0-3]\./gi,
      /"express"\s*:\s*"[<^~]?[0-3]\./gi,
      /"jquery"\s*:\s*"[<^~]?[12]\./gi,
      /"moment"\s*:\s*"/gi,
      /"request"\s*:\s*"/gi,
      /"node-uuid"\s*:\s*"/gi,
      /"node-serialize"\s*:\s*"/gi,
    ],
    recommendation: 'Run npm audit / pip audit / bundler audit regularly. Update dependencies. Use automated tools like Dependabot.',
  },

  // ==================== ADDITIONAL PATTERNS ====================
  {
    id: 'MISC-014',
    title: 'Hardcoded IP Address',
    severity: 'low',
    category: 'Security Misconfiguration',
    cwe: 'CWE-547',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['all'],
    patterns: [
      /(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?/g,
    ],
    recommendation: 'Use environment variables or configuration files for IP addresses. Never hardcode internal IPs.',
  },
  {
    id: 'MISC-015',
    title: 'Information Exposure via Error Messages',
    severity: 'medium',
    category: 'Data Exposure',
    cwe: 'CWE-209',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /res\.(?:send|json)\s*\(.*(?:err|error)\.(?:stack|message)/gi,
      /traceback\.print_exc/gi,
      /e\.printStackTrace\s*\(\s*\)/gi,
      /res\.status\s*\(\s*500\s*\)\.send\s*\(\s*(?:err|error)/gi,
    ],
    recommendation: 'Return generic error messages to users. Log detailed errors server-side only.',
  },
  {
    id: 'MISC-016',
    title: 'Unhandled Promise Rejection',
    severity: 'low',
    category: 'Code Quality',
    cwe: 'CWE-755',
    owasp: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript'],
    patterns: [
      /\.then\s*\([^)]+\)\s*(?!\.catch)/g,
      /async\s+function\s+\w+\s*\([^)]*\)\s*\{(?:(?!try\s*\{).)*\bawait\b/gs,
    ],
    recommendation: 'Always handle promise rejections with .catch() or try/catch in async functions.',
  },
  {
    id: 'MISC-017',
    title: 'HTTP Without TLS (Insecure Protocol)',
    severity: 'medium',
    category: 'Cryptography',
    cwe: 'CWE-319',
    owasp: 'A02:2021 - Cryptographic Failures',
    languages: ['all'],
    patterns: [
      /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[a-zA-Z0-9]/gi,
    ],
    recommendation: 'Use HTTPS for all external connections. HTTP traffic can be intercepted.',
  },
  
  // ==================== NEW PENTEST ENHANCEMENTS ====================
  {
    id: 'PRIVESC-001',
    title: 'Potential IDOR (Insecure Direct Object Reference)',
    severity: 'high',
    category: 'Access Control',
    cwe: 'CWE-639',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'php', 'java'],
    patterns: [
      /req\.(?:query|params)\.(?:id|user_id|account_id|order_id)/gi,
      /\$_(?:GET|POST|REQUEST)\[['"](?:id|user_id|account_id)['"]\]/gi,
      /request\.getParameter\(['"](?:id|user_id)['"]\)/gi,
    ],
    antiPatterns: [/req\.user\.id/gi, /session\.user_id/gi, /authorize\(/gi, /checkAccess/gi, /verifyOwner/gi],
    recommendation: 'Always verify that the authenticated user has permission to access the requested ID.',
  },
  {
    id: 'PRIVESC-002',
    title: 'Mass Assignment / Over-posting Risk',
    severity: 'high',
    category: 'Access Control',
    cwe: 'CWE-915',
    owasp: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'python', 'ruby'],
    patterns: [
      /Object\.assign\([^,]+,\s*req\.body\)/gi,
      /\.update\(\s*req\.body\s*\)/gi,
      /\.create\(\s*req\.body\s*\)/gi,
      /User\.new\(\s*params\s*\)/gi,
    ],
    antiPatterns: [/pick\(/gi, /permitted_params/gi, /whitelist/gi, /allowlist/gi],
    recommendation: 'Never bind raw request bodies directly to models. Use Data Transfer Objects (DTOs) or explicitly pick allowed fields.',
  },
  {
    id: 'LOGIC-001',
    title: 'Potential Race Condition',
    severity: 'medium',
    category: 'Business Logic',
    cwe: 'CWE-362',
    owasp: 'A04:2021 - Insecure Design',
    languages: ['javascript', 'python', 'java'],
    patterns: [
      /await\s+.*(?:find|get|select).*;\s*(?:if|while).*await\s+.*(?:update|save|decrement|increment)/gi,
      /findOne\(\).*\.then\(.*\.save\(\)/gi,
    ],
    antiPatterns: [/\$inc/gi, /transaction/gi, /mutex/gi, /lock/gi, /updateMany/gi],
    recommendation: 'Avoid Read-Modify-Write cycles without locks. Use database atomic operations (like $inc) or transactions.',
  },
  {
    id: 'AUTH-004',
    title: 'Missing Authentication Check',
    severity: 'high',
    category: 'Access Control',
    cwe: 'CWE-306',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    languages: ['javascript', 'python'],
    patterns: [
      /app\.(?:get|post|put|delete)\(['"]\/(?:admin|dashboard|settings|profile)/gi,
      /router\.(?:get|post|put|delete)\(['"]\/(?:admin|dashboard|settings)/gi,
    ],
    antiPatterns: [/authMiddleware/gi, /requireAuth/gi, /isAuthenticated/gi, /checkAdmin/gi, /jwt/gi, /passport/gi, /ensureLoggedIn/gi],
    recommendation: 'Ensure all sensitive routes have proper authentication middleware applied.',
  },
];

// ============ LANGUAGE DETECTION ============

const LANGUAGE_EXTENSIONS = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.tsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.vue': 'javascript',
  '.svelte': 'javascript',
  '.php': 'php',
  '.phtml': 'php',
  '.py': 'python',
  '.pyw': 'python',
  '.java': 'java',
  '.kt': 'java',
  '.cs': 'csharp',
  '.rb': 'ruby',
  '.go': 'go',
  '.rs': 'go',
  '.html': 'html',
  '.htm': 'html',
  '.ejs': 'html',
  '.hbs': 'html',
  '.pug': 'html',
  '.twig': 'html',
  '.blade.php': 'php',
  '.css': 'css',
  '.scss': 'css',
  '.json': 'json',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.xml': 'xml',
  '.sql': 'sql',
  '.sh': 'shell',
  '.bash': 'shell',
  '.env': 'env',
  '.cfg': 'config',
  '.conf': 'config',
  '.ini': 'config',
  '.toml': 'config',
};

function detectLanguage(filename) {
  const lower = filename.toLowerCase();
  // Check compound extensions first
  for (const [ext, lang] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (lower.endsWith(ext)) return lang;
  }
  return 'unknown';
}

// ============ ANALYZER ============

function analyzeCode(code, filename, language = null) {
  if (!language) language = detectLanguage(filename);

  const lines = code.split('\n');
  const findings = [];
  const analyzed = {
    filename,
    language,
    totalLines: lines.length,
    findings: []
  };

  for (const rule of VULNERABILITY_RULES) {
    // Check if rule applies to this language
    if (!rule.languages.includes('all') && !rule.languages.includes(language)) continue;

    for (const pattern of rule.patterns) {
      // Reset regex lastIndex
      pattern.lastIndex = 0;

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum].trim();

        // Skip empty lines and pure comments
        if (!line || line.startsWith('//') || line.startsWith('#') || line.startsWith('*') || line.startsWith('/*')) continue;

        pattern.lastIndex = 0;
        const match = pattern.exec(line);

        if (match) {
          // Check anti-patterns (if the file contains mitigations)
          let mitigated = false;
          if (rule.antiPatterns) {
            // Check nearby lines (within 20 lines)
            const nearbyCode = lines.slice(Math.max(0, lineNum - 10), Math.min(lines.length, lineNum + 10)).join('\n');
            for (const antiPattern of rule.antiPatterns) {
              antiPattern.lastIndex = 0;
              if (antiPattern.test(nearbyCode)) {
                mitigated = true;
                break;
              }
            }
          }

          if (!mitigated) {
            // Get context (surrounding lines)
            const contextStart = Math.max(0, lineNum - 2);
            const contextEnd = Math.min(lines.length, lineNum + 3);
            const context = lines.slice(contextStart, contextEnd)
              .map((l, i) => {
                const num = contextStart + i + 1;
                const marker = num === lineNum + 1 ? '>>>' : '   ';
                return `${marker} ${num}: ${l}`;
              })
              .join('\n');

            // Avoid duplicate findings for same rule + line
            const duplicate = findings.find(f =>
              f.ruleId === rule.id && f.line === lineNum + 1
            );
            if (duplicate) continue;

            findings.push({
              ruleId: rule.id,
              severity: rule.severity,
              title: rule.title,
              category: rule.category,
              description: `${rule.title} detected in ${filename} at line ${lineNum + 1}`,
              details: `File: ${filename}\nLine: ${lineNum + 1}\nCode: ${line.substring(0, 200)}`,
              recommendation: rule.recommendation,
              fix: rule.fix || '',
              evidence: context,
              cwe: rule.cwe,
              owasp: rule.owasp,
              line: lineNum + 1,
              column: match.index,
              matchedText: match[0].substring(0, 100),
              filename,
            });
          }
        }
      }
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

  analyzed.findings = findings;
  return analyzed;
}

function analyzeMultipleFiles(files, progressCallback = null) {
  const allFindings = [];
  const fileResults = [];
  let totalVulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const result = analyzeCode(file.content, file.name, file.language);
    fileResults.push(result);

    for (const finding of result.findings) {
      allFindings.push(finding);
      totalVulns[finding.severity] = (totalVulns[finding.severity] || 0) + 1;
    }

    if (progressCallback) {
      progressCallback({
        scanner: 'code-analyzer',
        progress: Math.round(((i + 1) / files.length) * 100),
        message: `Analyzed ${i + 1}/${files.length} files — ${allFindings.length} issues found`
      });
    }
  }

  return {
    name: 'Static Code Analysis',
    category: 'Code Analysis',
    icon: '[Icon]',
    summary: `Analyzed ${files.length} files — ${allFindings.length} issues (${totalVulns.critical} critical, ${totalVulns.high} high, ${totalVulns.medium} medium, ${totalVulns.low} low)`,
    filesAnalyzed: files.length,
    totalVulnerabilities: allFindings.length,
    vulnerabilityCounts: totalVulns,
    fileResults,
    findings: allFindings,
  };
}

module.exports = {
  analyzeCode,
  analyzeMultipleFiles,
  detectLanguage,
  VULNERABILITY_RULES,
  LANGUAGE_EXTENSIONS
};
