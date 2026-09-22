/**
 * VFN-CyberSite — Vulnerability Scanner
 * Active testing for SQL injection, XSS, path traversal, and more
 */

const http = require('http');
const https = require('https');
const url = require('url');
const cheerio = require('cheerio');
const querystring = require('querystring');

// ============ PAYLOADS ============

const SQLI_PAYLOADS = [
  { payload: "' OR '1'='1", type: 'auth-bypass', desc: 'Classic OR bypass' },
  { payload: "' OR '1'='1'--", type: 'auth-bypass', desc: 'OR bypass with comment' },
  { payload: "' OR '1'='1'/*", type: 'auth-bypass', desc: 'OR bypass with block comment' },
  { payload: "1' AND '1'='1", type: 'boolean', desc: 'Boolean-based true' },
  { payload: "1' AND '1'='2", type: 'boolean', desc: 'Boolean-based false' },
  { payload: "' UNION SELECT NULL--", type: 'union', desc: 'UNION injection probe' },
  { payload: "' UNION SELECT NULL,NULL--", type: 'union', desc: 'UNION 2 columns' },
  { payload: "' UNION SELECT NULL,NULL,NULL--", type: 'union', desc: 'UNION 3 columns' },
  { payload: "1; WAITFOR DELAY '0:0:5'--", type: 'time-based', desc: 'MSSQL time delay' },
  { payload: "1' AND SLEEP(3)--", type: 'time-based', desc: 'MySQL time delay' },
  { payload: "1' AND pg_sleep(3)--", type: 'time-based', desc: 'PostgreSQL time delay' },
  { payload: "1'||(SELECT ''FROM DUAL)||'", type: 'oracle', desc: 'Oracle injection' },
  { payload: "admin'--", type: 'auth-bypass', desc: 'Comment out password check' },
  { payload: "' HAVING 1=1--", type: 'error-based', desc: 'Error-based (HAVING)' },
  { payload: "' GROUP BY columnnames HAVING 1=1--", type: 'error-based', desc: 'Error-based (GROUP BY)' },
  { payload: "1' ORDER BY 1--", type: 'order-by', desc: 'Column count probe' },
  { payload: "1' ORDER BY 100--", type: 'order-by', desc: 'Column count overflow' },
];

const SQLI_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /MySql Error/i,
  /valid MySQL result/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /ERROR:\s+syntax error at or near/i,
  /ORA-\d{5}/i,
  /Oracle.*Driver/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /Unclosed quotation mark/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /mssql_query/i,
  /SQLServer JDBC Driver/i,
  /com\.microsoft\.sqlserver\.jdbc/i,
  /SQLITE_ERROR/i,
  /SQLite3::/i,
  /SQLite\/JDBCDriver/i,
  /near ".*": syntax error/i,
  /You have an error in your SQL syntax/i,
  /Incorrect syntax near/i,
  /quoted string not properly terminated/i,
  /DBD::mysql/i,
  /supplied argument is not a valid MySQL/i,
  /SQLSTATE\[/i,
  /PDOException/i,
  /Doctrine\\DBAL/i,
  /PG::SyntaxError/i,
  /unterminated quoted string/i,
  /SQL command not properly ended/i,
];

const XSS_PAYLOADS = [
  { payload: '<script>alert("CyberScanXSS")</script>', type: 'basic', desc: 'Basic script injection' },
  { payload: '"><script>alert("CyberScanXSS")</script>', type: 'break-attr', desc: 'Breaking out of attribute' },
  { payload: "'>< script>alert('CyberScanXSS')</script>", type: 'break-attr', desc: 'Single-quote attribute break' },
  { payload: '<img src=x onerror=alert("CyberScanXSS")>', type: 'event-handler', desc: 'Image error event' },
  { payload: '<svg onload=alert("CyberScanXSS")>', type: 'svg', desc: 'SVG onload event' },
  { payload: '<body onload=alert("CyberScanXSS")>', type: 'body', desc: 'Body onload event' },
  { payload: '"><img src=x onerror=alert("CyberScanXSS")>', type: 'break-img', desc: 'Attribute break + img' },
  { payload: "javascript:alert('CyberScanXSS')", type: 'proto', desc: 'JavaScript protocol' },
  { payload: '<div onmouseover=alert("CyberScanXSS")>test</div>', type: 'event', desc: 'Mouse event handler' },
  { payload: '{{7*7}}', type: 'ssti', desc: 'Template injection probe' },
  { payload: '${7*7}', type: 'ssti', desc: 'Template literal injection' },
  { payload: '<iframe src="javascript:alert(\'CyberScanXSS\')">', type: 'iframe', desc: 'Iframe JavaScript src' },
  { payload: '"><svg/onload=alert("CyberScanXSS")>', type: 'svg-break', desc: 'SVG with attribute break' },
];

const PATH_TRAVERSAL_PAYLOADS = [
  { payload: '../../../etc/passwd', desc: 'Unix password file' },
  { payload: '....//....//....//etc/passwd', desc: 'Double-encoded traversal' },
  { payload: '..\\..\\..\\windows\\win.ini', desc: 'Windows ini file' },
  { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', desc: 'URL-encoded traversal' },
  { payload: '..%252f..%252f..%252fetc%252fpasswd', desc: 'Double URL-encoded' },
  { payload: '/etc/passwd%00', desc: 'Null byte injection' },
  { payload: '....//....//....//etc//passwd', desc: 'Filter bypass attempt' },
];

const OPEN_REDIRECT_PAYLOADS = [
  { payload: '//evil.com', desc: 'Protocol-relative URL' },
  { payload: 'https://evil.com', desc: 'Absolute URL redirect' },
  { payload: '/\\evil.com', desc: 'Backslash bypass' },
  { payload: '//evil%2ecom', desc: 'Encoded dot' },
  { payload: '/%0d/evil.com', desc: 'CRLF redirect' },
];

function makeRequest(targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      timeout: options.timeout || 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        ...options.headers
      },
      rejectUnauthorized: false,
    };

    if (options.body) {
      reqOptions.headers['Content-Type'] = options.contentType || 'application/x-www-form-urlencoded';
      reqOptions.headers['Content-Length'] = Buffer.byteLength(options.body);
    }

    const startTime = Date.now();
    let timer = null;
    let isDone = false;
    let activeReq = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
    };

    const done = (result) => {
      if (isDone) return;
      isDone = true;
      cleanup();
      resolve(result);
    };

    timer = setTimeout(() => {
      if (activeReq) {
        try { activeReq.destroy(); } catch {}
      }
      done({ statusCode: 0, headers: {}, body: '', responseTime: Date.now() - startTime, url: targetUrl, timedOut: true });
    }, timeout);

    const req = client.request(reqOptions, (res) => {
      let body = '';
      const finish = () => {
        done({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          responseTime: Date.now() - startTime,
          url: targetUrl
        });
      };

      res.on('data', chunk => {
        body += chunk;
        if (body.length > 200000) {
          try { res.destroy(); } catch {}
          finish();
        }
      });
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', () => finish());
    });

    activeReq = req;
    req.on('error', (err) => {
      done({ statusCode: 0, headers: {}, body: '', responseTime: Date.now() - startTime, url: targetUrl, error: err.message });
    });

    if (options.body) req.write(options.body);
    req.end();
  });
}

async function findForms(targetUrl, html) {
  const $ = cheerio.load(html);
  const forms = [];

  $('form').each((_, form) => {
    const $form = $(form);
    const action = $form.attr('action') || '';
    const method = ($form.attr('method') || 'GET').toUpperCase();
    const inputs = [];

    $form.find('input, textarea, select').each((_, input) => {
      const $input = $(input);
      inputs.push({
        name: $input.attr('name') || '',
        type: $input.attr('type') || 'text',
        value: $input.attr('value') || '',
        tag: input.tagName
      });
    });

    // Resolve action URL
    let actionUrl = action;
    if (!action || action === '#' || action === '') {
      actionUrl = targetUrl;
    } else if (action.startsWith('/')) {
      const parsed = new URL(targetUrl);
      actionUrl = `${parsed.protocol}//${parsed.host}${action}`;
    } else if (!action.startsWith('http')) {
      actionUrl = new URL(action, targetUrl).href;
    }

    forms.push({ action: actionUrl, method, inputs });
  });

  // Also find URL parameters
  try {
    const parsed = new URL(targetUrl);
    if (parsed.search) {
      const params = new URLSearchParams(parsed.search);
      const paramInputs = [];
      for (const [key, value] of params) {
        paramInputs.push({ name: key, type: 'url-param', value, tag: 'param' });
      }
      if (paramInputs.length > 0) {
        forms.push({ action: targetUrl, method: 'GET', inputs: paramInputs, isUrlParams: true });
      }
    }
  } catch { /* ignore */ }

  return forms;
}

async function testSQLInjection(targetUrl, forms, progressCallback) {
  const findings = [];
  let tested = 0;

  for (const form of forms) {
    for (const input of form.inputs) {
      if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button') continue;

      // Get baseline response
      const baselineData = {};
      form.inputs.forEach(inp => { if (inp.name) baselineData[inp.name] = inp.value || 'test'; });

      let baselineResponse;
      try {
        if (form.method === 'GET') {
          const baseUrl = new URL(form.action);
          Object.entries(baselineData).forEach(([k, v]) => baseUrl.searchParams.set(k, v));
          baselineResponse = await makeRequest(baseUrl.href);
        } else {
          baselineResponse = await makeRequest(form.action, {
            method: 'POST',
            body: querystring.stringify(baselineData),
            contentType: 'application/x-www-form-urlencoded'
          });
        }
      } catch { continue; }

      // Test each SQLi payload
      for (const sqli of SQLI_PAYLOADS.slice(0, 8)) {
        const testData = { ...baselineData };
        testData[input.name] = sqli.payload;

        let response;
        try {
          if (form.method === 'GET') {
            const testUrl = new URL(form.action);
            Object.entries(testData).forEach(([k, v]) => testUrl.searchParams.set(k, v));
            response = await makeRequest(testUrl.href);
          } else {
            response = await makeRequest(form.action, {
              method: 'POST',
              body: querystring.stringify(testData),
              contentType: 'application/x-www-form-urlencoded'
            });
          }
        } catch { continue; }

        // Check for SQL errors in response
        const errorFound = SQLI_ERROR_PATTERNS.find(pattern => pattern.test(response.body));
        if (errorFound) {
          findings.push({
            severity: 'critical',
            title: `SQL Injection — Error-Based (${input.name})`,
            description: `The input "${input.name}" on ${form.action} is vulnerable to SQL injection. Database error messages were returned.`,
            details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nPayload: ${sqli.payload}\nType: ${sqli.desc}\nError pattern: ${errorFound}`,
            recommendation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL queries. Implement input validation and WAF.',
            evidence: `Payload: ${sqli.payload}\nResponse contained SQL error matching: ${errorFound}\nResponse snippet: ${response.body.match(errorFound)?.[0]?.substring(0, 200)}`,
            cwe: 'CWE-89',
            owasp: 'A03:2021 - Injection'
          });
          break; // Move to next input
        }

        // Time-based detection
        if (sqli.type === 'time-based' && response.responseTime > 4500) {
          findings.push({
            severity: 'critical',
            title: `SQL Injection — Time-Based (${input.name})`,
            description: `The input "${input.name}" may be vulnerable to time-based blind SQL injection. Response was delayed.`,
            details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nPayload: ${sqli.payload}\nResponse time: ${response.responseTime}ms (expected < 3000ms)`,
            recommendation: 'Use parameterized queries. Implement input validation.',
            evidence: `Payload: ${sqli.payload}\nResponse time: ${response.responseTime}ms (normal: ${baselineResponse?.responseTime || 'N/A'}ms)`,
            cwe: 'CWE-89',
            owasp: 'A03:2021 - Injection'
          });
          break;
        }

        // Boolean-based detection
        if (sqli.type === 'boolean' && baselineResponse) {
          const similarity = Math.abs(response.body.length - baselineResponse.body.length);
          if (sqli.payload.includes("'1'='1") && similarity > 100) {
            // Compare with false condition
            const falseData = { ...baselineData };
            falseData[input.name] = "1' AND '1'='2";
            let falseResponse;
            try {
              if (form.method === 'GET') {
                const testUrl = new URL(form.action);
                Object.entries(falseData).forEach(([k, v]) => testUrl.searchParams.set(k, v));
                falseResponse = await makeRequest(testUrl.href);
              } else {
                falseResponse = await makeRequest(form.action, { method: 'POST', body: querystring.stringify(falseData) });
              }

              if (Math.abs(response.body.length - falseResponse.body.length) > 100) {
                findings.push({
                  severity: 'high',
                  title: `Possible SQL Injection — Boolean-Based (${input.name})`,
                  description: `The input "${input.name}" shows different responses for true/false SQL conditions.`,
                  details: `True payload response: ${response.body.length} bytes\nFalse payload response: ${falseResponse.body.length} bytes\nBaseline: ${baselineResponse.body.length} bytes`,
                  recommendation: 'Use parameterized queries. Further manual testing recommended.',
                  evidence: `True: "${sqli.payload}" → ${response.body.length} bytes\nFalse: "1' AND '1'='2" → ${falseResponse.body.length} bytes`,
                  cwe: 'CWE-89',
                  owasp: 'A03:2021 - Injection'
                });
                break;
              }
            } catch { /* ignore */ }
          }
        }

        tested++;
      }
    }
  }

  return findings;
}

async function testXSS(targetUrl, forms) {
  const findings = [];

  for (const form of forms) {
    for (const input of form.inputs) {
      if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button' || input.type === 'password') continue;

      for (const xss of XSS_PAYLOADS.slice(0, 6)) {
        const testData = {};
        form.inputs.forEach(inp => { if (inp.name) testData[inp.name] = inp.value || 'test'; });
        testData[input.name] = xss.payload;

        let response;
        try {
          if (form.method === 'GET') {
            const testUrl = new URL(form.action);
            Object.entries(testData).forEach(([k, v]) => testUrl.searchParams.set(k, v));
            response = await makeRequest(testUrl.href);
          } else {
            response = await makeRequest(form.action, {
              method: 'POST',
              body: querystring.stringify(testData),
              contentType: 'application/x-www-form-urlencoded'
            });
          }
        } catch { continue; }

        // Check if payload is reflected in response
        if (response.body && response.body.includes(xss.payload)) {
          findings.push({
            severity: 'high',
            title: `Reflected XSS — ${input.name}`,
            description: `The input "${input.name}" reflects user input without sanitization, allowing XSS attacks.`,
            details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nPayload type: ${xss.desc}\nPayload was reflected in the response body.`,
            recommendation: 'Encode all output (HTML entity encoding). Use Content-Security-Policy header. Implement input validation.',
            evidence: `Payload: ${xss.payload}\nReflected in response body`,
            cwe: 'CWE-79',
            owasp: 'A03:2021 - Injection'
          });
          break;
        }

        // Check for template injection (SSTI)
        if (xss.type === 'ssti' && response.body) {
          if (response.body.includes('49')) { // 7*7 = 49
            findings.push({
              severity: 'critical',
              title: `Server-Side Template Injection (SSTI) — ${input.name}`,
              description: `The input "${input.name}" is vulnerable to template injection. The expression ${xss.payload} was evaluated server-side.`,
              details: `Form: ${form.method} ${form.action}\nPayload: ${xss.payload}\nResult "49" found in response (7*7=49)`,
              recommendation: 'Never pass user input directly into template engines. Use template sandboxing.',
              evidence: `Payload: ${xss.payload}\nResponse contains "49" indicating server-side evaluation`,
              cwe: 'CWE-1336',
              owasp: 'A03:2021 - Injection'
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}

async function testPathTraversal(targetUrl, forms) {
  const findings = [];

  const traversalIndicators = [
    'root:', '/bin/bash', '/bin/sh',  // /etc/passwd
    '[fonts]', '[extensions]',        // win.ini
    'daemon:', 'nobody:',             // /etc/passwd
  ];

  for (const form of forms) {
    for (const input of form.inputs) {
      if (!input.name || input.type === 'submit' || input.type === 'hidden') continue;

      for (const traversal of PATH_TRAVERSAL_PAYLOADS.slice(0, 4)) {
        const testData = {};
        form.inputs.forEach(inp => { if (inp.name) testData[inp.name] = inp.value || 'test'; });
        testData[input.name] = traversal.payload;

        let response;
        try {
          if (form.method === 'GET') {
            const testUrl = new URL(form.action);
            Object.entries(testData).forEach(([k, v]) => testUrl.searchParams.set(k, v));
            response = await makeRequest(testUrl.href);
          } else {
            response = await makeRequest(form.action, { method: 'POST', body: querystring.stringify(testData) });
          }
        } catch { continue; }

        if (response.body) {
          const found = traversalIndicators.find(indicator => response.body.includes(indicator));
          if (found) {
            findings.push({
              severity: 'critical',
              title: `Path Traversal — ${input.name}`,
              description: `The input "${input.name}" is vulnerable to directory traversal. File contents were returned.`,
              details: `Payload: ${traversal.payload}\nIndicator found: "${found}"`,
              recommendation: 'Validate and sanitize file paths. Use a whitelist of allowed files. Never use user input directly in file operations.',
              evidence: `Payload: ${traversal.payload}\nResponse contained: "${found}"`,
              cwe: 'CWE-22',
              owasp: 'A01:2021 - Broken Access Control'
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}

async function testOpenRedirect(targetUrl) {
  const findings = [];
  const parsed = new URL(targetUrl);
  const redirectParams = ['url', 'redirect', 'next', 'return', 'returnTo', 'return_to', 'dest', 'destination', 'redir', 'redirect_uri', 'redirect_url', 'continue', 'goto', 'target', 'link', 'r', 'u'];

  for (const param of redirectParams) {
    for (const payload of OPEN_REDIRECT_PAYLOADS.slice(0, 3)) {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, payload.payload);

      let response;
      try {
        response = await makeRequest(testUrl.href, { timeout: 5000 });
      } catch { continue; }

      if (response.statusCode >= 300 && response.statusCode < 400) {
        const location = response.headers.location || '';
        if (location.includes('evil.com') || location.includes('evil%2e')) {
          findings.push({
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter`,
            description: `The parameter "${param}" allows redirecting users to arbitrary external domains.`,
            details: `URL: ${testUrl.href}\nRedirect location: ${location}`,
            recommendation: 'Validate redirect URLs against a whitelist of allowed domains. Use relative URLs only.',
            evidence: `Parameter: ${param}\nPayload: ${payload.payload}\nRedirected to: ${location}`,
            cwe: 'CWE-601',
            owasp: 'A01:2021 - Broken Access Control'
          });
          break;
        }
      }
    }
  }

  return findings;
}

async function checkHTTPMethods(targetUrl) {
  const findings = [];
  const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];

  // OPTIONS request
  try {
    const response = await makeRequest(targetUrl, { method: 'OPTIONS', timeout: 5000 });
    const allowed = response.headers.allow || response.headers['access-control-allow-methods'] || '';
    
    if (allowed) {
      const methods = allowed.split(',').map(m => m.trim().toUpperCase());
      const dangerous = methods.filter(m => dangerousMethods.includes(m));

      if (dangerous.length > 0) {
        findings.push({
          severity: dangerous.includes('TRACE') ? 'high' : 'medium',
          title: `Dangerous HTTP Methods Allowed`,
          description: `The server allows potentially dangerous HTTP methods: ${dangerous.join(', ')}`,
          details: `Allowed methods: ${allowed}`,
          recommendation: 'Disable unnecessary HTTP methods. Only allow GET, POST, HEAD as needed.',
          evidence: `OPTIONS response: Allow: ${allowed}`,
          cwe: 'CWE-749',
          owasp: 'A05:2021 - Security Misconfiguration'
        });
      }
    }
  } catch { /* ignore */ }

  // TRACE method
  try {
    const response = await makeRequest(targetUrl, { method: 'TRACE', timeout: 5000 });
    if (response.statusCode === 200 && response.body.includes('TRACE')) {
      findings.push({
        severity: 'high',
        title: 'TRACE Method Enabled (Cross-Site Tracing)',
        description: 'The TRACE HTTP method is enabled, which can be used for Cross-Site Tracing (XST) attacks.',
        details: 'TRACE reflects the request back, potentially exposing cookies and auth headers.',
        recommendation: 'Disable the TRACE method on the web server.',
        evidence: `TRACE / returned HTTP ${response.statusCode}`,
        cwe: 'CWE-693',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  } catch { /* ignore */ }

  return findings;
}

async function runVulnScan(targetUrl, html = null, progressCallback = null) {
  const findings = [];

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 5, message: 'Fetching target page...' });

  // Fetch page if not provided
  if (!html) {
    try {
      const response = await makeRequest(targetUrl);
      html = response.body;
    } catch (err) {
      return {
        name: 'Vulnerability Scanner',
        category: 'Active Testing',
        icon: '[Icon]',
        summary: `Could not connect: ${err.message}`,
        findings: [{ severity: 'info', title: 'Connection failed', description: err.message, details: '', recommendation: '', evidence: '', cwe: 'N/A', owasp: 'N/A' }]
      };
    }
  }

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 10, message: 'Discovering forms and input fields...' });

  // Find forms and inputs
  const forms = await findForms(targetUrl, html);

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 20, message: `Found ${forms.length} forms. Testing SQL injection...` });

  // SQL Injection tests
  const sqliFindings = await testSQLInjection(targetUrl, forms, progressCallback);
  findings.push(...sqliFindings);

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 45, message: 'Testing XSS vulnerabilities...' });

  // XSS tests
  const xssFindings = await testXSS(targetUrl, forms);
  findings.push(...xssFindings);

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 60, message: 'Testing path traversal...' });

  // Path Traversal tests
  const pathFindings = await testPathTraversal(targetUrl, forms);
  findings.push(...pathFindings);

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 75, message: 'Testing open redirects...' });

  // Open Redirect tests
  const redirectFindings = await testOpenRedirect(targetUrl);
  findings.push(...redirectFindings);

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 90, message: 'Checking HTTP methods...' });

  // HTTP Methods check
  const methodFindings = await checkHTTPMethods(targetUrl);
  findings.push(...methodFindings);

  // Check for sensitive info in HTML
  const $ = cheerio.load(html);

  // Check for HTML comments with sensitive info
  const comments = [];
  const findComments = (node) => {
    if (node.type === 'comment') {
      comments.push(node.data);
    }
    if (node.children) {
      node.children.forEach(findComments);
    }
  };
  $('*').each((_, el) => {
    if (el.children) el.children.forEach(findComments);
  });

  const sensitiveCommentPatterns = [
    /password/i, /passwd/i, /secret/i, /api[_-]?key/i,
    /todo.*fix/i, /hack/i, /bug/i, /vulnerability/i,
    /admin/i, /credential/i, /token/i, /database/i,
    /debug/i, /temporary/i, /remove.*before/i
  ];

  for (const comment of comments) {
    const matchedPattern = sensitiveCommentPatterns.find(p => p.test(comment));
    if (matchedPattern) {
      findings.push({
        severity: 'low',
        title: 'Sensitive Information in HTML Comments',
        description: 'HTML comments contain potentially sensitive information.',
        details: `Comment: <!-- ${comment.substring(0, 200)} -->`,
        recommendation: 'Remove sensitive comments from production HTML.',
        evidence: `<!-- ${comment.substring(0, 200)} -->`,
        cwe: 'CWE-615',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
      break;
    }
  }

  // Check for forms without CSRF tokens
  $('form[method="post" i], form[method="POST"]').each((_, form) => {
    const $form = $(form);
    const hasCSRF = $form.find('input[name*="csrf" i], input[name*="token" i], input[name*="_token" i], input[name="authenticity_token"], input[name="__RequestVerificationToken"]').length > 0;
    if (!hasCSRF) {
      const action = $form.attr('action') || targetUrl;
      findings.push({
        severity: 'medium',
        title: `Missing CSRF Token: ${action}`,
        description: 'A POST form lacks a CSRF token, making it vulnerable to Cross-Site Request Forgery.',
        details: `Form action: ${action}`,
        recommendation: 'Add CSRF token to all POST forms. Use framework-provided CSRF protection.',
        evidence: `Form action="${action}" method="POST" — no CSRF token found`,
        cwe: 'CWE-352',
        owasp: 'A01:2021 - Broken Access Control'
      });
    }
  });

  // Check for password fields without autocomplete="off"
  $('input[type="password"]').each((_, input) => {
    const $input = $(input);
    if ($input.attr('autocomplete') !== 'off' && $input.attr('autocomplete') !== 'new-password') {
      findings.push({
        severity: 'low',
        title: 'Password Field Autocomplete Enabled',
        description: 'Password field allows browser autocomplete, which may store credentials.',
        details: `Input name: ${$input.attr('name') || 'unnamed'}`,
        recommendation: 'Add autocomplete="off" or autocomplete="new-password" to password fields.',
        evidence: `<input type="password" name="${$input.attr('name') || ''}" autocomplete="${$input.attr('autocomplete') || 'not set'}">`,
        cwe: 'CWE-522',
        owasp: 'A07:2021 - Identification and Authentication Failures'
      });
    }
  });

  if (progressCallback) progressCallback({ scanner: 'vuln-scanner', progress: 100, message: 'Vulnerability scan complete' });

  return {
    name: 'Vulnerability Scanner',
    category: 'Active Testing',
    icon: '[Icon]',
    summary: `Tested ${forms.length} forms — Found ${findings.length} vulnerabilities`,
    formsFound: forms.length,
    findings
  };
}

module.exports = { runVulnScan };
