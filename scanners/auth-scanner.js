/**
 * VFN-CyberSite — Broken Authentication Scanner
 * Comprehensive authentication and session management testing
 * Tests: Default creds, Session security, JWT, Password policy, Auth bypass, MFA
 */

const http = require('http');
const https = require('https');
const querystring = require('querystring');
const cheerio = require('cheerio');
const crypto = require('crypto');

// ============ DEFAULT CREDENTIALS DATABASE ============

const DEFAULT_CREDENTIALS = [
  { user: 'admin', pass: 'admin' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'admin', pass: 'admin123' },
  { user: 'admin', pass: '1234' },
  { user: 'admin', pass: '12345' },
  { user: 'admin', pass: 'admin1' },
  { user: 'admin', pass: 'administrator' },
  { user: 'admin', pass: 'changeme' },
  { user: 'admin', pass: 'letmein' },
  { user: 'admin', pass: 'pass' },
  { user: 'admin', pass: 'root' },
  { user: 'admin', pass: 'toor' },
  { user: 'admin', pass: 'qwerty' },
  { user: 'admin', pass: 'abc123' },
  { user: 'admin', pass: 'welcome' },
  { user: 'admin', pass: 'master' },
  { user: 'root', pass: 'root' },
  { user: 'root', pass: 'password' },
  { user: 'root', pass: 'toor' },
  { user: 'root', pass: '123456' },
  { user: 'root', pass: 'admin' },
  { user: 'test', pass: 'test' },
  { user: 'test', pass: '123456' },
  { user: 'test', pass: 'test123' },
  { user: 'user', pass: 'user' },
  { user: 'user', pass: 'password' },
  { user: 'user', pass: '123456' },
  { user: 'guest', pass: 'guest' },
  { user: 'guest', pass: '' },
  { user: 'demo', pass: 'demo' },
  { user: 'operator', pass: 'operator' },
  { user: 'manager', pass: 'manager' },
  { user: 'support', pass: 'support' },
  { user: 'info', pass: 'info' },
  { user: 'webmaster', pass: 'webmaster' },
  { user: 'sysadmin', pass: 'sysadmin' },
  { user: 'postgres', pass: 'postgres' },
  { user: 'mysql', pass: 'mysql' },
  { user: 'oracle', pass: 'oracle' },
  { user: 'ftp', pass: 'ftp' },
  { user: 'anonymous', pass: '' },
  { user: 'admin', pass: 'P@ssw0rd' },
  { user: 'admin', pass: 'Admin123' },
  { user: 'sa', pass: '' },
  { user: 'sa', pass: 'sa' },
  { user: 'tomcat', pass: 'tomcat' },
  { user: 'jenkins', pass: 'jenkins' },
  { user: 'admin', pass: 'secret' },
  { user: 'pi', pass: 'raspberry' },
];

// ============ LOGIN FORM ENDPOINTS ============

const LOGIN_PATHS = [
  '/login', '/signin', '/sign-in', '/auth/login', '/admin/login',
  '/user/login', '/account/login', '/wp-login.php', '/administrator',
  '/api/login', '/api/auth/login', '/api/v1/auth/login',
  '/auth', '/authenticate', '/session/new', '/login.php',
  '/login.asp', '/login.aspx', '/login.html', '/login.jsp',
  '/accounts/login', '/member/login', '/portal/login',
];

// ============ HTTP HELPER ============

function makeRequest(targetUrl, options = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch { return resolve(null); }
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
        ...options.headers
      },
      rejectUnauthorized: false,
    };

    if (options.body) {
      reqOptions.headers['Content-Type'] = options.contentType || 'application/x-www-form-urlencoded';
      reqOptions.headers['Content-Length'] = Buffer.byteLength(options.body);
    }

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
      done(null);
    }, options.timeout || 8000);

    const req = client.request(reqOptions, (res) => {
      let body = '';
      const finish = () => {
        done({ statusCode: res.statusCode, headers: res.headers, body, url: targetUrl });
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
    req.on('error', () => done(null));
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ============ LOGIN FORM DISCOVERY ============

async function findLoginForms(targetUrl, html) {
  const loginForms = [];

  // Try common login paths
  const pathsToCheck = [targetUrl, ...LOGIN_PATHS.map(p => targetUrl.replace(/\/+$/, '') + p)];

  for (const path of pathsToCheck.slice(0, 15)) {
    try {
      const response = await makeRequest(path);
      if (!response || response.statusCode >= 400) continue;

      const $ = cheerio.load(response.body);
      $('form').each((_, form) => {
        const $form = $(form);
        const hasPassword = $form.find('input[type="password"]').length > 0;
        if (!hasPassword) return;

        const inputs = [];
        let userField = null, passField = null;

        $form.find('input').each((_, input) => {
          const $input = $(input);
          const name = $input.attr('name') || '';
          const type = $input.attr('type') || 'text';

          if (type === 'password') passField = name;
          else if (['text', 'email'].includes(type) && /user|email|login|name|account/i.test(name)) userField = name;
          else if (type === 'text' && !userField) userField = name;

          inputs.push({ name, type, value: $input.attr('value') || '' });
        });

        if (userField && passField) {
          let action = $form.attr('action') || path;
          if (action.startsWith('/')) { const p = new URL(targetUrl); action = `${p.protocol}//${p.host}${action}`; }
          else if (!action.startsWith('http')) action = new URL(action, path).href;

          loginForms.push({
            url: path,
            action,
            method: ($form.attr('method') || 'POST').toUpperCase(),
            userField,
            passField,
            inputs,
            csrfField: inputs.find(i => /csrf|token|_token|nonce/i.test(i.name)),
          });
        }
      });
    } catch { continue; }
  }

  return loginForms;
}

// ============ TEST FUNCTIONS ============

async function testDefaultCredentials(loginForms, findings, progressCallback) {
  if (loginForms.length === 0) return;

  const form = loginForms[0]; // Use first found login form
  let tested = 0;
  const maxTests = 20; // Limit to prevent lockout

  for (const cred of DEFAULT_CREDENTIALS.slice(0, maxTests)) {
    const data = {};
    form.inputs.forEach(inp => { if (inp.name && inp.value) data[inp.name] = inp.value; });
    data[form.userField] = cred.user;
    data[form.passField] = cred.pass;

    const response = await makeRequest(form.action, {
      method: form.method,
      body: querystring.stringify(data),
      contentType: 'application/x-www-form-urlencoded',
    });

    if (!response) continue;
    tested++;

    // Check for successful login indicators
    const successIndicators = [
      response.statusCode === 302 && response.headers.location && !/login|error|fail/i.test(response.headers.location),
      /dashboard|welcome|profile|home|admin|logout|sign.?out/i.test(response.body) && !/invalid|error|incorrect|failed|wrong/i.test(response.body),
      response.headers['set-cookie'] && /session|auth|token/i.test(JSON.stringify(response.headers['set-cookie'])),
    ];

    if (successIndicators.some(Boolean)) {
      findings.push({
        severity: 'critical',
        title: `Default Credentials — ${cred.user}:${cred.pass}`,
        description: `Login form at ${form.action} accepts default credentials (${cred.user}:${cred.pass}). This allows unauthorized access.`,
        details: `Login URL: ${form.url}\nAction: ${form.action}\nUsername field: ${form.userField}\nPassword field: ${form.passField}\nCredentials: ${cred.user}:${cred.pass}\nResponse: HTTP ${response.statusCode}`,
        recommendation: 'Change all default credentials. Enforce strong password policies. Implement account lockout after failed attempts.',
        evidence: `POST ${form.action}\n${form.userField}=${cred.user}&${form.passField}=${cred.pass}\nResult: HTTP ${response.statusCode}${response.headers.location ? '\nRedirect: ' + response.headers.location : ''}`,
        cwe: 'CWE-798',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
      return; // Found one, stop testing
    }
  }
}

async function testBruteForceProtection(loginForms, findings) {
  if (loginForms.length === 0) return;
  const form = loginForms[0];

  // Send 10 rapid failed login attempts
  let blocked = false;
  let lastStatus = 0;
  const responses = [];

  for (let i = 0; i < 10; i++) {
    const data = {};
    form.inputs.forEach(inp => { if (inp.name && inp.value) data[inp.name] = inp.value; });
    data[form.userField] = 'admin';
    data[form.passField] = `wrong_password_${i}_${Date.now()}`;

    const response = await makeRequest(form.action, {
      method: form.method,
      body: querystring.stringify(data),
      contentType: 'application/x-www-form-urlencoded',
    });

    if (!response) continue;
    responses.push(response.statusCode);
    lastStatus = response.statusCode;

    // Check if we got blocked
    if (response.statusCode === 429 || response.statusCode === 403 ||
        /rate.?limit|too.?many|locked|blocked|captcha/i.test(response.body)) {
      blocked = true;
      break;
    }
  }

  if (!blocked && responses.length >= 8) {
    findings.push({
      severity: 'high',
      title: 'Missing Brute Force Protection',
      description: `Login form at ${form.action} allows unlimited login attempts without rate limiting, lockout, or CAPTCHA.`,
      details: `10 rapid login attempts were accepted without any blocking.\nLogin URL: ${form.url}\nAll responses: ${responses.join(', ')}`,
      recommendation: 'Implement rate limiting (e.g., 5 attempts per minute). Add account lockout after 10 failed attempts. Consider CAPTCHA after 3 failures.',
      evidence: `10 consecutive failed logins → all returned HTTP ${lastStatus}\nNo rate limiting, lockout, or CAPTCHA detected`,
      cwe: 'CWE-307',
      owasp: 'A07:2021 - Identification and Authentication Failures',
    });
  }
}

async function testSessionSecurity(targetUrl, findings) {
  // Fetch the page and check cookies
  const response = await makeRequest(targetUrl);
  if (!response) return;

  const setCookies = response.headers['set-cookie'];
  if (!setCookies) return;

  const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];

  for (const cookie of cookies) {
    const cookieName = cookie.split('=')[0].trim();
    const cookieValue = cookie.split('=')[1]?.split(';')[0] || '';
    const issues = [];

    // Check security flags
    if (!/httponly/i.test(cookie)) issues.push('Missing HttpOnly flag — vulnerable to XSS cookie theft');
    if (!/secure/i.test(cookie) && targetUrl.startsWith('https')) issues.push('Missing Secure flag — cookie sent over HTTP');
    if (!/samesite/i.test(cookie)) issues.push('Missing SameSite attribute — vulnerable to CSRF');

    // Check session ID entropy
    if (/session|sess|sid|auth|token/i.test(cookieName)) {
      const entropy = calculateEntropy(cookieValue);
      if (entropy < 3.5 && cookieValue.length > 0) {
        issues.push(`Low session ID entropy (${entropy.toFixed(2)} bits/char) — predictable sessions`);
      }
      if (cookieValue.length < 16) {
        issues.push(`Short session ID (${cookieValue.length} chars) — brute force risk`);
      }

      // Check if session ID is sequential or predictable
      if (/^\d+$/.test(cookieValue)) {
        issues.push('Numeric-only session ID — highly predictable');
      }
    }

    if (issues.length > 0) {
      findings.push({
        severity: issues.length >= 3 ? 'high' : 'medium',
        title: `Insecure Session: ${cookieName}`,
        description: `Cookie "${cookieName}" has ${issues.length} security issues:\n${issues.map(i => '• ' + i).join('\n')}`,
        details: `Cookie: ${cookie.substring(0, 200)}\nIssues:\n${issues.join('\n')}`,
        recommendation: `Set cookie with: HttpOnly; Secure; SameSite=Strict; Path=/\nUse cryptographically random session IDs with at least 128 bits of entropy.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 300)}\n\nIssues found:\n${issues.join('\n')}`,
        cwe: 'CWE-614',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
    }
  }

  // Check for session fixation
  const response2 = await makeRequest(targetUrl);
  if (response2?.headers['set-cookie']) {
    const cookies2 = Array.isArray(response2.headers['set-cookie']) ? response2.headers['set-cookie'] : [response2.headers['set-cookie']];
    for (const c1 of cookies) {
      for (const c2 of cookies2) {
        const name1 = c1.split('=')[0].trim();
        const name2 = c2.split('=')[0].trim();
        const val1 = c1.split('=')[1]?.split(';')[0];
        const val2 = c2.split('=')[1]?.split(';')[0];

        if (name1 === name2 && val1 === val2 && /session|sess|sid/i.test(name1)) {
          findings.push({
            severity: 'medium',
            title: `Session Fixation Risk: ${name1}`,
            description: `Same session ID "${name1}" issued across multiple requests. Session may not be regenerated properly.`,
            details: `Cookie: ${name1}\nRequest 1 value: ${val1}\nRequest 2 value: ${val2}`,
            recommendation: 'Regenerate session IDs on authentication. Never reuse session IDs across requests.',
            evidence: `Two consecutive requests received identical session ID: ${val1?.substring(0, 50)}`,
            cwe: 'CWE-384',
            owasp: 'A07:2021 - Identification and Authentication Failures',
          });
        }
      }
    }
  }
}

async function testJWTSecurity(targetUrl, html, findings) {
  // Look for JWT tokens in responses, cookies, and page content
  const jwtPattern = /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g;

  const response = await makeRequest(targetUrl);
  if (!response) return;

  const allContent = response.body + JSON.stringify(response.headers);
  const tokens = allContent.match(jwtPattern) || [];

  for (const token of tokens.slice(0, 3)) {
    try {
      const parts = token.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

      const issues = [];

      // Algorithm checks
      if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        issues.push({ severity: 'critical', issue: 'Algorithm set to "none" — JWT signature not verified' });
      }
      if (header.alg === 'HS256' && parts[2]?.length < 10) {
        issues.push({ severity: 'high', issue: 'Weak HS256 signature detected — possible weak secret' });
      }

      // Payload checks
      if (payload.exp && payload.exp < Date.now() / 1000) {
        issues.push({ severity: 'medium', issue: `Token expired (exp: ${new Date(payload.exp * 1000).toISOString()})` });
      }
      if (!payload.exp) {
        issues.push({ severity: 'high', issue: 'No expiration (exp) claim — token never expires' });
      }
      if (payload.admin === true || payload.role === 'admin' || payload.is_admin === true) {
        issues.push({ severity: 'high', issue: `Admin privileges in token (admin=${payload.admin || payload.role || payload.is_admin})` });
      }

      // Check for sensitive data
      const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'cc_number'];
      for (const key of sensitiveKeys) {
        if (payload[key]) {
          issues.push({ severity: 'critical', issue: `Sensitive data in JWT: ${key}` });
        }
      }

      if (issues.length > 0) {
        const maxSeverity = issues.find(i => i.severity === 'critical') ? 'critical' : issues.find(i => i.severity === 'high') ? 'high' : 'medium';
        findings.push({
          severity: maxSeverity,
          title: 'JWT Token Security Issues',
          description: `JWT token found with ${issues.length} security issues:\n${issues.map(i => '• [' + i.severity + '] ' + i.issue).join('\n')}`,
          details: `Algorithm: ${header.alg}\nType: ${header.typ}\nPayload keys: ${Object.keys(payload).join(', ')}\nIssues:\n${issues.map(i => i.issue).join('\n')}`,
          recommendation: 'Use RS256 instead of HS256. Always verify signatures. Set short expiration. Never store sensitive data in JWT.',
          evidence: `Token header: ${JSON.stringify(header)}\nToken payload: ${JSON.stringify(payload).substring(0, 300)}`,
          cwe: 'CWE-347',
          owasp: 'A07:2021 - Identification and Authentication Failures',
        });
      }
    } catch { /* malformed JWT */ }
  }
}

async function testAuthBypass(targetUrl, findings) {
  const bypassHeaders = [
    { name: 'X-Original-URL', value: '/admin', desc: 'X-Original-URL bypass' },
    { name: 'X-Rewrite-URL', value: '/admin', desc: 'X-Rewrite-URL bypass' },
    { name: 'X-Custom-IP-Authorization', value: '127.0.0.1', desc: 'IP-based auth bypass' },
    { name: 'X-Forwarded-For', value: '127.0.0.1', desc: 'X-Forwarded-For localhost bypass' },
    { name: 'X-Remote-IP', value: '127.0.0.1', desc: 'X-Remote-IP bypass' },
    { name: 'X-Originating-IP', value: '127.0.0.1', desc: 'X-Originating-IP bypass' },
    { name: 'X-Real-IP', value: '127.0.0.1', desc: 'X-Real-IP bypass' },
    { name: 'X-Host', value: 'localhost', desc: 'X-Host bypass' },
  ];

  const adminPaths = ['/admin', '/admin/', '/dashboard', '/panel', '/api/admin', '/api/users'];

  for (const adminPath of adminPaths) {
    const baseUrl = targetUrl.replace(/\/+$/, '') + adminPath;

    // Normal request (should be blocked)
    const normalResp = await makeRequest(baseUrl);
    if (!normalResp || (normalResp.statusCode !== 401 && normalResp.statusCode !== 403)) continue;

    // Test bypass headers
    for (const bypass of bypassHeaders) {
      const bypassResp = await makeRequest(baseUrl, {
        headers: { [bypass.name]: bypass.value }
      });

      if (bypassResp && bypassResp.statusCode >= 200 && bypassResp.statusCode < 400 && bypassResp.statusCode !== 301 && bypassResp.statusCode !== 302) {
        findings.push({
          severity: 'critical',
          title: `Authentication Bypass — ${bypass.desc}`,
          description: `Protected endpoint ${adminPath} can be accessed by adding header "${bypass.name}: ${bypass.value}".`,
          details: `Endpoint: ${baseUrl}\nNormal response: HTTP ${normalResp.statusCode}\nBypass response: HTTP ${bypassResp.statusCode}\nHeader: ${bypass.name}: ${bypass.value}`,
          recommendation: 'Do not rely on HTTP headers for access control. Implement server-side authentication/authorization on all protected endpoints.',
          evidence: `Normal: GET ${baseUrl} → HTTP ${normalResp.statusCode}\nBypass: GET ${baseUrl} + ${bypass.name}: ${bypass.value} → HTTP ${bypassResp.statusCode}`,
          cwe: 'CWE-288',
          owasp: 'A07:2021 - Identification and Authentication Failures',
        });
        break;
      }
    }

    // Test method override
    const methodResp = await makeRequest(baseUrl, { method: 'POST' });
    if (methodResp && methodResp.statusCode >= 200 && methodResp.statusCode < 400 && methodResp.statusCode !== 301) {
      if (normalResp.statusCode === 401 || normalResp.statusCode === 403) {
        findings.push({
          severity: 'high',
          title: `Authentication Bypass — HTTP Method Override (${adminPath})`,
          description: `Protected endpoint returns different response for POST vs GET, possibly bypassing auth.`,
          details: `GET ${baseUrl} → HTTP ${normalResp.statusCode}\nPOST ${baseUrl} → HTTP ${methodResp.statusCode}`,
          recommendation: 'Apply authentication checks regardless of HTTP method.',
          evidence: `GET → ${normalResp.statusCode}, POST → ${methodResp.statusCode}`,
          cwe: 'CWE-288',
          owasp: 'A07:2021 - Identification and Authentication Failures',
        });
      }
    }
  }
}

async function testPasswordResetSecurity(targetUrl, findings) {
  const resetPaths = [
    '/forgot-password', '/forgot', '/password/reset', '/api/password/reset',
    '/reset-password', '/password-reset', '/account/forgot',
    '/api/forgot-password', '/users/password/new',
  ];

  for (const path of resetPaths) {
    const fullUrl = targetUrl.replace(/\/+$/, '') + path;
    const response = await makeRequest(fullUrl);
    if (!response || response.statusCode >= 400) continue;

    // Found a password reset page
    const $ = cheerio.load(response.body);
    const form = $('form').first();
    if (form.length === 0) continue;

    // Check for Host header injection
    const hostInjResp = await makeRequest(fullUrl, {
      method: 'POST',
      headers: { 'Host': 'evil.com', 'X-Forwarded-Host': 'evil.com' },
      body: 'email=test@test.com',
      contentType: 'application/x-www-form-urlencoded',
    });

    if (hostInjResp && hostInjResp.statusCode < 400 && hostInjResp.body && /evil\.com/i.test(hostInjResp.body)) {
      findings.push({
        severity: 'high',
        title: 'Password Reset — Host Header Injection',
        description: `Password reset at ${fullUrl} may be vulnerable to host header poisoning, allowing reset link hijacking.`,
        details: `Endpoint: ${fullUrl}\nInjected Host: evil.com\nResponse reflects injected host`,
        recommendation: 'Use a hardcoded application URL for password reset links. Never use the Host header to construct URLs.',
        evidence: `POST ${fullUrl} with Host: evil.com\nResponse contains "evil.com"`,
        cwe: 'CWE-640',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
    }

    // Check for user enumeration via reset
    const validUser = await makeRequest(fullUrl, {
      method: 'POST',
      body: 'email=admin@' + new URL(targetUrl).hostname,
      contentType: 'application/x-www-form-urlencoded',
    });
    const invalidUser = await makeRequest(fullUrl, {
      method: 'POST',
      body: 'email=nonexistent_user_xyz_12345@doesnotexist.invalid',
      contentType: 'application/x-www-form-urlencoded',
    });

    if (validUser && invalidUser && validUser.body && invalidUser.body) {
      const diff = Math.abs(validUser.body.length - invalidUser.body.length);
      if (diff > 50 || validUser.statusCode !== invalidUser.statusCode) {
        findings.push({
          severity: 'medium',
          title: 'User Enumeration via Password Reset',
          description: `Password reset form returns different responses for valid vs invalid email addresses, enabling user enumeration.`,
          details: `Valid email response: ${validUser.body.length} bytes (HTTP ${validUser.statusCode})\nInvalid email response: ${invalidUser.body.length} bytes (HTTP ${invalidUser.statusCode})`,
          recommendation: 'Return identical response for both valid and invalid email addresses: "If an account exists, a reset link has been sent."',
          evidence: `Valid email → ${validUser.body.length} bytes\nInvalid email → ${invalidUser.body.length} bytes\nDifference: ${diff} bytes`,
          cwe: 'CWE-204',
          owasp: 'A07:2021 - Identification and Authentication Failures',
        });
      }
    }

    break; // Only test first found reset form
  }
}

async function testUserEnumeration(loginForms, findings) {
  if (loginForms.length === 0) return;
  const form = loginForms[0];

  // Test with likely valid username
  const data1 = {};
  form.inputs.forEach(inp => { if (inp.name && inp.value) data1[inp.name] = inp.value; });
  data1[form.userField] = 'admin';
  data1[form.passField] = 'wrong_password_test_12345';

  // Test with clearly invalid username
  const data2 = { ...data1 };
  data2[form.userField] = 'nonexistent_user_xyz_' + Date.now();

  const resp1 = await makeRequest(form.action, { method: form.method, body: querystring.stringify(data1), contentType: 'application/x-www-form-urlencoded' });
  const resp2 = await makeRequest(form.action, { method: form.method, body: querystring.stringify(data2), contentType: 'application/x-www-form-urlencoded' });

  if (resp1 && resp2) {
    const diff = Math.abs(resp1.body.length - resp2.body.length);
    if (diff > 30 || resp1.statusCode !== resp2.statusCode) {
      findings.push({
        severity: 'medium',
        title: 'User Enumeration via Login Form',
        description: `Login form returns different responses for valid vs invalid usernames, enabling attacker to enumerate valid accounts.`,
        details: `Valid username ("admin") response: ${resp1.body.length} bytes (HTTP ${resp1.statusCode})\nInvalid username response: ${resp2.body.length} bytes (HTTP ${resp2.statusCode})\nDifference: ${diff} bytes`,
        recommendation: 'Return identical generic error message: "Invalid username or password" for both cases.',
        evidence: `"admin" + wrong password → ${resp1.body.length} bytes (HTTP ${resp1.statusCode})\nRandom username + wrong password → ${resp2.body.length} bytes (HTTP ${resp2.statusCode})`,
        cwe: 'CWE-204',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
    }
  }
}

// ============ UTILITY ============

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ============ MAIN SCANNER ============

async function runAuthScan(targetUrl, html = null, progressCallback = null) {
  const findings = [];

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 5, message: '[Auth] Discovering login forms...' });

  // Fetch page if needed
  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { html = ''; }
  }

  const loginForms = await findLoginForms(targetUrl, html);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 15, message: `[Auth] Found ${loginForms.length} login forms. Testing default credentials...` });

  // Test 1: Default Credentials
  await testDefaultCredentials(loginForms, findings, progressCallback);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 30, message: '[Auth] Testing brute force protection...' });

  // Test 2: Brute Force Protection
  await testBruteForceProtection(loginForms, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 40, message: '[Auth] Checking user enumeration...' });

  // Test 3: User Enumeration
  await testUserEnumeration(loginForms, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 50, message: '[Auth] Analyzing session security...' });

  // Test 4: Session Security
  await testSessionSecurity(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 65, message: '[Auth] Testing JWT security...' });

  // Test 5: JWT Security
  await testJWTSecurity(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 75, message: '[Auth] Testing authentication bypass...' });

  // Test 6: Auth Bypass
  await testAuthBypass(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 88, message: '[Auth] Testing password reset security...' });

  // Test 7: Password Reset
  await testPasswordResetSecurity(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'auth-scanner', progress: 100, message: `[Auth] Complete — ${findings.length} authentication issues found` });

  return {
    name: 'Broken Authentication',
    category: 'Authentication',
    icon: '🔐',
    summary: `Tested ${loginForms.length} login forms — ${findings.length} authentication issues found`,
    loginFormsFound: loginForms.length,
    testsPerformed: ['Default Credentials', 'Brute Force Protection', 'User Enumeration', 'Session Security', 'JWT Analysis', 'Auth Bypass', 'Password Reset Security'],
    findings,
  };
}

module.exports = { runAuthScan };
