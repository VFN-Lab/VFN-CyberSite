/**
 * VFN-CyberSite — Privilege Escalation Scanner
 * Tests for horizontal/vertical privilege escalation & access control flaws
 * IDOR, Role manipulation, Access control, Mass assignment
 */

const http = require('http');
const https = require('https');
const querystring = require('querystring');
const cheerio = require('cheerio');

// ============ IDOR TEST PATTERNS ============

const IDOR_PARAMS = [
  'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
  'profile_id', 'profileId', 'order_id', 'orderId', 'doc_id',
  'document_id', 'file_id', 'fileId', 'record_id', 'recordId',
  'item_id', 'itemId', 'invoice_id', 'invoiceId', 'ticket_id',
  'message_id', 'messageId', 'project_id', 'report_id',
];

const ADMIN_PARAMS = [
  { param: 'role', values: ['admin', 'administrator', 'superadmin', 'root', 'super'] },
  { param: 'is_admin', values: ['true', '1', 'yes'] },
  { param: 'isAdmin', values: ['true', '1', 'yes'] },
  { param: 'admin', values: ['true', '1', 'yes'] },
  { param: 'access_level', values: ['admin', '99', '10', '0'] },
  { param: 'accessLevel', values: ['admin', '99', '10'] },
  { param: 'user_type', values: ['admin', 'superuser'] },
  { param: 'userType', values: ['admin', 'superuser'] },
  { param: 'privilege', values: ['admin', 'root', '1'] },
  { param: 'permissions', values: ['all', '*', 'admin'] },
  { param: 'group', values: ['admin', 'administrators'] },
  { param: 'verified', values: ['true', '1'] },
  { param: 'approved', values: ['true', '1'] },
  { param: 'status', values: ['active', 'approved', 'verified'] },
];

const ADMIN_ENDPOINTS = [
  '/admin', '/admin/', '/admin/dashboard', '/admin/users',
  '/admin/settings', '/admin/config', '/admin/logs',
  '/api/admin', '/api/admin/users', '/api/admin/settings',
  '/api/v1/admin', '/api/v2/admin',
  '/dashboard', '/dashboard/admin', '/management',
  '/panel', '/control', '/control-panel',
  '/administrator', '/moderator',
  '/api/users', '/api/users/all', '/api/accounts',
  '/api/config', '/api/settings', '/api/system',
  '/internal', '/internal/api', '/debug', '/debug/vars',
  '/actuator', '/actuator/env', '/actuator/health',
  '/api/v1/users', '/api/v1/accounts', '/api/v1/system',
  '/_admin', '/__admin', '/sys', '/system',
];

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

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

// ============ TEST FUNCTIONS ============

async function testIDOR(targetUrl, html, findings, progressCallback) {
  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; }
  }

  const $ = cheerio.load(html);

  // Find links/forms with ID parameters
  const urls = new Set();
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && (href.includes('id=') || /\/\d+/.test(href))) urls.add(href);
  });
  $('form[action]').each((_, el) => {
    const action = $(el).attr('action');
    if (action) urls.add(action);
  });

  // Also check URL parameters
  try {
    const parsed = new URL(targetUrl);
    for (const [key] of parsed.searchParams) {
      if (IDOR_PARAMS.includes(key.toLowerCase()) || IDOR_PARAMS.includes(key)) {
        urls.add(targetUrl);
      }
    }
  } catch {}

  // Test common API patterns for IDOR
  const apiPatterns = [
    '/api/users/1', '/api/users/2',
    '/api/user/1', '/api/user/2',
    '/api/account/1', '/api/account/2',
    '/api/profile/1', '/api/profile/2',
    '/api/order/1', '/api/order/2',
    '/api/v1/users/1', '/api/v1/users/2',
  ];

  const baseUrl = targetUrl.replace(/\/+$/, '');

  for (let i = 0; i < apiPatterns.length; i += 2) {
    const resp1 = await makeRequest(baseUrl + apiPatterns[i]);
    const resp2 = await makeRequest(baseUrl + apiPatterns[i + 1]);

    if (resp1 && resp2 && resp1.statusCode === 200 && resp2.statusCode === 200) {
      // Both returned data - potential IDOR
      if (resp1.body.length > 50 && resp2.body.length > 50 && resp1.body !== resp2.body) {
        const endpoint = apiPatterns[i].replace(/\/\d+$/, '/{id}');
        findings.push({
          severity: 'high',
          title: `IDOR — ${endpoint}`,
          description: `API endpoint ${endpoint} returns different user data for sequential IDs without proper authorization checks.`,
          details: `ID 1: HTTP ${resp1.statusCode} — ${resp1.body.length} bytes\nID 2: HTTP ${resp2.statusCode} — ${resp2.body.length} bytes\nBoth returned valid data with different content`,
          recommendation: 'Implement proper authorization checks. Verify the authenticated user owns the requested resource. Use UUIDs instead of sequential IDs.',
          evidence: `GET ${baseUrl}${apiPatterns[i]} → ${resp1.statusCode} (${resp1.body.length} bytes)\nGET ${baseUrl}${apiPatterns[i + 1]} → ${resp2.statusCode} (${resp2.body.length} bytes)\nDifferent data returned for sequential IDs`,
          cwe: 'CWE-639',
          owasp: 'A01:2021 - Broken Access Control',
        });
      }
    }
  }

  // Test IDOR in URL parameters
  for (const paramName of IDOR_PARAMS.slice(0, 8)) {
    const testUrl1 = new URL(targetUrl);
    testUrl1.searchParams.set(paramName, '1');
    const testUrl2 = new URL(targetUrl);
    testUrl2.searchParams.set(paramName, '2');

    const resp1 = await makeRequest(testUrl1.href);
    const resp2 = await makeRequest(testUrl2.href);

    if (resp1 && resp2 && resp1.statusCode === 200 && resp2.statusCode === 200) {
      if (resp1.body.length > 100 && resp2.body.length > 100 && Math.abs(resp1.body.length - resp2.body.length) > 50) {
        findings.push({
          severity: 'high',
          title: `IDOR — Parameter "${paramName}"`,
          description: `Changing the "${paramName}" parameter returns different data, suggesting insecure direct object references.`,
          details: `${paramName}=1 → ${resp1.body.length} bytes\n${paramName}=2 → ${resp2.body.length} bytes`,
          recommendation: 'Validate user authorization for each resource access. Use session-based lookups instead of user-supplied IDs.',
          evidence: `?${paramName}=1 → ${resp1.body.length} bytes\n?${paramName}=2 → ${resp2.body.length} bytes`,
          cwe: 'CWE-639',
          owasp: 'A01:2021 - Broken Access Control',
        });
        break;
      }
    }
  }
}

async function testRoleManipulation(targetUrl, findings) {
  const normalResp = await makeRequest(targetUrl);
  if (!normalResp) return;

  // Test top parameter-based role escalation
  for (const admin of ADMIN_PARAMS.slice(0, 4)) {
    const value = admin.values[0];
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set(admin.param, value);

    const manipResp = await makeRequest(testUrl.href);
    if (manipResp && manipResp.statusCode === 200) {
      const diff = Math.abs(manipResp.body.length - normalResp.body.length);
      if (diff > 100 && /admin|dashboard|manage|settings|config|panel/i.test(manipResp.body) && !/admin|dashboard|manage/i.test(normalResp.body)) {
        findings.push({
          severity: 'critical',
          title: `Privilege Escalation — ${admin.param}=${value}`,
          description: `Adding parameter "${admin.param}=${value}" grants admin-level access or reveals admin content.`,
          details: `Normal request: ${normalResp.body.length} bytes\nWith ${admin.param}=${value}: ${manipResp.body.length} bytes\nDifference: ${diff} bytes\nAdmin content detected in modified response`,
          recommendation: 'Never rely on client-side parameters for authorization. Implement server-side role validation using session data.',
          evidence: `Normal: ${normalResp.body.length} bytes\n?${admin.param}=${value}: ${manipResp.body.length} bytes\nAdmin-related content appeared`,
          cwe: 'CWE-269',
          owasp: 'A01:2021 - Broken Access Control',
        });
        break;
      }
    }
  }
}

async function testAdminPanelAccess(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const accessible = [];
  const endpoints = ADMIN_ENDPOINTS.slice(0, 16);
  const batchSize = 4;

  for (let i = 0; i < endpoints.length; i += batchSize) {
    const batch = endpoints.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(path => makeRequest(baseUrl + path, { timeout: 4000 }).then(res => ({ path, res }))));

    for (const { path, res } of results) {
      if (res && res.statusCode >= 200 && res.statusCode < 300) {
        if (res.body.length > 200 && /admin|dashboard|management|control|users|settings|config|system/i.test(res.body)) {
          accessible.push({ path, status: res.statusCode, size: res.body.length });
        }
      }
    }
  }

  if (accessible.length > 0) {
    findings.push({
      severity: 'critical',
      title: `Unprotected Admin Endpoints (${accessible.length})`,
      description: `${accessible.length} admin/management endpoints are accessible without authentication.`,
      details: accessible.map(a => `${a.path} → HTTP ${a.status} (${a.size} bytes)`).join('\n'),
      recommendation: 'Protect all admin endpoints with authentication and authorization. Implement role-based access control (RBAC).',
      evidence: accessible.map(a => `GET ${baseUrl}${a.path} → HTTP ${a.status}`).join('\n'),
      cwe: 'CWE-306',
      owasp: 'A01:2021 - Broken Access Control',
    });
  }
}

async function testHTTPMethodTampering(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const sensitivePaths = ['/admin', '/api/users', '/api/admin', '/api/settings', '/api/config', '/dashboard'];

  for (const path of sensitivePaths) {
    const fullUrl = baseUrl + path;
    const getResp = await makeRequest(fullUrl, { method: 'GET' });
    if (!getResp) continue;

    // If GET is blocked, try other methods
    if (getResp.statusCode === 401 || getResp.statusCode === 403 || getResp.statusCode === 405) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const altResp = await makeRequest(fullUrl, { method });
        if (!altResp) continue;

        if (altResp.statusCode >= 200 && altResp.statusCode < 300 && altResp.body.length > 100) {
          findings.push({
            severity: 'high',
            title: `HTTP Method Tampering — ${method} ${path}`,
            description: `Endpoint ${path} blocks GET (HTTP ${getResp.statusCode}) but allows ${method} (HTTP ${altResp.statusCode}).`,
            details: `GET ${fullUrl} → HTTP ${getResp.statusCode}\n${method} ${fullUrl} → HTTP ${altResp.statusCode} (${altResp.body.length} bytes)`,
            recommendation: 'Apply access control checks regardless of HTTP method. Disable unnecessary methods.',
            evidence: `GET → ${getResp.statusCode} (blocked)\n${method} → ${altResp.statusCode} (${altResp.body.length} bytes)`,
            cwe: 'CWE-650',
            owasp: 'A01:2021 - Broken Access Control',
          });
          break;
        }
      }
    }
  }
}

async function testMassAssignment(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const endpoints = [
    '/api/user', '/api/profile', '/api/account', '/api/register',
    '/api/update', '/api/settings', '/api/v1/user', '/api/v1/profile',
  ];

  for (const endpoint of endpoints) {
    // Try sending extra admin parameters
    const payload = {
      username: 'testuser',
      email: 'test@test.com',
      role: 'admin',
      is_admin: true,
      verified: true,
      admin: true,
      permissions: ['all'],
    };

    const response = await makeRequest(baseUrl + endpoint, {
      method: 'POST',
      body: JSON.stringify(payload),
      contentType: 'application/json',
      timeout: 8000,
    });

    if (!response || response.statusCode >= 400) continue;

    // Check if extra fields were accepted
    if (response.body && (
      /role.*admin/i.test(response.body) ||
      /is_admin.*true/i.test(response.body) ||
      /admin.*true/i.test(response.body) ||
      /verified.*true/i.test(response.body)
    )) {
      findings.push({
        severity: 'critical',
        title: `Mass Assignment — ${endpoint}`,
        description: `Endpoint ${endpoint} accepts and processes extra parameters like "role", "is_admin", potentially allowing privilege escalation.`,
        details: `Endpoint: POST ${baseUrl}${endpoint}\nPayload included: role=admin, is_admin=true, verified=true\nResponse appears to accept these fields`,
        recommendation: 'Implement allowlists for accepted parameters. Never bind user input directly to model properties. Use DTOs (Data Transfer Objects).',
        evidence: `POST ${baseUrl}${endpoint}\nBody: ${JSON.stringify(payload).substring(0, 200)}\nResponse: ${response.body.substring(0, 200)}`,
        cwe: 'CWE-915',
        owasp: 'A01:2021 - Broken Access Control',
      });
    }
  }
}

async function testForceBrowsing(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');

  // Test API versioning bypass
  const versionPaths = [
    { old: '/api/v2/users', new: '/api/v1/users' },
    { old: '/api/v3/admin', new: '/api/v2/admin' },
    { old: '/api/v2/config', new: '/api/v1/config' },
  ];

  for (const ver of versionPaths) {
    const newResp = await makeRequest(baseUrl + ver.old);
    const oldResp = await makeRequest(baseUrl + ver.new);

    if (newResp && oldResp) {
      if ((newResp.statusCode === 401 || newResp.statusCode === 403) &&
          oldResp.statusCode === 200 && oldResp.body.length > 50) {
        findings.push({
          severity: 'high',
          title: `API Version Bypass — ${ver.new}`,
          description: `Protected endpoint ${ver.old} can be accessed via older API version ${ver.new}.`,
          details: `${ver.old} → HTTP ${newResp.statusCode} (blocked)\n${ver.new} → HTTP ${oldResp.statusCode} (${oldResp.body.length} bytes)`,
          recommendation: 'Apply consistent access controls across all API versions. Deprecate old API versions securely.',
          evidence: `New API: ${ver.old} → ${newResp.statusCode}\nOld API: ${ver.new} → ${oldResp.statusCode}`,
          cwe: 'CWE-425',
          owasp: 'A01:2021 - Broken Access Control',
        });
      }
    }
  }
}

// ============ MAIN SCANNER ============

async function runPrivEscScan(targetUrl, html = null, progressCallback = null) {
  const findings = [];

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 5, message: '[PrivEsc] Starting privilege escalation testing...' });

  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { html = ''; }
  }

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 10, message: '[PrivEsc] Testing IDOR vulnerabilities...' });

  // Test 1: IDOR
  await testIDOR(targetUrl, html, findings, progressCallback);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 25, message: '[PrivEsc] Testing role manipulation...' });

  // Test 2: Role Manipulation
  await testRoleManipulation(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 40, message: '[PrivEsc] Scanning unprotected admin endpoints...' });

  // Test 3: Admin Panel Access
  await testAdminPanelAccess(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 55, message: '[PrivEsc] Testing HTTP method tampering...' });

  // Test 4: HTTP Method Tampering
  await testHTTPMethodTampering(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 70, message: '[PrivEsc] Testing mass assignment...' });

  // Test 5: Mass Assignment
  await testMassAssignment(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 85, message: '[PrivEsc] Testing force browsing & API versioning...' });

  // Test 6: Force Browsing
  await testForceBrowsing(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'privesc-scanner', progress: 100, message: `[PrivEsc] Complete — ${findings.length} privilege escalation issues found` });

  return {
    name: 'Privilege Escalation',
    category: 'Access Control',
    icon: '⬆️',
    summary: `${findings.length} privilege escalation vulnerabilities found`,
    testsPerformed: ['IDOR', 'Role Manipulation', 'Admin Panel Access', 'HTTP Method Tampering', 'Mass Assignment', 'API Version Bypass'],
    findings,
  };
}

module.exports = { runPrivEscScan };
