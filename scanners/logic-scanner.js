/**
 * VFN-CyberSite — Logic Flaw Scanner
 * Tests: Race conditions, Business logic, API abuse, Information disclosure, Workflow bypass
 * Supports Aggressive Mode for deeper testing
 */

const http = require('http');
const https = require('https');
const cheerio = require('cheerio');
const querystring = require('querystring');

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
      done(null);
    }, options.timeout || 8000);

    const req = client.request(reqOptions, (res) => {
      let body = '';
      const finish = () => {
        done({ statusCode: res.statusCode, headers: res.headers, body, responseTime: Date.now() - startTime, url: targetUrl });
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

// ============ CONCURRENT REQUEST HELPER ============

function makeRequestNoWait(targetUrl, options = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch { return resolve(null); }
    const client = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
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
      done(null);
    }, options.timeout || 8000);

    const req = client.request(reqOptions, (res) => {
      let body = '';
      const finish = () => {
        done({ statusCode: res.statusCode, headers: res.headers, body, responseTime: Date.now() - startTime });
      };

      res.on('data', chunk => {
        body += chunk;
        if (body.length > 100000) {
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

async function testRaceConditions(targetUrl, html, findings, aggressive) {
  if (!aggressive) {
    // In non-aggressive mode, just detect potential race condition endpoints
    if (!html) { try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; } }

    const $ = cheerio.load(html);
    const raceEndpoints = [];

    $('form[method="post" i], form[method="POST"]').each((_, form) => {
      const action = $(form).attr('action') || targetUrl;
      const hasQuantity = $(form).find('input[name*="quantity" i], input[name*="amount" i], input[name*="count" i], input[name*="qty" i]').length > 0;
      const hasPrice = $(form).find('input[name*="price" i], input[name*="total" i], input[name*="cost" i]').length > 0;
      const hasCoupon = $(form).find('input[name*="coupon" i], input[name*="code" i], input[name*="discount" i], input[name*="promo" i]').length > 0;

      if (hasQuantity || hasPrice || hasCoupon) {
        raceEndpoints.push({ action, hasQuantity, hasPrice, hasCoupon });
      }
    });

    if (raceEndpoints.length > 0) {
      findings.push({
        severity: 'medium',
        title: `Potential Race Condition Endpoints (${raceEndpoints.length})`,
        description: `Found ${raceEndpoints.length} forms with quantity/price/coupon fields that may be vulnerable to race conditions.`,
        details: `Endpoints:\n${raceEndpoints.map(e => `  ${e.action} — ${[e.hasQuantity ? 'quantity' : '', e.hasPrice ? 'price' : '', e.hasCoupon ? 'coupon' : ''].filter(Boolean).join(', ')}`).join('\n')}\n\nEnable Aggressive Mode to test concurrently.`,
        recommendation: 'Implement server-side locking/transactions for sensitive operations. Use database-level constraints.',
        evidence: `${raceEndpoints.length} endpoints with quantity/price/coupon fields detected`,
        cwe: 'CWE-362',
        owasp: 'A04:2021 - Insecure Design',
      });
    }
    return;
  }

  // Aggressive mode: actually test concurrent requests
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const raceTestPaths = [
    '/api/transfer', '/api/withdraw', '/api/redeem',
    '/api/coupon', '/api/apply-coupon', '/api/discount',
    '/api/order', '/api/checkout', '/api/payment',
    '/api/vote', '/api/like', '/api/follow',
  ];

  for (const path of raceTestPaths) {
    const endpoint = baseUrl + path;

    // Send 10 concurrent requests
    const concurrentRequests = Array(10).fill(null).map(() =>
      makeRequestNoWait(endpoint, {
        method: 'POST',
        body: JSON.stringify({ amount: 1 }),
        contentType: 'application/json',
        timeout: 8000,
      })
    );

    const results = await Promise.all(concurrentRequests);
    const validResults = results.filter(r => r && r.statusCode >= 200 && r.statusCode < 500);

    if (validResults.length >= 5) {
      // Check if all succeeded (potential race condition)
      const successes = validResults.filter(r => r.statusCode >= 200 && r.statusCode < 300);
      if (successes.length > 1) {
        findings.push({
          severity: 'high',
          title: `Race Condition — ${path}`,
          description: `Endpoint ${path} accepted ${successes.length}/10 concurrent requests without proper locking.`,
          details: `10 concurrent requests sent to ${endpoint}\n${successes.length} succeeded (HTTP 2xx)\n${validResults.length - successes.length} failed\nPotential for double-spending, coupon reuse, or duplicate transactions`,
          recommendation: 'Implement mutex locks or database transactions. Use idempotency keys for payment operations.',
          evidence: `10 concurrent POST ${path}\n${successes.length} accepted simultaneously`,
          cwe: 'CWE-362',
          owasp: 'A04:2021 - Insecure Design',
        });
      }
    }
  }
}

async function testInputValidation(targetUrl, html, findings) {
  if (!html) { try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; } }

  const $ = cheerio.load(html);

  // Find forms with numeric inputs
  $('form').each((_, form) => {
    const $form = $(form);
    let action = $form.attr('action') || targetUrl;
    if (action.startsWith('/')) action = `${new URL(targetUrl).origin}${action}`;
    else if (!action.startsWith('http')) action = new URL(action, targetUrl).href;
    const method = ($form.attr('method') || 'GET').toUpperCase();

    const numericInputs = [];
    $form.find('input[type="number"], input[name*="quantity" i], input[name*="amount" i], input[name*="price" i], input[name*="count" i], input[name*="qty" i]').each((_, input) => {
      const name = $(input).attr('name');
      if (name) numericInputs.push(name);
    });

    if (numericInputs.length === 0) return;

    // Test boundary values
    const boundaryTests = [
      { value: '-1', desc: 'Negative value' },
      { value: '0', desc: 'Zero value' },
      { value: '999999999', desc: 'Very large number' },
      { value: '0.0001', desc: 'Very small decimal' },
      { value: '-999999', desc: 'Large negative' },
      { value: 'NaN', desc: 'Not a number' },
      { value: 'Infinity', desc: 'Infinity value' },
      { value: '1e308', desc: 'Scientific notation overflow' },
    ];

    for (const input of numericInputs.slice(0, 2)) {
      findings.push({
        severity: 'medium',
        title: `Input Validation — Numeric Field "${input}"`,
        description: `Form at ${action} has numeric input "${input}" that should be tested for boundary values, negative numbers, and overflow.`,
        details: `Form: ${method} ${action}\nField: ${input}\nTest values to verify:\n${boundaryTests.map(t => `  ${t.value} — ${t.desc}`).join('\n')}`,
        recommendation: 'Validate numeric inputs server-side: check for negative values, zero, overflow, and data type. Never rely on client-side validation.',
        evidence: `Numeric field "${input}" found in form ${action}`,
        cwe: 'CWE-20',
        owasp: 'A04:2021 - Insecure Design',
      });
    }
  });
}

async function testBusinessLogic(targetUrl, html, findings, aggressive) {
  if (!html) { try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; } }

  const $ = cheerio.load(html);
  const baseUrl = targetUrl.replace(/\/+$/, '');

  // Check for price manipulation in forms
  $('form').each((_, form) => {
    const $form = $(form);
    const hasPriceField = $form.find('input[name*="price" i], input[name*="total" i], input[name*="cost" i], input[name*="amount" i]').length > 0;
    const hasHiddenPrice = $form.find('input[type="hidden"][name*="price" i], input[type="hidden"][name*="total" i], input[type="hidden"][name*="amount" i]').length > 0;

    if (hasHiddenPrice) {
      const hiddenInput = $form.find('input[type="hidden"][name*="price" i], input[type="hidden"][name*="total" i], input[type="hidden"][name*="amount" i]').first();
      const name = hiddenInput.attr('name');
      const value = hiddenInput.attr('value');

      findings.push({
        severity: 'high',
        title: `Business Logic — Client-Side Price Control`,
        description: `Hidden field "${name}" with value "${value}" controls pricing client-side. Attackers can modify this value.`,
        details: `Form has hidden input: <input type="hidden" name="${name}" value="${value}">\nThis price/amount value can be tampered with using browser DevTools or proxy.`,
        recommendation: 'NEVER trust client-side price values. Calculate prices server-side based on product ID and quantity. Verify all prices against the database.',
        evidence: `<input type="hidden" name="${name}" value="${value}">`,
        cwe: 'CWE-639',
        owasp: 'A04:2021 - Insecure Design',
      });
    }
  });

  // Test for coupon/discount abuse
  const couponEndpoints = [
    '/api/coupon', '/api/apply-coupon', '/api/discount',
    '/api/promo', '/api/voucher', '/apply-coupon',
    '/cart/coupon', '/checkout/coupon',
  ];

  if (aggressive) {
    for (const path of couponEndpoints) {
      const endpoint = baseUrl + path;

      // Test coupon code reuse
      const testCoupon = 'TESTCODE123';
      const resp1 = await makeRequest(endpoint, {
        method: 'POST',
        body: JSON.stringify({ code: testCoupon }),
        contentType: 'application/json',
      });

      if (resp1 && resp1.statusCode >= 200 && resp1.statusCode < 300) {
        // Try applying same coupon again
        const resp2 = await makeRequest(endpoint, {
          method: 'POST',
          body: JSON.stringify({ code: testCoupon }),
          contentType: 'application/json',
        });

        if (resp2 && resp2.statusCode >= 200 && resp2.statusCode < 300) {
          findings.push({
            severity: 'high',
            title: `Business Logic — Coupon Code Reuse`,
            description: `Endpoint ${path} allows applying the same coupon code multiple times.`,
            details: `First application: HTTP ${resp1.statusCode}\nSecond application: HTTP ${resp2.statusCode}\nSame coupon accepted twice`,
            recommendation: 'Track coupon usage per user/session. Enforce single-use or usage limits server-side.',
            evidence: `POST ${endpoint} with code="${testCoupon}" accepted twice`,
            cwe: 'CWE-837',
            owasp: 'A04:2021 - Insecure Design',
          });
        }
      }
    }
  }
}

async function testRateLimiting(targetUrl, findings, aggressive) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const sensitiveEndpoints = [
    '/api/login', '/login', '/api/auth', '/auth/login',
    '/api/forgot-password', '/forgot-password',
    '/api/register', '/register', '/signup',
    '/api/otp', '/api/verify', '/verify-otp',
    '/api/search', '/search',
  ];

  const concurrency = aggressive ? 30 : 15;

  for (const path of sensitiveEndpoints) {
    const endpoint = baseUrl + path;

    // First check if endpoint exists
    const checkResp = await makeRequest(endpoint, { timeout: 5000 });
    if (!checkResp || checkResp.statusCode === 404) continue;

    // Send rapid requests
    const requests = Array(concurrency).fill(null).map((_, i) =>
      makeRequestNoWait(endpoint, {
        method: 'POST',
        body: JSON.stringify({ email: `test${i}@test.com`, password: `pass${i}` }),
        contentType: 'application/json',
        timeout: 8000,
      })
    );

    const results = await Promise.all(requests);
    const validResults = results.filter(r => r !== null);
    const blocked = validResults.filter(r => r.statusCode === 429 || r.statusCode === 403);
    const accepted = validResults.filter(r => r.statusCode >= 200 && r.statusCode < 400);

    if (blocked.length === 0 && accepted.length >= concurrency * 0.6) {
      findings.push({
        severity: 'high',
        title: `Missing Rate Limiting — ${path}`,
        description: `Endpoint ${path} accepts ${accepted.length}/${concurrency} rapid concurrent requests without rate limiting.`,
        details: `${concurrency} concurrent requests sent\nAccepted: ${accepted.length}\nBlocked (429/403): ${blocked.length}\nNo rate limiting detected`,
        recommendation: 'Implement rate limiting: 5 requests/minute for login, 3 for password reset, 10 for search. Use express-rate-limit or similar.',
        evidence: `${concurrency} concurrent POST ${path}\n${accepted.length} accepted, 0 rate-limited\nEndpoint is vulnerable to brute force`,
        cwe: 'CWE-307',
        owasp: 'A07:2021 - Identification and Authentication Failures',
      });
    }
  }
}

async function testInformationDisclosure(targetUrl, html, findings) {
  const response = await makeRequest(targetUrl);
  if (!response) return;

  const body = response.body;
  const headers = response.headers;

  // Check for stack traces / debug info
  const debugPatterns = [
    { pattern: /at [\w.]+\s*\([\w/\\.:]+:\d+:\d+\)/g, desc: 'Node.js stack trace', severity: 'high' },
    { pattern: /Traceback \(most recent call last\)/g, desc: 'Python traceback', severity: 'high' },
    { pattern: /java\.\w+\.[\w.]+Exception/g, desc: 'Java exception', severity: 'high' },
    { pattern: /Fatal error:.*in .*\.php on line \d+/g, desc: 'PHP fatal error', severity: 'high' },
    { pattern: /Warning:.*in .*\.php on line \d+/g, desc: 'PHP warning', severity: 'medium' },
    { pattern: /Notice:.*in .*\.php on line \d+/g, desc: 'PHP notice', severity: 'low' },
    { pattern: /Microsoft\.AspNetCore/g, desc: '.NET error details', severity: 'high' },
    { pattern: /System\.Exception/g, desc: '.NET system exception', severity: 'high' },
  ];

  for (const dp of debugPatterns) {
    dp.pattern.lastIndex = 0;
    if (dp.pattern.test(body)) {
      findings.push({
        severity: dp.severity,
        title: `Information Disclosure — ${dp.desc}`,
        description: `Response contains ${dp.desc}, exposing internal application details.`,
        details: `Pattern: ${dp.desc}\nFound in response body of ${targetUrl}`,
        recommendation: 'Disable debug mode in production. Implement generic error pages. Log errors server-side only.',
        evidence: `${dp.desc} found in response`,
        cwe: 'CWE-209',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }
  }

  // Check for internal paths/IPs
  const pathPatterns = [
    { pattern: /(?:\/home\/\w+|\/var\/www|\/usr\/share|\/opt\/\w+|C:\\\\[\w\\]+)/g, desc: 'Internal file path' },
    { pattern: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g, desc: 'Internal IP address' },
  ];

  for (const pp of pathPatterns) {
    pp.pattern.lastIndex = 0;
    const match = pp.pattern.exec(body);
    if (match) {
      findings.push({
        severity: 'medium',
        title: `Information Disclosure — ${pp.desc}`,
        description: `Response exposes ${pp.desc}: "${match[0]}"`,
        details: `Found: ${match[0]}\nThis reveals internal infrastructure information to attackers.`,
        recommendation: 'Remove internal paths and IPs from responses. Use relative paths.',
        evidence: `${pp.desc} found: ${match[0]}`,
        cwe: 'CWE-200',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }
  }

  // Check for source code leakage
  const sourcePatterns = [
    { pattern: /<%[\s\S]*?%>/g, desc: 'ASP/JSP source code' },
    { pattern: /<\?php[\s\S]*?\?>/g, desc: 'PHP source code' },
    { pattern: /\bSELECT\s+\*\s+FROM\s+\w+/gi, desc: 'SQL query in output' },
    { pattern: /BEGIN\s+TRANSACTION|COMMIT|ROLLBACK/gi, desc: 'SQL transaction keywords' },
  ];

  for (const sp of sourcePatterns) {
    sp.pattern.lastIndex = 0;
    if (sp.pattern.test(body)) {
      findings.push({
        severity: 'high',
        title: `Source Code Leakage — ${sp.desc}`,
        description: `Response contains ${sp.desc}, potentially exposing application logic.`,
        details: `Pattern: ${sp.desc}\nThis may reveal business logic, database structure, or authentication mechanisms.`,
        recommendation: 'Ensure server-side code is properly processed, not served as raw text. Check web server configuration.',
        evidence: `${sp.desc} detected in response body`,
        cwe: 'CWE-540',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }
  }

  // Check for verbose error messages on invalid input
  const errorTriggers = ['?id=999999999', '?test=<script>', '?id=-1', '?debug=true', '?trace=1'];
  for (const trigger of errorTriggers) {
    const errorResp = await makeRequest(targetUrl + trigger);
    if (!errorResp) continue;

    for (const dp of debugPatterns) {
      dp.pattern.lastIndex = 0;
      if (dp.pattern.test(errorResp.body) && !dp.pattern.test(body)) {
        findings.push({
          severity: dp.severity,
          title: `Error-Triggered Information Disclosure`,
          description: `Invalid input (${trigger}) triggers ${dp.desc} in response.`,
          details: `URL: ${targetUrl}${trigger}\n${dp.desc} exposed only on error condition`,
          recommendation: 'Implement custom error handlers. Never expose stack traces or internal errors to users.',
          evidence: `${targetUrl}${trigger} → ${dp.desc} in response`,
          cwe: 'CWE-209',
          owasp: 'A05:2021 - Security Misconfiguration',
        });
        break;
      }
    }
  }
}

async function testWorkflowBypass(targetUrl, html, findings) {
  if (!html) { try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; } }

  const baseUrl = targetUrl.replace(/\/+$/, '');

  // Test multi-step form skipping
  const wizardSteps = [
    { step1: '/register/step1', step2: '/register/step2', step3: '/register/step3', final: '/register/complete' },
    { step1: '/checkout/cart', step2: '/checkout/shipping', step3: '/checkout/payment', final: '/checkout/confirm' },
    { step1: '/onboarding/step1', step2: '/onboarding/step2', final: '/onboarding/complete' },
    { step1: '/signup/details', step2: '/signup/verify', final: '/signup/complete' },
    { step1: '/order/details', step2: '/order/payment', final: '/order/confirm' },
  ];

  for (const wizard of wizardSteps) {
    // Try accessing final step directly
    const finalResp = await makeRequest(baseUrl + wizard.final);
    if (finalResp && finalResp.statusCode >= 200 && finalResp.statusCode < 300 && finalResp.body.length > 200) {
      // Check if step1 exists (validates this is a real wizard)
      const step1Resp = await makeRequest(baseUrl + wizard.step1);
      if (step1Resp && step1Resp.statusCode >= 200 && step1Resp.statusCode < 400) {
        findings.push({
          severity: 'high',
          title: `Workflow Bypass — Direct Step Access`,
          description: `Multi-step process can be bypassed by directly accessing ${wizard.final} without completing prior steps.`,
          details: `Step 1: ${wizard.step1} (exists)\nFinal: ${wizard.final} → HTTP ${finalResp.statusCode} (${finalResp.body.length} bytes)\nPrior steps can be skipped`,
          recommendation: 'Validate workflow state server-side. Ensure each step verifies completion of prior steps.',
          evidence: `GET ${baseUrl}${wizard.final} → HTTP ${finalResp.statusCode} (accessible without prior steps)`,
          cwe: 'CWE-841',
          owasp: 'A04:2021 - Insecure Design',
        });
      }
    }
  }
}

async function testGraphQLAbuse(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const graphqlPaths = ['/graphql', '/api/graphql', '/gql', '/query', '/v1/graphql'];

  for (const path of graphqlPaths) {
    const endpoint = baseUrl + path;

    // Test introspection
    const introspectionQuery = JSON.stringify({
      query: '{ __schema { types { name fields { name } } } }'
    });

    const resp = await makeRequest(endpoint, {
      method: 'POST',
      body: introspectionQuery,
      contentType: 'application/json',
    });

    if (resp && resp.statusCode === 200 && resp.body.includes('__schema')) {
      findings.push({
        severity: 'medium',
        title: `GraphQL Introspection Enabled — ${path}`,
        description: `GraphQL endpoint ${path} has introspection enabled, exposing the entire API schema.`,
        details: `Endpoint: ${endpoint}\nIntrospection query succeeded\nThe full API schema is visible to attackers`,
        recommendation: 'Disable introspection in production. Implement query depth limiting and complexity analysis.',
        evidence: `POST ${endpoint}\n__schema query returned type information`,
        cwe: 'CWE-200',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }

    // Test query depth attack
    const deepQuery = JSON.stringify({
      query: '{ user { friends { friends { friends { friends { friends { name } } } } } } }'
    });

    const deepResp = await makeRequest(endpoint, {
      method: 'POST',
      body: deepQuery,
      contentType: 'application/json',
    });

    if (deepResp && deepResp.statusCode === 200 && !deepResp.body.includes('depth')) {
      findings.push({
        severity: 'medium',
        title: `GraphQL — No Query Depth Limit`,
        description: `GraphQL endpoint accepts deeply nested queries without depth limiting.`,
        details: `6-level deep query accepted without restriction\nThis can be abused for DoS attacks`,
        recommendation: 'Implement query depth limits (max 5-10 levels). Add query complexity analysis.',
        evidence: `Deep nested query accepted at ${endpoint}`,
        cwe: 'CWE-400',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
    }
  }
}

async function testAPIKeyExposure(targetUrl, html, findings) {
  if (!html) { try { const r = await makeRequest(targetUrl); html = r.body; } catch { return; } }

  const apiKeyPatterns = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_-]{20,})['"`]/gi, desc: 'API Key' },
    { pattern: /(?:sk_live_|pk_live_)[a-zA-Z0-9]{20,}/g, desc: 'Stripe Live Key' },
    { pattern: /(?:sk_test_|pk_test_)[a-zA-Z0-9]{20,}/g, desc: 'Stripe Test Key' },
    { pattern: /AKIA[0-9A-Z]{16}/g, desc: 'AWS Access Key' },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, desc: 'GitHub Personal Token' },
    { pattern: /(?:firebase|google)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"`]([a-zA-Z0-9_-]{20,})['"`]/gi, desc: 'Firebase/Google API Key' },
    { pattern: /(?:maps|youtube|analytics).*key\s*[:=]\s*['"`]([a-zA-Z0-9_-]{20,})['"`]/gi, desc: 'Google Service Key' },
    { pattern: /Bearer\s+[a-zA-Z0-9_-]{20,}/g, desc: 'Bearer Token' },
    { pattern: /(?:access_token|auth_token|token)\s*[:=]\s*['"`]([a-zA-Z0-9_.-]{20,})['"`]/gi, desc: 'Access Token' },
  ];

  for (const ap of apiKeyPatterns) {
    ap.pattern.lastIndex = 0;
    const match = ap.pattern.exec(html);
    if (match) {
      findings.push({
        severity: ap.desc.includes('Live') || ap.desc.includes('AWS') ? 'critical' : 'high',
        title: `API Key Exposed — ${ap.desc}`,
        description: `${ap.desc} found in page source code. This key may be used by attackers.`,
        details: `Type: ${ap.desc}\nFound in: page source\nValue (partial): ${match[0].substring(0, 40)}...`,
        recommendation: 'Remove API keys from client-side code. Use environment variables and server-side proxy for API calls.',
        evidence: `${ap.desc} found: ${match[0].substring(0, 50)}...`,
        cwe: 'CWE-312',
        owasp: 'A02:2021 - Cryptographic Failures',
      });
    }
  }
}

// ============ MAIN SCANNER ============

async function runLogicScan(targetUrl, html = null, options = {}, progressCallback = null) {
  const findings = [];
  const aggressive = options.aggressive || false;

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 5, message: '[Logic] Starting logic flaw analysis...' });

  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { html = ''; }
  }

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 10, message: `[Logic] Testing race conditions${aggressive ? ' (Aggressive)' : ''}...` });

  // Test 1: Race Conditions
  await testRaceConditions(targetUrl, html, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 22, message: '[Logic] Testing input validation gaps...' });

  // Test 2: Input Validation
  await testInputValidation(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 35, message: '[Logic] Testing business logic flaws...' });

  // Test 3: Business Logic
  await testBusinessLogic(targetUrl, html, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 48, message: '[Logic] Testing rate limiting...' });

  // Test 4: Rate Limiting
  await testRateLimiting(targetUrl, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 60, message: '[Logic] Scanning for information disclosure...' });

  // Test 5: Information Disclosure
  await testInformationDisclosure(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 72, message: '[Logic] Testing workflow bypass...' });

  // Test 6: Workflow Bypass
  await testWorkflowBypass(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 82, message: '[Logic] Testing GraphQL abuse...' });

  // Test 7: GraphQL Abuse
  await testGraphQLAbuse(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 92, message: '[Logic] Checking for API key exposure...' });

  // Test 8: API Key Exposure
  await testAPIKeyExposure(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'logic-scanner', progress: 100, message: `[Logic] Complete — ${findings.length} logic flaws found` });

  return {
    name: 'Logic Flaw Scanner',
    category: 'Business Logic',
    icon: '🧩',
    summary: `${findings.length} logic flaws found${aggressive ? ' (Aggressive Mode)' : ''}`,
    aggressive,
    testsPerformed: [
      'Race Conditions', 'Input Validation', 'Business Logic',
      'Rate Limiting', 'Information Disclosure', 'Workflow Bypass',
      'GraphQL Abuse', 'API Key Exposure',
    ],
    findings,
  };
}

module.exports = { runLogicScan };
