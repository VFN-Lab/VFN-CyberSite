/**
 * VFN-CyberSite — HTTP Security Headers Scanner
 * Analyzes HTTP response headers for security best practices
 */

const http = require('http');
const https = require('https');
const url = require('url');

const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'high',
    description: 'Enforces HTTPS connections, preventing protocol downgrade and cookie hijacking.',
    recommendation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    cwe: 'CWE-319',
    owasp: 'A02:2021 - Cryptographic Failures',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      const maxAge = value.match(/max-age=(\d+)/i);
      if (!maxAge) return { pass: false, detail: 'max-age directive is missing' };
      const age = parseInt(maxAge[1]);
      if (age < 31536000) return { pass: false, detail: `max-age is too short (${age}s). Should be at least 31536000 (1 year)` };
      const issues = [];
      if (!/includeSubDomains/i.test(value)) issues.push('Missing includeSubDomains directive');
      if (!/preload/i.test(value)) issues.push('Missing preload directive');
      if (issues.length > 0) return { pass: false, detail: issues.join('. ') };
      return { pass: true, detail: 'Properly configured' };
    }
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    severity: 'high',
    description: 'Prevents XSS, clickjacking, and other code injection attacks.',
    recommendation: "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing — no protection against XSS' };
      const issues = [];
      if (/unsafe-inline/i.test(value) && !/nonce-/i.test(value) && !/sha256-/i.test(value)) {
        issues.push("Uses 'unsafe-inline' without nonce/hash — weakens XSS protection");
      }
      if (/unsafe-eval/i.test(value)) issues.push("Uses 'unsafe-eval' — allows eval() execution");
      if (/\*/.test(value) && !/\*\./.test(value)) issues.push("Uses wildcard (*) — too permissive");
      if (!/default-src/i.test(value)) issues.push('Missing default-src directive');
      if (!/frame-ancestors/i.test(value)) issues.push('Missing frame-ancestors directive (clickjacking)');
      if (issues.length > 0) return { pass: false, detail: issues.join('. ') };
      return { pass: true, detail: 'CSP is configured' };
    }
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    description: 'Prevents MIME type sniffing which can lead to XSS.',
    recommendation: 'Add header: X-Content-Type-Options: nosniff',
    cwe: 'CWE-16',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      if (value.toLowerCase() !== 'nosniff') return { pass: false, detail: `Invalid value "${value}". Must be "nosniff"` };
      return { pass: true, detail: 'Properly configured' };
    }
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'medium',
    description: 'Prevents clickjacking attacks by controlling iframe embedding.',
    recommendation: 'Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)',
    cwe: 'CWE-1021',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing — vulnerable to clickjacking' };
      const v = value.toUpperCase();
      if (v !== 'DENY' && v !== 'SAMEORIGIN') return { pass: false, detail: `Weak value "${value}". Use DENY or SAMEORIGIN` };
      return { pass: true, detail: `Set to ${v}` };
    }
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'low',
    description: 'Legacy XSS filter. Modern browsers use CSP instead, but still recommended.',
    recommendation: 'Add header: X-XSS-Protection: 0 (if CSP is configured) or X-XSS-Protection: 1; mode=block',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'medium',
    description: 'Controls how much referrer information is sent with requests.',
    recommendation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy)',
    cwe: 'CWE-200',
    owasp: 'A01:2021 - Broken Access Control',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing — full URL may leak in Referer header' };
      const insecure = ['unsafe-url', 'no-referrer-when-downgrade'];
      if (insecure.includes(value.toLowerCase())) return { pass: false, detail: `Value "${value}" may leak sensitive URLs` };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'medium',
    description: 'Controls browser features and APIs (camera, microphone, geolocation, etc.).',
    recommendation: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    cwe: 'CWE-16',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing — browser features not restricted' };
      return { pass: true, detail: 'Feature restrictions configured' };
    }
  },
  'x-permitted-cross-domain-policies': {
    name: 'X-Permitted-Cross-Domain-Policies',
    severity: 'low',
    description: 'Controls Adobe Flash/Acrobat cross-domain policies.',
    recommendation: 'Add header: X-Permitted-Cross-Domain-Policies: none',
    cwe: 'CWE-16',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      if (value.toLowerCase() !== 'none') return { pass: false, detail: `Should be "none" unless needed` };
      return { pass: true, detail: 'Properly configured' };
    }
  },
  'cache-control': {
    name: 'Cache-Control',
    severity: 'low',
    description: 'Controls caching behavior. Sensitive pages should not be cached.',
    recommendation: 'For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate, private',
    cwe: 'CWE-524',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'No caching policy specified' };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
  'cross-origin-opener-policy': {
    name: 'Cross-Origin-Opener-Policy (COOP)',
    severity: 'medium',
    description: 'Isolates browsing context to prevent cross-origin attacks.',
    recommendation: 'Add header: Cross-Origin-Opener-Policy: same-origin',
    cwe: 'CWE-346',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
  'cross-origin-resource-policy': {
    name: 'Cross-Origin-Resource-Policy (CORP)',
    severity: 'medium',
    description: 'Prevents cross-origin reads of resources.',
    recommendation: 'Add header: Cross-Origin-Resource-Policy: same-origin',
    cwe: 'CWE-346',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
  'cross-origin-embedder-policy': {
    name: 'Cross-Origin-Embedder-Policy (COEP)',
    severity: 'low',
    description: 'Prevents loading cross-origin resources without explicit permission.',
    recommendation: 'Add header: Cross-Origin-Embedder-Policy: require-corp',
    cwe: 'CWE-346',
    owasp: 'A05:2021 - Security Misconfiguration',
    validate(value) {
      if (!value) return { pass: false, detail: 'Header is missing' };
      return { pass: true, detail: `Set to: ${value}` };
    }
  },
};

const INFO_HEADERS_TO_CHECK = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-varnish',
  'via',
];

function fetchHeaders(targetUrl, timeout = 8000) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (e) {
      return reject(new Error('Invalid URL'));
    }

    const client = parsed.protocol === 'https:' ? https : http;
    let timer = null;
    let isDone = false;
    let activeReq = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
    };

    const done = (err, result) => {
      if (isDone) return;
      isDone = true;
      cleanup();
      if (err) reject(err);
      else resolve(result);
    };

    timer = setTimeout(() => {
      if (activeReq) {
        try { activeReq.destroy(); } catch {}
      }
      done(new Error('Request timed out'));
    }, timeout);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'CyberScan-Pro/1.0 Security-Scanner',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      rejectUnauthorized: false,
    };

    const req = client.request(options, (res) => {
      let body = '';
      const finish = () => {
        done(null, {
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          url: targetUrl
        });
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
    req.on('error', (err) => done(err));
    req.end();
  });
}

async function runHeaderScan(targetUrl, progressCallback = null) {
  const findings = [];
  let response;

  try {
    if (progressCallback) progressCallback({ scanner: 'header-scanner', progress: 10, message: 'Fetching HTTP headers...' });
    response = await fetchHeaders(targetUrl);
  } catch (err) {
    return {
      name: 'HTTP Security Headers',
      category: 'Headers',
      icon: '[Icon]',
      summary: `Failed to fetch headers: ${err.message}`,
      findings: [{
        severity: 'info',
        title: 'Unable to fetch headers',
        description: `Could not connect to ${targetUrl}: ${err.message}`,
        details: err.stack,
        recommendation: 'Ensure the target URL is accessible.',
        evidence: err.message,
        cwe: 'N/A',
        owasp: 'N/A'
      }]
    };
  }

  if (progressCallback) progressCallback({ scanner: 'header-scanner', progress: 40, message: 'Analyzing security headers...' });

  const headers = response.headers;
  let passCount = 0;
  let failCount = 0;
  const headerResults = [];

  // Check security headers
  for (const [headerKey, config] of Object.entries(SECURITY_HEADERS)) {
    const headerValue = headers[headerKey] || null;
    const result = config.validate(headerValue);

    headerResults.push({
      header: config.name,
      present: !!headerValue,
      value: headerValue,
      pass: result.pass,
      detail: result.detail
    });

    if (!result.pass) {
      failCount++;
      findings.push({
        severity: config.severity,
        title: `Missing/Weak: ${config.name}`,
        description: config.description,
        details: result.detail,
        recommendation: config.recommendation,
        evidence: headerValue ? `Current value: ${headerValue}` : 'Header not present in response',
        cwe: config.cwe,
        owasp: config.owasp
      });
    } else {
      passCount++;
    }
  }

  if (progressCallback) progressCallback({ scanner: 'header-scanner', progress: 70, message: 'Checking information disclosure...' });

  // Check for information disclosure headers
  for (const headerName of INFO_HEADERS_TO_CHECK) {
    const value = headers[headerName];
    if (value) {
      findings.push({
        severity: 'low',
        title: `Information Disclosure: ${headerName}`,
        description: `The "${headerName}" header reveals server technology information that helps attackers fingerprint the system.`,
        details: `Header "${headerName}" is set to: "${value}"`,
        recommendation: `Remove or obfuscate the "${headerName}" header to prevent information disclosure.`,
        evidence: `${headerName}: ${value}`,
        cwe: 'CWE-200',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  }

  // Check for cookies without security flags
  const setCookieHeaders = headers['set-cookie'];
  if (setCookieHeaders) {
    const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0].trim();
      const issues = [];
      if (!/httponly/i.test(cookie)) issues.push('Missing HttpOnly flag');
      if (!/secure/i.test(cookie)) issues.push('Missing Secure flag');
      if (!/samesite/i.test(cookie)) issues.push('Missing SameSite attribute');
      
      if (issues.length > 0) {
        findings.push({
          severity: issues.length >= 2 ? 'high' : 'medium',
          title: `Insecure Cookie: ${cookieName}`,
          description: `Cookie "${cookieName}" is missing security attributes: ${issues.join(', ')}`,
          details: `Full Set-Cookie header: ${cookie}`,
          recommendation: `Set cookie with all security flags: Set-Cookie: ${cookieName}=value; HttpOnly; Secure; SameSite=Strict; Path=/`,
          evidence: cookie,
          cwe: 'CWE-614',
          owasp: 'A05:2021 - Security Misconfiguration'
        });
      }
    }
  }

  if (progressCallback) progressCallback({ scanner: 'header-scanner', progress: 100, message: 'Header analysis complete' });

  return {
    name: 'HTTP Security Headers',
    category: 'Headers',
    icon: '[Icon]',
    summary: `${passCount} passed, ${failCount} failed out of ${Object.keys(SECURITY_HEADERS).length} checks`,
    headerResults,
    findings
  };
}

module.exports = { runHeaderScan, SECURITY_HEADERS, fetchHeaders };
