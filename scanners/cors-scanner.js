/**
 * VFN-CyberSite — CORS Scanner
 * Tests for Cross-Origin Resource Sharing misconfigurations
 */

const http = require('http');
const https = require('https');

const TEST_ORIGINS = [
  { origin: 'https://evil.com', desc: 'External malicious domain' },
  { origin: 'https://attacker.evil.com', desc: 'Attacker subdomain' },
  { origin: 'null', desc: 'Null origin (sandboxed iframe)' },
  // Dynamic tests added based on target domain
];

function makeOPTIONSRequest(targetUrl, origin, timeout = 6000) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return resolve(null);
    }

    const client = parsed.protocol === 'https:' ? https : http;
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
    }, timeout);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'OPTIONS',
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'Origin': origin,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Authorization, Content-Type',
      },
      rejectUnauthorized: false,
    };

    const req = client.request(options, (res) => {
      let body = '';
      const finish = () => {
        done({
          statusCode: res.statusCode,
          headers: res.headers,
          allowOrigin: res.headers['access-control-allow-origin'],
          allowCredentials: res.headers['access-control-allow-credentials'],
          allowMethods: res.headers['access-control-allow-methods'],
          allowHeaders: res.headers['access-control-allow-headers'],
          exposeHeaders: res.headers['access-control-expose-headers'],
          maxAge: res.headers['access-control-max-age'],
        });
      };

      res.on('data', c => {
        body += c;
        if (body.length > 50000) {
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
    req.end();
  });
}

const makeCORSRequest = makeOPTIONSRequest;

function makeGETRequest(targetUrl, origin, timeout = 6000) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return resolve(null);
    }

    const client = parsed.protocol === 'https:' ? https : http;
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
    }, timeout);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'Origin': origin,
      },
      rejectUnauthorized: false,
    };

    const req = client.request(options, (res) => {
      let body = '';
      const finish = () => {
        done({
          statusCode: res.statusCode,
          headers: res.headers,
          allowOrigin: res.headers['access-control-allow-origin'],
          allowCredentials: res.headers['access-control-allow-credentials'],
        });
      };

      res.on('data', c => {
        body += c;
        if (body.length > 50000) {
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
    req.end();
  });
}

async function runCORSScan(targetUrl, progressCallback = null) {
  const findings = [];
  const parsed = new URL(targetUrl);
  const targetDomain = parsed.hostname;

  // Build dynamic test origins
  const origins = [
    ...TEST_ORIGINS,
    { origin: `https://${targetDomain}.evil.com`, desc: 'Domain suffix attack' },
    { origin: `https://evil${targetDomain}`, desc: 'Domain prefix attack' },
    { origin: `https://evil.com.${targetDomain}`, desc: 'Subdomain spoofing' },
    { origin: `http://${targetDomain}`, desc: 'HTTP downgrade (same domain)' },
  ];

  if (progressCallback) progressCallback({ scanner: 'cors-scanner', progress: 10, message: 'Testing CORS preflight requests...' });

  let hasVuln = false;
  const results = [];

  for (let i = 0; i < origins.length; i++) {
    const test = origins[i];

    // Test with OPTIONS (preflight)
    const preflightResult = await makeCORSRequest(targetUrl, test.origin);

    // Test with GET (simple request)
    const getResult = await makeGETRequest(targetUrl, test.origin);

    const result = preflightResult || getResult;
    if (!result) continue;

    results.push({
      origin: test.origin,
      desc: test.desc,
      allowOrigin: result.allowOrigin,
      allowCredentials: result.allowCredentials
    });

    // Check for wildcard origin
    if (result.allowOrigin === '*') {
      if (result.allowCredentials === 'true') {
        findings.push({
          severity: 'critical',
          title: 'CORS: Wildcard Origin with Credentials',
          description: 'The server allows any origin (*) WITH credentials. This is a critical misconfiguration that allows any website to make authenticated requests.',
          details: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\nNote: Browsers block this combination, but the server config is dangerous.`,
          recommendation: 'Never use wildcard (*) origin with credentials. Implement a whitelist of allowed origins.',
          evidence: `Origin: ${test.origin}\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          cwe: 'CWE-942',
          owasp: 'A05:2021 - Security Misconfiguration'
        });
        hasVuln = true;
      } else if (!hasVuln) {
        findings.push({
          severity: 'medium',
          title: 'CORS: Wildcard Origin (*)',
          description: 'The server allows requests from any origin. While credentials are not shared, this may expose non-sensitive data.',
          details: `Access-Control-Allow-Origin: *`,
          recommendation: 'Restrict CORS to specific trusted origins unless the API is intentionally public.',
          evidence: `Access-Control-Allow-Origin: *`,
          cwe: 'CWE-942',
          owasp: 'A05:2021 - Security Misconfiguration'
        });
        hasVuln = true;
      }
    }

    // Check if attacker origin is reflected
    if (result.allowOrigin === test.origin && test.origin !== `https://${targetDomain}` && test.origin !== `http://${targetDomain}`) {
      const severity = result.allowCredentials === 'true' ? 'critical' : 'high';
      findings.push({
        severity,
        title: `CORS: Origin Reflection — ${test.desc}`,
        description: `The server reflects the attacker's origin "${test.origin}" in Access-Control-Allow-Origin.${result.allowCredentials === 'true' ? ' Combined with credentials, this allows full account takeover from any website.' : ''}`,
        details: `Origin sent: ${test.origin}\nAccess-Control-Allow-Origin: ${result.allowOrigin}\nAccess-Control-Allow-Credentials: ${result.allowCredentials || 'not set'}\nAttack scenario: ${test.desc}`,
        recommendation: 'Implement a strict whitelist of allowed origins. Validate the Origin header against the whitelist.',
        evidence: `Origin: ${test.origin}\nResponse: Access-Control-Allow-Origin: ${result.allowOrigin}${result.allowCredentials ? '\nAccess-Control-Allow-Credentials: ' + result.allowCredentials : ''}`,
        cwe: 'CWE-942',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
      hasVuln = true;
    }

    // Check null origin
    if (test.origin === 'null' && result.allowOrigin === 'null') {
      findings.push({
        severity: 'high',
        title: 'CORS: Null Origin Allowed',
        description: 'The server allows the null origin, which can be triggered via sandboxed iframes, allowing cross-origin attacks.',
        details: 'Null origin is sent by sandboxed iframes and certain redirect scenarios.',
        recommendation: 'Do not allow the null origin. Remove null from the allowed origins list.',
        evidence: `Origin: null\nAccess-Control-Allow-Origin: null`,
        cwe: 'CWE-942',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
      hasVuln = true;
    }

    if (progressCallback) {
      progressCallback({
        scanner: 'cors-scanner',
        progress: 10 + Math.round(((i + 1) / origins.length) * 85),
        message: `Testing origin ${i + 1}/${origins.length}...`
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      title: 'CORS Properly Configured',
      description: 'No CORS misconfigurations detected. The server correctly restricts cross-origin requests.',
      details: 'All tested origins were properly rejected.',
      recommendation: 'Continue monitoring CORS configuration as the application evolves.',
      evidence: 'All test origins rejected or properly restricted',
      cwe: 'N/A',
      owasp: 'N/A'
    });
  }

  if (progressCallback) progressCallback({ scanner: 'cors-scanner', progress: 100, message: 'CORS analysis complete' });

  return {
    name: 'CORS Scanner',
    category: 'Access Control',
    icon: '[Icon]',
    summary: `Tested ${origins.length} origins — ${findings.filter(f => f.severity !== 'info').length} issues found`,
    results,
    findings
  };
}

module.exports = { runCORSScan };
