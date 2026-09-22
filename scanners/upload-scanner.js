/**
 * VFN-CyberSite — File Upload Vulnerability Scanner
 * Tests: Extension bypass, Content-Type bypass, Polyglot files, SVG XSS, Upload endpoint discovery
 * Supports Aggressive Mode for deeper testing
 */

const http = require('http');
const https = require('https');
const cheerio = require('cheerio');

// ============ UPLOAD ENDPOINT DISCOVERY ============

const UPLOAD_PATHS = [
  '/upload', '/upload/', '/api/upload', '/api/v1/upload',
  '/file/upload', '/files/upload', '/media/upload',
  '/image/upload', '/images/upload', '/img/upload',
  '/avatar/upload', '/profile/upload', '/photo/upload',
  '/attachment/upload', '/document/upload', '/docs/upload',
  '/api/file', '/api/files', '/api/media', '/api/image',
  '/api/v1/file', '/api/v1/files', '/api/v1/media',
  '/wp-content/uploads/', '/uploads/', '/upload/files/',
  '/filemanager', '/file-manager', '/elfinder',
  '/ckeditor/upload', '/tinymce/upload', '/editor/upload',
  '/import', '/api/import', '/bulk-upload',
];

const UPLOAD_DIRS = [
  '/uploads/', '/upload/', '/files/', '/media/',
  '/images/', '/img/', '/assets/uploads/',
  '/content/uploads/', '/wp-content/uploads/',
  '/user-content/', '/attachments/', '/documents/',
  '/static/uploads/', '/public/uploads/', '/data/',
];

// ============ DANGEROUS FILE EXTENSIONS ============

const DANGEROUS_EXTENSIONS = {
  webShells: [
    { ext: '.php', mime: 'application/x-php', desc: 'PHP web shell' },
    { ext: '.php5', mime: 'application/x-php', desc: 'PHP5 web shell' },
    { ext: '.php7', mime: 'application/x-php', desc: 'PHP7 web shell' },
    { ext: '.phtml', mime: 'application/x-php', desc: 'PHP HTML hybrid' },
    { ext: '.phar', mime: 'application/x-php', desc: 'PHP Archive' },
    { ext: '.asp', mime: 'application/x-asp', desc: 'ASP web shell' },
    { ext: '.aspx', mime: 'application/x-aspx', desc: 'ASPX web shell' },
    { ext: '.jsp', mime: 'application/x-jsp', desc: 'JSP web shell' },
    { ext: '.jspx', mime: 'application/x-jsp', desc: 'JSPX web shell' },
    { ext: '.cgi', mime: 'application/x-cgi', desc: 'CGI script' },
    { ext: '.pl', mime: 'application/x-perl', desc: 'Perl script' },
    { ext: '.py', mime: 'application/x-python', desc: 'Python script' },
    { ext: '.rb', mime: 'application/x-ruby', desc: 'Ruby script' },
    { ext: '.sh', mime: 'application/x-sh', desc: 'Shell script' },
    { ext: '.shtml', mime: 'text/html', desc: 'Server-parsed HTML' },
  ],
  doubleExtensions: [
    { ext: '.php.jpg', desc: 'PHP disguised as JPEG' },
    { ext: '.php.png', desc: 'PHP disguised as PNG' },
    { ext: '.php.gif', desc: 'PHP disguised as GIF' },
    { ext: '.asp.jpg', desc: 'ASP disguised as JPEG' },
    { ext: '.jsp.png', desc: 'JSP disguised as PNG' },
    { ext: '.php.pdf', desc: 'PHP disguised as PDF' },
    { ext: '.php.doc', desc: 'PHP disguised as DOC' },
    { ext: '.php5.jpg', desc: 'PHP5 disguised as JPEG' },
    { ext: '.phtml.jpg', desc: 'PHTML disguised as JPEG' },
  ],
  caseManipulation: [
    { ext: '.pHp', desc: 'Mixed case PHP' },
    { ext: '.PhP', desc: 'Mixed case PHP variant' },
    { ext: '.PHP', desc: 'Uppercase PHP' },
    { ext: '.Php', desc: 'Capitalized PHP' },
    { ext: '.pHP', desc: 'Mixed case PHP variant 2' },
    { ext: '.AsP', desc: 'Mixed case ASP' },
    { ext: '.JsP', desc: 'Mixed case JSP' },
  ],
  specialChars: [
    { ext: '.php%00.jpg', desc: 'Null byte injection' },
    { ext: '.php%0a.jpg', desc: 'Newline injection' },
    { ext: '.php.', desc: 'Trailing dot' },
    { ext: '.php ', desc: 'Trailing space' },
    { ext: '.php::$DATA', desc: 'NTFS alternate data stream' },
    { ext: '.php%20', desc: 'URL-encoded space' },
    { ext: '.php....', desc: 'Multiple trailing dots' },
    { ext: '.php;.jpg', desc: 'Semicolon bypass (IIS)' },
  ],
  dangerousContent: [
    {
      name: 'SVG with JavaScript',
      ext: '.svg',
      mime: 'image/svg+xml',
      content: '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
      desc: 'SVG XSS payload'
    },
    {
      name: 'HTML file',
      ext: '.html',
      mime: 'text/html',
      content: '<html><body><script>alert("XSS")</script></body></html>',
      desc: 'HTML stored XSS'
    },
    {
      name: 'XML with entity',
      ext: '.xml',
      mime: 'text/xml',
      content: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
      desc: 'XXE via file upload'
    },
    {
      name: 'HTM file',
      ext: '.htm',
      mime: 'text/html',
      content: '<html><body><img src=x onerror=alert("XSS")></body></html>',
      desc: 'HTM stored XSS'
    },
  ],
};

// ============ MAGIC BYTES ============

const MAGIC_BYTES = {
  gif: Buffer.from('GIF89a'),
  png: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  jpg: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]),
  pdf: Buffer.from('%PDF-1.4'),
  zip: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
};

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
        ...options.headers
      },
      rejectUnauthorized: false,
    };

    if (options.rawBody) {
      reqOptions.headers['Content-Length'] = options.rawBody.length;
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
    if (options.rawBody) req.write(options.rawBody);
    req.end();
  });
}

// ============ MULTIPART UPLOAD HELPER ============

function buildMultipartBody(filename, content, fieldName = 'file', contentType = 'application/octet-stream') {
  const boundary = '----CyberScanBoundary' + Date.now().toString(36);
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\n`),
    Buffer.from(`Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n`),
    Buffer.from(`Content-Type: ${contentType}\r\n\r\n`),
    Buffer.isBuffer(content) ? content : Buffer.from(content),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { body, boundary };
}

// ============ TEST FUNCTIONS ============

async function discoverUploadEndpoints(targetUrl, html, findings) {
  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { return []; }
  }

  const endpoints = [];
  const baseUrl = targetUrl.replace(/\/+$/, '');

  // Find file upload forms in HTML
  const $ = cheerio.load(html);
  $('input[type="file"]').each((_, el) => {
    const form = $(el).closest('form');
    let action = form.attr('action') || targetUrl;
    if (action.startsWith('/')) action = `${new URL(targetUrl).origin}${action}`;
    else if (!action.startsWith('http')) action = new URL(action, targetUrl).href;
    const fieldName = $(el).attr('name') || 'file';
    endpoints.push({ url: action, method: (form.attr('method') || 'POST').toUpperCase(), fieldName, source: 'html-form' });
  });

  // Probe common upload paths
  for (const path of UPLOAD_PATHS) {
    const resp = await makeRequest(baseUrl + path, { timeout: 5000 });
    if (resp && resp.statusCode >= 200 && resp.statusCode < 400) {
      endpoints.push({ url: baseUrl + path, method: 'POST', fieldName: 'file', source: 'discovery' });
    }
  }

  return endpoints;
}

async function discoverUploadDirs(targetUrl, findings) {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const accessible = [];

  for (const dir of UPLOAD_DIRS) {
    const resp = await makeRequest(baseUrl + dir, { timeout: 5000 });
    if (resp && resp.statusCode >= 200 && resp.statusCode < 300) {
      accessible.push({ path: dir, status: resp.statusCode, size: resp.body.length });

      // Check for directory listing
      if (/Index of|Parent Directory|<a href=".*">/i.test(resp.body)) {
        findings.push({
          severity: 'high',
          title: `Directory Listing — ${dir}`,
          description: `Upload directory ${dir} has directory listing enabled, exposing all uploaded files.`,
          details: `GET ${baseUrl}${dir} → HTTP ${resp.statusCode}\nDirectory listing is enabled`,
          recommendation: 'Disable directory listing. Add an index.html or configure the web server to deny directory browsing.',
          evidence: `GET ${baseUrl}${dir} → HTTP ${resp.statusCode}\nDirectory listing visible`,
          cwe: 'CWE-548',
          owasp: 'A01:2021 - Broken Access Control',
        });
      }
    }
  }

  return accessible;
}

async function testExtensionBypass(endpoints, findings, aggressive) {
  if (endpoints.length === 0) return;

  const testSets = aggressive
    ? [...DANGEROUS_EXTENSIONS.webShells, ...DANGEROUS_EXTENSIONS.doubleExtensions, ...DANGEROUS_EXTENSIONS.caseManipulation, ...DANGEROUS_EXTENSIONS.specialChars]
    : [...DANGEROUS_EXTENSIONS.webShells.slice(0, 5), ...DANGEROUS_EXTENSIONS.doubleExtensions.slice(0, 3), ...DANGEROUS_EXTENSIONS.caseManipulation.slice(0, 2)];

  for (const endpoint of endpoints.slice(0, 3)) {
    const accepted = [];
    const blocked = [];

    for (const test of testSets) {
      const ext = test.ext;
      const filename = `cyberscan_test${ext}`;
      const content = '<?php echo "CyberScan_Upload_Test"; ?>';
      const { body, boundary } = buildMultipartBody(filename, content, endpoint.fieldName, test.mime || 'application/octet-stream');

      const response = await makeRequest(endpoint.url, {
        method: 'POST',
        rawBody: body,
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        timeout: 10000,
      });

      if (!response) continue;

      if (response.statusCode >= 200 && response.statusCode < 400 && !/error|rejected|invalid|not allowed|forbidden/i.test(response.body)) {
        accepted.push({ ext, desc: test.desc });
      } else {
        blocked.push({ ext, desc: test.desc });
      }
    }

    if (accepted.length > 0) {
      const hasDangerous = accepted.some(a =>
        ['.php', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.py', '.sh'].includes(a.ext) ||
        a.ext.includes('.php')
      );

      findings.push({
        severity: hasDangerous ? 'critical' : 'high',
        title: `File Upload — ${accepted.length} Dangerous Extensions Accepted`,
        description: `Upload endpoint ${endpoint.url} accepts ${accepted.length} potentially dangerous file extensions.`,
        details: `Endpoint: ${endpoint.url}\nAccepted extensions:\n${accepted.map(a => `  ${a.ext} — ${a.desc}`).join('\n')}\n\nBlocked extensions:\n${blocked.map(b => `  ${b.ext} — ${b.desc}`).join('\n')}`,
        recommendation: 'Implement a strict allowlist of safe extensions (e.g., .jpg, .png, .pdf). Validate file content, not just extension. Rename uploaded files.',
        evidence: `${accepted.length} dangerous extensions accepted:\n${accepted.map(a => a.ext).join(', ')}`,
        cwe: 'CWE-434',
        owasp: 'A01:2021 - Broken Access Control',
      });
    }
  }
}

async function testContentTypeBypass(endpoints, findings, aggressive) {
  if (endpoints.length === 0) return;

  const mimeTests = [
    { filename: 'test.php', declaredMime: 'image/jpeg', desc: 'PHP with image/jpeg MIME' },
    { filename: 'test.php', declaredMime: 'image/png', desc: 'PHP with image/png MIME' },
    { filename: 'test.php', declaredMime: 'image/gif', desc: 'PHP with image/gif MIME' },
    { filename: 'test.php', declaredMime: 'application/pdf', desc: 'PHP with PDF MIME' },
    { filename: 'test.asp', declaredMime: 'image/jpeg', desc: 'ASP with image/jpeg MIME' },
    { filename: 'test.jsp', declaredMime: 'image/png', desc: 'JSP with image/png MIME' },
  ];

  const tests = aggressive ? mimeTests : mimeTests.slice(0, 3);

  for (const endpoint of endpoints.slice(0, 2)) {
    for (const test of tests) {
      const content = '<?php echo "CyberScan_MIME_Test"; ?>';
      const { body, boundary } = buildMultipartBody(test.filename, content, endpoint.fieldName, test.declaredMime);

      const response = await makeRequest(endpoint.url, {
        method: 'POST',
        rawBody: body,
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        timeout: 10000,
      });

      if (response && response.statusCode >= 200 && response.statusCode < 400 && !/error|rejected|invalid/i.test(response.body)) {
        findings.push({
          severity: 'critical',
          title: `File Upload — Content-Type Bypass (${test.desc})`,
          description: `Upload endpoint accepts ${test.filename} when Content-Type is set to ${test.declaredMime}, bypassing MIME validation.`,
          details: `Endpoint: ${endpoint.url}\nFilename: ${test.filename}\nDeclared MIME: ${test.declaredMime}\nValidation bypassed`,
          recommendation: 'Validate file content (magic bytes), not just Content-Type header. The Content-Type is client-controlled and cannot be trusted.',
          evidence: `Uploaded ${test.filename} with Content-Type: ${test.declaredMime} → Accepted`,
          cwe: 'CWE-434',
          owasp: 'A01:2021 - Broken Access Control',
        });
        break;
      }
    }
  }
}

async function testMagicByteBypass(endpoints, findings, aggressive) {
  if (!aggressive || endpoints.length === 0) return;

  const polyglotTests = [
    {
      desc: 'GIF89a + PHP (Polyglot)',
      filename: 'polyglot.gif.php',
      content: Buffer.concat([MAGIC_BYTES.gif, Buffer.from('\n<?php echo "CyberScan_Polyglot"; ?>\n')]),
      mime: 'image/gif',
    },
    {
      desc: 'PNG + PHP (Polyglot)',
      filename: 'polyglot.png.php',
      content: Buffer.concat([MAGIC_BYTES.png, Buffer.from('\n<?php echo "CyberScan_Polyglot"; ?>\n')]),
      mime: 'image/png',
    },
    {
      desc: 'JPEG + PHP (Polyglot)',
      filename: 'polyglot.jpg.php',
      content: Buffer.concat([MAGIC_BYTES.jpg, Buffer.from('\n<?php echo "CyberScan_Polyglot"; ?>\n')]),
      mime: 'image/jpeg',
    },
    {
      desc: 'PDF + PHP (Polyglot)',
      filename: 'polyglot.pdf.php',
      content: Buffer.concat([MAGIC_BYTES.pdf, Buffer.from('\n<?php echo "CyberScan_Polyglot"; ?>\n')]),
      mime: 'application/pdf',
    },
  ];

  for (const endpoint of endpoints.slice(0, 2)) {
    for (const test of polyglotTests) {
      const { body, boundary } = buildMultipartBody(test.filename, test.content, endpoint.fieldName, test.mime);

      const response = await makeRequest(endpoint.url, {
        method: 'POST',
        rawBody: body,
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        timeout: 10000,
      });

      if (response && response.statusCode >= 200 && response.statusCode < 400 && !/error|rejected/i.test(response.body)) {
        findings.push({
          severity: 'critical',
          title: `File Upload — Polyglot Bypass (${test.desc})`,
          description: `Upload accepts polyglot file ${test.filename} with valid magic bytes + embedded PHP code.`,
          details: `Endpoint: ${endpoint.url}\nFile: ${test.filename}\nMIME: ${test.mime}\nMagic bytes: Valid ${test.mime.split('/')[1]}\nPayload: PHP code embedded after magic bytes`,
          recommendation: 'Use a dedicated file validation library. Check file content beyond magic bytes. Store uploads outside webroot. Rename files with random names.',
          evidence: `Polyglot file accepted: ${test.filename}\nMagic bytes: ${test.mime} (valid)\nContains: PHP code after header bytes`,
          cwe: 'CWE-434',
          owasp: 'A01:2021 - Broken Access Control',
        });
        break;
      }
    }
  }
}

async function testSVGXSS(endpoints, findings) {
  if (endpoints.length === 0) return;

  for (const dangerous of DANGEROUS_EXTENSIONS.dangerousContent) {
    for (const endpoint of endpoints.slice(0, 2)) {
      const { body, boundary } = buildMultipartBody(
        `test${dangerous.ext}`,
        dangerous.content,
        endpoint.fieldName,
        dangerous.mime
      );

      const response = await makeRequest(endpoint.url, {
        method: 'POST',
        rawBody: body,
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        timeout: 10000,
      });

      if (response && response.statusCode >= 200 && response.statusCode < 400 && !/error|rejected/i.test(response.body)) {
        findings.push({
          severity: 'high',
          title: `File Upload — ${dangerous.name} Accepted`,
          description: `Upload endpoint accepts ${dangerous.ext} files containing ${dangerous.desc}.`,
          details: `Endpoint: ${endpoint.url}\nFile: test${dangerous.ext}\nContent: ${dangerous.content.substring(0, 100)}\nType: ${dangerous.desc}`,
          recommendation: `Block ${dangerous.ext} file uploads or sanitize content. SVG files should be sanitized to remove script tags. HTML/HTM uploads should be blocked.`,
          evidence: `Uploaded test${dangerous.ext} with ${dangerous.desc} → Accepted`,
          cwe: dangerous.ext === '.svg' || dangerous.ext === '.html' ? 'CWE-79' : 'CWE-434',
          owasp: 'A03:2021 - Injection',
        });
        break;
      }
    }
  }
}

async function testUploadSizeLimit(endpoints, findings) {
  if (endpoints.length === 0) return;

  for (const endpoint of endpoints.slice(0, 2)) {
    // Try uploading a large file (5MB of data)
    const largeContent = Buffer.alloc(5 * 1024 * 1024, 'A');
    const { body, boundary } = buildMultipartBody('large_test.jpg', largeContent, endpoint.fieldName, 'image/jpeg');

    const response = await makeRequest(endpoint.url, {
      method: 'POST',
      rawBody: body,
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      timeout: 30000,
    });

    if (response && response.statusCode >= 200 && response.statusCode < 400) {
      findings.push({
        severity: 'medium',
        title: 'File Upload — No Size Limit Enforced',
        description: `Upload endpoint accepts files over 5MB. Lack of size limits can lead to denial of service (disk exhaustion).`,
        details: `Endpoint: ${endpoint.url}\nUploaded: 5MB file → HTTP ${response.statusCode}`,
        recommendation: 'Enforce maximum file size limits server-side. Set limits in web server config (e.g., client_max_body_size in nginx).',
        evidence: `5MB upload → HTTP ${response.statusCode} (Accepted)`,
        cwe: 'CWE-400',
        owasp: 'A05:2021 - Security Misconfiguration',
      });
      break;
    }
  }
}

// ============ MAIN SCANNER ============

async function runUploadScan(targetUrl, html = null, options = {}, progressCallback = null) {
  const findings = [];
  const aggressive = options.aggressive || false;

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 5, message: '[Upload] Discovering upload endpoints...' });

  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { html = ''; }
  }

  // Phase 1: Discover endpoints
  const endpoints = await discoverUploadEndpoints(targetUrl, html, findings);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 15, message: `[Upload] Found ${endpoints.length} upload endpoints. Scanning upload directories...` });

  // Phase 2: Check upload directories
  await discoverUploadDirs(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 25, message: '[Upload] Testing extension bypass...' });

  // Phase 3: Extension bypass
  await testExtensionBypass(endpoints, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 45, message: '[Upload] Testing Content-Type bypass...' });

  // Phase 4: Content-Type bypass
  await testContentTypeBypass(endpoints, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 60, message: '[Upload] Testing magic byte / polyglot bypass...' });

  // Phase 5: Magic byte polyglot bypass (aggressive only)
  await testMagicByteBypass(endpoints, findings, aggressive);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 75, message: '[Upload] Testing SVG/HTML XSS uploads...' });

  // Phase 6: SVG/HTML/XML dangerous content
  await testSVGXSS(endpoints, findings);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 90, message: '[Upload] Testing upload size limits...' });

  // Phase 7: Size limit test
  if (aggressive) await testUploadSizeLimit(endpoints, findings);

  if (progressCallback) progressCallback({ scanner: 'upload-scanner', progress: 100, message: `[Upload] Complete — ${findings.length} upload vulnerabilities found` });

  return {
    name: 'File Upload Vulnerabilities',
    category: 'File Upload',
    icon: '📁',
    summary: `Found ${endpoints.length} upload endpoints — ${findings.length} vulnerabilities found`,
    endpointsFound: endpoints.length,
    aggressive,
    testsPerformed: [
      'Endpoint Discovery', 'Upload Directory Exposure', 'Extension Bypass',
      'Content-Type Bypass', aggressive ? 'Polyglot/Magic Byte Bypass' : null,
      'SVG/HTML XSS Upload', aggressive ? 'Size Limit Testing' : null,
    ].filter(Boolean),
    findings,
  };
}

module.exports = { runUploadScan };
