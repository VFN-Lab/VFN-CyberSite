/**
 * VFN-CyberSite — Directory Scanner (Brute Force)
 * Discovers hidden files, directories, and sensitive endpoints
 */

const http = require('http');
const https = require('https');

const SENSITIVE_PATHS = [
  // Environment & Config
  { path: '/.env', severity: 'critical', desc: 'Environment file — may contain database credentials, API keys' },
  { path: '/.env.bak', severity: 'critical', desc: 'Environment backup file' },
  { path: '/.env.local', severity: 'critical', desc: 'Local environment file' },
  { path: '/.env.production', severity: 'critical', desc: 'Production environment file' },
  { path: '/.env.development', severity: 'critical', desc: 'Development environment file' },
  { path: '/config.php', severity: 'high', desc: 'PHP configuration file' },
  { path: '/config.yml', severity: 'high', desc: 'YAML configuration file' },
  { path: '/config.json', severity: 'high', desc: 'JSON configuration file' },
  { path: '/settings.py', severity: 'high', desc: 'Django settings file' },
  { path: '/application.properties', severity: 'high', desc: 'Spring application config' },
  { path: '/web.config', severity: 'high', desc: 'IIS web configuration' },
  { path: '/appsettings.json', severity: 'high', desc: '.NET application settings' },
  { path: '/.htaccess', severity: 'medium', desc: 'Apache configuration — may reveal server config' },
  { path: '/.htpasswd', severity: 'critical', desc: 'Apache password file' },
  { path: '/nginx.conf', severity: 'high', desc: 'Nginx configuration' },

  // Version Control
  { path: '/.git/config', severity: 'critical', desc: 'Git config — exposed source code repository' },
  { path: '/.git/HEAD', severity: 'critical', desc: 'Git HEAD — confirms .git exposure' },
  { path: '/.git/logs/HEAD', severity: 'critical', desc: 'Git commit log' },
  { path: '/.svn/entries', severity: 'critical', desc: 'SVN repository exposed' },
  { path: '/.svn/wc.db', severity: 'critical', desc: 'SVN working copy database' },
  { path: '/.hg/hgrc', severity: 'critical', desc: 'Mercurial repository config' },
  { path: '/.gitignore', severity: 'low', desc: 'Gitignore file — reveals project structure' },

  // Admin Panels
  { path: '/admin', severity: 'high', desc: 'Admin panel' },
  { path: '/admin/', severity: 'high', desc: 'Admin panel' },
  { path: '/administrator', severity: 'high', desc: 'Administrator panel' },
  { path: '/admin/login', severity: 'high', desc: 'Admin login page' },
  { path: '/wp-admin/', severity: 'high', desc: 'WordPress admin panel' },
  { path: '/wp-login.php', severity: 'high', desc: 'WordPress login page' },
  { path: '/wp-config.php', severity: 'critical', desc: 'WordPress config (DB credentials)' },
  { path: '/cpanel', severity: 'high', desc: 'cPanel interface' },
  { path: '/plesk', severity: 'high', desc: 'Plesk panel' },
  { path: '/panel', severity: 'medium', desc: 'Control panel' },
  { path: '/dashboard', severity: 'medium', desc: 'Dashboard interface' },
  { path: '/manager', severity: 'medium', desc: 'Management interface' },
  { path: '/console', severity: 'high', desc: 'Console interface' },
  { path: '/phpmyadmin', severity: 'critical', desc: 'phpMyAdmin — database management' },
  { path: '/phpmyadmin/', severity: 'critical', desc: 'phpMyAdmin — database management' },
  { path: '/adminer.php', severity: 'critical', desc: 'Adminer — database management' },

  // PHP Info
  { path: '/phpinfo.php', severity: 'high', desc: 'PHP info page — reveals server configuration' },
  { path: '/info.php', severity: 'high', desc: 'PHP info page' },
  { path: '/test.php', severity: 'medium', desc: 'Test file — may contain debug info' },
  { path: '/php_info.php', severity: 'high', desc: 'PHP info page' },

  // Backup Files
  { path: '/backup/', severity: 'critical', desc: 'Backup directory' },
  { path: '/backup.sql', severity: 'critical', desc: 'SQL backup file' },
  { path: '/backup.zip', severity: 'critical', desc: 'Backup archive' },
  { path: '/dump.sql', severity: 'critical', desc: 'Database dump' },
  { path: '/database.sql', severity: 'critical', desc: 'Database export' },
  { path: '/db.sql', severity: 'critical', desc: 'Database file' },
  { path: '/data.sql', severity: 'critical', desc: 'Data export' },
  { path: '/backup.tar.gz', severity: 'critical', desc: 'Backup archive' },
  { path: '/site.tar.gz', severity: 'critical', desc: 'Site backup' },

  // API & Documentation
  { path: '/api/', severity: 'low', desc: 'API endpoint' },
  { path: '/api/v1/', severity: 'low', desc: 'API v1 endpoint' },
  { path: '/api/v2/', severity: 'low', desc: 'API v2 endpoint' },
  { path: '/swagger/', severity: 'medium', desc: 'Swagger API documentation' },
  { path: '/swagger/index.html', severity: 'medium', desc: 'Swagger UI' },
  { path: '/swagger.json', severity: 'medium', desc: 'Swagger JSON spec' },
  { path: '/api-docs', severity: 'medium', desc: 'API documentation' },
  { path: '/openapi.json', severity: 'medium', desc: 'OpenAPI specification' },
  { path: '/graphql', severity: 'medium', desc: 'GraphQL endpoint' },
  { path: '/graphiql', severity: 'high', desc: 'GraphiQL interactive IDE' },

  // Debug & Development
  { path: '/debug', severity: 'high', desc: 'Debug endpoint' },
  { path: '/debug/', severity: 'high', desc: 'Debug interface' },
  { path: '/debug/pprof/', severity: 'high', desc: 'Go profiler' },
  { path: '/trace', severity: 'high', desc: 'Trace endpoint' },
  { path: '/status', severity: 'low', desc: 'Status page' },
  { path: '/health', severity: 'low', desc: 'Health check' },
  { path: '/healthcheck', severity: 'low', desc: 'Health check' },
  { path: '/metrics', severity: 'medium', desc: 'Prometheus metrics' },
  { path: '/server-info', severity: 'high', desc: 'Server information' },
  { path: '/server-status', severity: 'high', desc: 'Server status page' },
  { path: '/_profiler', severity: 'high', desc: 'Symfony profiler' },
  { path: '/__debug__/', severity: 'high', desc: 'Django debug toolbar' },

  // CI/CD & DevOps
  { path: '/Dockerfile', severity: 'medium', desc: 'Docker configuration' },
  { path: '/docker-compose.yml', severity: 'high', desc: 'Docker Compose — may contain secrets' },
  { path: '/.dockerenv', severity: 'medium', desc: 'Docker environment indicator' },
  { path: '/Jenkinsfile', severity: 'medium', desc: 'Jenkins pipeline' },
  { path: '/.github/', severity: 'low', desc: 'GitHub configuration' },
  { path: '/.gitlab-ci.yml', severity: 'medium', desc: 'GitLab CI config' },
  { path: '/.circleci/config.yml', severity: 'medium', desc: 'CircleCI config' },
  { path: '/Makefile', severity: 'low', desc: 'Makefile — reveals build process' },

  // Package Manifests
  { path: '/package.json', severity: 'low', desc: 'Node.js dependencies — may reveal vulnerabilities' },
  { path: '/package-lock.json', severity: 'low', desc: 'Locked Node.js dependencies' },
  { path: '/composer.json', severity: 'low', desc: 'PHP Composer dependencies' },
  { path: '/composer.lock', severity: 'low', desc: 'Locked PHP dependencies' },
  { path: '/requirements.txt', severity: 'low', desc: 'Python dependencies' },
  { path: '/Gemfile', severity: 'low', desc: 'Ruby dependencies' },
  { path: '/go.mod', severity: 'low', desc: 'Go dependencies' },
  { path: '/pom.xml', severity: 'low', desc: 'Maven dependencies (Java)' },

  // Sensitive Files
  { path: '/robots.txt', severity: 'info', desc: 'Robots file — may reveal hidden paths' },
  { path: '/sitemap.xml', severity: 'info', desc: 'Sitemap — reveals URL structure' },
  { path: '/crossdomain.xml', severity: 'medium', desc: 'Flash cross-domain policy' },
  { path: '/clientaccesspolicy.xml', severity: 'medium', desc: 'Silverlight access policy' },
  { path: '/.well-known/security.txt', severity: 'info', desc: 'Security contact information' },
  { path: '/security.txt', severity: 'info', desc: 'Security contact information' },
  { path: '/humans.txt', severity: 'info', desc: 'Humans.txt' },
  { path: '/readme.md', severity: 'low', desc: 'README file' },
  { path: '/README.md', severity: 'low', desc: 'README file' },
  { path: '/CHANGELOG.md', severity: 'low', desc: 'Changelog — reveals version history' },
  { path: '/LICENSE', severity: 'info', desc: 'License file' },
  { path: '/error_log', severity: 'high', desc: 'Error log file' },
  { path: '/access.log', severity: 'high', desc: 'Access log file' },
  { path: '/debug.log', severity: 'high', desc: 'Debug log file' },
  { path: '/logs/', severity: 'high', desc: 'Logs directory' },

  // Misc
  { path: '/xmlrpc.php', severity: 'high', desc: 'WordPress XML-RPC — brute force vector' },
  { path: '/install', severity: 'high', desc: 'Installation script' },
  { path: '/setup', severity: 'high', desc: 'Setup page' },
  { path: '/test', severity: 'medium', desc: 'Test page' },
  { path: '/temp/', severity: 'medium', desc: 'Temporary files' },
  { path: '/tmp/', severity: 'medium', desc: 'Temporary files' },
  { path: '/uploads/', severity: 'medium', desc: 'Upload directory' },
  { path: '/upload/', severity: 'medium', desc: 'Upload directory' },
  { path: '/files/', severity: 'medium', desc: 'Files directory' },
  { path: '/old/', severity: 'medium', desc: 'Old site version' },
  { path: '/bak/', severity: 'medium', desc: 'Backup directory' },
  { path: '/.DS_Store', severity: 'medium', desc: 'macOS directory metadata' },
  { path: '/Thumbs.db', severity: 'low', desc: 'Windows thumbnail cache' },
  { path: '/elmah.axd', severity: 'high', desc: '.NET error logging' },
  { path: '/trace.axd', severity: 'high', desc: '.NET trace viewer' },

  // Cloud specific
  { path: '/.aws/credentials', severity: 'critical', desc: 'AWS credentials file' },
  { path: '/firebase.json', severity: 'high', desc: 'Firebase configuration' },
  { path: '/google-services.json', severity: 'high', desc: 'Google services config' },
];

function probeUrl(targetUrl, path, timeout = 8000) {
  return new Promise((resolve) => {
    const fullUrl = targetUrl.replace(/\/+$/, '') + path;
    let parsed;
    try {
      parsed = new URL(fullUrl);
    } catch {
      resolve({ path, status: 0, found: false });
      return;
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
      done({ path, status: 0, found: false });
    }, timeout);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*',
      },
      rejectUnauthorized: false,
    };

    const req = client.request(options, (res) => {
      let body = '';
      const finish = () => {
        const found = res.statusCode >= 200 && res.statusCode < 400 && res.statusCode !== 301 && res.statusCode !== 302;
        done({
          path,
          status: res.statusCode,
          found,
          size: body.length,
          contentType: res.headers['content-type'] || '',
          redirect: res.headers.location || null,
          bodySnippet: body.substring(0, 300)
        });
      };

      res.on('data', chunk => {
        body += chunk;
        if (body.length > 10000) {
          try { res.destroy(); } catch {}
          finish();
        }
      });
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', () => finish());
    });

    activeReq = req;
    req.on('error', () => done({ path, status: 0, found: false }));
    req.end();
  });
}

async function runDirScan(targetUrl, options = {}, progressCallback = null) {
  const {
    concurrency = 15,
    customPaths = [],
    timeout = 8000
  } = options;

  const findings = [];
  const discovered = [];
  const allPaths = [...SENSITIVE_PATHS, ...customPaths.map(p => ({ path: p, severity: 'medium', desc: 'Custom path' }))];
  const totalPaths = allPaths.length;
  let scanned = 0;

  for (let i = 0; i < allPaths.length; i += concurrency) {
    const batch = allPaths.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(item => probeUrl(targetUrl, item.path, timeout))
    );

    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const pathInfo = batch[j];
      scanned++;

      if (result.found) {
        discovered.push({
          path: result.path,
          status: result.status,
          size: result.size,
          contentType: result.contentType,
          severity: pathInfo.severity
        });

        // Don't report info-level as findings
        if (pathInfo.severity !== 'info') {
          findings.push({
            severity: pathInfo.severity,
            title: `Exposed: ${result.path}`,
            description: pathInfo.desc,
            details: `HTTP ${result.status} — Content-Type: ${result.contentType} — Size: ${result.size} bytes`,
            recommendation: `Restrict access to ${result.path}. Use web server configuration to deny access, or remove the file if not needed.`,
            evidence: `GET ${targetUrl}${result.path} → HTTP ${result.status}${result.bodySnippet ? '\nPreview: ' + result.bodySnippet.substring(0, 150) : ''}`,
            cwe: pathInfo.severity === 'critical' ? 'CWE-538' : 'CWE-200',
            owasp: 'A01:2021 - Broken Access Control'
          });
        }
      }
    }

    if (progressCallback) {
      progressCallback({
        scanner: 'dir-scanner',
        progress: Math.round((scanned / totalPaths) * 100),
        message: `Scanning directories... ${scanned}/${totalPaths} — ${discovered.length} found`
      });
    }
  }

  // Check robots.txt for hidden paths
  const robotsResult = await probeUrl(targetUrl, '/robots.txt', timeout);
  if (robotsResult.found && robotsResult.bodySnippet) {
    const disallowed = robotsResult.bodySnippet.match(/Disallow:\s*(.+)/gi);
    if (disallowed) {
      const hiddenPaths = disallowed
        .map(d => d.replace(/Disallow:\s*/i, '').trim())
        .filter(p => p && p !== '/');

      if (hiddenPaths.length > 0) {
        findings.push({
          severity: 'info',
          title: 'Hidden Paths in robots.txt',
          description: `robots.txt reveals ${hiddenPaths.length} disallowed paths that may contain sensitive content.`,
          details: `Disallowed paths:\n${hiddenPaths.join('\n')}`,
          recommendation: 'Review disallowed paths — robots.txt is publicly visible and does not prevent access.',
          evidence: hiddenPaths.join(', '),
          cwe: 'CWE-200',
          owasp: 'A01:2021 - Broken Access Control'
        });

        // Probe discovered hidden paths
        for (const hiddenPath of hiddenPaths.slice(0, 20)) {
          const cleanPath = hiddenPath.replace(/\*/g, '');
          if (cleanPath && !allPaths.some(p => p.path === cleanPath)) {
            const probeResult = await probeUrl(targetUrl, cleanPath, timeout);
            if (probeResult.found) {
              discovered.push({
                path: cleanPath,
                status: probeResult.status,
                size: probeResult.size,
                contentType: probeResult.contentType,
                severity: 'medium',
                source: 'robots.txt'
              });
            }
          }
        }
      }
    }
  }

  return {
    name: 'Directory Scanner',
    category: 'Discovery',
    icon: '[Icon]',
    summary: `Scanned ${totalPaths} paths — ${discovered.length} accessible`,
    discovered,
    findings
  };
}

module.exports = { runDirScan, SENSITIVE_PATHS };
