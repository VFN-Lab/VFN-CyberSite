/**
 * VFN-CyberSite — DNS Scanner
 * DNS record enumeration and subdomain discovery
 */

const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolveCname = promisify(dns.resolveCname);
const resolveSoa = promisify(dns.resolveSoa);
const resolveSrv = promisify(dns.resolveSrv);
const reverse = promisify(dns.reverse);

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
  'admin', 'administrator', 'panel', 'cpanel', 'whm', 'plesk',
  'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
  'api', 'api2', 'dev', 'development', 'staging', 'stage', 'test', 'testing',
  'beta', 'alpha', 'demo', 'sandbox',
  'cdn', 'static', 'assets', 'media', 'img', 'images',
  'app', 'apps', 'mobile', 'm',
  'blog', 'cms', 'portal', 'intranet', 'extranet',
  'db', 'database', 'mysql', 'sql', 'postgres', 'mongo', 'redis',
  'vpn', 'remote', 'gateway', 'proxy', 'firewall',
  'git', 'svn', 'repo', 'jenkins', 'ci', 'cd', 'deploy',
  'monitoring', 'grafana', 'kibana', 'prometheus', 'nagios',
  'backup', 'bak', 'old', 'new', 'v2',
  'secure', 'auth', 'login', 'sso', 'oauth',
  'shop', 'store', 'pay', 'payment', 'billing',
  'docs', 'doc', 'help', 'support', 'wiki', 'kb',
  'forum', 'community', 'chat',
  'autodiscover', 'autoconfig', 'exchange', 'owa',
  'cloud', 'aws', 'azure', 'gcp',
  'status', 'health', 'uptime',
  'internal', 'private', 'corp',
  's3', 'bucket', 'storage',
  'calendar', 'crm', 'erp',
  'elastic', 'search', 'solr',
  'rabbitmq', 'kafka', 'queue',
];

async function safeResolve(fn, ...args) {
  try {
    return await fn(...args);
  } catch {
    return null;
  }
}

async function checkSubdomain(subdomain, domain) {
  const fqdn = `${subdomain}.${domain}`;
  try {
    const addresses = await resolve4(fqdn);
    if (addresses && addresses.length > 0) {
      return { subdomain, fqdn, addresses, exists: true };
    }
  } catch {
    // Not found
  }
  return { subdomain, fqdn, exists: false };
}

async function runDNSScan(targetUrl, progressCallback = null) {
  const findings = [];
  let domain;

  try {
    const parsed = new URL(targetUrl);
    domain = parsed.hostname;
    // Strip 'www.' prefix to get root domain for subdomain enumeration
    domain = domain.replace(/^www\./, '');
  } catch {
    return {
      name: 'DNS Analysis',
      category: 'Network',
      icon: '[Icon]',
      summary: 'Invalid URL',
      findings: [{ severity: 'info', title: 'Invalid URL', description: 'Could not parse URL', details: '', recommendation: '', evidence: targetUrl, cwe: 'N/A', owasp: 'N/A' }]
    };
  }

  if (progressCallback) progressCallback({ scanner: 'dns-scanner', progress: 5, message: 'Resolving DNS records...' });

  const records = {};

  // Resolve all record types
  const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.all([
    safeResolve(resolve4, domain),
    safeResolve(resolve6, domain),
    safeResolve(resolveMx, domain),
    safeResolve(resolveNs, domain),
    safeResolve(resolveTxt, domain),
    safeResolve(resolveCname, domain),
    safeResolve(resolveSoa, domain),
  ]);

  records.A = a;
  records.AAAA = aaaa;
  records.MX = mx;
  records.NS = ns;
  records.TXT = txt;
  records.CNAME = cname;
  records.SOA = soa;

  if (progressCallback) progressCallback({ scanner: 'dns-scanner', progress: 20, message: 'Checking DNS security records...' });

  // Check for SPF record
  const txtRecords = txt ? txt.flat() : [];
  const spfRecord = txtRecords.find(r => r.startsWith('v=spf1'));
  if (!spfRecord) {
    findings.push({
      severity: 'medium',
      title: 'Missing SPF Record',
      description: 'No SPF record found. The domain may be vulnerable to email spoofing.',
      details: 'SPF (Sender Policy Framework) specifies which servers are allowed to send email on behalf of the domain.',
      recommendation: 'Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider)',
      evidence: 'No TXT record starting with v=spf1 found',
      cwe: 'CWE-290',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  } else {
    // Check SPF strength
    if (spfRecord.includes('+all')) {
      findings.push({
        severity: 'high',
        title: 'SPF Record Too Permissive (+all)',
        description: 'SPF record ends with +all, which allows any server to send email for this domain.',
        details: `SPF Record: ${spfRecord}`,
        recommendation: 'Change +all to ~all (softfail) or -all (hardfail)',
        evidence: spfRecord,
        cwe: 'CWE-290',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  }

  // Check for DMARC record
  const dmarcDomain = `_dmarc.${domain}`;
  const dmarcRecords = await safeResolve(resolveTxt, dmarcDomain);
  const dmarcFlat = dmarcRecords ? dmarcRecords.flat() : [];
  const dmarcRecord = dmarcFlat.find(r => r.startsWith('v=DMARC1'));

  if (!dmarcRecord) {
    findings.push({
      severity: 'medium',
      title: 'Missing DMARC Record',
      description: 'No DMARC record found. Combined with missing SPF, this significantly increases email spoofing risk.',
      details: 'DMARC builds on SPF and DKIM to provide email authentication and reporting.',
      recommendation: 'Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
      evidence: `No DMARC TXT record found at ${dmarcDomain}`,
      cwe: 'CWE-290',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  } else if (dmarcRecord.includes('p=none')) {
    findings.push({
      severity: 'low',
      title: 'DMARC Policy Set to None',
      description: 'DMARC record exists but policy is set to "none", meaning failed emails are still delivered.',
      details: `DMARC Record: ${dmarcRecord}`,
      recommendation: 'Change DMARC policy to p=quarantine or p=reject',
      evidence: dmarcRecord,
      cwe: 'CWE-290',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // Check DKIM selector
  const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mail'];
  let dkimFound = false;
  for (const selector of dkimSelectors) {
    const dkimDomain = `${selector}._domainkey.${domain}`;
    const dkimRecords = await safeResolve(resolveTxt, dkimDomain);
    if (dkimRecords) {
      dkimFound = true;
      break;
    }
  }

  if (!dkimFound) {
    findings.push({
      severity: 'low',
      title: 'No DKIM Record Found (Common Selectors)',
      description: 'Could not find DKIM records using common selector names.',
      details: `Checked selectors: ${dkimSelectors.join(', ')}`,
      recommendation: 'Ensure DKIM is configured with your email provider.',
      evidence: 'No DKIM TXT records found',
      cwe: 'CWE-290',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  if (progressCallback) progressCallback({ scanner: 'dns-scanner', progress: 40, message: 'Enumerating subdomains...' });

  // Subdomain enumeration
  const discoveredSubdomains = [];
  const batchSize = 20;

  for (let i = 0; i < COMMON_SUBDOMAINS.length; i += batchSize) {
    const batch = COMMON_SUBDOMAINS.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(sub => checkSubdomain(sub, domain))
    );

    for (const result of results) {
      if (result.exists) {
        discoveredSubdomains.push(result);
      }
    }

    if (progressCallback) {
      const progress = 40 + Math.round((i / COMMON_SUBDOMAINS.length) * 55);
      progressCallback({
        scanner: 'dns-scanner',
        progress,
        message: `Enumerating subdomains... ${i + batch.length}/${COMMON_SUBDOMAINS.length} checked — ${discoveredSubdomains.length} found`
      });
    }
  }

  // Check for potential subdomain takeover
  for (const sub of discoveredSubdomains) {
    const cnameRecords = await safeResolve(resolveCname, sub.fqdn);
    if (cnameRecords) {
      for (const cname of cnameRecords) {
        const dangerousCnames = [
          'herokuapp.com', 'herokudns.com', 'github.io', 'pages.github.com',
          'azurewebsites.net', 'cloudapp.net', 'trafficmanager.net',
          's3.amazonaws.com', 's3-website', 'elasticbeanstalk.com',
          'shopify.com', 'fastly.net', 'ghost.io', 'pantheon.io',
          'zendesk.com', 'readme.io', 'surge.sh', 'bitbucket.io',
          'netlify.app', 'fly.dev', 'vercel.app'
        ];

        if (dangerousCnames.some(d => cname.includes(d))) {
          // Try to resolve the CNAME target
          const targetResolved = await safeResolve(resolve4, cname);
          if (!targetResolved) {
            findings.push({
              severity: 'high',
              title: `Potential Subdomain Takeover: ${sub.fqdn}`,
              description: `${sub.fqdn} has a CNAME pointing to ${cname} which may be unclaimed.`,
              details: 'If the service at the CNAME target is not configured, an attacker could claim it and serve malicious content.',
              recommendation: `Verify that the service at ${cname} is properly configured, or remove the DNS record.`,
              evidence: `${sub.fqdn} → CNAME → ${cname} (unresolvable)`,
              cwe: 'CWE-284',
              owasp: 'A05:2021 - Security Misconfiguration'
            });
          }
        }
      }
    }
  }

  // Zone transfer check
  if (ns) {
    for (const nameserver of ns.slice(0, 3)) {
      try {
        const axfrResult = await new Promise((resolve, reject) => {
          const dnsResolve = new dns.Resolver();
          dnsResolve.setServers([nameserver]);
          dnsResolve.resolve(domain, 'ANY', (err, records) => {
            if (err) reject(err);
            else resolve(records);
          });
        });
        // If we get results, zone transfer might be possible
      } catch {
        // Expected - zone transfer should be denied
      }
    }
  }

  if (progressCallback) progressCallback({ scanner: 'dns-scanner', progress: 100, message: 'DNS analysis complete' });

  return {
    name: 'DNS Analysis',
    category: 'Network',
    icon: '[Icon]',
    summary: `${Object.keys(records).filter(k => records[k]).length} record types found — ${discoveredSubdomains.length} subdomains discovered`,
    records,
    subdomains: discoveredSubdomains,
    findings
  };
}

module.exports = { runDNSScan };
