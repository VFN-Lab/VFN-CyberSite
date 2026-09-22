/**
 * VFN-CyberSite — Port Scanner
 * TCP Connect scan using Node.js net module
 */

const net = require('net');

const COMMON_PORTS = {
  21: { service: 'FTP', risk: 'high', desc: 'File Transfer Protocol — often has weak auth' },
  22: { service: 'SSH', risk: 'info', desc: 'Secure Shell — check for outdated versions' },
  23: { service: 'Telnet', risk: 'critical', desc: 'Telnet — unencrypted, should be disabled' },
  25: { service: 'SMTP', risk: 'medium', desc: 'Simple Mail Transfer — may allow relay' },
  53: { service: 'DNS', risk: 'low', desc: 'Domain Name System' },
  80: { service: 'HTTP', risk: 'info', desc: 'Unencrypted web server' },
  110: { service: 'POP3', risk: 'medium', desc: 'Post Office Protocol — unencrypted' },
  111: { service: 'RPCBind', risk: 'high', desc: 'RPC services — often exploitable' },
  135: { service: 'MSRPC', risk: 'high', desc: 'Microsoft RPC — potential for exploits' },
  139: { service: 'NetBIOS', risk: 'high', desc: 'NetBIOS Session — information disclosure' },
  143: { service: 'IMAP', risk: 'medium', desc: 'Internet Message Access — unencrypted' },
  443: { service: 'HTTPS', risk: 'info', desc: 'Encrypted web server' },
  445: { service: 'SMB', risk: 'critical', desc: 'Server Message Block — high-value target' },
  993: { service: 'IMAPS', risk: 'info', desc: 'IMAP over SSL' },
  995: { service: 'POP3S', risk: 'info', desc: 'POP3 over SSL' },
  1433: { service: 'MSSQL', risk: 'critical', desc: 'Microsoft SQL Server — should not be exposed' },
  1521: { service: 'Oracle DB', risk: 'critical', desc: 'Oracle Database — should not be exposed' },
  2049: { service: 'NFS', risk: 'high', desc: 'Network File System — information exposure' },
  3306: { service: 'MySQL', risk: 'critical', desc: 'MySQL Database — should not be exposed' },
  3389: { service: 'RDP', risk: 'high', desc: 'Remote Desktop — brute force target' },
  5432: { service: 'PostgreSQL', risk: 'critical', desc: 'PostgreSQL — should not be exposed' },
  5900: { service: 'VNC', risk: 'high', desc: 'Virtual Network Computing — often weak auth' },
  5985: { service: 'WinRM', risk: 'high', desc: 'Windows Remote Management' },
  6379: { service: 'Redis', risk: 'critical', desc: 'Redis — often no authentication' },
  8080: { service: 'HTTP-Alt', risk: 'medium', desc: 'Alternative HTTP — may be admin panel' },
  8443: { service: 'HTTPS-Alt', risk: 'low', desc: 'Alternative HTTPS' },
  8888: { service: 'HTTP-Alt', risk: 'medium', desc: 'Alternative HTTP service' },
  9090: { service: 'Web Console', risk: 'medium', desc: 'Management console' },
  9200: { service: 'Elasticsearch', risk: 'critical', desc: 'Elasticsearch — often unauthenticated' },
  9300: { service: 'Elasticsearch', risk: 'critical', desc: 'Elasticsearch transport' },
  11211: { service: 'Memcached', risk: 'high', desc: 'Memcached — often unauthenticated' },
  27017: { service: 'MongoDB', risk: 'critical', desc: 'MongoDB — often no authentication' },
  27018: { service: 'MongoDB', risk: 'critical', desc: 'MongoDB shard' },
  50000: { service: 'SAP', risk: 'high', desc: 'SAP Management Console' },
};

function scanPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const done = (status, banner = '') => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ port, status, banner: banner.trim() });
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      // Try to grab banner
      socket.write('HEAD / HTTP/1.0\r\n\r\n');
      let bannerData = '';
      socket.on('data', (data) => {
        bannerData += data.toString().substring(0, 512);
      });
      setTimeout(() => done('open', bannerData), 800);
    });

    socket.on('timeout', () => done('closed'));
    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') done('closed');
      else if (err.code === 'EHOSTUNREACH') done('filtered');
      else if (err.code === 'ETIMEDOUT') done('filtered');
      else done('closed');
    });
    socket.on('close', () => done('closed'));

    socket.connect(port, host);
  });
}

async function runPortScan(host, options = {}, progressCallback = null) {
  const {
    ports = Object.keys(COMMON_PORTS).map(Number),
    concurrency = 50,
    timeout = 3000
  } = options;

  const findings = [];
  const openPorts = [];
  const totalPorts = ports.length;
  let scannedCount = 0;

  // Scan in batches for concurrency control
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(port => scanPort(host, port, timeout))
    );

    for (const result of results) {
      scannedCount++;
      if (result.status === 'open') {
        const portInfo = COMMON_PORTS[result.port] || {
          service: 'Unknown',
          risk: 'info',
          desc: 'Unknown service'
        };

        openPorts.push({
          port: result.port,
          service: portInfo.service,
          banner: result.banner,
          risk: portInfo.risk
        });

        const severity = portInfo.risk === 'critical' ? 'critical'
          : portInfo.risk === 'high' ? 'high'
          : portInfo.risk === 'medium' ? 'medium'
          : 'low';

        // Only report medium+ as findings
        if (['critical', 'high', 'medium'].includes(portInfo.risk)) {
          findings.push({
            severity,
            title: `Open Port: ${result.port} (${portInfo.service})`,
            description: portInfo.desc,
            details: `Port ${result.port} is open and running ${portInfo.service}. ${result.banner ? 'Banner: ' + result.banner.substring(0, 200) : ''}`,
            recommendation: severity === 'critical'
              ? `Port ${result.port} (${portInfo.service}) should NOT be exposed to the internet. Use firewall rules to restrict access or move the service behind a VPN.`
              : severity === 'high'
              ? `Consider restricting access to port ${result.port} (${portInfo.service}) using firewall rules. Ensure strong authentication is enabled.`
              : `Review if port ${result.port} (${portInfo.service}) needs to be publicly accessible.`,
            evidence: `TCP connect to ${host}:${result.port} succeeded` + (result.banner ? `\nBanner: ${result.banner.substring(0, 200)}` : ''),
            cwe: 'CWE-200',
            owasp: 'A05:2021 - Security Misconfiguration'
          });
        }
      }
    }

    if (progressCallback) {
      progressCallback({
        scanner: 'port-scanner',
        progress: Math.round((scannedCount / totalPorts) * 100),
        message: `Scanned ${scannedCount}/${totalPorts} ports — Found ${openPorts.length} open`
      });
    }
  }

  return {
    name: 'Port Scanner',
    category: 'Network',
    icon: '[Icon]',
    summary: `Scanned ${totalPorts} ports — ${openPorts.length} open`,
    openPorts,
    findings
  };
}

module.exports = { runPortScan, COMMON_PORTS };
