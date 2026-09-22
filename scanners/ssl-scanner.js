/**
 * VFN-CyberSite — SSL/TLS Scanner
 * Analyzes SSL certificates, protocols, and cipher strength
 */

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');

async function runSSLScan(targetUrl, progressCallback = null) {
  const findings = [];
  let parsed;

  try {
    parsed = new URL(targetUrl);
  } catch {
    return {
      name: 'SSL/TLS Analysis',
      category: 'Encryption',
      icon: '[Icon]',
      summary: 'Invalid URL',
      findings: [{ severity: 'info', title: 'Invalid URL', description: 'Could not parse the target URL', details: '', recommendation: 'Provide a valid URL', evidence: targetUrl, cwe: 'N/A', owasp: 'N/A' }]
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      name: 'SSL/TLS Analysis',
      category: 'Encryption',
      icon: '[Icon]',
      summary: 'No HTTPS — CRITICAL',
      findings: [{
        severity: 'critical',
        title: 'No SSL/TLS — Site uses HTTP',
        description: 'The website does not use HTTPS. All traffic is transmitted in plaintext.',
        details: 'Without SSL/TLS, all data including passwords, session tokens, and personal information can be intercepted by attackers (Man-in-the-Middle attacks).',
        recommendation: 'Obtain an SSL certificate (e.g., from Let\'s Encrypt for free) and configure the web server to enforce HTTPS.',
        evidence: `Protocol: ${parsed.protocol}`,
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures'
      }]
    };
  }

  const host = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port) : 443;

  if (progressCallback) progressCallback({ scanner: 'ssl-scanner', progress: 10, message: 'Connecting via TLS...' });

  // Get certificate info
  let certInfo = null;
  let tlsSocket = null;
  let protocolVersion = null;
  let cipherInfo = null;

  try {
    const result = await new Promise((resolve, reject) => {
      const socket = tls.connect({
        host,
        port,
        rejectUnauthorized: false,
        servername: host,
        minVersion: 'TLSv1',
      }, () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        resolve({
          cert,
          cipher,
          protocol,
          authorized,
          authError
        });
        socket.end();
      });

      socket.on('error', reject);
      socket.setTimeout(10000, () => {
        socket.destroy();
        reject(new Error('TLS connection timed out'));
      });
    });

    certInfo = result.cert;
    cipherInfo = result.cipher;
    protocolVersion = result.protocol;

    if (progressCallback) progressCallback({ scanner: 'ssl-scanner', progress: 40, message: 'Analyzing certificate...' });

    // Certificate validation
    if (!result.authorized) {
      findings.push({
        severity: 'high',
        title: 'SSL Certificate Validation Failed',
        description: `The SSL certificate is not trusted: ${result.authError}`,
        details: `Authorization error: ${result.authError}`,
        recommendation: 'Obtain a certificate from a trusted Certificate Authority (CA). Ensure the certificate chain is complete.',
        evidence: `Error: ${result.authError}`,
        cwe: 'CWE-295',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    }

    // Certificate expiry
    if (certInfo.valid_to) {
      const expiryDate = new Date(certInfo.valid_to);
      const now = new Date();
      const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry < 0) {
        findings.push({
          severity: 'critical',
          title: 'SSL Certificate EXPIRED',
          description: `The SSL certificate expired ${Math.abs(daysUntilExpiry)} days ago.`,
          details: `Expiry date: ${certInfo.valid_to}`,
          recommendation: 'Renew the SSL certificate immediately.',
          evidence: `Expired on: ${certInfo.valid_to}`,
          cwe: 'CWE-298',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      } else if (daysUntilExpiry < 30) {
        findings.push({
          severity: 'high',
          title: 'SSL Certificate Expiring Soon',
          description: `The SSL certificate will expire in ${daysUntilExpiry} days.`,
          details: `Expiry date: ${certInfo.valid_to}`,
          recommendation: 'Renew the SSL certificate before it expires. Consider setting up auto-renewal.',
          evidence: `Expires on: ${certInfo.valid_to} (${daysUntilExpiry} days remaining)`,
          cwe: 'CWE-298',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    }

    // Self-signed certificate
    if (certInfo.issuer && certInfo.subject) {
      const issuerCN = certInfo.issuer.CN || '';
      const subjectCN = certInfo.subject.CN || '';
      if (issuerCN === subjectCN && !certInfo.issuerCertificate) {
        findings.push({
          severity: 'high',
          title: 'Self-Signed SSL Certificate',
          description: 'The certificate appears to be self-signed, which browsers do not trust.',
          details: `Issuer: ${issuerCN}, Subject: ${subjectCN}`,
          recommendation: 'Use a certificate from a trusted CA like Let\'s Encrypt (free).',
          evidence: `Issuer CN: ${issuerCN}\nSubject CN: ${subjectCN}`,
          cwe: 'CWE-295',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    }

    // Subject Alternative Names
    if (certInfo.subjectaltname) {
      const sans = certInfo.subjectaltname.split(',').map(s => s.trim());
      if (!sans.some(s => s.includes(host))) {
        findings.push({
          severity: 'medium',
          title: 'Hostname Mismatch',
          description: `The hostname "${host}" is not listed in the certificate's Subject Alternative Names.`,
          details: `SANs: ${certInfo.subjectaltname}`,
          recommendation: 'Ensure the certificate covers the correct hostname.',
          evidence: `Host: ${host}\nSANs: ${certInfo.subjectaltname}`,
          cwe: 'CWE-297',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    }

    if (progressCallback) progressCallback({ scanner: 'ssl-scanner', progress: 60, message: 'Checking TLS protocol version...' });

    // TLS Protocol version
    if (protocolVersion) {
      const weakProtocols = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'];
      if (weakProtocols.includes(protocolVersion)) {
        findings.push({
          severity: protocolVersion.startsWith('SSL') ? 'critical' : 'high',
          title: `Weak TLS Protocol: ${protocolVersion}`,
          description: `The server is using ${protocolVersion} which is deprecated and vulnerable.`,
          details: `${protocolVersion} is known to have cryptographic weaknesses.`,
          recommendation: 'Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.',
          evidence: `Negotiated protocol: ${protocolVersion}`,
          cwe: 'CWE-326',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    }

    if (progressCallback) progressCallback({ scanner: 'ssl-scanner', progress: 80, message: 'Analyzing cipher suite...' });

    // Cipher suite analysis
    if (cipherInfo) {
      const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
      const cipherName = cipherInfo.name || '';
      const isWeak = weakCiphers.some(w => cipherName.toUpperCase().includes(w));

      if (isWeak) {
        findings.push({
          severity: 'high',
          title: `Weak Cipher Suite: ${cipherName}`,
          description: 'The server is using a cipher suite known to be weak or vulnerable.',
          details: `Cipher: ${cipherName}, Protocol: ${cipherInfo.version}`,
          recommendation: 'Configure the server to use strong cipher suites only (e.g., AES-GCM, ChaCha20-Poly1305).',
          evidence: `Cipher: ${cipherName}\nStandard name: ${cipherInfo.standardName || 'N/A'}`,
          cwe: 'CWE-327',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }

      // Check key exchange strength
      if (cipherInfo.name && /DHE/.test(cipherInfo.name) && !/ECDHE/.test(cipherInfo.name)) {
        findings.push({
          severity: 'medium',
          title: 'Non-ECDHE Key Exchange',
          description: 'Server uses DHE key exchange instead of ECDHE, which may use weaker parameters.',
          details: `Cipher: ${cipherInfo.name}`,
          recommendation: 'Prefer ECDHE key exchange for better performance and security.',
          evidence: `Cipher: ${cipherName}`,
          cwe: 'CWE-326',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    }

    // Check for HTTPS redirect from HTTP
    try {
      const httpUrl = targetUrl.replace('https://', 'http://');
      const httpRedirect = await new Promise((resolve, reject) => {
        const req = require('http').get(httpUrl, { timeout: 5000 }, (res) => {
          resolve({
            statusCode: res.statusCode,
            location: res.headers.location
          });
          res.destroy();
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
      });

      if (httpRedirect && httpRedirect.statusCode !== 301 && httpRedirect.statusCode !== 308) {
        findings.push({
          severity: 'medium',
          title: 'HTTP Not Redirecting to HTTPS',
          description: 'The HTTP version of the site does not properly redirect to HTTPS.',
          details: `HTTP response code: ${httpRedirect.statusCode}`,
          recommendation: 'Configure a 301 permanent redirect from HTTP to HTTPS.',
          evidence: `HTTP status: ${httpRedirect.statusCode}, Location: ${httpRedirect.location || 'none'}`,
          cwe: 'CWE-319',
          owasp: 'A02:2021 - Cryptographic Failures'
        });
      }
    } catch { /* ignore */ }

  } catch (err) {
    findings.push({
      severity: 'high',
      title: 'TLS Connection Failed',
      description: `Could not establish TLS connection: ${err.message}`,
      details: err.stack,
      recommendation: 'Ensure the server supports TLS and is accepting connections.',
      evidence: err.message,
      cwe: 'CWE-319',
      owasp: 'A02:2021 - Cryptographic Failures'
    });
  }

  if (progressCallback) progressCallback({ scanner: 'ssl-scanner', progress: 100, message: 'SSL/TLS analysis complete' });

  const certSummary = certInfo ? {
    subject: certInfo.subject,
    issuer: certInfo.issuer,
    validFrom: certInfo.valid_from,
    validTo: certInfo.valid_to,
    serialNumber: certInfo.serialNumber,
    fingerprint: certInfo.fingerprint256,
    sans: certInfo.subjectaltname,
  } : null;

  return {
    name: 'SSL/TLS Analysis',
    category: 'Encryption',
    icon: '[Icon]',
    summary: findings.length === 0
      ? `SSL/TLS is properly configured (${protocolVersion}, ${cipherInfo?.name || 'N/A'})`
      : `Found ${findings.length} issue(s) — Protocol: ${protocolVersion || 'N/A'}`,
    certificate: certSummary,
    protocol: protocolVersion,
    cipher: cipherInfo ? { name: cipherInfo.name, version: cipherInfo.version, standardName: cipherInfo.standardName } : null,
    findings
  };
}

module.exports = { runSSLScan };
