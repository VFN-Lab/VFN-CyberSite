/**
 * VFN-CyberSite — Scanner Orchestrator
 * Coordinates all 14 scanners and manages scan sessions
 * Supports Aggressive Mode for deeper testing
 */

const { runPortScan } = require('./port-scanner');
const { runHeaderScan } = require('./header-scanner');
const { runSSLScan } = require('./ssl-scanner');
const { runDirScan } = require('./dir-scanner');
const { runVulnScan } = require('./vuln-scanner');
const { runCORSScan } = require('./cors-scanner');
const { runDNSScan } = require('./dns-scanner');
const { runTechDetection } = require('./tech-detector');
const { analyzeMultipleFiles } = require('./code-analyzer');
const { runCrawler } = require('./crawler');

// === NEW PENTEST SCANNERS ===
const { runAdvancedSQLiScan } = require('./sqli-scanner');
const { runAuthScan } = require('./auth-scanner');
const { runPrivEscScan } = require('./privesc-scanner');
const { runUploadScan } = require('./upload-scanner');
const { runLogicScan } = require('./logic-scanner');

// Store active scans
const activeScans = new Map();

function generateScanId() {
  return 'scan_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);
}

function calculateSecurityScore(allFindings) {
  let score = 100;
  const deductions = {
    critical: 20,
    high: 10,
    medium: 5,
    low: 2,
    info: 0
  };

  for (const finding of allFindings) {
    score -= deductions[finding.severity] || 0;
  }

  score = Math.max(0, Math.min(100, score));

  let grade;
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 85) grade = 'A-';
  else if (score >= 80) grade = 'B+';
  else if (score >= 75) grade = 'B';
  else if (score >= 70) grade = 'B-';
  else if (score >= 65) grade = 'C+';
  else if (score >= 60) grade = 'C';
  else if (score >= 55) grade = 'C-';
  else if (score >= 50) grade = 'D+';
  else if (score >= 45) grade = 'D';
  else if (score >= 40) grade = 'D-';
  else grade = 'F';

  return { score, grade };
}

async function runFullURLScan(targetUrl, options = {}, progressCallback = null) {
  const scanId = generateScanId();
  const scanResults = {
    id: scanId,
    type: 'url',
    target: targetUrl,
    startTime: new Date().toISOString(),
    status: 'running',
    progress: 0,
    scanners: {},
    allFindings: [],
    score: null,
    endTime: null,
  };

  activeScans.set(scanId, scanResults);

  const broadcast = (data) => {
    const currentBase = Math.round((completedScanners / totalScanners) * 100);
    scanResults.progress = Math.min(99, Math.max(scanResults.progress, currentBase));
    if (progressCallback) progressCallback({ ...data, progress: scanResults.progress, scanId });
  };

  const aggressive = options.aggressive || false;

  const enabledScanners = {
    crawler: options.crawler !== false,
    headers: options.headers !== false,
    ssl: options.ssl !== false,
    ports: options.ports !== false,
    dirs: options.dirs !== false,
    vulns: options.vulns !== false,
    cors: options.cors !== false,
    dns: options.dns !== false,
    tech: options.tech !== false,
    // New pentest scanners
    advSqli: options.advSqli !== false,
    auth: options.auth !== false,
    privesc: options.privesc !== false,
    upload: options.upload !== false,
    logic: options.logic !== false,
  };

  const totalScanners = Object.values(enabledScanners).filter(Boolean).length;
  let completedScanners = 0;

  const updateOverallProgress = (scannerName, scannerProgress, originalMessage) => {
    const baseProgress = Math.round((completedScanners / totalScanners) * 100);
    const scannerContribution = Math.round((scannerProgress / 100) * (100 / totalScanners));
    scanResults.progress = Math.min(99, Math.max(scanResults.progress, baseProgress + scannerContribution));

    if (progressCallback) {
      progressCallback({
        scanId,
        scanner: scannerName,
        progress: scanResults.progress,
        scannerProgress,
        message: originalMessage || `[${scannerName}] ${scannerProgress}%`
      });
    }
  };

  try {
    // Phase 1: Reconnaissance
    if (enabledScanners.crawler) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 1] Crawling target website...' });
      scanResults.scanners.crawler = await runCrawler(targetUrl, { maxPages: 25, maxDepth: 3 }, (p) => updateOverallProgress('crawler', p.progress, p.message));
      completedScanners++;
    }

    const rootPage = scanResults.scanners.crawler?.pages?.[0];
    const initialHtml = rootPage?.body || null;
    const initialHeaders = rootPage?.headers || null;

    if (enabledScanners.tech) {
      broadcast({ scanner: 'orchestrator', message: '[Detect] Identifying technologies...' });
      scanResults.scanners.tech = await runTechDetection(targetUrl, initialHtml, initialHeaders, (p) => updateOverallProgress('tech', p.progress));
      if (scanResults.scanners.tech.findings) scanResults.allFindings.push(...scanResults.scanners.tech.findings);
      completedScanners++;
    }

    if (enabledScanners.dns) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 2] DNS & Subdomain analysis...' });
      scanResults.scanners.dns = await runDNSScan(targetUrl, (p) => updateOverallProgress('dns', p.progress));
      if (scanResults.scanners.dns.findings) scanResults.allFindings.push(...scanResults.scanners.dns.findings);
      completedScanners++;
    }

    // Phase 2: Network Analysis
    if (enabledScanners.ports) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 3] TCP Port scanning...' });
      scanResults.scanners.ports = await runPortScan(new URL(targetUrl).hostname, {}, (p) => updateOverallProgress('ports', p.progress));
      if (scanResults.scanners.ports.findings) scanResults.allFindings.push(...scanResults.scanners.ports.findings);
      completedScanners++;
    }

    if (enabledScanners.ssl) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 3] Analyzing SSL/TLS...' });
      scanResults.scanners.ssl = await runSSLScan(targetUrl, (p) => updateOverallProgress('ssl', p.progress));
      if (scanResults.scanners.ssl.findings) scanResults.allFindings.push(...scanResults.scanners.ssl.findings);
      completedScanners++;
    }

    // Phase 3: HTTP Analysis
    if (enabledScanners.headers) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 4] Checking security headers...' });
      scanResults.scanners.headers = await runHeaderScan(targetUrl, (p) => updateOverallProgress('headers', p.progress));
      if (scanResults.scanners.headers.findings) scanResults.allFindings.push(...scanResults.scanners.headers.findings);
      completedScanners++;
    }

    if (enabledScanners.cors) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 4] Testing CORS configuration...' });
      scanResults.scanners.cors = await runCORSScan(targetUrl, (p) => updateOverallProgress('cors', p.progress));
      if (scanResults.scanners.cors.findings) scanResults.allFindings.push(...scanResults.scanners.cors.findings.filter(f => f.severity !== 'info'));
      completedScanners++;
    }

    // Phase 4: Discovery
    if (enabledScanners.dirs) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 5] Directory scanning...' });
      scanResults.scanners.dirs = await runDirScan(targetUrl, {}, (p) => updateOverallProgress('dirs', p.progress));
      if (scanResults.scanners.dirs.findings) scanResults.allFindings.push(...scanResults.scanners.dirs.findings);
      completedScanners++;
    }

    // Phase 5: Active Vulnerability Testing
    if (enabledScanners.vulns) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 6] Active vulnerability testing...' });
      scanResults.scanners.vulns = await runVulnScan(targetUrl, initialHtml, (p) => updateOverallProgress('vulns', p.progress));
      if (scanResults.scanners.vulns.findings) scanResults.allFindings.push(...scanResults.scanners.vulns.findings);
      completedScanners++;
    }

    // ======== NEW PENTEST PHASES ========

    // Phase 6: Advanced SQL Injection
    if (enabledScanners.advSqli) {
      broadcast({ scanner: 'orchestrator', message: `[Phase 7] Advanced SQL Injection testing${aggressive ? ' (Aggressive)' : ''}...` });
      scanResults.scanners.advSqli = await runAdvancedSQLiScan(targetUrl, initialHtml, (p) => updateOverallProgress('advSqli', p.progress));
      if (scanResults.scanners.advSqli.findings) scanResults.allFindings.push(...scanResults.scanners.advSqli.findings);
      completedScanners++;
    }

    // Phase 7: Broken Authentication
    if (enabledScanners.auth) {
      broadcast({ scanner: 'orchestrator', message: `[Phase 8] Broken Authentication testing${aggressive ? ' (Aggressive)' : ''}...` });
      scanResults.scanners.auth = await runAuthScan(targetUrl, initialHtml, (p) => updateOverallProgress('auth', p.progress));
      if (scanResults.scanners.auth.findings) scanResults.allFindings.push(...scanResults.scanners.auth.findings);
      completedScanners++;
    }

    // Phase 8: Privilege Escalation
    if (enabledScanners.privesc) {
      broadcast({ scanner: 'orchestrator', message: '[Phase 9] Privilege Escalation testing...' });
      scanResults.scanners.privesc = await runPrivEscScan(targetUrl, initialHtml, (p) => updateOverallProgress('privesc', p.progress));
      if (scanResults.scanners.privesc.findings) scanResults.allFindings.push(...scanResults.scanners.privesc.findings);
      completedScanners++;
    }

    // Phase 9: File Upload Vulnerabilities
    if (enabledScanners.upload) {
      broadcast({ scanner: 'orchestrator', message: `[Phase 10] File Upload vulnerability testing${aggressive ? ' (Aggressive)' : ''}...` });
      scanResults.scanners.upload = await runUploadScan(targetUrl, initialHtml, { aggressive }, (p) => updateOverallProgress('upload', p.progress));
      if (scanResults.scanners.upload.findings) scanResults.allFindings.push(...scanResults.scanners.upload.findings);
      completedScanners++;
    }

    // Phase 10: Logic Flaws
    if (enabledScanners.logic) {
      broadcast({ scanner: 'orchestrator', message: `[Phase 11] Logic Flaw analysis${aggressive ? ' (Aggressive)' : ''}...` });
      scanResults.scanners.logic = await runLogicScan(targetUrl, initialHtml, { aggressive }, (p) => updateOverallProgress('logic', p.progress));
      if (scanResults.scanners.logic.findings) scanResults.allFindings.push(...scanResults.scanners.logic.findings);
      completedScanners++;
    }

    // Calculate score
    scanResults.score = calculateSecurityScore(scanResults.allFindings);
    
    // Count by severity
    scanResults.severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of scanResults.allFindings) {
      scanResults.severityCounts[f.severity] = (scanResults.severityCounts[f.severity] || 0) + 1;
    }

    scanResults.aggressive = aggressive;
    scanResults.status = 'completed';
    scanResults.endTime = new Date().toISOString();
    scanResults.progress = 100;

    broadcast({ scanner: 'orchestrator', progress: 100, message: `[System] Scan complete!${aggressive ? ' (Aggressive Mode)' : ''}` });

  } catch (err) {
    scanResults.status = 'error';
    scanResults.error = err.message;
    scanResults.endTime = new Date().toISOString();
  }

  return scanResults;
}

async function runCodeScan(files, progressCallback = null) {
  const scanId = generateScanId();
  const startTime = new Date().toISOString();

  if (progressCallback) {
    progressCallback({ scanId, scanner: 'code-analyzer', progress: 0, message: 'Starting code analysis...' });
  }

  const result = analyzeMultipleFiles(files, progressCallback);

  const scanResults = {
    id: scanId,
    type: 'code',
    target: `${files.length} files`,
    startTime,
    status: 'completed',
    progress: 100,
    scanners: { codeAnalysis: result },
    allFindings: result.findings,
    severityCounts: result.vulnerabilityCounts,
    score: calculateSecurityScore(result.findings),
    endTime: new Date().toISOString(),
  };

  activeScans.set(scanId, scanResults);
  return scanResults;
}

function getScan(scanId) {
  return activeScans.get(scanId) || null;
}

function getAllScans() {
  return [...activeScans.values()].map(s => ({
    id: s.id,
    type: s.type,
    target: s.target,
    status: s.status,
    progress: s.progress,
    startTime: s.startTime,
    endTime: s.endTime,
    score: s.score,
    findingsCount: s.allFindings?.length || 0,
    severityCounts: s.severityCounts
  }));
}

module.exports = {
  runFullURLScan,
  runCodeScan,
  getScan,
  getAllScans,
  calculateSecurityScore,
  generateScanId,
};
