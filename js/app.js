/**
 * VFN-CyberSite — Frontend Application
 * SPA Router, State Management, UI Rendering
 */

// ============ API BASE ============
const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:') ? 'http://localhost:3000' : '';

// ============ i18n ============
let currentLang = 'en';
try { currentLang = localStorage.getItem('cyberscan-lang') || 'en'; } catch (e) {}

function t(key) {
  return typeof translations !== 'undefined' && translations[currentLang] && translations[currentLang][key] 
    ? translations[currentLang][key] 
    : key;
}

function initI18n() {
  document.dir = currentLang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.lang = currentLang;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (el.tagName === 'INPUT' && el.type === 'text') {
      el.placeholder = t(key);
    } else {
      el.innerHTML = t(key);
    }
  });
  document.querySelectorAll('[data-i18n-tooltip]').forEach(el => {
    const key = el.getAttribute('data-i18n-tooltip');
    el.setAttribute('data-tooltip', t(key));
    if (el.title) el.title = t(key);
  });
  const ls = document.getElementById('lang-switcher');
  if (ls) ls.value = currentLang;
}

function changeLanguage(lang) {
  currentLang = lang;
  try { localStorage.setItem('cyberscan-lang', lang); } catch (e) {}
  initI18n();
  if (state.scanResults) renderResults(state.scanResults);
}

window.addEventListener('DOMContentLoaded', initI18n);

window.addEventListener('load', () => {
  const splash = document.getElementById('splash-screen');
  if (splash) {
    setTimeout(() => {
      splash.classList.add('hidden-splash');
      setTimeout(() => {
        splash.style.display = 'none';
      }, 600); // Wait for CSS transition
    }, 1500); // Simulated delay for visual effect
  }
});
// ============ STATE ============
let initialTheme = 'dark';
let initialHistory = '[]';
try {
  initialTheme = localStorage.getItem('cyberscan-theme') || 'dark';
  initialHistory = localStorage.getItem('cyberscan-history') || '[]';
} catch (e) {}

const state = {
  currentPage: 'home',
  theme: initialTheme,
  uploadedFiles: [],
  scanResults: null,
  scanProgress: null,
  activeFilter: 'all',
  scanHistory: JSON.parse(initialHistory),
};
if (typeof window !== 'undefined') window.state = state;

// ============ THEME ============
function setTheme(theme) {
  state.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('cyberscan-theme', theme); } catch (e) {}
}
setTheme(state.theme);

function toggleTheme() {
  setTheme(state.theme === 'dark' ? 'light' : 'dark');
}

// ============ ROUTER ============
function navigateTo(page) {
  state.currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

  const pageEl = document.getElementById(`page-${page}`);
  const navEl = document.querySelector(`[data-page="${page}"]`);
  if (pageEl) {
    pageEl.classList.add('active');
    pageEl.classList.add('page-enter');
    setTimeout(() => pageEl.classList.remove('page-enter'), 400);
  }
  if (navEl) navEl.classList.add('active');

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============ FILE UPLOAD ============
function initFileUpload() {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('file-input');
  if (!zone || !input) return;

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('dragover');
  });

  zone.addEventListener('dragleave', () => {
    zone.classList.remove('dragover');
  });

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
  });

  input.addEventListener('change', (e) => {
    handleFiles(e.target.files);
  });
}

function handleFiles(fileList) {
  if (!fileList) return;
  const files = Array.from(fileList);
  for (const file of files) {
    if (file.size > 10 * 1024 * 1024) {
      showToast('warning', 'File too large', `${file.name} exceeds 10MB limit`);
      continue;
    }
    if (!state.uploadedFiles.find(f => f.name === file.name)) {
      state.uploadedFiles.push(file);
    }
  }
  renderFileList();
  updateScanButton();
  const input = document.getElementById('file-input');
  if (input) input.value = '';
}

function removeFile(index) {
  state.uploadedFiles.splice(index, 1);
  renderFileList();
  updateScanButton();
}

function clearFiles() {
  state.uploadedFiles = [];
  renderFileList();
  updateScanButton();
  const input = document.getElementById('file-input');
  if (input) input.value = '';
}

function updateScanButton() {
  const btn = document.getElementById('btn-code-scan') || document.getElementById('btn-scan-code');
  const heroBtn = document.getElementById('hero-btn-code-scan');
  const hasFiles = state.uploadedFiles && state.uploadedFiles.length > 0;
  
  if (btn) {
    btn.disabled = !hasFiles;
  }
  if (heroBtn) {
    heroBtn.disabled = !hasFiles;
  }
}

function renderFileList() {
  const container = document.getElementById('file-list');
  const heroContainer = document.getElementById('hero-file-list');
  
  if (state.uploadedFiles.length === 0) {
    if (container) container.innerHTML = '';
    if (heroContainer) heroContainer.innerHTML = '';
    return;
  }

  const langIcons = { javascript: '🟨', php: '🐘', python: '🐍', java: '☕', csharp: '🟦', ruby: '💎', go: '🐹', html: '🌐', css: '🎨', json: '📋', yaml: '📝', sql: '🗄️', shell: '⚙️' };

  const htmlContent = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span class="file-item-name">${state.uploadedFiles.length} ${t('files_selected')}</span>
      <button class="btn btn-ghost btn-sm" onclick="clearFiles()">${t('clear_all')}</button>
    </div>
    ${state.uploadedFiles.map((file, i) => {
      const ext = file.name.split('.').pop().toLowerCase();
      const langMap = { js: 'javascript', jsx: 'javascript', ts: 'javascript', tsx: 'javascript', py: 'python', rb: 'ruby', cs: 'csharp', htm: 'html' };
      const lang = langMap[ext] || ext;
      const icon = '<i class="fa-solid fa-file"></i>';
      const size = file.size < 1024 ? `${file.size} B` : file.size < 1048576 ? `${(file.size / 1024).toFixed(1)} KB` : `${(file.size / 1048576).toFixed(1)} MB`;
      return `
        <div class="file-item">
          <div class="file-item-info">
            <span class="file-item-icon">${icon}</span>
            <span class="file-item-name">${file.name}</span>
            <span class="file-item-size">${size}</span>
          </div>
          <button class="file-item-remove" onclick="removeFile(${i})">✕</button>
        </div>
      `;
    }).join('')}
  `;

  if (container) container.innerHTML = htmlContent;
  if (heroContainer) heroContainer.innerHTML = htmlContent;
}

// ============ HERO SEARCH MODE ============
function toggleSearchMode(mode) {
  const urlMode = document.getElementById('url-search-mode');
  const codeMode = document.getElementById('code-search-mode');
  if (!urlMode || !codeMode) return;

  if (mode === 'code') {
    urlMode.classList.add('hidden');
    codeMode.classList.remove('hidden');
    initHeroFileUpload();
  } else {
    codeMode.classList.add('hidden');
    urlMode.classList.remove('hidden');
  }
}

function startURLScanFromHero() {
  const heroInput = document.getElementById('hero-url-input');
  const mainInput = document.getElementById('url-input');
  if (heroInput && mainInput) {
    mainInput.value = heroInput.value;
    startURLScan();
  }
}

function startCodeScanFromHero() {
  startCodeScan();
}

function toggleAggressiveMode() {
  const checkbox = document.getElementById('aggressive-mode');
  if (!checkbox) return;
  checkbox.checked = !checkbox.checked;
  syncAggressiveHeroButton();
}

function syncAggressiveHeroButton() {
  const checkbox = document.getElementById('aggressive-mode');
  const heroBtn = document.getElementById('hero-aggressive-btn');
  if (!checkbox || !heroBtn) return;
  
  if (checkbox.checked) {
    heroBtn.style.color = 'var(--color-critical)';
    heroBtn.style.background = 'var(--color-critical-bg)';
  } else {
    heroBtn.style.color = '';
    heroBtn.style.background = '';
  }
}

// Add an event listener to the checkbox itself to keep the hero button in sync if user clicks the checkbox
document.addEventListener('DOMContentLoaded', () => {
  const checkbox = document.getElementById('aggressive-mode');
  if (checkbox) {
    checkbox.addEventListener('change', syncAggressiveHeroButton);
  }
});

function initHeroFileUpload() {
  const zone = document.getElementById('hero-upload-zone');
  const input = document.getElementById('hero-file-input');
  if (!zone || !input) return;

  if (zone.dataset.initialized) return;
  zone.dataset.initialized = 'true';

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('dragover');
  });

  zone.addEventListener('dragleave', () => {
    zone.classList.remove('dragover');
  });

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    handleHeroFiles(e.dataTransfer.files);
  });
}

function handleHeroFiles(fileList) {
  handleFiles(fileList);
}

// ============ VERIFICATION LOGIC ============
let pendingVerificationDomain = '';
let pendingVerificationToken = '';

async function handleVerification(url) {
  try {
    let domainUrl = url;
    if (!domainUrl.startsWith('http://') && !domainUrl.startsWith('https://')) {
      domainUrl = 'https://' + domainUrl;
    }
    const domain = new URL(domainUrl).hostname;
    
    // Generate token / Check if verified
    const res = await fetch(`${API_BASE}/api/verify/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    
    if (data.status === 'ALREADY_VERIFIED') {
      return true; // Proceed to scan
    }
    
    if (data.status === 'TOKEN_GENERATED') {
      pendingVerificationDomain = data.domain;
      pendingVerificationToken = data.token;
      
      // Show modal
      document.getElementById('verify-domain-name').textContent = data.domain;
      document.getElementById('verify-file-content').textContent = `Security Scanner Verification\nDomain: ${data.domain}\nToken: ${data.token}`;
      document.getElementById('verify-file-link').href = `https://${data.domain}/security-scanner-verification.txt`;
      document.getElementById('verify-file-link').textContent = `https://${data.domain}/security-scanner-verification.txt`;
      
      document.getElementById('verification-modal').classList.remove('hidden');
      return false; // Wait for user to verify
    }
  } catch (err) {
    showToast('Error checking verification', 'error');
    return false;
  }
}

async function checkVerification() {
  const btn = document.getElementById('btn-verify-check');
  btn.disabled = true;
  btn.textContent = 'Verifying...';
  
  try {
    const res = await fetch(`${API_BASE}/api/verify/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: pendingVerificationDomain, token: pendingVerificationToken })
    });
    
    const data = await res.json();
    if (data.status === 'SUCCESS') {
      document.getElementById('verification-modal').classList.add('hidden');
      showToast('Domain Verified Successfully!', 'success');
      // Automatically resume scan
      executeStartURLScan();
    } else {
      showToast(data.error || 'Verification Failed. Make sure the file is uploaded.', 'error');
    }
  } catch (err) {
    showToast('Network error during verification', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify & Start Scan';
  }
}

// ============ SCANNING ============
async function startURLScan() {
  const urlInput = document.getElementById('url-input');
  const url = urlInput.value.trim();

  if (!url) {
    showToast(t('invalid_url'), 'error');
    return;
  }
  
  // 1. Trigger verification check
  const isVerified = await handleVerification(url);
  if (!isVerified) return; // Modal is showing, wait for checkVerification()
  
  // 2. If already verified, execute scan
  executeStartURLScan();
}

async function executeStartURLScan() {
  const urlInput = document.getElementById('url-input');
  let url = urlInput.value.trim();

  if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;

  // Gather options
  const options = {};
  document.querySelectorAll('.scan-option input[type="checkbox"]').forEach(cb => {
    options[cb.dataset.scanner] = cb.checked;
  });

  // Aggressive Mode
  const aggressiveCheckbox = document.getElementById('aggressive-mode');
  if (aggressiveCheckbox && aggressiveCheckbox.checked) {
    options.aggressive = true;
  }

  navigateTo('scanning');
  resetProgressUI();

  try {
    const res = await fetch(`${API_BASE}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, options })
    });
    const data = await res.json();

    if (data.error) return showToast('error', 'Scan Failed', data.error);

    // Listen for progress via SSE
    listenToProgress(data.scanId);
  } catch (err) {
    showToast('error', 'Connection Error', 'Could not connect to server');
    navigateTo('url-scanner');
  }
}

async function startCodeScan() {
  if (state.uploadedFiles.length === 0) return;

  navigateTo('scanning');
  resetProgressUI();

  const formData = new FormData();
  state.uploadedFiles.forEach(file => formData.append('files', file));

  try {
    const res = await fetch(`${API_BASE}/api/scan/code`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();

    if (data.error) return showToast('error', 'Scan Failed', data.error);

    listenToProgress(data.scanId);
  } catch (err) {
    showToast('error', 'Connection Error', 'Could not connect to server');
    navigateTo('code-scanner');
  }
}

function listenToProgress(scanId) {
  const eventSource = new EventSource(`${API_BASE}/api/scan/${scanId}/progress`);
  const logContainer = document.getElementById('scan-log');

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.connected) return;

    // Update progress
    if (data.progress !== undefined) {
      updateProgress(data.progress, data.message);
    }

    // Add log entry
    if (data.message && logContainer) {
      const entry = document.createElement('div');
      entry.className = 'log-entry';
      entry.textContent = `[${new Date().toLocaleTimeString()}] ${data.message}`;
      logContainer.appendChild(entry);
      logContainer.scrollTop = logContainer.scrollHeight;
    }

    // Scan complete
    if (data.completed && data.result) {
      eventSource.close();
      state.scanResults = data.result;

      // Save to history
      const historyEntry = {
        id: data.result.id,
        target: data.result.target,
        type: data.result.type,
        score: data.result.score,
        findingsCount: data.result.allFindings?.length || 0,
        severityCounts: data.result.severityCounts,
        date: new Date().toISOString()
      };
      state.scanHistory.unshift(historyEntry);
      if (state.scanHistory.length > 20) state.scanHistory = state.scanHistory.slice(0, 20);
      try { localStorage.setItem('cyberscan-history', JSON.stringify(state.scanHistory)); } catch (e) {}

      setTimeout(() => {
        navigateTo('results');
        renderResults(data.result);
      }, 800);
    }

    if (data.error) {
      eventSource.close();
      showToast('error', t('invalid_url'), data.message);
      navigateTo('home');
    }
  };

  eventSource.onerror = () => {
    eventSource.close();
    // Try to fetch results directly
    setTimeout(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/scan/${scanId}`);
        const result = await res.json();
        if (result && result.status === 'completed') {
          state.scanResults = result;
          navigateTo('results');
          renderResults(result);
        }
      } catch { /* ignore */ }
    }, 2000);
  };
}

function resetProgressUI() {
  const percent = document.getElementById('scan-percent');
  const message = document.getElementById('scan-message');
  const bar = document.getElementById('scan-progress-bar');
  const log = document.getElementById('scan-log');

  if (percent) percent.textContent = '0%';
  if (message) message.textContent = t('scan_init');
  if (bar) bar.style.width = '0%';
  if (log) log.innerHTML = '';
}

function updateProgress(progress, message) {
  const percent = document.getElementById('scan-percent');
  const msg = document.getElementById('scan-message');
  const bar = document.getElementById('scan-progress-bar');

  if (percent) percent.textContent = `${progress}%`;
  if (msg) msg.textContent = message;
  if (bar) bar.style.width = `${progress}%`;
}

// ============ RESULTS RENDERING ============
function renderResults(result) {
  if (!result) return;

  renderScoreCircle(result.score);
  renderSeverityBars(result.severityCounts);
  renderScannerCards(result.scanners);
  renderFindings(result.allFindings);
  renderDetailsTab(result);

  // Target info
  const targetEl = document.getElementById('result-target');
  const timeEl = document.getElementById('result-time');
  const countEl = document.getElementById('result-findings-count');

  if (targetEl) targetEl.textContent = result.target;
  if (timeEl) {
    const start = new Date(result.startTime);
    const end = new Date(result.endTime);
    const duration = Math.round((end - start) / 1000);
    timeEl.textContent = `${duration}s`;
  }
  if (countEl) countEl.textContent = result.allFindings?.length || 0;
}

function renderScoreCircle(score) {
  if (!score) return;
  const circle = document.getElementById('score-circle-fg');
  const numberEl = document.getElementById('score-number');
  const gradeEl = document.getElementById('score-grade');
  const labelEl = document.getElementById('score-label');

  if (!circle) return;

  const circumference = 2 * Math.PI * 88;
  const offset = circumference - (score.score / 100) * circumference;

  circle.style.strokeDasharray = circumference;
  circle.style.strokeDashoffset = circumference;

  // Animate
  setTimeout(() => {
    circle.style.strokeDashoffset = offset;
  }, 200);

  // Set grade class
  let gradeClass = 'grade-f';
  if (score.score >= 80) gradeClass = 'grade-a';
  else if (score.score >= 65) gradeClass = 'grade-b';
  else if (score.score >= 50) gradeClass = 'grade-c';
  else if (score.score >= 35) gradeClass = 'grade-d';

  circle.className = `score-circle-fg ${gradeClass}`;

  if (numberEl) {
    animateCounter(numberEl, 0, score.score, 1500);
  }
  if (gradeEl) {
    gradeEl.textContent = score.grade;
    gradeEl.className = `score-grade ${gradeClass}`;
  }
  if (labelEl) {
    const labels = {
      'A+': 'Excellent Security', 'A': 'Great Security', 'A-': 'Good Security',
      'B+': 'Above Average', 'B': 'Average Security', 'B-': 'Below Average',
      'C+': 'Needs Improvement', 'C': 'Fair', 'C-': 'Concerning',
      'D+': 'Poor Security', 'D': 'Very Poor', 'D-': 'Critical Issues',
      'F': 'FAILING — Immediate Action Required'
    };
    labelEl.textContent = labels[score.grade] || '';
  }
}

function animateCounter(element, start, end, duration) {
  const startTime = Date.now();
  const update = () => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);
    element.textContent = current;
    if (progress < 1) requestAnimationFrame(update);
  };
  update();
}

function renderSeverityBars(counts) {
  if (!counts) return;
  const container = document.getElementById('severity-bars');
  if (!container) return;

  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const severities = ['critical', 'high', 'medium', 'low', 'info'];

  container.innerHTML = severities.map(sev => `
    <div class="severity-bar-item">
      <span class="severity-bar-label ${sev}">${sev}</span>
      <div class="severity-bar-track">
        <div class="severity-bar-fill ${sev}" style="width: 0%" data-width="${(counts[sev] || 0) / total * 100}%"></div>
      </div>
      <span class="severity-bar-count">${counts[sev] || 0}</span>
    </div>
  `).join('');

  // Animate bars
  setTimeout(() => {
    container.querySelectorAll('.severity-bar-fill').forEach(bar => {
      bar.style.width = bar.dataset.width;
    });
  }, 300);
}

function renderScannerCards(scanners) {
  const container = document.getElementById('scanner-results');
  if (!container || !scanners) return;

  container.innerHTML = Object.entries(scanners).map(([key, scanner]) => {
    let faIcon = 'fa-solid fa-shield-halved';
    let iconColor = 'var(--color-cyan)';

    if (key === 'advSqli' || key === 'vulns') {
      faIcon = 'fa-solid fa-syringe';
      iconColor = 'var(--color-high)';
    } else if (key === 'auth' || key === 'privesc') {
      faIcon = 'fa-solid fa-key';
      iconColor = 'var(--color-critical)';
    } else if (key === 'logic') {
      faIcon = 'fa-solid fa-puzzle-piece';
      iconColor = 'var(--color-low)';
    } else if (key === 'upload') {
      faIcon = 'fa-solid fa-cloud-arrow-up';
      iconColor = 'var(--color-medium)';
    } else if (key === 'dirs') {
      faIcon = 'fa-solid fa-folder-open';
      iconColor = 'var(--color-medium)';
    } else if (key === 'ports' || key === 'tech') {
      faIcon = 'fa-solid fa-network-wired';
      iconColor = 'var(--color-cyan)';
    } else if (key === 'dns' || key === 'headers' || key === 'ssl' || key === 'cors') {
      faIcon = 'fa-solid fa-server';
      iconColor = 'var(--color-purple)';
    }

    let tKey = key;
    if (key === 'advSqli') tKey = 'sqli';
    if (key === 'ports') tKey = 'port_scan';
    if (key === 'dirs') tKey = 'dir';
    if (key === 'vulns') tKey = 'active_vuln';

    const transName = t('mod_' + tKey);
    const transDesc = t('mod_' + tKey + '_desc');

    return `
    <div class="scanner-result-card">
      <div class="scanner-icon" style="color:${iconColor}; font-size:24px;">
        <i class="${faIcon}"></i>
      </div>
      <div class="scanner-info">
        <div class="scanner-name">${transName !== 'mod_' + tKey ? transName : scanner.name}</div>
        <div class="scanner-summary">${transDesc !== 'mod_' + tKey + '_desc' ? transDesc : (scanner.summary || '')}</div>
      </div>
      <div class="scanner-findings-count" style="color: ${scanner.findings?.length > 0 ? 'var(--color-high)' : 'var(--color-low)'}">
        ${scanner.findings?.length || 0}
      </div>
    </div>
  `}).join('');
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  const countEl = document.getElementById('findings-total-count');
  if (!container) return;

  if (countEl) countEl.textContent = findings?.length || 0;

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg></div>
        <div class="empty-state-title">${t('empty_vulns')}</div>
        <div class="empty-state-desc">${t('empty_vulns_desc')}</div>
      </div>
    `;
    return;
  }

  const filtered = state.activeFilter === 'all'
    ? findings
    : findings.filter(f => f.severity === state.activeFilter);

  container.innerHTML = filtered.map((finding, i) => `
    <div class="finding-card" data-index="${i}" onclick="toggleFinding(this)">
      <div class="finding-card-header">
        <div class="finding-severity-dot ${finding.severity}"></div>
        <span class="badge badge-${finding.severity}">${finding.severity}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
        <span class="finding-chevron">▼</span>
      </div>
      <div class="finding-card-body">
        <div class="finding-detail">
          <div class="finding-detail-label">Description</div>
          <div class="finding-detail-value">${escapeHtml(finding.description)}</div>
        </div>
        ${finding.details ? `
          <div class="finding-detail">
            <div class="finding-detail-label">Details</div>
            <div class="finding-evidence">${escapeHtml(finding.details)}</div>
          </div>
        ` : ''}
        ${finding.evidence ? `
          <div class="finding-detail">
            <div class="finding-detail-label">Evidence</div>
            <div class="finding-evidence">${escapeHtml(finding.evidence)}</div>
          </div>
        ` : ''}
        ${finding.recommendation ? `
          <div class="finding-recommendation">
            <strong>💡 ${t('pdf_remediation').replace(':', '')}:</strong> ${escapeHtml(finding.recommendation)}
          </div>
        ` : ''}
        ${finding.fix ? `
          <div class="finding-fix">
            <div class="finding-detail-label">${t('pdf_fix').replace(':', '')}</div>
            <div class="finding-evidence">${escapeHtml(finding.fix)}</div>
          </div>
        ` : ''}
        <div class="finding-tags">
          ${finding.cwe && finding.cwe !== 'N/A' ? `<span class="finding-tag">${finding.cwe}</span>` : ''}
          ${finding.owasp && finding.owasp !== 'N/A' ? `<span class="finding-tag">${finding.owasp}</span>` : ''}
          ${finding.filename ? `<span class="finding-tag">📄 ${finding.filename}${finding.line ? ':' + finding.line : ''}</span>` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

function renderDetailsTab(result) {
  // Tech detection
  const techContainer = document.getElementById('tech-grid');
  if (techContainer && result.scanners?.tech?.technologies) {
    techContainer.innerHTML = result.scanners.tech.technologies.map(t => `
      <div class="tech-item">
        <span class="tech-icon">${t.icon}</span>
        <div>
          <div class="tech-name">${t.name}</div>
          <div class="tech-category">${t.category}</div>
        </div>
      </div>
    `).join('') || `<div class="empty-state-desc">${t('no_tech')}</div>`;
  }

  // Subdomains
  const subContainer = document.getElementById('subdomains-grid');
  if (subContainer && result.scanners?.dns?.subdomains) {
    subContainer.innerHTML = result.scanners.dns.subdomains.map(s => `
      <div class="subdomain-item">
        <span>🌐</span>
        <span>${s.fqdn}</span>
        <span class="subdomain-ip">${s.addresses?.[0] || ''}</span>
      </div>
    `).join('') || `<div class="empty-state-desc">${t('no_sub')}</div>`;
  }

  // Open ports
  const portsContainer = document.getElementById('ports-grid');
  if (portsContainer && result.scanners?.ports?.openPorts) {
    portsContainer.innerHTML = result.scanners.ports.openPorts.map(p => `
      <div class="port-item ${p.risk}">
        <div>
          <span class="port-number">${p.port}</span>
          <span class="port-service"> — ${p.service}</span>
        </div>
        <span class="badge badge-${p.risk === 'critical' ? 'critical' : p.risk === 'high' ? 'high' : p.risk === 'medium' ? 'medium' : 'low'}">${p.risk}</span>
      </div>
    `).join('') || `<div class="empty-state-desc">${t('no_ports')}</div>`;
  }

  // SSL info
  const sslContainer = document.getElementById('ssl-info');
  if (sslContainer && result.scanners?.ssl) {
    const ssl = result.scanners.ssl;
    sslContainer.innerHTML = `
      <div class="stats-grid" style="margin-bottom:var(--space-4)">
        <div class="stat-card">
          <div class="stat-value" style="font-size:var(--fs-xl);color:var(--color-cyan)">${ssl.protocol || 'N/A'}</div>
          <div class="stat-label">${t('protocol')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="font-size:var(--fs-xl);color:var(--color-purple)">${ssl.cipher?.name?.substring(0, 15) || 'N/A'}</div>
          <div class="stat-label">${t('cipher')}</div>
        </div>
        ${ssl.certificate ? `
          <div class="stat-card">
            <div class="stat-value" style="font-size:var(--fs-base);color:var(--color-text-primary)">${ssl.certificate.validTo ? new Date(ssl.certificate.validTo).toLocaleDateString() : 'N/A'}</div>
            <div class="stat-label">${t('expires')}</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="font-size:var(--fs-base);color:var(--color-text-primary)">${ssl.certificate.issuer?.O || ssl.certificate.issuer?.CN || 'N/A'}</div>
            <div class="stat-label">${t('issuer')}</div>
          </div>
        ` : ''}
      </div>
    `;
  }

  // Headers
  const headersContainer = document.getElementById('headers-table');
  if (headersContainer && result.scanners?.headers?.headerResults) {
    headersContainer.innerHTML = `
      <table style="width:100%;border-collapse:collapse;">
        <thead>
          <tr style="border-bottom:1px solid var(--color-border)">
            <th style="text-align:left;padding:8px;font-size:var(--fs-xs);color:var(--color-text-secondary);text-transform:uppercase">${t('header')}</th>
            <th style="text-align:center;padding:8px;font-size:var(--fs-xs);color:var(--color-text-secondary)">${t('status')}</th>
            <th style="text-align:left;padding:8px;font-size:var(--fs-xs);color:var(--color-text-secondary)">${t('details')}</th>
          </tr>
        </thead>
        <tbody>
          ${result.scanners.headers.headerResults.map(h => `
            <tr style="border-bottom:1px solid var(--color-border)">
              <td style="padding:8px;font-size:var(--fs-sm);font-weight:var(--fw-medium)">${h.header}</td>
              <td style="text-align:center;padding:8px;color:${h.pass ? 'var(--color-low)' : 'var(--color-high)'};font-weight:bold">${h.pass ? t('pass') : t('fail')}</td>
              <td style="padding:8px;font-size:var(--fs-xs);color:var(--color-text-secondary)">${escapeHtml(h.detail)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }
}

function toggleFinding(el) {
  el.classList.toggle('expanded');
}

function filterFindings(severity) {
  state.activeFilter = severity;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.filter-btn[data-severity="${severity}"]`)?.classList.add('active');
  if (state.scanResults) renderFindings(state.scanResults.allFindings);
}

function switchResultsTab(tab) {
  document.querySelectorAll('.results-tab-content').forEach(t => t.classList.add('hidden'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(`results-tab-${tab}`)?.classList.remove('hidden');
  document.querySelector(`.tab[data-tab="${tab}"]`)?.classList.add('active');
}

// ============ PDF EXPORT ============
function exportPDF() {
  if (!state.scanResults) return;
  const r = state.scanResults;
  const findings = r.allFindings || [];

  let html = `
    <html dir="${currentLang === 'ar' ? 'rtl' : 'ltr'}"><head><title>VFN-CyberSite — ${t('res_title')}</title>
    <style>
      body { font-family: ${currentLang === 'ar' ? "'Arial', sans-serif" : "'Times New Roman', Times, serif"}; padding: 40px; color: #000; line-height: 1.6; direction: ${currentLang === 'ar' ? 'rtl' : 'ltr'}; text-align: ${currentLang === 'ar' ? 'right' : 'left'}; }
      .header-container { display: flex; justify-content: space-between; border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px; }
      h1 { color: #000; margin: 0; font-size: 28px; text-transform: uppercase; letter-spacing: 1px; }
      h2 { color: #000; margin-top: 30px; border-bottom: 1px solid #000; padding-bottom: 5px; font-size: 20px; text-transform: uppercase; }
      .score { text-align: center; font-size: 64px; font-weight: bold; margin: 20px 0; color: #000 !important; }
      .grade { text-align: center; font-size: 24px; font-weight: bold; color: #000 !important; text-transform: uppercase; }
      .finding { border: 1px solid #000; padding: 16px; margin: 16px 0; page-break-inside: avoid; }
      .critical { border-${currentLang === 'ar' ? 'right' : 'left'}: 6px solid #000; }
      .high { border-${currentLang === 'ar' ? 'right' : 'left'}: 4px solid #333; }
      .medium { border-${currentLang === 'ar' ? 'right' : 'left'}: 2px solid #666; }
      .low { border-${currentLang === 'ar' ? 'right' : 'left'}: 1px solid #999; }
      .severity { display: inline-block; padding: 4px 8px; border: 1px solid #000; font-size: 11px; font-weight: bold; text-transform: uppercase; background: #fff; color: #000; }
      .meta { font-size: 12px; color: #000; font-family: 'Arial', sans-serif; }
      pre { background: #fff; border: 1px dashed #000; padding: 12px; overflow-x: auto; font-size: 12px; font-family: monospace; color: #000; direction: ltr; text-align: left; }
      .recommendation { border: 1px solid #000; padding: 12px; margin-top: 8px; background: #fff; color: #000; }
      .summary-grid { display: flex; gap: 20px; margin: 20px 0; }
      .summary-box { flex: 1; text-align: center; padding: 20px; border: 1px solid #000; }
      .summary-box .number { font-size: 36px; font-weight: bold; color: #000 !important; }
      .summary-box .label { font-size: 12px; color: #000; text-transform: uppercase; font-weight: bold; }
      @media print { body { padding: 20px; } .finding { page-break-inside: avoid; } }
    </style></head><body>
    
    <div class="header-container">
      <div>
        <h1>VFN-CyberSite</h1>
        <div style="font-size: 14px; font-weight: bold; text-transform: uppercase;">${t('pdf_official_report')}</div>
      </div>
    </div>

    <p class="meta">
      <strong>${t('res_target')}</strong> ${escapeHtml(r.target)}<br>
      <strong>Date:</strong> ${new Date().toLocaleString()}<br>
      <strong>Scan ID:</strong> ${r.id}
    </p>

    <h2>${t('pdf_score')}</h2>
    
    <div class="score">${r.score.score}/100</div>
    <div class="grade">${t('pdf_grade')}: ${r.score.grade}</div>

    <h2>${t('pdf_exec_summary')}</h2>
    
    <div class="summary-grid">
      <div class="summary-box"><div class="number">${r.severityCounts?.critical || 0}</div><div class="label">${t('filter_critical')}</div></div>
      <div class="summary-box"><div class="number">${r.severityCounts?.high || 0}</div><div class="label">${t('filter_high')}</div></div>
      <div class="summary-box"><div class="number">${r.severityCounts?.medium || 0}</div><div class="label">${t('filter_medium')}</div></div>
      <div class="summary-box"><div class="number">${r.severityCounts?.low || 0}</div><div class="label">${t('filter_low')}</div></div>
    </div>

    <h2>${t('pdf_findings_plan')} (${findings.length})</h2>

    ${findings.map((f, i) => `
      <div class="finding ${f.severity}">
        <span class="severity ${f.severity}">${f.severity}</span>
        <strong style="font-size: 16px; margin-${currentLang === 'ar' ? 'right' : 'left'}: 8px;">${escapeHtml(f.title)}</strong>
        
        <p><strong>${t('pdf_threat')}</strong><br> ${escapeHtml(f.description)}</p>
        
        ${f.evidence ? `<pre><strong>${t('pdf_evidence')}</strong>\n${escapeHtml(f.evidence)}</pre>` : ''}
        
        ${f.recommendation ? `
          <div class="recommendation">
            <strong>${t('pdf_remediation')}</strong><br>
            ${escapeHtml(f.recommendation)}
          </div>
        ` : ''}
        
        ${f.fix ? `
          <pre><strong>${t('pdf_fix')}</strong>\n${escapeHtml(f.fix)}</pre>
        ` : ''}
        <p class="meta" style="margin-top: 12px;"><strong>${t('pdf_ref')}</strong> ${f.cwe || ''} ${f.owasp ? '| ' + f.owasp : ''}</p>
      </div>
    `).join('')}

    <h2 style="margin-top: 40px;">${t('pdf_disclaimer')}</h2>
    
    <p class="meta">
      ${t('pdf_disclaimer_text')}
    </p>
    </body></html>
  `;

  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  setTimeout(() => w.print(), 500);
}

// ============ TOAST NOTIFICATIONS ============
function showToast(type, title, message) {
  const container = document.getElementById('toast-container') || createToastContainer();
  const icons = { 
    success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00c853" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>', 
    error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff1744" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>', 
    warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff6d00" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>', 
    info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0097a7" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>' 
  };

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      <div class="toast-message">${message}</div>
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('closing');
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

function createToastContainer() {
  const container = document.createElement('div');
  container.id = 'toast-container';
  container.className = 'toast-container';
  document.body.appendChild(container);
  return container;
}

// ============ UTILITIES ============
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ============ INITIALIZATION ============
function initApp() {
  initFileUpload();
  navigateTo('home');

  // Theme toggle
  const themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  // Check server health
  if (typeof fetch !== 'undefined') {
    fetch(`${API_BASE}/api/health`).then(r => r.json()).then(data => {
      if (data.status === 'ok') {
        console.log('🛡️ VFN-CyberSite — Connected to server');
      }
    }).catch(() => {
      showToast('error', 'Server Offline', 'Cannot connect to the backend server');
    });
  }
}

// Global window assignments
if (typeof window !== 'undefined') {
  window.handleFiles = handleFiles;
  window.clearFiles = clearFiles;
  window.removeFile = removeFile;
  window.updateScanButton = updateScanButton;
  window.startCodeScan = startCodeScan;
  window.startURLScan = startURLScan;
  window.navigateTo = navigateTo;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
