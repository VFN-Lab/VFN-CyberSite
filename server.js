/**
 * VFN-CyberSite — Express Server
 * Backend API for security scanning with SSE progress updates
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { runFullURLScan, runCodeScan, getScan, getAllScans } = require('./scanners/index');
const { detectLanguage } = require('./scanners/code-analyzer');
const { generateToken, verifyDomain, isDomainVerified, normalizeDomain } = require('./scanners/verification/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Local results store (server-side)
const scanResultsStore = new Map();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, '.')));

// CORS for local development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// File upload config
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = Object.keys(require('./scanners/code-analyzer').LANGUAGE_EXTENSIONS);
    // Allow all text-like files
    if (allowed.includes(ext) || ['.txt', '.md', '.log', '.env', '.cfg', '.conf', '.ini', '.properties', '.gradle', '.lock'].includes(ext)) {
      cb(null, true);
    } else {
      cb(null, true); // Accept all for now, will filter by content
    }
  }
});

// SSE clients for real-time progress
const sseClients = new Map(); // scanId -> [response objects]

function sendSSE(scanId, data) {
  const clients = sseClients.get(scanId) || [];
  const message = `data: ${JSON.stringify(data)}\n\n`;
  clients.forEach(res => {
    try { res.write(message); } catch { /* client disconnected */ }
  });
}

// ============ API ROUTES ============

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', name: 'VFN-CyberSite' });
});

// Get all scans
app.get('/api/scans', (req, res) => {
  res.json(getAllScans());
});

// Get specific scan results
app.get('/api/scan/:id', (req, res) => {
  const scan = scanResultsStore.get(req.params.id) || getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

// SSE endpoint for real-time progress
app.get('/api/scan/:id/progress', (req, res) => {
  const scanId = req.params.id;

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  res.write(`data: ${JSON.stringify({ connected: true, scanId })}\n\n`);

  // Check if scan is already completed
  const scan = scanResultsStore.get(scanId) || getScan(scanId);
  if (scan && scan.status === 'completed') {
    res.write(`data: ${JSON.stringify({ scanner: scan.type === 'code' ? 'code-analyzer' : 'orchestrator', progress: 100, message: 'Scan complete!', completed: true, result: scan })}\n\n`);
    res.end();
    return;
  }

  if (!sseClients.has(scanId)) sseClients.set(scanId, []);
  sseClients.get(scanId).push(res);

  req.on('close', () => {
    const clients = sseClients.get(scanId) || [];
    sseClients.set(scanId, clients.filter(c => c !== res));
  });
});

// ============ VERIFICATION ENDPOINTS ============

app.post('/api/verify/generate', (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = normalizeDomain(domain);
  if (isDomainVerified(cleanDomain)) {
    return res.json({ status: 'ALREADY_VERIFIED', domain: cleanDomain });
  }

  const token = generateToken(cleanDomain);
  res.json({ status: 'TOKEN_GENERATED', domain: cleanDomain, token });
});

app.post('/api/verify/check', async (req, res) => {
  const { domain, token } = req.body;
  if (!domain || !token) return res.status(400).json({ error: 'Domain and token are required' });

  if (isDomainVerified(domain)) {
    return res.json({ status: 'SUCCESS' });
  }

  const success = await verifyDomain(domain, token);
  if (success) {
    res.json({ status: 'SUCCESS' });
  } else {
    res.status(400).json({ status: 'FAILED', error: 'Verification failed. Please ensure the file is uploaded correctly.' });
  }
});

// Start URL scan
app.post('/api/scan/url', async (req, res) => {
  let { url, options } = req.body;

  if (!url) return res.status(400).json({ error: 'URL is required' });

  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // --- STRICT VERIFICATION ENFORCEMENT ---
  const cleanDomain = normalizeDomain(url);
  if (!isDomainVerified(cleanDomain)) {
    return res.status(403).json({ error: 'Domain Ownership Verification Required' });
  }
  // ---------------------------------------

  // Start scan in background
  const scanId = 'scan_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);

  // Respond immediately with scanId
  res.json({ scanId, message: 'Scan started', target: url });

  // Run scan async with progress broadcast
  setTimeout(async () => {
    try {
      const result = await runFullURLScan(url, options || {}, (progress) => {
        sendSSE(scanId, progress);
      });

      // Override the internal scanId and store
      result.id = scanId;
      scanResultsStore.set(scanId, result);
      sendSSE(scanId, { scanner: 'orchestrator', progress: 100, message: 'Scan complete!', completed: true, result });
    } catch (err) {
      sendSSE(scanId, { scanner: 'orchestrator', progress: 100, message: `Error: ${err.message}`, error: true });
    }
  }, 1000);
});

// Start code scan (file upload)
app.post('/api/scan/code', upload.array('files', 100), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }

  const files = req.files.map(file => ({
    name: file.originalname,
    content: file.buffer.toString('utf-8'),
    language: detectLanguage(file.originalname),
    size: file.size
  }));

  const scanId = 'scan_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);

  // Respond immediately
  res.json({ scanId, message: 'Code scan started', filesCount: files.length });

  // Run analysis
  try {
    const result = await runCodeScan(files, (progress) => {
      sendSSE(scanId, progress);
    });

    result.id = scanId;
    scanResultsStore.set(scanId, result);
    sendSSE(scanId, { scanner: 'code-analyzer', progress: 100, message: 'Analysis complete!', completed: true, result });
  } catch (err) {
    sendSSE(scanId, { scanner: 'code-analyzer', progress: 100, message: `Error: ${err.message}`, error: true });
  }
});

// Scan code passed as text (no file upload needed)
app.post('/api/scan/code-text', async (req, res) => {
  const { files } = req.body;

  if (!files || !Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files array is required' });
  }

  const processedFiles = files.map(f => ({
    name: f.name || 'unknown',
    content: f.content || '',
    language: f.language || detectLanguage(f.name || ''),
  }));

  const scanId = 'scan_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);

  res.json({ scanId, message: 'Code scan started', filesCount: processedFiles.length });

  try {
    const result = await runCodeScan(processedFiles, (progress) => {
      sendSSE(scanId, progress);
    });

    result.id = scanId;
    scanResultsStore.set(scanId, result);
    sendSSE(scanId, { scanner: 'code-analyzer', progress: 100, message: 'Analysis complete!', completed: true, result });
  } catch (err) {
    sendSSE(scanId, { scanner: 'code-analyzer', progress: 100, message: `Error: ${err.message}`, error: true });
  }
});

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log('');
  console.log(`
  ================================================
  
      [VFN-CyberSite] - Enterprise Security Scanner
      
      Server running on http://localhost:${PORT}
      
      [NOTICE] Use only on systems you own or 
               have explicit permission to test.
               
  ================================================
  `);
  console.log('');
});

module.exports = app;
