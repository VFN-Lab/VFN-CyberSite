# Contributing to VFN-CyberSite

Thanks for checking out the project. Whether you are fixing a bug, adding a new security check, or improving the UI, contributions are welcome.

---

## Development Setup

1. Fork the repo and clone it locally:
   ```bash
   git clone https://github.com/VFN-Lab/VFN-CyberSite.git
   cd VFN-CyberSite
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the dev server (with hot-reload):
   ```bash
   npm run dev
   ```

4. Open `http://localhost:3000` in your browser.

---

## How Scanners Work

All vulnerability checks live inside the `scanners/` directory. Each scanner is a separate module that exports an async function.

A typical scanner looks like this:

```javascript
const axios = require('axios');

async function scanMyFeature(targetUrl, options = {}, onProgress = () => {}) {
  const findings = [];
  onProgress({ scanner: 'my-feature', progress: 50, message: 'Checking endpoints...' });

  try {
    const res = await axios.get(`${targetUrl}/test-path`, {
      timeout: 5000,
      validateStatus: () => true
    });

    if (res.data && res.data.includes('vulnerable_marker')) {
      findings.push({
        title: 'Vulnerability Title',
        severity: 'high', // 'critical' | 'high' | 'medium' | 'low' | 'info'
        category: 'Injection',
        description: 'What the vulnerability is and how it was triggered.',
        remediation: 'How the developer should fix it.',
        cwe: 'CWE-xxx'
      });
    }
  } catch (err) {
    // Fail gracefully so the rest of the scan continues
  }

  onProgress({ scanner: 'my-feature', progress: 100, message: 'Done.' });
  return findings;
}

module.exports = { scanMyFeature };
```

To wire it into the scan pipeline:
1. Import your function in `scanners/index.js`.
2. Add it inside `runFullURLScan()`.
3. Push its findings into `allFindings`.

### Rules for Scanners:
- **Always set timeouts:** Every network request must have a timeout (usually 5–8 seconds). Never let a non-responsive server hang the entire scan.
- **Fail gracefully:** Wrap network calls in `try/catch`. One failing endpoint should never crash the scan or the server.
- **No destructive payloads:** We test for security flaws; we never drop database tables or modify server data.

---

## Frontend & Translations

The frontend is written in plain HTML, CSS, and vanilla JavaScript—no React, Vue, or build steps required.

- **UI files:** `index.html`, `css/`, and `js/app.js`.
- **Translations:** CyberSite supports English, Arabic, and French. All UI strings live in `js/translations.js`. If you add any new text to the interface, make sure to add keys to `en`, `ar`, and `fr`.

---

## Pull Request Guidelines

1. Create a clean branch for your changes:
   ```bash
   git checkout -b fix-sqli-timeout
   ```
2. Keep PRs focused on one thing (don't mix a bug fix with a total UI redesign).
3. Test your changes locally before submitting.
4. Try to avoid adding heavy npm packages if existing dependencies or native Node.js APIs can do the job.
5. Open a PR with a clear summary of what you changed and why.

---

## Ethics

This project is built by VFN Media Lab to help programmers and website owners secure their own applications. Please do not submit pull requests containing exploits or tools meant for unauthorized attacks.
