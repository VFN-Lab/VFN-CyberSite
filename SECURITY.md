# Security Policy & Ethical Use Guidelines

## Important Legal & Ethical Disclaimer

Developed by VFN Media Lab, this project is designed to benefit programmers and enhance website security; it is not intended for hacking any websites.

> Official Release Notice: The official release of CyberSite is safe by design and incorporates mandatory root-level domain verification. It strictly does not permit scanning or posing threats to external websites. It is exclusively tailored for auditing your own websites. Any third-party copies, modified builds, or forks that remove or bypass this verification mechanism are not official releases of this software.

- Only scan assets you own or have explicit, documented authorization to test.

- Scanning targets without prior mutual consent is illegal in most jurisdictions and violates laws such as the US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and international cybercrime legislation.

- CyberSite incorporates a Mandatory Domain Ownership Verification System to enforce responsible usage and prevent unauthorized scanning.

- VFN-CyberSite serves as an automated baseline scanner and is not a definitive security guarantee. It does not replace comprehensive manual penetration testing or consulting with a qualified cybersecurity professional.

- The developers, VFN Media Lab, and contributors assume no liability and are not responsible for any misuse, damage, or legal consequences caused by this tool or altered copies.

---

## Mandatory Domain Ownership Verification

To ensure ethical compliance:

1. URL scanning will strictly refuse to execute unless ownership is confirmed via root-level file token placement (`security-scanner-verification.txt`).

2. Verification tokens are cryptographically randomized per target.

3. Verification status is checked before any scanner module initializes.

---

## Reporting a Vulnerability in CyberSite

If you discover a security flaw or vulnerability within the CyberSite codebase itself, we appreciate your help in responsibly disclosing it.

### How to Report:

1. Do not disclose the issue publicly (avoid opening public GitHub issues for undisclosed vulnerabilities).

2. Submit a detailed report with:

   - Description of the vulnerability.

   - Proof of Concept (PoC) or reproducible steps.

   - Affected components (`scanners/`, `server.js`, frontend, etc.).

   - Potential impact and suggested mitigations.

3. We will acknowledge receipt of your report within 48 hours and work with you to test and release a patch.

Thank you for helping keep the open source security community safe.