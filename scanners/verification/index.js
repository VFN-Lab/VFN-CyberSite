const crypto = require('crypto');
const axios = require('axios');

// In-memory store for verification state
// In a production environment with multiple nodes, this should be Redis or a database.
const verificationTokens = new Map(); // domain -> token
const verifiedDomains = new Set();    // Set of successfully verified domains

/**
 * Generate a unique verification token for a domain.
 * @param {string} domain - The target domain
 * @returns {string} The generated token
 */
function generateToken(domain) {
  // Normalize domain
  const cleanDomain = normalizeDomain(domain);
  
  // Generate a robust unique token
  const rawToken = crypto.randomBytes(32).toString('hex');
  const token = `security-token-${rawToken.substring(0, 16)}`;
  
  verificationTokens.set(cleanDomain, token);
  console.log(`[Verification] Generated token for ${cleanDomain}: ${token}`);
  return token;
}

/**
 * Normalizes a URL to just the domain name.
 */
function normalizeDomain(urlStr) {
  try {
    let cleanUrl = urlStr;
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }
    const urlObj = new URL(cleanUrl);
    return urlObj.hostname;
  } catch (e) {
    return urlStr;
  }
}

/**
 * Verify a domain by checking the uploaded file.
 * @param {string} domain 
 * @param {string} expectedToken 
 * @returns {Promise<boolean>}
 */
async function verifyDomain(domain, expectedToken) {
  const cleanDomain = normalizeDomain(domain);
  
  // Verify token matches what we have in store (prevents bypassing generation)
  const storedToken = verificationTokens.get(cleanDomain);
  if (!storedToken || storedToken !== expectedToken) {
    console.log(`[Verification] FAILED: Token mismatch for ${cleanDomain}. Expected: ${storedToken}, Got: ${expectedToken}`);
    return false;
  }

  const fileUrl = `https://${cleanDomain}/security-scanner-verification.txt`;
  const fallbackUrl = `http://${cleanDomain}/security-scanner-verification.txt`;

  try {
    let content = '';
    try {
      console.log(`[Verification] Attempting to fetch ${fileUrl}`);
      // Use https.Agent with rejectUnauthorized: false if we want to allow invalid SSL during verification,
      // but to be strict, we can just let axios handle it. For pentesting tools, it's common to ignore SSL errors.
      const https = require('https');
      const agent = new https.Agent({ rejectUnauthorized: false });
      const response = await axios.get(fileUrl, { timeout: 10000, maxRedirects: 5, httpsAgent: agent });
      content = response.data;
    } catch (httpsError) {
      console.log(`[Verification] HTTPS failed, trying HTTP: ${fallbackUrl}`);
      const response = await axios.get(fallbackUrl, { timeout: 10000, maxRedirects: 5 });
      content = response.data;
    }

    if (!content || typeof content !== 'string') {
      console.log(`[Verification] FAILED: Empty or non-text response for ${cleanDomain}`);
      return false;
    }

    // Check strict formatting
    const isHeaderValid = content.includes('Security Scanner Verification');
    const isDomainValid = content.includes(`Domain:\n${cleanDomain}`) || content.includes(`Domain:\r\n${cleanDomain}`) || content.includes(`Domain: ${cleanDomain}`);
    const isTokenValid = content.includes(`Token:\n${expectedToken}`) || content.includes(`Token:\r\n${expectedToken}`) || content.includes(`Token: ${expectedToken}`);

    if (isHeaderValid && isDomainValid && isTokenValid) {
      console.log(`[Verification] SUCCESS: Verified ${cleanDomain}`);
      verifiedDomains.add(cleanDomain);
      verificationTokens.delete(cleanDomain); // Consume the token
      return true;
    } else {
      console.log(`[Verification] FAILED: Content mismatch for ${cleanDomain}`);
      return false;
    }
  } catch (err) {
    console.log(`[Verification] FAILED: Could not fetch file for ${cleanDomain} - ${err.message}`);
    return false;
  }
}

/**
 * Check if a domain has been previously verified
 * @param {string} domain 
 * @returns {boolean}
 */
function isDomainVerified(domain) {
  return verifiedDomains.has(normalizeDomain(domain));
}

module.exports = {
  generateToken,
  verifyDomain,
  isDomainVerified,
  normalizeDomain,
  verifiedDomains
};
