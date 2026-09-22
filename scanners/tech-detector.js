/**
 * VFN-CyberSite — Technology Detector
 * Fingerprints web technologies, frameworks, servers, and CMS
 */

const http = require('http');
const https = require('https');
const cheerio = require('cheerio');

const TECH_SIGNATURES = {
  // Web Servers
  servers: [
    { name: 'Apache', patterns: { headers: [/apache/i], body: [] }, icon: '[Icon]', category: 'Web Server' },
    { name: 'Nginx', patterns: { headers: [/nginx/i], body: [] }, icon: '[Icon]', category: 'Web Server' },
    { name: 'IIS', patterns: { headers: [/microsoft-iis/i, /asp\.net/i], body: [] }, icon: '[Icon]', category: 'Web Server' },
    { name: 'LiteSpeed', patterns: { headers: [/litespeed/i], body: [] }, icon: '[Icon]', category: 'Web Server' },
    { name: 'Cloudflare', patterns: { headers: [/cloudflare/i, /cf-ray/i], body: [] }, icon: '[Icon]', category: 'CDN/WAF' },
    { name: 'AWS CloudFront', patterns: { headers: [/cloudfront/i, /amz/i], body: [] }, icon: '[Icon]', category: 'CDN' },
    { name: 'Vercel', patterns: { headers: [/vercel/i], body: [] }, icon: '[Icon]', category: 'Platform' },
    { name: 'Netlify', patterns: { headers: [/netlify/i], body: [] }, icon: '[Icon]', category: 'Platform' },
    { name: 'Heroku', patterns: { headers: [/heroku/i], body: [] }, icon: '[Icon]', category: 'Platform' },
  ],

  // CMS
  cms: [
    { name: 'WordPress', patterns: { headers: [], body: [/wp-content/i, /wp-includes/i, /wordpress/i, /wp-json/i] }, icon: '[Icon]', category: 'CMS', risk: 'Monitor for plugin vulnerabilities' },
    { name: 'Drupal', patterns: { headers: [/x-drupal/i], body: [/drupal/i, /sites\/default\/files/i] }, icon: '[Icon]', category: 'CMS' },
    { name: 'Joomla', patterns: { headers: [], body: [/joomla/i, /com_content/i, /\/media\/jui\//i] }, icon: '[Icon]', category: 'CMS' },
    { name: 'Shopify', patterns: { headers: [], body: [/shopify/i, /cdn\.shopify\.com/i] }, icon: '[Icon]', category: 'E-Commerce' },
    { name: 'Magento', patterns: { headers: [], body: [/magento/i, /mage\//i, /varien/i] }, icon: '[Icon]', category: 'E-Commerce' },
    { name: 'Ghost', patterns: { headers: [/x-ghost/i], body: [/ghost/i] }, icon: '[Icon]', category: 'CMS' },
    { name: 'Wix', patterns: { headers: [], body: [/wixsite\.com/i, /_wix_/i, /wix\.com/i] }, icon: '[Icon]', category: 'Website Builder' },
    { name: 'Squarespace', patterns: { headers: [], body: [/squarespace/i, /sqsp/i] }, icon: '[Icon]', category: 'Website Builder' },
  ],

  // Frontend Frameworks
  frontend: [
    { name: 'React', patterns: { headers: [], body: [/react/i, /__react/i, /data-reactroot/i, /_next/i, /react-dom/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'Next.js', patterns: { headers: [/x-nextjs/i], body: [/_next\/static/i, /__NEXT_DATA__/i, /next\.js/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'Vue.js', patterns: { headers: [], body: [/vue\.js/i, /vue\.min\.js/i, /data-v-/i, /vue-router/i, /__vue/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'Nuxt.js', patterns: { headers: [], body: [/__nuxt/i, /_nuxt\//i, /nuxt\.js/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'Angular', patterns: { headers: [], body: [/angular/i, /ng-version/i, /ng-app/i, /ng-controller/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'Svelte', patterns: { headers: [], body: [/svelte/i, /__svelte/i] }, icon: '[Icon]', category: 'Frontend' },
    { name: 'jQuery', patterns: { headers: [], body: [/jquery/i, /jquery\.min\.js/i] }, icon: '[Icon]', category: 'Library' },
    { name: 'Bootstrap', patterns: { headers: [], body: [/bootstrap/i, /bootstrap\.min\.css/i, /bootstrap\.min\.js/i] }, icon: '[Icon]', category: 'CSS Framework' },
    { name: 'Tailwind CSS', patterns: { headers: [], body: [/tailwindcss/i, /tailwind/i] }, icon: '[Icon]', category: 'CSS Framework' },
  ],

  // Backend / Languages
  backend: [
    { name: 'PHP', patterns: { headers: [/x-powered-by:.*php/i, /phpsessid/i], body: [/\.php/i] }, icon: '[Icon]', category: 'Language' },
    { name: 'ASP.NET', patterns: { headers: [/x-aspnet-version/i, /x-aspnetmvc-version/i, /asp\.net/i], body: [/\.aspx/i, /\.ashx/i, /__VIEWSTATE/i] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Python/Django', patterns: { headers: [/csrftoken/i], body: [/django/i, /csrfmiddlewaretoken/i] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Python/Flask', patterns: { headers: [/werkzeug/i], body: [] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Ruby on Rails', patterns: { headers: [/x-request-id/i, /x-runtime/i], body: [/rails/i, /authenticity_token/i, /csrf-token/i] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Express.js', patterns: { headers: [/x-powered-by:.*express/i], body: [] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Java/Spring', patterns: { headers: [/jsessionid/i], body: [/spring/i, /\.jsp/i] }, icon: '[Icon]', category: 'Framework' },
    { name: 'Laravel', patterns: { headers: [], body: [/laravel/i, /laravel_session/i] }, icon: '[Icon]', category: 'Framework' },
  ],

  // Analytics & Marketing
  analytics: [
    { name: 'Google Analytics', patterns: { headers: [], body: [/google-analytics\.com/i, /googletagmanager\.com/i, /gtag/i, /ga\.js/i, /analytics\.js/i] }, icon: '[Icon]', category: 'Analytics' },
    { name: 'Google Tag Manager', patterns: { headers: [], body: [/googletagmanager\.com/i, /GTM-/i] }, icon: '[Icon]', category: 'Tag Manager' },
    { name: 'Facebook Pixel', patterns: { headers: [], body: [/fbevents\.js/i, /facebook\.net\/en_US\/fbevents/i, /fbq\(/i] }, icon: '[Icon]', category: 'Analytics' },
    { name: 'Hotjar', patterns: { headers: [], body: [/hotjar\.com/i, /hj\(/i] }, icon: '[Icon]', category: 'Analytics' },
    { name: 'Mixpanel', patterns: { headers: [], body: [/mixpanel\.com/i, /mixpanel/i] }, icon: '[Icon]', category: 'Analytics' },
  ],

  // Security
  security: [
    { name: 'reCAPTCHA', patterns: { headers: [], body: [/recaptcha/i, /google\.com\/recaptcha/i] }, icon: '[Icon]', category: 'Security' },
    { name: 'hCaptcha', patterns: { headers: [], body: [/hcaptcha\.com/i, /hcaptcha/i] }, icon: '[Icon]', category: 'Security' },
    { name: 'ModSecurity', patterns: { headers: [/mod_security/i], body: [] }, icon: '[Icon]', category: 'WAF' },
    { name: 'Sucuri WAF', patterns: { headers: [/sucuri/i, /x-sucuri/i], body: [] }, icon: '[Icon]', category: 'WAF' },
    { name: 'AWS WAF', patterns: { headers: [/awselb/i, /aws/i], body: [] }, icon: '[Icon]', category: 'WAF' },
  ],
};

const { fetchPage } = require('./crawler');

async function runTechDetection(targetUrl, html = null, headers = null, progressCallback = null) {
  const findings = [];
  const detectedTech = [];

  if (progressCallback) progressCallback({ scanner: 'tech-detector', progress: 10, message: 'Fetching page for analysis...' });

  if (!html || !headers) {
    try {
      const response = await fetchPage(targetUrl);
      html = response.body;
      headers = response.headers;
    } catch (err) {
      return {
        name: 'Technology Detection',
        category: 'Reconnaissance',
        icon: '[Icon]',
        summary: `Failed: ${err.message}`,
        technologies: [],
        findings: []
      };
    }
  }

  if (progressCallback) progressCallback({ scanner: 'tech-detector', progress: 30, message: 'Analyzing technologies...' });

  // Convert headers to a single string for pattern matching
  const headerStr = Object.entries(headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('\n');

  // Scan all categories
  const categories = Object.keys(TECH_SIGNATURES);
  for (const category of categories) {
    for (const tech of TECH_SIGNATURES[category]) {
      let detected = false;
      let evidence = [];

      // Check headers
      for (const pattern of tech.patterns.headers) {
        if (pattern.test(headerStr)) {
          detected = true;
          const match = headerStr.match(pattern);
          evidence.push(`Header: ${match ? match[0] : 'matched'}`);
        }
      }

      // Check body
      for (const pattern of tech.patterns.body) {
        if (pattern.test(html)) {
          detected = true;
          const match = html.match(pattern);
          evidence.push(`Body: ${match ? match[0].substring(0, 100) : 'matched'}`);
        }
      }

      if (detected) {
        detectedTech.push({
          name: tech.name,
          icon: tech.icon,
          category: tech.category,
          evidence
        });
      }
    }
  }

  if (progressCallback) progressCallback({ scanner: 'tech-detector', progress: 60, message: 'Extracting version information...' });

  // Extract version information from meta tags and scripts
  const $ = cheerio.load(html);
  const versions = {};

  // Generator meta tag
  const generator = $('meta[name="generator"]').attr('content');
  if (generator) {
    detectedTech.push({
      name: generator,
      icon: '[Icon]',
      category: 'Generator',
      evidence: [`<meta name="generator" content="${generator}">`]
    });

    // Report if version is exposed
    const versionMatch = generator.match(/\d+\.\d+(\.\d+)?/);
    if (versionMatch) {
      findings.push({
        severity: 'low',
        title: `Version Disclosure: ${generator}`,
        description: `The generator meta tag reveals the exact version of the CMS/framework being used.`,
        details: `<meta name="generator" content="${generator}">`,
        recommendation: 'Remove the generator meta tag to prevent version disclosure.',
        evidence: `<meta name="generator" content="${generator}">`,
        cwe: 'CWE-200',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  }

  // Check for exposed version in X-Powered-By
  if (headers['x-powered-by']) {
    findings.push({
      severity: 'low',
      title: `Technology Disclosure: X-Powered-By: ${headers['x-powered-by']}`,
      description: 'The X-Powered-By header reveals server technology and version.',
      details: `X-Powered-By: ${headers['x-powered-by']}`,
      recommendation: 'Remove the X-Powered-By header.',
      evidence: `X-Powered-By: ${headers['x-powered-by']}`,
      cwe: 'CWE-200',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // Check for exposed Server header
  if (headers['server']) {
    const server = headers['server'];
    const versionMatch = server.match(/\d+\.\d+(\.\d+)?/);
    if (versionMatch) {
      findings.push({
        severity: 'medium',
        title: `Server Version Disclosure: ${server}`,
        description: 'The Server header reveals the exact web server version, helping attackers find known vulnerabilities.',
        details: `Server: ${server}`,
        recommendation: 'Configure the web server to hide or obfuscate the Server header.',
        evidence: `Server: ${server}`,
        cwe: 'CWE-200',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  }

  // Detect JavaScript libraries with versions
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src') || '';
    const versionPatterns = [
      { pattern: /jquery[.-](\d+\.\d+\.\d+)/i, name: 'jQuery' },
      { pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, name: 'Bootstrap' },
      { pattern: /angular[.-](\d+\.\d+\.\d+)/i, name: 'Angular' },
      { pattern: /vue[.-](\d+\.\d+\.\d+)/i, name: 'Vue.js' },
      { pattern: /react[.-](\d+\.\d+\.\d+)/i, name: 'React' },
      { pattern: /lodash[.-](\d+\.\d+\.\d+)/i, name: 'Lodash' },
      { pattern: /moment[.-](\d+\.\d+\.\d+)/i, name: 'Moment.js' },
    ];

    for (const vp of versionPatterns) {
      const match = src.match(vp.pattern);
      if (match) {
        versions[vp.name] = match[1];
      }
    }
  });

  if (progressCallback) progressCallback({ scanner: 'tech-detector', progress: 100, message: 'Technology detection complete' });

  return {
    name: 'Technology Detection',
    category: 'Reconnaissance',
    icon: '[Icon]',
    summary: `Detected ${detectedTech.length} technologies`,
    technologies: detectedTech,
    versions,
    findings
  };
}

module.exports = { runTechDetection };
