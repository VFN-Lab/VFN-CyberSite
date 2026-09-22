/**
 * VFN-CyberSite — Web Crawler (High Performance & Resilient)
 * Discovers pages, forms, endpoints, and assets on target website
 */

const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { URL } = require('url');
const cheerio = require('cheerio');

function normalizeHost(h) {
  return (h || '').replace(/^www\./i, '').toLowerCase();
}

function fetchPage(targetUrl, options = {}) {
  const {
    timeout = 8000,
    maxBytes = 1.5 * 1024 * 1024, // 1.5MB max body to prevent memory issues
    redirectCount = 0
  } = options;

  return new Promise((resolve, reject) => {
    if (redirectCount > 5) return reject(new Error('Too many redirects'));

    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return reject(new Error('Invalid URL'));
    }

    const client = parsed.protocol === 'https:' ? https : http;
    let timer = null;
    let isDone = false;
    let activeReq = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
    };

    const done = (err, result) => {
      if (isDone) return;
      isDone = true;
      cleanup();
      if (err) reject(err);
      else resolve(result);
    };

    // Absolute hard timer to guarantee execution never hangs
    timer = setTimeout(() => {
      if (activeReq) {
        try { activeReq.destroy(); } catch {}
      }
      done(new Error('Request timeout exceeded'));
    }, timeout);

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      rejectUnauthorized: false
    };

    const req = client.request(reqOptions, (res) => {
      // Follow redirects
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        cleanup();
        try { res.destroy(); } catch {}
        try {
          const redirectUrl = new URL(res.headers.location, targetUrl).href;
          fetchPage(redirectUrl, { timeout, maxBytes, redirectCount: redirectCount + 1 })
            .then(r => done(null, r))
            .catch(e => done(e));
        } catch (e) {
          done(new Error('Invalid redirect URL'));
        }
        return;
      }

      const encoding = res.headers['content-encoding'];
      let stream = res;
      if (encoding === 'gzip') {
        const gunzip = zlib.createGunzip();
        res.pipe(gunzip);
        stream = gunzip;
      } else if (encoding === 'deflate') {
        const inflate = zlib.createInflate();
        res.pipe(inflate);
        stream = inflate;
      } else if (encoding === 'br') {
        const brotli = zlib.createBrotliDecompress();
        res.pipe(brotli);
        stream = brotli;
      }

      let body = '';
      let totalLength = 0;

      const finishStream = () => {
        done(null, {
          url: targetUrl,
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          contentType: res.headers['content-type'] || ''
        });
      };

      stream.on('data', (chunk) => {
        body += chunk.toString('utf8');
        totalLength += chunk.length;
        if (totalLength >= maxBytes) {
          try { res.destroy(); } catch {}
          try { stream.destroy(); } catch {}
          finishStream();
        }
      });

      stream.on('end', finishStream);
      stream.on('close', finishStream);
      stream.on('error', (err) => {
        if (body.length > 0) finishStream();
        else done(err);
      });
      res.on('error', (err) => {
        if (body.length > 0) finishStream();
        else done(err);
      });
    });

    activeReq = req;
    req.on('error', (err) => done(err));
    req.end();
  });
}

const IGNORED_EXTENSIONS = /\.(jpg|jpeg|png|gif|bmp|svg|webp|ico|css|js|woff|woff2|ttf|eot|mp4|webm|mp3|wav|ogg|pdf|zip|tar|gz|rar|7z|exe|dmg|apk|iso|docx|xlsx|pptx)$/i;

function extractLinks($, baseUrl) {
  const links = new Set();
  const baseParsed = new URL(baseUrl);
  const baseHost = normalizeHost(baseParsed.hostname);

  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
    try {
      const resolved = new URL(href, baseUrl);
      // Support matching domain with or without www
      if (normalizeHost(resolved.hostname) === baseHost) {
        resolved.hash = '';
        if (!IGNORED_EXTENSIONS.test(resolved.pathname)) {
          links.add(resolved.href);
        }
      }
    } catch { /* invalid URL */ }
  });

  return [...links];
}

function extractForms($, baseUrl) {
  const forms = [];
  $('form').each((_, form) => {
    const $form = $(form);
    const action = $form.attr('action') || '';
    const method = ($form.attr('method') || 'GET').toUpperCase();
    const inputs = [];

    $form.find('input, textarea, select').each((_, inp) => {
      const $inp = $(inp);
      inputs.push({
        name: $inp.attr('name') || '',
        type: $inp.attr('type') || 'text',
        value: $inp.attr('value') || '',
        placeholder: $inp.attr('placeholder') || '',
        required: $inp.attr('required') !== undefined,
        tag: inp.tagName.toLowerCase()
      });
    });

    let actionUrl;
    try {
      actionUrl = new URL(action, baseUrl).href;
    } catch {
      actionUrl = baseUrl;
    }

    forms.push({ action: actionUrl, method, inputs, page: baseUrl });
  });
  return forms;
}

function extractAssets($, baseUrl) {
  const assets = { scripts: [], styles: [], images: [], iframes: [] };

  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (src) {
      try { assets.scripts.push(new URL(src, baseUrl).href); } catch {}
    }
  });

  $('link[rel="stylesheet"][href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href) {
      try { assets.styles.push(new URL(href, baseUrl).href); } catch {}
    }
  });

  $('img[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (src) {
      try { assets.images.push(new URL(src, baseUrl).href); } catch {}
    }
  });

  $('iframe[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (src) {
      try { assets.iframes.push(new URL(src, baseUrl).href); } catch {}
    }
  });

  return assets;
}

async function runCrawler(targetUrl, options = {}, progressCallback = null) {
  const {
    maxPages = 25,
    maxDepth = 3,
    timeout = 8000,
    concurrency = 3
  } = options;

  const visited = new Set();
  const queue = [{ url: targetUrl, depth: 0 }];
  const pages = [];
  const allForms = [];
  const allAssets = { scripts: new Set(), styles: new Set(), images: new Set(), iframes: new Set() };
  const errors = [];

  const reportProgress = (currentUrl) => {
    if (progressCallback) {
      const progress = Math.min(100, Math.round((visited.size / maxPages) * 100));
      progressCallback({
        scanner: 'crawler',
        progress,
        message: `Crawling ${visited.size}/${maxPages} — ${(currentUrl || '').substring(0, 60)}...`
      });
    }
  };

  while (queue.length > 0 && visited.size < maxPages) {
    const batch = [];
    while (queue.length > 0 && (visited.size + batch.length) < maxPages && batch.length < concurrency) {
      const next = queue.shift();
      if (!visited.has(next.url) && next.depth <= maxDepth) {
        visited.add(next.url);
        batch.push(next);
      }
    }

    if (batch.length === 0) break;

    reportProgress(batch[0].url);

    const batchResults = await Promise.all(batch.map(async (item) => {
      try {
        const response = await fetchPage(item.url, { timeout });
        return { item, response };
      } catch (err) {
        return { item, error: err.message };
      }
    }));

    for (const resObj of batchResults) {
      const { item, response, error } = resObj;
      if (error) {
        errors.push({ url: item.url, error });
        continue;
      }

      if (!response || !response.contentType.includes('text/html')) continue;

      try {
        const $ = cheerio.load(response.body);
        const title = $('title').text().trim();

        pages.push({
          url: item.url,
          title,
          statusCode: response.statusCode,
          depth: item.depth,
          size: response.body.length,
          headers: response.headers,
          body: item.depth === 0 ? response.body : response.body.substring(0, 100000),
          bodySnippet: response.body.substring(0, 500)
        });

        // Extract forms
        const forms = extractForms($, item.url);
        allForms.push(...forms);

        // Extract assets
        const assets = extractAssets($, item.url);
        assets.scripts.forEach(s => allAssets.scripts.add(s));
        assets.styles.forEach(s => allAssets.styles.add(s));
        assets.images.forEach(s => allAssets.images.add(s));
        assets.iframes.forEach(s => allAssets.iframes.add(s));

        // Queue new internal links
        if (item.depth < maxDepth) {
          const links = extractLinks($, item.url);
          for (const link of links) {
            if (!visited.has(link) && !queue.some(q => q.url === link)) {
              queue.push({ url: link, depth: item.depth + 1 });
            }
          }
        }
      } catch (e) {
        errors.push({ url: item.url, error: e.message });
      }
    }
  }

  if (progressCallback) {
    progressCallback({ scanner: 'crawler', progress: 100, message: `Crawling complete (${pages.length} pages found)` });
  }

  return {
    name: 'Web Crawler',
    category: 'Reconnaissance',
    icon: '[Icon]',
    summary: `Crawled ${pages.length} pages — Found ${allForms.length} forms`,
    pages,
    forms: allForms,
    assets: {
      scripts: [...allAssets.scripts],
      styles: [...allAssets.styles],
      images: [...allAssets.images],
      iframes: [...allAssets.iframes]
    },
    errors,
    findings: []
  };
}

module.exports = { runCrawler, fetchPage };
