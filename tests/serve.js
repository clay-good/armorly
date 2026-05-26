// Tiny static server for Playwright fixtures.
// Intentionally dependency-free so the test harness only needs Playwright.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, 'fixtures');
const PORT = 8421;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

http
  .createServer((req, res) => {
    // Path traversal guard: resolve and verify it stays inside ROOT.
    const safePath = path.normalize(decodeURIComponent(req.url.split('?')[0]));
    const filePath = path.join(ROOT, safePath === '/' ? 'index.html' : safePath);
    if (!filePath.startsWith(ROOT)) {
      res.statusCode = 403;
      res.end('forbidden');
      return;
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.statusCode = 404;
        res.end('not found');
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
      res.end(data);
    });
  })
  .listen(PORT, '127.0.0.1', () => {
    console.log(`[fixtures] http://127.0.0.1:${PORT}/`);
  });
