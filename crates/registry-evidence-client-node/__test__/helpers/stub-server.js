'use strict';

const http = require('node:http');

/**
 * Start a loopback-only HTTP server for one test's stub Evidence deployment.
 *
 * `routes` maps `"METHOD /path"` to a handler `(req, res, body) => void`; a
 * request that matches no route gets a plain 404. Every request is recorded
 * in the returned `requests` array before its handler runs, so a test can
 * assert exactly how many requests reached the stub, not just what the
 * client returned.
 */
function startStubServer(routes) {
  const requests = [];
  // A Map, not the caller's object: the lookup key carries a request line the
  // test client controls, and a plain object would let one resolve to an
  // inherited `Object.prototype` member instead of a stub route.
  const table = new Map(Object.entries(routes));
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const handler = table.get(`${req.method} ${req.url}`);
      if (typeof handler !== 'function') {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('no stub route for this request');
        return;
      }
      handler(req, res, body);
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}/`,
        requests,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

module.exports = { startStubServer };
