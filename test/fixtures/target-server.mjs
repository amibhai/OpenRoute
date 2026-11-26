// A tiny HTTP site for end-to-end tests: answers every request with the Host
// header it was asked for, so a test can tell which site actually loaded.

import http from "node:http";

export function startTarget({ port = 0 } = {}) {
  const log = [];
  const server = http.createServer((req, res) => {
    log.push({ host: req.headers.host, url: req.url, at: Date.now() });
    if (req.url.startsWith("/generate_204")) { res.writeHead(204); res.end(); return; }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(`<!doctype html><title>${req.headers.host}</title><h1 id="who">OK from ${req.headers.host}</h1>`);
  });
  return new Promise((r) => server.listen(port, "127.0.0.1", () => r({
    port: server.address().port,
    log,
    close: () => new Promise((res) => { server.closeAllConnections?.(); server.close(() => res()); })
  })));
}
