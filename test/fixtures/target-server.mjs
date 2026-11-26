// A tiny HTTP site for end-to-end tests: answers every request with the Host
// header it was asked for, so a test can tell which site actually loaded.

import http from "node:http";

// statusFor(host) lets a test censor the direct path (e.g. 451 for one host).
export function startTarget({ port = 0, statusFor = () => 200 } = {}) {
  const log = [];
  const server = http.createServer((req, res) => {
    log.push({ host: req.headers.host, url: req.url, at: Date.now() });
    if (req.url.startsWith("/generate_204")) { res.writeHead(204); res.end(); return; }
    if (req.url.startsWith("/success.txt")) { res.writeHead(200, { "content-type": "text/plain" }); res.end("success\n"); return; }
    if (req.url.startsWith("/hotspot-detect.html")) { res.writeHead(200, { "content-type": "text/html" }); res.end("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); return; }
    const status = statusFor(String(req.headers.host || "").split(":")[0]);
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(status === 200
      ? `<!doctype html><title>${req.headers.host}</title><h1 id="who">OK from ${req.headers.host}</h1>`
      : `<!doctype html><title>${status}</title><h1 id="who">Blocked (${status})</h1>`);
  });
  return new Promise((r) => server.listen(port, "127.0.0.1", () => r({
    port: server.address().port,
    log,
    close: () => new Promise((res) => { server.closeAllConnections?.(); server.close(() => res()); })
  })));
}
