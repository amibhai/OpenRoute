// Minimal RFC 1928 SOCKS5 server for end-to-end tests (no-auth, CONNECT).
// Every request is logged with the *hostname the browser asked for*, which is
// how tests prove split-tunnel routing (only routed hosts appear) and remote
// DNS (the browser sent a name, not an IP).
//
//   const s = await startSocks5({ resolve: (host, port) => ({ host: "127.0.0.1", port: 8080 }) });
//   s.log  →  [{ host: "blocked.test", port: 8999, at }]

import net from "node:net";

const REPLY = (code) => Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]);

export function startSocks5({ port = 0, resolve = (host, p) => ({ host, port: p }), refuse = () => false } = {}) {
  const log = [];
  const sockets = new Set();
  const server = net.createServer((client) => {
    sockets.add(client);
    client.on("close", () => sockets.delete(client));
    client.on("error", () => {});
    let buf = Buffer.alloc(0);
    let stage = "greeting";
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === "greeting") {
        if (buf.length < 2) return;
        const n = buf[1];
        if (buf[0] !== 5) return client.destroy();
        if (buf.length < 2 + n) return;
        buf = buf.subarray(2 + n);
        client.write(Buffer.from([5, 0])); // "no authentication"
        stage = "request";
      }
      if (stage === "request") {
        if (buf.length < 5) return;
        const atyp = buf[3];
        let host, end;
        if (atyp === 1) { end = 8; if (buf.length < end + 2) return; host = [...buf.subarray(4, 8)].join("."); }
        else if (atyp === 3) { end = 5 + buf[4]; if (buf.length < end + 2) return; host = buf.subarray(5, end).toString("utf8"); }
        else if (atyp === 4) {
          end = 20; if (buf.length < end + 2) return;
          host = Array.from({ length: 8 }, (_, i) => buf.readUInt16BE(4 + i * 2).toString(16)).join(":");
        } else return client.end(REPLY(8));
        const dport = buf.readUInt16BE(end);
        const rest = buf.subarray(end + 2);
        client.off("data", onData);
        stage = "connected";
        if (buf[1] !== 1) return client.end(REPLY(7)); // only CONNECT
        log.push({ host, port: dport, at: Date.now() });
        if (refuse(host, dport)) return client.end(REPLY(2));
        const dest = resolve(host, dport);
        if (!dest) return client.end(REPLY(4));
        const upstream = net.connect(dest.port, dest.host, () => {
          client.write(REPLY(0));
          if (rest.length) upstream.write(rest);
          upstream.pipe(client);
          client.pipe(upstream);
        });
        sockets.add(upstream);
        upstream.on("close", () => sockets.delete(upstream));
        upstream.on("error", () => client.end(REPLY(5)));
        client.on("close", () => upstream.destroy());
      }
    };
    client.on("data", onData);
  });
  return new Promise((resolveStart) => server.listen(port, "127.0.0.1", () => resolveStart({
    port: server.address().port,
    log,
    hosts: () => [...new Set(log.map((l) => l.host))],
    close: () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); })
  })));
}
