#!/usr/bin/env node
// Generates the public key that pins OpenRoute's *unpacked* Chromium extension
// ID, so "Load unpacked" from any folder on any machine yields the same ID and
// the native companion can pre-authorize it (no copy-pasting IDs).
//
//   node scripts/gen-key.mjs            # print a new key + its extension ID
//   node scripts/gen-key.mjs --id KEY   # print the ID a given manifest "key" yields
//
// Only the PUBLIC key goes into manifest.json. The private key is not needed to
// load an unpacked extension and is deliberately not written anywhere.

import { createHash, generateKeyPairSync } from "node:crypto";

export function extensionIdFromKey(base64Spki) {
  const der = Buffer.from(base64Spki, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode("a".charCodeAt(0) + parseInt(c, 16))).join("");
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` || process.argv[1]?.endsWith("gen-key.mjs")) {
  const i = process.argv.indexOf("--id");
  if (i !== -1) {
    console.log(extensionIdFromKey(process.argv[i + 1]));
  } else {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    console.log(JSON.stringify({ key: spki, id: extensionIdFromKey(spki) }, null, 2));
  }
}
