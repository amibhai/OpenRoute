// Every string a user can see lives in _locales/en/messages.json, and the
// code and the messages agree: no missing keys, no unused ones, no page text
// outside the messages, and every {placeholder} a message needs is filled by
// every call that uses it (a forgotten one would show users a literal "{x}").

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import * as LABELS from "../../src/ui/labels.js";

const ROOT = new URL("../../", import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), "utf8");
const MESSAGES = JSON.parse(read("_locales/en/messages.json"));
const MANIFEST = JSON.parse(read("manifest.json"));
const HTML = readdirSync(new URL("src/ui/", ROOT)).filter((f) => f.endsWith(".html")).map((f) => [f, read(`src/ui/${f}`)]);
const JS = ["src/ui/popup.js", "src/ui/options.js", "src/ui/onboarding.js", "src/ui/shared/i18n.js", "src/background/background.js"]
  .map((f) => [f, read(f)]);
const placeholders = (s) => new Set([...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]));

// ---- tiny source scanners ----------------------------------------------------

function skipString(src, i) {
  const q = src[i];
  for (i++; i < src.length; i++) {
    if (src[i] === "\\") i++;
    else if (src[i] === q) return i;
  }
  return i;
}

// Top-level property names of the object literal starting at src[start] === "{".
function objectKeys(src, start) {
  const keys = new Set();
  let depth = 0;
  let token = "";
  let expectKey = true;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      i = skipString(src, i);
      continue;
    }
    if ("{([".includes(c)) {
      depth++;
      continue;
    }
    if ("})]".includes(c)) {
      depth--;
      if (depth === 0) {
        if (expectKey && token) keys.add(token); // trailing shorthand
        break;
      }
      continue;
    }
    if (depth !== 1) continue;
    if (expectKey) {
      if (/[\w$]/.test(c)) token += c;
      else if (c === ":" || c === ",") {
        if (token) keys.add(token);
        token = "";
        if (c === ":") expectKey = false;
      }
    } else if (c === ",") {
      expectKey = true;
      token = "";
    }
  }
  return keys;
}

// Every t("key") / t("key", {…}) call: vars is null (no argument), a Set of
// property names, or "dynamic" (a variable we can't see into).
function tCalls(src) {
  const out = [];
  const re = /\bt\(\s*"([A-Za-z0-9_]+)"\s*(,)?/g;
  for (let m; (m = re.exec(src));) {
    let vars = null;
    if (m[2]) {
      let i = re.lastIndex;
      while (/\s/.test(src[i])) i++;
      vars = src[i] === "{" ? objectKeys(src, i) : "dynamic";
    }
    out.push({ key: m[1], vars });
  }
  return out;
}

function htmlKeys(html) {
  const keys = [...html.matchAll(/data-i18n="([^"]+)"/g)].map((m) => m[1]);
  for (const m of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of m[1].split(",")) keys.push(pair.split(":")[1].trim());
  }
  return keys;
}

// Message keys held in labels.js (tones like "good" and mode ids aren't keys).
function labelKeys() {
  const keys = new Set();
  const walk = (v) => {
    if (typeof v === "string") {
      if (Object.prototype.hasOwnProperty.call(MESSAGES, v)) keys.add(v);
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object" && !(v instanceof Set)) Object.values(v).forEach(walk);
  };
  for (const [name, v] of Object.entries(LABELS)) if (name !== "RESOLVER_NAMES" && typeof v !== "function") walk(v);
  return keys;
}

const manifestKeys = () => [...JSON.stringify(MANIFEST).matchAll(/__MSG_(\w+)__/g)].map((m) => m[1]);

// ---- tests ------------------------------------------------------------------

test("messages.json is well-formed for every browser", () => {
  for (const [key, entry] of Object.entries(MESSAGES)) {
    assert.match(key, /^[A-Za-z0-9_@]+$/, `bad key ${key}`);
    assert.equal(typeof entry.message, "string", key);
    assert.ok(entry.message.length > 0, `${key} is empty`);
    assert.equal(typeof entry.description, "string", `${key} needs a description (it may be empty)`);
    // "$" starts the browsers' own placeholder syntax; messages use {name}.
    assert.ok(!entry.message.includes("$"), `${key} contains "$"`);
  }
  assert.ok(MESSAGES.extName.message.length <= 75, "Chrome caps the name at 75 characters");
  assert.ok(MESSAGES.extDescription.message.length <= 132, "Chrome caps the description at 132 characters");
  assert.match(MESSAGES.localeDir.message, /^(ltr|rtl)$/);
});

test("every key the code, pages, labels and manifest use exists", () => {
  const missing = [];
  for (const [file, html] of HTML) for (const k of htmlKeys(html)) if (!MESSAGES[k]) missing.push(`${file}: ${k}`);
  for (const [file, src] of JS) for (const { key } of tCalls(src)) if (!MESSAGES[key]) missing.push(`${file}: ${key}`);
  for (const k of manifestKeys()) if (!MESSAGES[k]) missing.push(`manifest: ${k}`);
  // labels.js values that look like keys but aren't in the messages:
  const keyLike = (v) => typeof v === "string" && /^[a-z]+[A-Z][A-Za-z0-9]*$|^[a-z]+_[a-z0-9]+$/.test(v);
  const walk = (v, path) => {
    if (keyLike(v) && !MESSAGES[v]) missing.push(`labels.js ${path}: ${v}`);
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
    else if (v && typeof v === "object" && !(v instanceof Set)) for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
  };
  for (const [name, v] of Object.entries(LABELS)) if (typeof v !== "function") walk(v, name);
  assert.deepEqual(missing, []);
});

test("no message is unused", () => {
  const used = new Set([...labelKeys(), ...manifestKeys()]);
  for (const [, html] of HTML) htmlKeys(html).forEach((k) => used.add(k));
  for (const [, src] of JS) tCalls(src).forEach(({ key }) => used.add(key));
  assert.deepEqual(Object.keys(MESSAGES).filter((k) => !used.has(k)), []);
});

test("every placeholder a message needs is passed, and nothing else", () => {
  const problems = [];
  for (const [file, src] of JS) {
    for (const { key, vars } of tCalls(src)) {
      if (!MESSAGES[key] || vars === "dynamic") continue;
      const need = placeholders(MESSAGES[key].message);
      const got = vars || new Set();
      for (const p of need) if (!got.has(p)) problems.push(`${file}: t("${key}") doesn't pass {${p}}`);
      for (const p of got) if (!need.has(p)) problems.push(`${file}: t("${key}") passes {${p}} the message doesn't use`);
    }
  }
  // Keys only ever used without variables (pages, label maps) can't have placeholders…
  const bare = new Set(labelKeys());
  for (const [, html] of HTML) htmlKeys(html).forEach((k) => bare.add(k));
  // …except the timeline's, which eventText() fills from one shared object.
  const options = read("src/ui/options.js");
  const eventVars = objectKeys(options, options.indexOf("{", options.indexOf("return t(key, {")));
  for (const k of [...Object.values(LABELS.EVENT), ...Object.values(LABELS.EVENT_MANUAL)]) {
    bare.delete(k);
    for (const p of placeholders(MESSAGES[k].message)) if (!eventVars.has(p)) problems.push(`eventText() doesn't provide {${p}} for ${k}`);
  }
  for (const k of bare) if (placeholders(MESSAGES[k].message).size) problems.push(`${k} has placeholders but is used without variables`);
  assert.deepEqual(problems, []);
});

test("pages carry no text of their own", () => {
  const icon = /^[\s\d⚙✓•]*$/u; // glyphs and step numbers aren't words
  for (const [file, html] of HTML) {
    const body = html.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "").replace(/<!--[\s\S]*?-->/g, "");
    const text = [...body.matchAll(/>([^<]+)</g)].map((m) => m[1]).filter((s) => !icon.test(s));
    assert.deepEqual(text, [], `${file} has hard-coded text`);
    const attrs = [...body.matchAll(/\s(title|placeholder|aria-label)="([^"]*)"/g)].map((m) => `${m[1]}="${m[2]}"`);
    assert.deepEqual(attrs, [], `${file} has hard-coded attributes (use data-i18n-attr)`);
    assert.ok(!/<img(?![^>]*\balt=)/.test(body), `${file}: every image needs alt (empty when decorative)`);
  }
});
