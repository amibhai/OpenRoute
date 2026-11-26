/* global chrome, document, getComputedStyle, matchMedia -- audit() and the waitFor callbacks run inside the pages */
// The UI in a real browser: the popup and every dashboard section render
// without errors, are fully translated, give every control an accessible
// name, meet WCAG AA contrast in light and dark mode, don't overflow in RTL,
// and their main actions work — including routing the site in another tab
// from the popup, through a real SOCKS5 proxy.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startSocks5 } from "../fixtures/socks5-server.mjs";
import { startTarget } from "../fixtures/target-server.mjs";
import { launchWithExtension, waitFor } from "./helpers/chromium.mjs";

let target, socks, browser, ui;

before(async () => {
  target = await startTarget();
  socks = await startSocks5({ resolve: () => ({ host: "127.0.0.1", port: target.port }) });
  // allUrls: the popup reads the other tab's URL (a user grants this for
  // deep detection; activeTab covers it when the toolbar button is clicked).
  browser = await launchWithExtension({ hostRules: ["MAP shop.test 127.0.0.1"], allUrls: true });
  ui = `chrome-extension://${browser.extensionId}/src/ui/`;
  for (const t of (await browser.send("getState")).transports) await browser.send("removeTransport", { id: t.id });
  const add = await browser.send("addTransport", { transport: { id: "fixture", label: "Fixture proxy", scheme: "socks5", host: "127.0.0.1", port: socks.port } });
  assert.equal(add?.ok, true, JSON.stringify(add));
});

after(async () => {
  await browser?.close();
  await socks?.close?.();
  await target?.close();
});

// Runs inside the page. Returns a list of problems (empty = good).
function audit() {
  const problems = [];
  const shown = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  for (const el of document.querySelectorAll("[data-i18n]")) {
    const text = el.textContent.trim();
    if (!text || text === el.dataset.i18n) problems.push(`untranslated: ${el.dataset.i18n}`);
  }
  const nameOf = (el) => (el.getAttribute("aria-label") || [...(el.labels || [])].map((l) => l.textContent).join(" ") ||
    el.getAttribute("title") || el.textContent || "").trim();
  for (const el of document.querySelectorAll("button, a[href], input:not([type=hidden]):not([type=file]), select, textarea, [role=img]")) {
    if (!shown(el) && !el.matches("input[type=radio]")) continue;
    if (el.matches("[role=img]") ? !el.getAttribute("aria-label") : !nameOf(el)) problems.push(`no accessible name: ${el.outerHTML.slice(0, 90)}`);
  }
  for (const img of document.images) if (!img.hasAttribute("alt")) problems.push(`img without alt: ${img.src}`);

  // WCAG contrast of every piece of visible text against what's behind it.
  const parse = (c) => {
    const m = /rgba?\(([^)]+)\)/.exec(c);
    if (!m) return null;
    const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return { rgb: p.slice(0, 3), a: p.length > 3 ? p[3] : 1 };
  };
  const over = (top, bottom) => top.rgb.map((c, i) => c * top.a + bottom[i] * (1 - top.a));
  const backdrop = (el) => {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0) {
        layers.push(c);
        if (c.a >= 1) break;
      }
    }
    let rgb = matchMedia("(prefers-color-scheme: dark)").matches ? [0, 0, 0] : [255, 255, 255];
    for (const l of layers.reverse()) rgb = over(l, rgb);
    return rgb;
  };
  const lum = (rgb) => {
    const f = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2]);
  };
  for (const el of document.querySelectorAll("body *")) {
    if (!shown(el) || el.closest("[disabled], [aria-busy=true], .sr-only, .skip")) continue;
    if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
    const s = getComputedStyle(el);
    const bg = backdrop(el);
    const fgc = parse(s.color);
    const fg = over(fgc, bg);
    const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
    const ratio = (a + 0.05) / (b + 0.05);
    const size = parseFloat(s.fontSize);
    const large = size >= 24 || (Number(s.fontWeight) >= 700 && size >= 18.66);
    if (ratio < (large ? 3 : 4.5)) problems.push(`contrast ${ratio.toFixed(2)}: "${el.textContent.trim().slice(0, 40)}" (${s.color} on rgb(${bg.map(Math.round)}))`);
  }
  const root = document.documentElement;
  if (root.scrollWidth > root.clientWidth + 1) problems.push(`horizontal overflow: ${root.scrollWidth} > ${root.clientWidth}`);
  return problems;
}

async function openPage(file, { width = 1100, height = 900 } = {}) {
  const page = await browser.context.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.setViewportSize({ width, height });
  await page.goto(ui + file);
  return { page, errors };
}

async function auditBothSchemes(page, label) {
  const found = [];
  for (const colorScheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme });
    for (const p of await page.evaluate(audit)) found.push(`${label} ${colorScheme}: ${p}`);
  }
  await page.emulateMedia({ colorScheme: "light" });
  return found;
}

test("the popup is translated, accessible and AA-contrast in light, dark and RTL", async () => {
  const { page, errors } = await openPage("popup.html", { width: 380, height: 760 });
  await page.waitForFunction(() => document.querySelector("#tabHost")?.textContent.trim());
  const problems = await auditBothSchemes(page, "popup");
  await page.evaluate(() => { document.documentElement.dir = "rtl"; });
  problems.push(...(await auditBothSchemes(page, "popup rtl")));
  assert.deepEqual(problems, []);
  assert.deepEqual(errors, []);
  await page.close();
});

test("the popup knows the site in the current tab and routes it", async () => {
  const site = await browser.context.newPage();
  await site.goto(`http://shop.test:${target.port}/`);
  const { page, errors } = await openPage("popup.html", { width: 380, height: 760 });
  await page.waitForFunction(() => document.querySelector("#tabHost")?.textContent === "shop.test", null, { timeout: 15000 });
  const status = await page.textContent("#tabStatus");
  assert.match(status, /Direct/);

  await page.getByRole("button", { name: "Route this site" }).click();
  await waitFor(async () => (await browser.send("tabState", { url: `http://shop.test:${target.port}/` }))?.routed, { message: "site routed" });
  // The site's tab reloads onto the proxy, and its badge says so.
  await waitFor(() => socks.log.some((c) => String(c.host).startsWith("shop.test")), { message: "traffic through the proxy" });
  const tabId = await browser.control.evaluate(async () => (await chrome.tabs.query({ url: "*://shop.test/*" }))[0]?.id);
  await waitFor(async () => (await browser.control.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId)) === "✓", { message: "tab badge ✓" });
  await page.reload();
  await page.waitForFunction(() => /Fixture proxy/.test(document.querySelector("#tabDetail")?.textContent || ""), null, { timeout: 15000 });
  assert.deepEqual(errors, []);
  await page.close();
  await site.close();
});

test("every dashboard section renders clean, and its main actions work", async () => {
  const { page, errors } = await openPage("options.html#sites");
  await page.waitForFunction(() => document.querySelector("#version")?.textContent.trim());
  const problems = [];
  for (const section of ["sites", "transports", "dns", "rules", "settings", "diagnostics"]) {
    await page.click(`.side a[href="#${section}"]`);
    await page.waitForFunction((s) => !document.getElementById(s).hidden, section);
    assert.equal(await page.getAttribute(`.side a[href="#${section}"]`, "aria-current"), "page");
    problems.push(...(await auditBothSchemes(page, section)));
  }
  await page.setViewportSize({ width: 390, height: 900 }); // phone width: one column, no overflow
  problems.push(...(await auditBothSchemes(page, "diagnostics narrow")));
  await page.setViewportSize({ width: 1100, height: 900 });
  // Right-to-left: the layout mirrors and nothing spills off the page.
  await page.evaluate(() => { document.documentElement.dir = "rtl"; });
  for (const section of ["sites", "transports", "settings"]) {
    await page.click(`.side a[href="#${section}"]`);
    problems.push(...(await auditBothSchemes(page, `${section} rtl`)));
  }
  await page.evaluate(() => { document.documentElement.dir = "ltr"; });
  assert.deepEqual(problems, []);

  // Rules: add one, see it listed and stored.
  await page.click('.side a[href="#rules"]');
  await page.fill("#alwaysInput", "example.org");
  await page.click("#alwaysForm button[type=submit]");
  await page.waitForFunction(() => /example\.org/.test(document.querySelector("#alwaysList").textContent));
  assert.deepEqual((await browser.send("getState")).rules.always, ["example.org"]);

  // Settings: the mode switch is a real radio group.
  await page.click('.side a[href="#settings"]');
  await page.getByRole("radio", { name: "All sites" }).check();
  await waitFor(async () => (await browser.send("getState")).settings.mode === "full", { message: "mode saved" });
  await page.getByRole("radio", { name: "Smart" }).check();
  await waitFor(async () => (await browser.send("getState")).settings.mode === "smart", { message: "mode restored" });

  // Backup: a real download of a real backup.
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#exportBtn")]);
  const backup = JSON.parse(readFileSync(await download.path(), "utf8"));
  assert.equal(backup.format, "openroute-backup");
  assert.deepEqual(backup.rules.always, ["example.org"]);

  // Diagnostics: the timeline tells what happened, in words.
  await page.click('.side a[href="#diagnostics"]');
  await page.waitForFunction(() => document.querySelectorAll("#timeline li").length > 0);
  const first = await page.textContent("#timeline li");
  assert.ok(!/event[A-Z]/.test(first), `timeline shows a raw key: ${first}`);

  assert.deepEqual(errors, []);
  await page.close();
});
