// Tiny DOM helpers for extension pages. Everything that came from storage or
// the network is inserted as text, never as HTML.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = String(v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "value") node[k] = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function setChildren(node, ...children) {
  node.replaceChildren(...children.flat(Infinity).filter((c) => c != null && c !== false));
}

// "in 5 minutes" / "3 hours ago", in the language the page is shown in.
export function relTime(ts, lang, now = Date.now()) {
  if (!ts) return "";
  const s = Math.round((ts - now) / 1000);
  const abs = Math.abs(s);
  const fmt = new Intl.RelativeTimeFormat(lang || undefined, { numeric: "auto" });
  if (abs < 60) return fmt.format(s, "second");
  if (abs < 3600) return fmt.format(Math.round(s / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(s / 3600), "hour");
  return fmt.format(Math.round(s / 86400), "day");
}

// Runs an async action from a button: disables it and shows a busy label
// while it runs, so a slow companion call can't be fired twice.
export async function busy(button, busyText, fn) {
  const old = button.textContent;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  if (busyText) button.textContent = busyText;
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.textContent = old;
  }
}

// Saves a JSON object as a file (no downloads permission needed).
export function downloadJson(name, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = el("a", { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
