// Message lookup for the background and the pages alike.
//
// Strings live in _locales/<lang>/messages.json. They use {name} placeholders
// that are filled here rather than the browser's $1 / $NAME$ machinery, so a
// message behaves the same in Chromium, Firefox and the test mock, and a
// translator sees one simple syntax. A missing message falls back to its key
// (visible, never blank) — the test suite makes sure none are missing.

export function translate(api, key, vars) {
  let s;
  try {
    s = api?.i18n?.getMessage?.(key) || "";
  } catch {
    s = "";
  }
  if (!s) s = key;
  if (vars) {
    s = s.replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(vars, k) && vars[k] != null ? String(vars[k]) : m));
  }
  return s;
}
