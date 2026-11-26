// Page-side i18n: t() for strings built in code, localize() for the
// data-i18n markers in HTML. Pages carry no visible text of their own (the
// test suite checks), so adding a language is one messages.json file.

import { getApi } from "./messaging.js";
import { translate } from "../../shared/i18n.js";

const api = getApi();

export const t = (key, vars) => translate(api, key, vars);

// The language actually shown: the one the messages are in, which can
// differ from the browser's UI language when no translation exists yet.
export const locale = () => t("localeCode");

// <el data-i18n="key">                       → textContent
// <el data-i18n-attr="placeholder:key, …">  → attributes
export function localize(root = document) {
  for (const node of root.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const node of root.querySelectorAll("[data-i18n-attr]")) {
    for (const pair of node.dataset.i18nAttr.split(",")) {
      const [attr, key] = pair.split(":").map((s) => s.trim());
      if (attr && key) node.setAttribute(attr, t(key));
    }
  }
  if (root === document) {
    document.documentElement.lang = locale();
    document.documentElement.dir = t("localeDir") === "rtl" ? "rtl" : "ltr";
  }
}
