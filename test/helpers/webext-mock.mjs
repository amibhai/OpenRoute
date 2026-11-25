// In-memory WebExtension API double for OpenRoute's unit tests.
//
// Models the subset of chrome.* / browser.* the extension touches, promise-
// based like MV3, in two flavors:
//   "chromium" — proxy.settings takes a Chromium PAC value; no proxy.onRequest
//   "firefox"  — proxy.onRequest (+ onError), proxy.settings that only accepts
//                Firefox-format values, dns.resolve, runtime.getBrowserInfo
//
// Everything the code under test does is observable through `mock.state`, and
// `mock` has helpers to drive events (navigations, alarms, worker restarts).

import { findProxy } from "./pac-vm.mjs";

const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const microtask = () => Promise.resolve();

export function createEvent() {
  const listeners = [];
  return {
    addListener(fn, ...extra) { listeners.push({ fn, extra }); },
    removeListener(fn) {
      const i = listeners.findIndex((l) => l.fn === fn);
      if (i >= 0) listeners.splice(i, 1);
    },
    hasListener(fn) { return listeners.some((l) => l.fn === fn); },
    hasListeners() { return listeners.length > 0; },
    get _listeners() { return listeners; },
    _clear() { listeners.length = 0; },
    // Calls every listener and waits for any promise they return.
    async _fire(...args) {
      const out = [];
      for (const l of [...listeners]) out.push(await l.fn(...args));
      return out;
    },
    _fireSync(...args) { return [...listeners].map((l) => l.fn(...args)); }
  };
}

function createStorageArea(areaName, globalOnChanged, events) {
  let data = {};
  const onChanged = createEvent();
  events.push(onChanged);
  const notify = (changes) => {
    if (!Object.keys(changes).length) return;
    // Chrome dispatches storage.onChanged asynchronously.
    queueMicrotask(() => {
      globalOnChanged._fireSync(clone(changes), areaName);
      onChanged._fireSync(clone(changes));
    });
  };
  return {
    _dump: () => clone(data),
    _load: (obj) => { data = clone(obj) || {}; },
    async get(keys) {
      await microtask();
      if (keys == null) return clone(data);
      if (typeof keys === "string") keys = [keys];
      const out = {};
      if (Array.isArray(keys)) {
        for (const k of keys) if (k in data) out[k] = clone(data[k]);
      } else {
        for (const [k, def] of Object.entries(keys)) out[k] = k in data ? clone(data[k]) : def;
      }
      return out;
    },
    async set(items) {
      await microtask();
      const changes = {};
      for (const [k, v] of Object.entries(items)) {
        if (v === undefined) continue;
        changes[k] = { oldValue: clone(data[k]), newValue: clone(v) };
        data[k] = clone(v);
      }
      notify(changes);
    },
    async remove(keys) {
      await microtask();
      const changes = {};
      for (const k of [].concat(keys)) {
        if (k in data) { changes[k] = { oldValue: clone(data[k]) }; delete data[k]; }
      }
      notify(changes);
    },
    async clear() {
      await microtask();
      const changes = {};
      for (const k of Object.keys(data)) changes[k] = { oldValue: clone(data[k]) };
      data = {};
      notify(changes);
    },
    async getBytesInUse() { return JSON.stringify(data).length; },
    async setAccessLevel() {},
    onChanged
  };
}

function createSetting(state, key, events, validate) {
  const onChange = createEvent();
  events.push(onChange);
  return {
    async get() {
      await microtask();
      const s = state.settings[key];
      return { value: clone(s.value), levelOfControl: s.levelOfControl };
    },
    async set({ value }) {
      await microtask();
      const s = state.settings[key];
      if (s.levelOfControl === "not_controllable") throw new Error("Can't modify regular settings: not controllable (policy)");
      if (validate) validate(value);
      s.history.push(clone(value));
      if (s.levelOfControl === "controlled_by_other_extensions") { s.ours = clone(value); return; }
      s.value = clone(value);
      s.levelOfControl = "controlled_by_this_extension";
      onChange._fireSync({ value: clone(value), levelOfControl: s.levelOfControl });
    },
    async clear() {
      await microtask();
      const s = state.settings[key];
      s.cleared++;
      if (s.levelOfControl === "controlled_by_this_extension") {
        s.value = clone(s.defaultValue);
        s.levelOfControl = "controllable_by_this_extension";
        onChange._fireSync({ value: clone(s.value), levelOfControl: s.levelOfControl });
      }
    },
    onChange
  };
}

const CHROMIUM_PROXY_MODES = ["direct", "auto_detect", "pac_script", "fixed_servers", "system"];
const FIREFOX_PROXY_TYPES = ["none", "autoDetect", "system", "manual", "autoConfig"];

export function createWebExtMock({ flavor = "chromium", extensionId = "openroute-test-id" } = {}) {
  const events = [];
  const ev = () => { const e = createEvent(); events.push(e); return e; };
  const isFirefox = flavor === "firefox";
  const origin = isFirefox ? `moz-extension://${extensionId}` : `chrome-extension://${extensionId}`;

  const state = {
    flavor,
    settings: {
      proxy: {
        value: isFirefox ? { proxyType: "system" } : { mode: "system" },
        defaultValue: isFirefox ? { proxyType: "system" } : { mode: "system" },
        levelOfControl: "controllable_by_this_extension",
        history: [], cleared: 0, ours: null
      },
      webRTCIPHandlingPolicy: {
        value: "default", defaultValue: "default",
        levelOfControl: "controllable_by_this_extension", history: [], cleared: 0, ours: null
      }
    },
    alarms: new Map(),
    alarmCreates: [],
    reloads: [],
    tabUpdates: [],
    createdTabs: [],
    removedTabs: [],
    tabs: new Map(),
    frames: new Map(),
    badges: new Map(),
    badgeColors: [],
    nativeHosts: new Map(),
    nativeConnects: 0,
    grantedOrigins: new Set(),
    grantedPermissions: new Set(),
    autoGrantPermissions: true,
    systemDns: new Map(),
    menus: [],
    netLog: [],
    lastError: undefined
  };

  const storageOnChanged = ev();
  const local = createStorageArea("local", storageOnChanged, events);
  const session = createStorageArea("session", storageOnChanged, events);

  const proxySettings = createSetting(state, "proxy", events, (value) => {
    if (isFirefox) {
      if (!value || !FIREFOX_PROXY_TYPES.includes(value.proxyType)) {
        throw new Error("proxy.settings.set: invalid proxyType (Firefox expects a proxyType, not a Chromium 'mode')");
      }
    } else if (!value || !CHROMIUM_PROXY_MODES.includes(value.mode)) {
      throw new Error("proxy.settings.set: invalid mode");
    } else if (value.mode === "pac_script" && !(value.pacScript && (value.pacScript.data || value.pacScript.url))) {
      throw new Error("proxy.settings.set: pac_script needs data or url");
    }
  });

  let nextTabId = 100;
  const runtimeOnMessage = ev();

  const api = {
    storage: { local, session, sync: createStorageArea("sync", storageOnChanged, events), onChanged: storageOnChanged },

    proxy: isFirefox
      ? { settings: proxySettings, onRequest: ev(), onError: ev() }
      : { settings: proxySettings, onProxyError: ev() },

    alarms: {
      async create(name, info = {}) {
        if (typeof name === "object") { info = name; name = ""; }
        await microtask();
        const delayMin = info.delayInMinutes ?? info.periodInMinutes ?? 0;
        const alarm = {
          name,
          scheduledTime: info.when ?? Date.now() + delayMin * 60000,
          ...(info.periodInMinutes ? { periodInMinutes: info.periodInMinutes } : {})
        };
        state.alarms.set(name, alarm);
        state.alarmCreates.push(clone(alarm));
      },
      async get(name = "") { await microtask(); return clone(state.alarms.get(name)); },
      async getAll() { await microtask(); return [...state.alarms.values()].map(clone); },
      async clear(name = "") { await microtask(); return state.alarms.delete(name); },
      async clearAll() { await microtask(); state.alarms.clear(); return true; },
      onAlarm: ev()
    },

    tabs: {
      async reload(tabId, props) { await microtask(); state.reloads.push({ tabId, props, at: Date.now() }); },
      async create(props = {}) {
        await microtask();
        const tab = { id: nextTabId++, url: props.url, active: props.active !== false };
        state.tabs.set(tab.id, tab);
        state.createdTabs.push(clone(props));
        return clone(tab);
      },
      async get(tabId) {
        await microtask();
        const t = state.tabs.get(tabId);
        if (!t) throw new Error(`No tab with id: ${tabId}.`);
        return clone(t);
      },
      async update(tabId, props = {}) {
        await microtask();
        state.tabUpdates.push({ tabId, ...clone(props), at: Date.now() });
        const t = state.tabs.get(tabId) || { id: tabId };
        Object.assign(t, props);
        state.tabs.set(tabId, t);
        return clone(t);
      },
      async query() { await microtask(); return [...state.tabs.values()].map(clone); },
      async remove(tabId) { await microtask(); state.removedTabs.push(tabId); state.tabs.delete(tabId); },
      async getCurrent() { await microtask(); return undefined; },
      onRemoved: ev(), onUpdated: ev(), onActivated: ev(), onCreated: ev()
    },

    webNavigation: {
      onErrorOccurred: ev(), onCompleted: ev(), onBeforeNavigate: ev(), onCommitted: ev(),
      async getFrame({ tabId, frameId }) { await microtask(); return clone(state.frames.get(`${tabId}:${frameId}`) || null); },
      async getAllFrames({ tabId }) {
        await microtask();
        return [...state.frames.entries()].filter(([k]) => k.startsWith(`${tabId}:`)).map(([, v]) => clone(v));
      }
    },

    webRequest: {
      onBeforeRequest: ev(), onHeadersReceived: ev(), onResponseStarted: ev(), onCompleted: ev(),
      onErrorOccurred: ev(), onBeforeRedirect: ev(), onAuthRequired: ev(), onSendHeaders: ev()
    },

    runtime: {
      id: extensionId,
      getURL: (p = "") => `${origin}/${String(p).replace(/^\//, "")}`,
      getManifest: () => ({ manifest_version: 3, version: "0.0.0-test", name: "OpenRoute (test)" }),
      async getPlatformInfo() { return { os: "win", arch: "x86-64" }; },
      onInstalled: ev(), onStartup: ev(), onMessage: runtimeOnMessage, onConnect: ev(),
      onSuspend: ev(), onUpdateAvailable: ev(),
      get lastError() { return state.lastError; },
      async sendMessage(message) {
        return dispatchMessage(clone(message), { id: extensionId, url: `${origin}/src/ui/popup.html`, origin });
      },
      connectNative(hostName) {
        state.nativeConnects++;
        return createNativePort(hostName);
      },
      async sendNativeMessage(hostName, message) {
        const host = state.nativeHosts.get(hostName);
        if (!host) throw new Error("Specified native messaging host not found.");
        return clone(await host(clone(message)));
      },
      async openOptionsPage() { state.createdTabs.push({ url: `${origin}/options` }); }
    },

    action: {
      async setBadgeText({ text, tabId }) { await microtask(); state.badges.set(tabId ?? "global", { ...(state.badges.get(tabId ?? "global") || {}), text }); },
      async getBadgeText({ tabId } = {}) { return state.badges.get(tabId ?? "global")?.text ?? ""; },
      async setBadgeBackgroundColor({ color, tabId }) { await microtask(); state.badgeColors.push({ color, tabId }); },
      async setTitle({ title, tabId }) { await microtask(); state.badges.set(tabId ?? "global", { ...(state.badges.get(tabId ?? "global") || {}), title }); },
      async setIcon() { await microtask(); },
      async setBadgeTextColor() { await microtask(); },
      onClicked: ev()
    },

    permissions: {
      async contains({ origins = [], permissions = [] } = {}) {
        await microtask();
        return origins.every((o) => state.grantedOrigins.has(o) || state.grantedOrigins.has("<all_urls>")) &&
               permissions.every((p) => state.grantedPermissions.has(p));
      },
      async request({ origins = [], permissions = [] } = {}) {
        await microtask();
        if (!state.autoGrantPermissions) return false;
        origins.forEach((o) => state.grantedOrigins.add(o));
        permissions.forEach((p) => state.grantedPermissions.add(p));
        return true;
      },
      async remove({ origins = [], permissions = [] } = {}) {
        await microtask();
        origins.forEach((o) => state.grantedOrigins.delete(o));
        permissions.forEach((p) => state.grantedPermissions.delete(p));
        return true;
      },
      async getAll() {
        await microtask();
        return { origins: [...state.grantedOrigins], permissions: [...state.grantedPermissions] };
      },
      onAdded: ev(), onRemoved: ev()
    },

    i18n: {
      getMessage: (name, subs) => {
        const s = [].concat(subs ?? []);
        return name ? `${name}${s.length ? `(${s.join(",")})` : ""}` : "";
      },
      getUILanguage: () => "en-US"
    },

    contextMenus: {
      create(props) { state.menus.push(clone(props)); return props.id; },
      async removeAll() { state.menus.length = 0; },
      async update() {},
      onClicked: ev()
    },

    commands: { onCommand: ev(), async getAll() { return []; } },

    idle: { onStateChanged: ev(), async queryState() { return "active"; } }
  };

  if (isFirefox) {
    api.runtime.getBrowserInfo = async () => ({ name: "Firefox", vendor: "Mozilla", version: "146.0", buildID: "0" });
    api.dns = {
      async resolve(hostname, flags = []) {
        await microtask();
        const r = state.systemDns.get(hostname);
        if (!r) throw new Error("NS_ERROR_UNKNOWN_HOST");
        return { addresses: [...r], canonicalName: hostname, isTRR: flags.includes("disable_trr") ? false : !!state.trrEnabled };
      }
    };
    api.menus = api.contextMenus;
  } else {
    api.privacy = { network: { webRTCIPHandlingPolicy: createSetting(state, "webRTCIPHandlingPolicy", events) } };
  }

  async function dispatchMessage(message, sender) {
    for (const { fn } of [...runtimeOnMessage._listeners]) {
      let responded = false;
      let resolveResponse;
      const viaCallback = new Promise((r) => { resolveResponse = r; });
      const sendResponse = (resp) => { if (!responded) { responded = true; resolveResponse(clone(resp)); } };
      const ret = fn(message, sender, sendResponse);
      if (ret === true) return viaCallback;                       // Chrome-style async response
      if (ret && typeof ret.then === "function") {                // Promise-style (Firefox, newer Chrome)
        const v = await ret;
        if (v !== undefined) return clone(v);
        if (responded) return viaCallback;
        continue;
      }
      if (responded) return viaCallback;
    }
    return undefined;
  }

  function createNativePort(hostName) {
    const onMessage = createEvent();
    const onDisconnect = createEvent();
    let connected = true;
    const port = {
      name: hostName,
      onMessage, onDisconnect,
      postMessage(msg) {
        if (!connected) throw new Error("Attempting to use a disconnected port object");
        const host = state.nativeHosts.get(hostName);
        Promise.resolve().then(async () => {
          if (!host) return;
          try {
            const resp = await host(clone(msg));
            if (connected && resp !== undefined) onMessage._fireSync(clone(resp));
          } catch (e) {
            if (!connected) return;
            connected = false;
            state.lastError = { message: String(e.message || e) };
            onDisconnect._fireSync(port);
            state.lastError = undefined;
          }
        });
      },
      disconnect() { connected = false; }
    };
    if (!state.nativeHosts.has(hostName)) {
      // Chromium: connectNative returns a port that disconnects with lastError.
      queueMicrotask(() => {
        if (!connected) return;
        connected = false;
        state.lastError = { message: "Specified native messaging host not found." };
        onDisconnect._fireSync(port);
        state.lastError = undefined;
      });
    }
    return port;
  }

  // ---- network (fetch) -----------------------------------------------------

  const routes = [];
  const net = {
    // handler(req) may return a Response, an object {status, headers, body,
    // json}, throw (→ network error), or never resolve (→ abort/timeout).
    route(match, handler) { routes.unshift({ match, handler }); return net; },
    clear() { routes.length = 0; },
    log: state.netLog
  };

  async function mockFetch(input, init = {}) {
    const url = typeof input === "string" ? input : input.url;
    const req = {
      url, method: (init.method || "GET").toUpperCase(),
      headers: new Headers(init.headers || {}), body: init.body, signal: init.signal, init
    };
    state.netLog.push({ url, method: req.method, at: Date.now() });
    const route = routes.find((r) =>
      typeof r.match === "function" ? r.match(req)
        : r.match instanceof RegExp ? r.match.test(url)
          : url.startsWith(r.match));
    if (!route) throw new TypeError(`Failed to fetch (no mock route for ${url})`);
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(new DOMException("The operation was aborted.", "AbortError"));
      if (init.signal) {
        if (init.signal.aborted) return onAbort();
        init.signal.addEventListener("abort", onAbort, { once: true });
      }
      Promise.resolve()
        .then(() => route.handler(req))
        .then((r) => {
          if (r instanceof Response) return r;
          if (r && typeof r === "object" && "status" in r) {
            const body = r.json !== undefined ? JSON.stringify(r.json) : r.body ?? null;
            return new Response(body, { status: r.status, headers: r.headers || {} });
          }
          return new Response(r == null ? null : String(r), { status: 200 });
        })
        .then(resolve, reject);
    });
  }

  // ---- helpers for tests ---------------------------------------------------

  const mock = {
    api,
    state,
    net,
    fetch: mockFetch,
    origin,

    install() {
      globalThis.chrome = api;
      if (isFirefox) globalThis.browser = api;
      else delete globalThis.browser;
      globalThis.fetch = mockFetch;
      return mock;
    },

    // Simulates the MV3 worker / event page being torn down and restarted:
    // all listeners vanish, persistent state (storage, alarms, settings) stays.
    restartWorker() {
      for (const e of events) e._clear();
      session._load({}); // storage.session survives a SW restart in Chrome; but not a browser restart
      return mock;
    },

    // Wait for queued microtasks/macrotasks to drain (real timers only).
    async settle(rounds = 5) {
      for (let i = 0; i < rounds; i++) await new Promise((r) => setImmediate(r));
    },

    setFrame(tabId, frameId, url, extra = {}) {
      state.frames.set(`${tabId}:${frameId}`, { frameId, parentFrameId: frameId === 0 ? -1 : 0, url, errorOccurred: false, ...extra });
      if (frameId === 0) state.tabs.set(tabId, { ...(state.tabs.get(tabId) || { id: tabId }), url });
    },

    async navigateFail({ tabId = 1, url, error, frameId = 0, ...extra }) {
      mock.setFrame(tabId, frameId, url, { errorOccurred: true });
      return api.webNavigation.onErrorOccurred._fire({
        tabId, frameId, url, error, timeStamp: Date.now(), processId: 1,
        ...(isFirefox ? {} : { frameType: frameId === 0 ? "outermost_frame" : "sub_frame", documentLifecycle: "active", parentFrameId: frameId === 0 ? -1 : 0 }),
        ...extra
      });
    },

    async navigateOk({ tabId = 1, url, frameId = 0, ...extra }) {
      mock.setFrame(tabId, frameId, url);
      return api.webNavigation.onCompleted._fire({
        tabId, frameId, url, timeStamp: Date.now(), processId: 1,
        ...(isFirefox ? {} : { frameType: frameId === 0 ? "outermost_frame" : "sub_frame", documentLifecycle: "active", parentFrameId: frameId === 0 ? -1 : 0 }),
        ...extra
      });
    },

    async fireAlarm(name) {
      const a = state.alarms.get(name) || { name, scheduledTime: Date.now() };
      return api.alarms.onAlarm._fire(clone(a));
    },

    async fireAllAlarms() {
      const out = [];
      for (const a of [...state.alarms.values()]) out.push(await api.alarms.onAlarm._fire(clone(a)));
      return out;
    },

    async sendMessage(message, sender) {
      return sender ? dispatchMessage(clone(message), sender) : api.runtime.sendMessage(message);
    },

    // What the browser would do with a request to `url` right now.
    //   Chromium → the PAC result string ("DIRECT", "SOCKS5 h:p; …"), honoring
    //              mandatory:false fallback semantics (broken PAC ⇒ DIRECT).
    //   Firefox  → the descriptor(s) returned by proxy.onRequest listeners.
    async resolveProxy(url) {
      if (isFirefox) {
        const listeners = api.proxy.onRequest._listeners;
        if (!listeners.length) return { type: "direct", reason: "no onRequest listener" };
        const requestInfo = { url, requestId: String(Math.random()), type: "main_frame", method: "GET", tabId: 1, frameId: 0, timeStamp: Date.now() };
        for (const { fn } of listeners) {
          const r = await fn(requestInfo);
          if (r) return r;
        }
        return { type: "direct" };
      }
      const v = state.settings.proxy.value;
      if (!v || v.mode !== "pac_script") return v?.mode === "fixed_servers" ? v : "DIRECT";
      try {
        return findProxy(v.pacScript.data, url);
      } catch (e) {
        if (v.pacScript.mandatory) return `ERR_MANDATORY_PROXY_CONFIGURATION_FAILED (${e.message})`;
        return "DIRECT";
      }
    },

    pacSource() {
      const v = state.settings.proxy.value;
      return v && v.mode === "pac_script" ? v.pacScript.data : null;
    },

    setNativeHost(name, handler) { state.nativeHosts.set(name, handler); },
    removeNativeHost(name) { state.nativeHosts.delete(name); }
  };

  return mock;
}
