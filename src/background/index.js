// Service-worker (Chromium) / event-page (Firefox) entry point.
//
// Listener registration happens synchronously on the first turn so the
// browser can wake us for navigation errors, alarms, messages and (on
// Firefox) proxy requests. Initialization (migration, routing restore) runs
// right after; every handler awaits it before touching state.

import { createBackground } from "./background.js";
import { getApi } from "./platform.js";

const bg = createBackground({ api: getApi() });
bg.registerListeners();
bg.ready();
