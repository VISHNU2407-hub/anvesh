/**
 * URL Lens — Manifest V3 service worker (ES module).
 *
 * All logic lives in lib/controller.js (dependency-injected, unit-tested).
 * This file only wires real Chrome APIs + the real fetch.
 *
 * Protection surfaces handled here:
 *   - runtime.onMessage: clicks intercepted by the content script, popup
 *     scans, warning-page actions, settings.
 *   - webNavigation.onBeforeNavigate: best-effort analysis of navigations the
 *     content script cannot intercept (address bar, server redirects). Chrome
 *     MV3 cannot cancel these before they start — see README limitations.
 */

import { LinkShieldController } from "../lib/controller.js";

const sessionStore = {
  async get(key) {
    const result = await chrome.storage.session.get(key);
    return result[key];
  },
  async set(key, value) {
    await chrome.storage.session.set({ [key]: value });
  },
};

const syncStore = {
  async get(key) {
    const result = await chrome.storage.sync.get(key);
    return result[key];
  },
  async set(key, value) {
    await chrome.storage.sync.set({ [key]: value });
  },
};

const controller = new LinkShieldController({
  fetchImpl: (...args) => fetch(...args),
  extensionBase: chrome.runtime.getURL(""),
  session: sessionStore,
  sync: syncStore,
  tabs: {
    update: (tabId, props) => chrome.tabs.update(tabId, props),
    create: (props) => chrome.tabs.create(props),
  },
  windows: {
    create: (props) => chrome.windows.create(props),
  },
  action: {
    async setBadge({ tabId, text, color }) {
      const opts = tabId === null || tabId === undefined ? {} : { tabId };
      await chrome.action.setBadgeText({ ...opts, text: text || "" });
      if (text && color) {
        await chrome.action.setBadgeBackgroundColor({ ...opts, color });
      }
    },
  },
  log: (...args) => console.log("[URLLens]", ...args),
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Claim only our own message types; return undefined synchronously for
  // anything else so content-script listeners can still respond (e.g.
  // "ls:page-info" used by the popup).
  const isOurs =
    msg &&
    typeof msg.type === "string" &&
    (msg.type.startsWith("ls:") || msg.type.startsWith("warning:"));
  if (!isOurs) {
    return undefined;
  }
  controller
    .handleMessage(msg, sender)
    .then((response) => {
      if (response === undefined) return;
      sendResponse(response);
    })
    .catch((err) => {
      console.error("[URLLens] message handler error", err);
      sendResponse({ ok: false, error: String((err && err.message) || err) });
    });
  return true; // keep the message channel open for the async response
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  void controller.onBeforeNavigate(details);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  controller.onTabRemoved(tabId);
});

// Surface the "requires a backend URL with host access" state early so the
// options page can prompt for optional permission when needed.
chrome.runtime.onInstalled.addListener(() => {
  console.log("[URLLens] installed/updated");
});
