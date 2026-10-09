/**
 * LinkShield AI content script (classic script — Manifest V3 content scripts
 * are not ES modules; lib/links.js is loaded before this file and exposes
 * globalThis.LinkShieldLinks).
 *
 * Intercepts clicks on protected links BEFORE navigation starts:
 *   1. Classify synchronously (scheme / same-document / origin policy).
 *   2. preventDefault() + stopImmediatePropagation() in the CAPTURE phase on
 *      window (registered at document_start, so page handlers registered
 *      later cannot re-trigger the navigation either).
 *   3. Ask the background service worker to analyze the destination and let
 *      IT perform the eventual navigation (or swap to the warning page).
 *
 * The extension never fetches or opens the destination URL here — the URL is
 * only handed to the background, which submits it to the analysis API.
 */
(() => {
  "use strict";
  if (window.__linkshieldInjected) return;
  window.__linkshieldInjected = true;

  const links = globalThis.LinkShieldLinks;
  if (!links) return; // lib/links.js failed to load — fail silently open

  let settings = { protectMode: "cross-origin" };
  try {
    chrome.storage.sync.get("settings", (stored) => {
      if (stored && stored.settings && stored.settings.protectMode) {
        settings = { protectMode: stored.settings.protectMode };
      }
    });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "sync" && changes.settings && changes.settings.newValue) {
        settings = { protectMode: changes.settings.newValue.protectMode || "cross-origin" };
      }
    });
  } catch (e) {
    /* storage unavailable — keep defaults */
  }

  let chip = null;
  function showChip(text, isError) {
    try {
      if (!chip) {
        chip = document.createElement("div");
        chip.id = "linkshield-chip";
        chip.style.cssText = [
          "position:fixed",
          "z-index:2147483647",
          "top:16px",
          "right:16px",
          "padding:10px 14px",
          "border-radius:10px",
          "font:600 13px/1.4 system-ui,sans-serif",
          "color:#fff",
          "background:#0f172a",
          "box-shadow:0 8px 24px rgba(0,0,0,.35)",
          "pointer-events:none",
          "max-width:320px",
        ].join(";");
      }
      chip.textContent = text;
      chip.style.background = isError ? "#b91c1c" : "#0f172a";
      (document.body || document.documentElement).appendChild(chip);
    } catch (e) {
      /* cosmetic only */
    }
  }

  function hideChip() {
    try {
      if (chip && chip.parentNode) chip.parentNode.removeChild(chip);
    } catch (e) {
      /* cosmetic only */
    }
  }

  function findAnchor(event) {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [];
    const start = path.length ? path[0] : event.target;
    if (!start || typeof start.closest !== "function") return null;
    return start.closest("a[href]");
  }

  function intentFrom(event, anchor) {
    if (event.type === "auxclick" && event.button === 1) {
      return { mode: "tab", active: false }; // middle click → background tab
    }
    if (event.shiftKey) return { mode: "window", active: true };
    if (event.ctrlKey || event.metaKey) return { mode: "tab", active: true };
    const target = (anchor.getAttribute("target") || "").toLowerCase();
    if (target && target !== "_self") return { mode: "tab", active: true };
    return { mode: "current" };
  }

  function handler(event) {
    if (event.defaultPrevented) return;
    if (event.type === "click" && event.button !== 0) return;
    if (event.type === "auxclick" && event.button !== 1) return;

    const anchor = findAnchor(event);
    if (!anchor) return;
    if (anchor.hasAttribute("download")) return; // downloads are not navigations

    const classified = links.classifyTarget({
      href: anchor.href,
      pageHref: window.location.href,
      protectMode: settings.protectMode,
    });
    if (!classified.protect) return;

    // Block the navigation BEFORE anything else can trigger it.
    event.preventDefault();
    event.stopImmediatePropagation();

    const intent = intentFrom(event, anchor);
    showChip("LinkShield AI is checking this link…", false);

    let settled = false;
    const fail = (why) => {
      if (settled) return;
      settled = true;
      showChip(`LinkShield: ${why} — link opened without verification.`, true);
      setTimeout(hideChip, 5000);
      // Documented fail-open policy: an extension-side error must never
      // strand the user's click. The background only returns ok:false on
      // hard errors (scan failures themselves come back ok:true with an
      // explicit "failed" record, and are allowed by policy).
      try {
        window.location.assign(classified.url);
      } catch (e) {
        /* give up silently */
      }
    };

    try {
      chrome.runtime.sendMessage(
        { type: "ls:analyze-click", url: classified.url, intent },
        (response) => {
          if (chrome.runtime.lastError) {
            fail(chrome.runtime.lastError.message || "background unavailable");
            return;
          }
          if (!response || !response.ok) {
            fail("analysis failed");
            return;
          }
          settled = true;
          hideChip();
          // For warn/block tiers the background already swapped this tab to
          // the warning page; for allow it performed the navigation.
        }
      );
    } catch (e) {
      fail("extension error");
    }
  }

  window.addEventListener("click", handler, true);
  window.addEventListener("auxclick", handler, true);

  // The popup asks the active tab for its URL (avoids the "tabs" permission).
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "linkshield:page-info") {
      return {
        url: window.location.href,
        title: document.title || "",
        protected: true,
      };
    }
    return undefined;
  });
})();
