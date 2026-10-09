/**
 * Link classification for the CONTENT SCRIPT.
 *
 * This file is loaded twice by different runtimes:
 *   - Chrome content scripts load it as a CLASSIC script (Manifest V3 content
 *     scripts cannot be ES modules without bundling), so it attaches itself to
 *     `globalThis.LinkShieldLinks`.
 *   - The Node test suite imports it as CommonJS (`module.exports`).
 *
 * Keep it dependency-free and side-effect-light.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.LinkShieldLinks = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var MAX_URL_LENGTH = 2048;
  // eslint-disable-next-line no-control-regex
  var CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

  function tryParse(str) {
    if (typeof str !== "string" || str.length === 0 || str.length > MAX_URL_LENGTH) {
      return null;
    }
    if (CONTROL_CHARS.test(str)) return null;
    try {
      var u = new URL(str);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      if (!u.hostname) return null;
      return u;
    } catch (e) {
      return null;
    }
  }

  function stripFragment(url) {
    var i = url.indexOf("#");
    return i === -1 ? url : url.slice(0, i);
  }

  /**
   * Decide whether a click on `href` (resolved by the browser) from a page at
   * `pageHref` must be intercepted and analyzed before navigating.
   *
   * @param {object} opts
   * @param {string} opts.href        Fully-resolved link URL (a.href).
   * @param {string} opts.pageHref    location.href of the current document.
   * @param {"cross-origin"|"all"} [opts.protectMode]
   * @returns {{protect: boolean, url?: string, reason?: string}}
   *   When protect=false, `reason` explains why the click is left alone:
   *   "invalid-url" | "too-long" | "unsupported-scheme" | "same-document" |
   *   "same-origin".
   */
  function classifyTarget(opts) {
    var href = opts && opts.href;
    var pageHref = opts && opts.pageHref;
    var mode = (opts && opts.protectMode) || "cross-origin";

    var target = tryParse(href);
    if (!target) {
      if (typeof href === "string" && href.length > MAX_URL_LENGTH) {
        return { protect: false, reason: "too-long" };
      }
      // javascript:, mailto:, tel:, data:, about:, relative garbage, ...
      return { protect: false, reason: "unsupported-scheme" };
    }

    var targetUrl = target.toString();

    // Same-document navigation (in-page anchor): nothing to analyze.
    if (stripFragment(targetUrl) === stripFragment(typeof pageHref === "string" ? pageHref : "")) {
      return { protect: false, reason: "same-document" };
    }
    try {
      var page = new URL(pageHref);
      if (page.protocol === "http:" || page.protocol === "https:") {
        var sameDoc =
          page.origin === target.origin &&
          stripFragment(page.toString()) === stripFragment(targetUrl);
        if (sameDoc) return { protect: false, reason: "same-document" };
      }
    } catch (e) {
      /* unparsable page URL — fall through to origin comparison below */
    }

    if (mode === "cross-origin") {
      var sameOrigin = false;
      try {
        sameOrigin = new URL(pageHref).origin === target.origin;
      } catch (e) {
        sameOrigin = false;
      }
      if (sameOrigin) return { protect: false, reason: "same-origin" };
    }

    return { protect: true, url: stripFragment(targetUrl) };
  }

  return {
    classifyTarget: classifyTarget,
    MAX_URL_LENGTH: MAX_URL_LENGTH,
  };
});
