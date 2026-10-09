/**
 * Content-script link classification (UMD module shared with content.js).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

// lib/links.js is a UMD file: under Node's ESM loader it attaches itself to
// globalThis (exactly as it does inside a Chrome content script).
import "../lib/links.js";

const links = globalThis.LinkShieldLinks;
const classify = links.classifyTarget;

const PAGE = "https://site.example/articles/1";

test("cross-origin links are protected by default", () => {
  const r = classify({ href: "https://evil.example/login", pageHref: PAGE });
  assert.equal(r.protect, true);
  assert.equal(r.url, "https://evil.example/login");
});

test("same-origin links are skipped in cross-origin mode", () => {
  const r = classify({ href: "https://site.example/other", pageHref: PAGE });
  assert.deepEqual(r, { protect: false, reason: "same-origin" });
});

test("same-origin links ARE protected in 'all' mode", () => {
  const r = classify({
    href: "https://site.example/other",
    pageHref: PAGE,
    protectMode: "all",
  });
  assert.equal(r.protect, true);
  assert.equal(r.url, "https://site.example/other");
});

test("same-document anchors are never protected", () => {
  const hash = classify({ href: `${PAGE}#section-2`, pageHref: PAGE });
  assert.deepEqual(hash, { protect: false, reason: "same-document" });

  const exact = classify({ href: PAGE, pageHref: PAGE });
  assert.deepEqual(exact, { protect: false, reason: "same-document" });
});

test("root path and bare origin count as the same document", () => {
  const r = classify({ href: "https://site.example/", pageHref: "https://site.example" });
  assert.equal(r.protect, false);
});

test("non-http(s) schemes are skipped", () => {
  const page = PAGE;
  for (const href of [
    "mailto:a@b.example",
    "javascript:alert(1)",
    "data:text/html,hi",
    "tel:+1234",
    "ftp://files.example/x",
    "about:blank",
    "chrome://settings",
    "chrome-extension://abc/popup.html",
  ]) {
    const r = classify({ href, pageHref: page });
    assert.equal(r.protect, false, href);
    assert.equal(r.reason, "unsupported-scheme", href);
  }
});

test("unparsable or empty hrefs are skipped", () => {
  assert.equal(classify({ href: "", pageHref: PAGE }).protect, false);
  assert.equal(classify({ href: "not a url", pageHref: PAGE }).protect, false);
  assert.equal(classify({ href: undefined, pageHref: PAGE }).protect, false);
});

test("control characters in href are rejected", () => {
  const r = classify({ href: "https://evil.example/pa\nth", pageHref: PAGE });
  assert.equal(r.protect, false);
});

test("over-long href is rejected", () => {
  const r = classify({ href: `https://evil.example/${"a".repeat(3000)}`, pageHref: PAGE });
  assert.equal(r.protect, false);
  assert.equal(r.reason, "too-long");
});

test("fragment is stripped from the protected target", () => {
  const r = classify({ href: "https://evil.example/x#y", pageHref: PAGE });
  assert.equal(r.url, "https://evil.example/x");
});

test("different ports are different origins → protected", () => {
  const r = classify({
    href: "https://site.example:8443/x",
    pageHref: "https://site.example/y",
  });
  assert.equal(r.protect, true);
});

test("http vs https on same host is cross-origin → protected", () => {
  const r = classify({
    href: "http://site.example/x",
    pageHref: "https://site.example/y",
  });
  assert.equal(r.protect, true);
});
