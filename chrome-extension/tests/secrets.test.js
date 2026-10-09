/**
 * Guardrails: no secrets committed into the extension, and the manifest keeps
 * host permissions minimal.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === "node_modules" || name === ".git") continue;
      walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

const TEXT_EXTS = new Set([".js", ".mjs", ".cjs", ".json", ".html", ".css", ".md"]);

test("no Google Safe Browsing keys (or key-looking secrets) anywhere in the extension", () => {
  const files = walk(ROOT).filter((f) => TEXT_EXTS.has(f.slice(f.lastIndexOf("."))));
  assert.ok(files.length > 10, "expected to scan the whole extension");

  const patterns = [
    /AIza[0-9A-Za-z_-]{35}/, // Google API key format
    /GOOGLE_SAFE_BROWSING_API_KEY\s*[:=]\s*["'][^"']+["']/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  ];

  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const pattern of patterns) {
      assert.ok(
        !pattern.test(content),
        `possible secret in ${file} matching ${pattern}`
      );
    }
  }
});

test("manifest host permissions stay minimal (default backend only)", () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.host_permissions, [
    "http://127.0.0.1:8000/*",
    "http://localhost:8000/*",
  ]);
  assert.deepEqual(manifest.permissions, ["storage", "webNavigation"]);
  // Any other backend origin must be requested optionally at runtime.
  assert.deepEqual(manifest.optional_host_permissions, ["http://*/*", "https://*/*"]);
  // No broad required permissions, no remote code.
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
});

test("the content script only registers on http(s) pages", () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.content_scripts[0].matches, ["http://*/*", "https://*/*"]);
});
