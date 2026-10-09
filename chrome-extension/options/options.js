/**
 * Options page: backend URL, scan timeout, link protection mode.
 *
 * Host permissions: the default backend origin ships as a required host
 * permission. Any OTHER origin is covered by optional_host_permissions and is
 * requested here — only from the Save click (a user gesture), and only when
 * it is not already granted.
 */

const $ = (id) => document.getElementById(id);

let permissionKnown = { granted: false, origins: [] };

function originPattern(backendUrl) {
  try {
    const u = new URL(backendUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return `${u.origin}/*`;
  } catch {
    return null;
  }
}

async function checkPermission(backendUrl) {
  const pattern = originPattern(backendUrl);
  if (!pattern) return false;
  try {
    return await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    return false;
  }
}

async function load() {
  const res = await chrome.runtime.sendMessage({ type: "ls:settings:get" });
  const settings = res && res.ok ? res.settings : {};
  $("backend-url").value = settings.backendUrl || "http://127.0.0.1:8000";
  $("timeout-ms").value = settings.timeoutMs || 8000;
  $("protect-mode").value = settings.protectMode || "cross-origin";

  permissionKnown.granted = await checkPermission($("backend-url").value);
  $("permission-note").hidden = permissionKnown.granted;
}

function setStatus(text, isError) {
  const el = $("status");
  el.textContent = text;
  el.classList.toggle("error", Boolean(isError));
}

async function save(event) {
  event.preventDefault();
  setStatus("", false);

  const backendUrl = $("backend-url").value.trim();
  const timeoutMs = Number($("timeout-ms").value);
  const protectMode = $("protect-mode").value;

  const pattern = originPattern(backendUrl);
  if (!pattern) {
    setStatus("Enter a valid http(s) URL.", true);
    return;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) {
    setStatus("Timeout must be 1000–30000 ms.", true);
    return;
  }

  // Request optional host access FIRST inside the click gesture if needed.
  if (!permissionKnown.granted) {
    try {
      const granted = await chrome.permissions.request({ origins: [pattern] });
      permissionKnown.granted = granted;
      if (!granted) {
        setStatus("Saved, but host access was not granted — scans will fail.", true);
      }
    } catch (err) {
      setStatus(`Permission failed: ${String(err && err.message)}`, true);
    }
  }

  const res = await chrome.runtime.sendMessage({
    type: "ls:settings:set",
    settings: { backendUrl, timeoutMs, protectMode },
  });

  if (res && res.ok) {
    $("permission-note").hidden = permissionKnown.granted;
    if (permissionKnown.granted) setStatus("Saved ✓");
    // Clear the status after a moment unless it is an error.
    if (!document.getElementById("status").classList.contains("error")) {
      setTimeout(() => setStatus("", false), 2500);
    }
  } else {
    setStatus("Save failed — no background worker.", true);
  }
}

$("settings-form").addEventListener("submit", save);
$("backend-url").addEventListener("change", async () => {
  permissionKnown.granted = await checkPermission($("backend-url").value);
  $("permission-note").hidden = permissionKnown.granted;
});

load().catch((err) => setStatus(String(err && err.message ? err.message : err), true));
