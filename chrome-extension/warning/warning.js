/**
 * Warning interstitial page controller.
 *
 * - Loads the stored analysis case (?case=<id>) from chrome.storage.session.
 * - Renders strictly via textContent (see lib/warning-view.js).
 * - "Continue Anyway" is only created for the medium (warn) tier, and the
 *   background independently refuses block-tier continuations.
 * - "Go Back" uses history.go(-1); if this tab has no back history (the
 *   warning opened as a brand-new tab), fall back to about:blank.
 */

import { backAction, buildWarningViewModel, renderWarning } from "../lib/warning-view.js";

function caseIdFromQuery() {
  try {
    return new URLSearchParams(window.location.search).get("case") || "";
  } catch {
    return "";
  }
}

async function loadCase(caseId) {
  const response = await chrome.runtime.sendMessage({
    type: "warning:details",
    caseId,
  });
  if (!response || !response.ok) return null;
  return response.record;
}

function goBack() {
  const action = backAction(window.history.length);
  if (action.type === "history-back") {
    window.history.back();
  } else {
    window.location.href = action.url; // no history → about:blank
  }
}

async function main() {
  const caseId = caseIdFromQuery();
  const record = await loadCase(caseId);
  const model = buildWarningViewModel(record);
  renderWarning(document, model);

  document.title = `${model.tier === "block" ? "Blocked" : "Warning"} — URL Lens`;

  const actions = document.getElementById("actions");
  if (actions) {
    actions.addEventListener("click", async (event) => {
      const btn = event.target && event.target.closest ? event.target.closest("button") : null;
      if (!btn) return;
      const action = btn.dataset.action;

      if (action === "back") {
        goBack();
        return;
      }

      if (action === "continue") {
        // Front-end guard: this button is never rendered for block tier.
        if (!model.showContinue) return;
        btn.disabled = true;
        try {
          const res = await chrome.runtime.sendMessage({
            type: "warning:continue",
            caseId,
          });
          if (!res || !res.ok || !res.url) {
            btn.disabled = false;
            const note = document.getElementById("continue-error");
            if (note) {
              note.hidden = false;
              note.textContent = "Continuing was refused by URL Lens.";
            }
            return;
          }
          // location.replace (not assign): keeps the interstitial out of the
          // tab's back history, so Back from the destination returns straight
          // to the page the user came from.
          window.location.replace(res.url);
        } catch (err) {
          btn.disabled = false;
          const note = document.getElementById("continue-error");
          if (note) {
            note.hidden = false;
            note.textContent = "Continuing failed — the extension could not reach its background worker.";
          }
        }
      }
    });
  }
}

main().catch((err) => {
  const headline = document.getElementById("headline");
  if (headline) headline.textContent = "URL Lens";
  const subline = document.getElementById("subline");
  if (subline) {
    subline.textContent = "Could not load warning details. Nothing was opened.";
  }
  console.error(err);
});
