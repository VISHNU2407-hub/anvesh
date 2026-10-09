/**
 * Warning-interstitial view model + renderer.
 *
 * buildWarningViewModel(caseRecord) is a pure function (unit-tested).
 * renderWarning(doc, model) writes ONLY via textContent — URL data and
 * finding text are never interpreted as HTML (the test DOM makes innerHTML
 * usage throw to enforce this).
 */

const TIER_BLOCK = "block";
const TIER_WARN = "warn";

const VERDICT_LABELS = {
  confirmed_malicious: "Confirmed malicious",
  suspicious: "Suspicious",
  unknown: "Unverified",
  verified_safe: "Verified safe",
};

const RISK_LABELS = {
  unknown: "Unknown risk",
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function displayUrl(url) {
  const cleaned = String(url ?? "").replace(/[\u0000-\u001F\u007F]/g, "");
  return cleaned.length > 200 ? `${cleaned.slice(0, 199)}…` : cleaned;
}

/**
 * @param {object|null} c  Stored warning case (from chrome.storage.session).
 * @returns {object} view model for the interstitial.
 */
export function buildWarningViewModel(c) {
  if (!c) {
    return {
      missing: true,
      tier: TIER_WARN,
      headline: "LinkShield AI",
      subline: "This warning has expired. Nothing was opened.",
      hostname: "",
      url: "",
      score: null,
      scorePct: 0,
      riskLabel: "",
      verdictLabel: "",
      unverifiedBanner: null,
      reasons: [],
      findings: [],
      advice: "",
      buttons: [{ id: "back", label: "Go Back", kind: "primary" }],
      showContinue: false,
    };
  }

  const tier = c.tier === TIER_BLOCK ? TIER_BLOCK : TIER_WARN;
  const hostname = (() => {
    try {
      return new URL(c.url).hostname || "";
    } catch {
      return "";
    }
  })();

  const score = typeof c.score === "number" && Number.isFinite(c.score) ? Math.round(c.score) : null;
  const reasons = Array.isArray(c.reasons) ? c.reasons.map(String) : [];
  const findings = (Array.isArray(c.findings) ? c.findings : [])
    .slice()
    .sort((a, b) => {
      const ai = SEVERITY_ORDER.indexOf(a && a.severity);
      const bi = SEVERITY_ORDER.indexOf(b && b.severity);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    })
    .map((f) => ({
      title: String((f && f.title) || ""),
      severity: String((f && f.severity) || "info"),
      description: f && f.description ? String(f.description) : "",
      engine: f && f.engine ? String(f.engine) : "",
    }));

  const unverifiedBanner = c.unverified
    ? "This URL was NOT verified as safe. “No known threats found” is not proof of safety — verify before trusting it."
    : null;

  const buttons =
    tier === TIER_BLOCK
      ? [{ id: "back", label: "Go Back to Safety", kind: "primary" }]
      : [
          { id: "back", label: "Go Back", kind: "secondary" },
          { id: "continue", label: "Continue Anyway", kind: "danger" },
        ];

  return {
    missing: false,
    tier,
    headline: tier === TIER_BLOCK ? "Dangerous link blocked" : "Suspicious link warning",
    subline:
      tier === TIER_BLOCK
        ? "LinkShield AI found strong evidence that this destination is dangerous. Navigation was stopped."
        : "LinkShield AI flagged this destination as potentially unsafe.",
    hostname,
    url: displayUrl(c.url),
    score,
    scorePct: score === null ? 0 : Math.max(0, Math.min(100, score)),
    riskLabel: c.riskLevel && RISK_LABELS[c.riskLevel] ? RISK_LABELS[c.riskLevel] : "",
    verdictLabel:
      c.verdict && VERDICT_LABELS[c.verdict] ? VERDICT_LABELS[c.verdict] : "",
    reputationLabel:
      c.reputationStatus === "threat_detected"
        ? "Known threat match"
        : c.reputationStatus === "no_known_threat"
          ? "No known threat (unverified)"
          : c.reputationStatus === "unavailable"
            ? "Reputation check unavailable"
            : "",
    unverifiedBanner,
    reasons,
    findings,
    advice: c.advice ? String(c.advice) : "",
    buttons,
    showContinue: tier === TIER_WARN, // NEVER true for the block tier
  };
}

/**
 * Decide how the interstitial's "Go Back" action should behave.
 * The original page is normally still in this tab's history because the
 * navigation was intercepted before it committed; brand-new tabs (the
 * warning opened for a ctrl/middle click) have no history to go back to.
 *
 * @param {number} historyLength window.history.length of the warning tab
 * @returns {{type: "history-back"} | {type: "navigate", url: string}}
 */
export function backAction(historyLength) {
  if (typeof historyLength === "number" && historyLength > 1) {
    return { type: "history-back" };
  }
  return { type: "navigate", url: "about:blank" };
}

/** Minimal DOM helpers so the renderer works with both real and fake docs. */
function setText(doc, id, text) {
  const el = doc.getElementById(id);
  if (el) el.textContent = text;
}

function setVisible(doc, id, visible) {
  const el = doc.getElementById(id);
  if (el) el.hidden = !visible;
}

/**
 * Render a view model into a document-like object.
 * Uses textContent exclusively; appends created elements.
 */
export function renderWarning(doc, model) {
  setText(doc, "headline", model.headline);
  setText(doc, "subline", model.subline);
  setText(doc, "hostname", model.hostname || "");
  setText(doc, "url", model.url || "");

  // Score block
  const scoreWrap = doc.getElementById("score-block");
  if (scoreWrap) scoreWrap.hidden = model.score === null;
  if (model.score !== null) {
    setText(doc, "score-label", `Risk score ${model.score}/100`);
    const fill = doc.getElementById("score-fill");
    if (fill) {
      fill.style.width = `${model.scorePct}%`;
      fill.className =
        model.score > 65 ? "fill high" : model.score >= 30 ? "fill medium" : "fill low";
    }
  }

  const chips = doc.getElementById("chips");
  if (chips) {
    chips.textContent = "";
    const labels = [model.riskLabel, model.verdictLabel, model.reputationLabel].filter(Boolean);
    for (const label of labels) {
      const chip = doc.createElement("span");
      chip.className = "chip";
      chip.textContent = label;
      chips.appendChild(chip);
    }
  }

  // Verification banner (always rendered when the case is unverified)
  setText(doc, "unverified-banner", model.unverifiedBanner || "");
  setVisible(doc, "unverified-banner", Boolean(model.unverifiedBanner));

  // Reasons
  const reasonsList = doc.getElementById("reasons");
  if (reasonsList) {
    reasonsList.textContent = "";
    for (const reason of model.reasons) {
      const li = doc.createElement("li");
      li.textContent = reason;
      reasonsList.appendChild(li);
    }
    setVisible(doc, "reasons-block", model.reasons.length > 0);
  }

  // Findings
  const findingsList = doc.getElementById("findings");
  if (findingsList) {
    findingsList.textContent = "";
    for (const f of model.findings) {
      const li = doc.createElement("li");
      li.className = `finding severity-${f.severity}`;
      const title = doc.createElement("span");
      title.className = "finding-title";
      title.textContent = `${f.title} (${f.severity})`;
      li.appendChild(title);
      if (f.description) {
        const desc = doc.createElement("span");
        desc.className = "finding-desc";
        desc.textContent = f.description;
        li.appendChild(desc);
      }
      if (f.engine) {
        const eng = doc.createElement("span");
        eng.className = "finding-engine";
        eng.textContent = `engine: ${f.engine}`;
        li.appendChild(eng);
      }
      findingsList.appendChild(li);
    }
    setVisible(doc, "findings-block", model.findings.length > 0);
  }

  setText(doc, "advice", model.advice || "");
  setVisible(doc, "advice-block", Boolean(model.advice));

  // Action buttons — the Continue button is created ONLY for warn tier.
  const actions = doc.getElementById("actions");
  if (actions) {
    actions.textContent = "";
    for (const b of model.buttons) {
      const btn = doc.createElement("button");
      btn.id = `btn-${b.id}`;
      btn.type = "button";
      btn.className = `btn ${b.kind}`;
      btn.textContent = b.label;
      btn.dataset.action = b.id;
      actions.appendChild(btn);
    }
  }
}
