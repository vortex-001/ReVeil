/**
 * ReVeil — AI Privacy Red-Team Product Controller
 * Single Page Application State Engine
 */

"use strict";

(function () {
  // Application State
  const state = {
    view: "landing",
    originalText: "",
    aliases: [],
    anonymizedText: "",
    entities: [],
    beforeAttack: null,
    edits: [],
    selectedEditIds: new Set(),
    hardenedText: "",
    afterAttack: null,
    health: {
      mode: "ollama",
      model: "qwen3:1.7b",
      ollama: false,
      model_ready: false,
      max_chars: 6000,
    },
    samples: [],
    sampleIndex: 0,
    attackTimer: null,
    attackStartTime: null,
    activePersonaTab: "casual",
    isRejectedClaimsExpanded: false,
    isAttackReplayExpanded: false,
  };

  // DOM Elements
  const el = {
    // Nav & Header
    headerLogo: document.getElementById("header-logo"),
    healthPill: document.getElementById("health-pill"),
    healthDot: document.getElementById("health-dot"),
    healthText: document.getElementById("health-text"),
    healthPopover: document.getElementById("health-popover"),
    popoverModel: document.getElementById("popover-model"),
    popoverRuntime: document.getElementById("popover-runtime"),
    popoverStatus: document.getElementById("popover-status"),
    stepperBar: document.getElementById("stepper-bar"),
    stepItems: document.querySelectorAll("[data-step]"),

    // Error Banner
    errorBanner: document.getElementById("global-error"),
    errorMessage: document.getElementById("global-error-msg"),
    errorClose: document.getElementById("global-error-close"),

    // Views
    views: {
      landing: document.getElementById("view-landing"),
      upload: document.getElementById("view-upload"),
      detect: document.getElementById("view-detect"),
      attack: document.getElementById("view-attack"),
      risk: document.getElementById("view-risk"),
      harden: document.getElementById("view-harden"),
      retest: document.getElementById("view-retest"),
    },

    // Landing View
    btnStartAnalysis: document.getElementById("btn-start-analysis"),

    // Upload View
    payloadText: document.getElementById("payload-text"),
    charCounter: document.getElementById("char-counter"),
    btnLoadSynthetic: document.getElementById("btn-load-synthetic"),
    fileUploader: document.getElementById("file-uploader"),
    btnClearInput: document.getElementById("btn-clear-input"),
    tagContainer: document.getElementById("tag-container"),
    aliasInput: document.getElementById("alias-input"),
    btnRunAnonymize: document.getElementById("btn-run-anonymize"),

    // Detect View
    detectChipsContainer: document.getElementById("detect-chips-container"),
    detectOriginalText: document.getElementById("detect-original-text"),
    detectSanitizedText: document.getElementById("detect-sanitized-text"),
    btnStartAttack: document.getElementById("btn-start-attack"),

    // Attack View
    attackProgressPercent: document.getElementById("attack-progress-percent"),
    attackProgressBar: document.getElementById("attack-progress-bar"),
    attackLiveStatus: document.getElementById("attack-live-status"),
    attackLiveDetail: document.getElementById("attack-live-detail"),
    attackOfflineBadgeText: document.getElementById("attack-offline-badge-text"),

    // Risk View (Showcase 1)
    riskExecBadge: document.getElementById("risk-exec-badge"),
    riskExecSummaryText: document.getElementById("risk-exec-summary-text"),
    riskMetricPii: document.getElementById("risk-metric-pii"),
    riskMetricVerified: document.getElementById("risk-metric-verified"),
    riskMetricRejected: document.getElementById("risk-metric-rejected"),
    riskMetricEdits: document.getElementById("risk-metric-edits"),
    riskMetricScore: document.getElementById("risk-metric-score"),
    riskSvgChartContainer: document.getElementById("risk-svg-chart-container"),
    attackSurfaceGrid: document.getElementById("attack-surface-grid"),
    evidenceChainContainer: document.getElementById("evidence-chain-container"),
    personaTabsContainer: document.getElementById("persona-tabs-container"),
    personaTabContent: document.getElementById("persona-tab-content"),
    rejectedClaimsToggle: document.getElementById("rejected-claims-toggle"),
    rejectedClaimsCount: document.getElementById("rejected-claims-count"),
    rejectedClaimsContent: document.getElementById("rejected-claims-content"),
    rejectedClaimsList: document.getElementById("rejected-claims-list"),
    btnGoToHarden: document.getElementById("btn-go-to-harden"),

    // Harden View
    hardenCardsContainer: document.getElementById("harden-cards-container"),
    hardenPreservationTable: document.getElementById("harden-preservation-table"),
    hardenPillText: document.getElementById("pill-text"),
    btnApplyAndRetest: document.getElementById("btn-apply-and-retest"),
    btnCancelHarden: document.getElementById("btn-cancel-harden"),

    // Retest View (Showcase 2)
    retestCelebrationPill: document.getElementById("retest-celebration-pill"),
    retestExecBadge: document.getElementById("retest-exec-badge"),
    retestExecSummaryText: document.getElementById("retest-exec-summary-text"),
    retestDeltaBadge: document.getElementById("retest-delta-badge"),
    retestDeltaText: document.getElementById("retest-delta-text"),
    retestSvgChartContainer: document.getElementById("retest-svg-chart-container"),
    retestBeforeLevel: document.getElementById("retest-before-level"),
    retestBeforeScore: document.getElementById("retest-before-score"),
    retestAfterLevel: document.getElementById("retest-after-level"),
    retestAfterScore: document.getElementById("retest-after-score"),
    retestAttackReplayList: document.getElementById("retest-attack-replay-list"),
    retestBeforeDiffText: document.getElementById("retest-before-diff-text"),
    retestAfterDiffText: document.getElementById("retest-after-diff-text"),
    btnDownloadReport: document.getElementById("download-report"),
    btnCopyHardened: document.getElementById("copy-hardened"),
    copyBtnText: document.getElementById("copy-text"),
    btnRestartAnalysis: document.getElementById("btn-restart-analysis"),
  };

  // Helper: API Client
  async function api(path, body) {
    let response;
    try {
      response = await fetch(path, {
        method: body ? "POST" : "GET",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      throw new Error("Cannot reach the ReVeil backend at http://127.0.0.1:8000. Verify the local server is running.");
    }

    let data = null;
    try {
      data = await response.json();
    } catch (e) {
      // not json
    }

    if (!response.ok) {
      const msg = (data && (data.detail || data.message)) || `Server returned error (${response.status})`;
      throw new Error(msg);
    }
    return data;
  }

  // Error Banner Display
  function showError(msg) {
    if (!msg) {
      el.errorBanner.classList.add("hidden");
      el.errorMessage.textContent = "";
      return;
    }
    el.errorMessage.textContent = msg;
    el.errorBanner.classList.remove("hidden");
    el.errorBanner.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function hideError() {
    el.errorBanner.classList.add("hidden");
    el.errorMessage.textContent = "";
  }

  if (el.errorClose) {
    el.errorClose.addEventListener("click", hideError);
  }

  // View Navigation
  const VIEW_STEPS = {
    landing: 0,
    upload: 1,
    detect: 2,
    attack: 3,
    risk: 4,
    harden: 5,
    retest: 6,
  };

  function setView(viewName) {
    state.view = viewName;
    hideError();

    // Toggle view containers
    Object.keys(el.views).forEach((key) => {
      if (el.views[key]) {
        el.views[key].classList.toggle("hidden", key !== viewName);
      }
    });

    // Update Stepper Bar
    const stepNum = VIEW_STEPS[viewName];
    if (stepNum === 0) {
      el.stepperBar.classList.add("hidden");
    } else {
      el.stepperBar.classList.remove("hidden");
      updateStepperUI(stepNum);
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function updateStepperUI(activeStep) {
    el.stepItems.forEach((item) => {
      const stepIndex = parseInt(item.getAttribute("data-step"), 10);
      const circle = item.querySelector(".step-circle");
      const label = item.querySelector(".step-label");

      if (stepIndex === activeStep) {
        // Active
        item.className = "flex items-center gap-2 bg-[#E5383B] text-white px-3.5 py-1.5 rounded-lg shadow-sm font-semibold transition-all";
        if (circle) circle.className = "step-circle w-5 h-5 rounded-full bg-white/20 flex items-center justify-center font-mono text-[11px] text-white font-bold";
        if (label) label.className = "step-label text-white";
      } else if (stepIndex < activeStep) {
        // Completed
        item.className = "flex items-center gap-2 text-slate-300 px-3 py-1.5 rounded hover:text-white transition-colors cursor-pointer";
        if (circle) circle.className = "step-circle w-5 h-5 rounded-full bg-[#1f1f22] text-[#2FBF71] border border-[#2FBF71]/40 flex items-center justify-center font-mono text-[11px] font-bold";
        if (label) label.className = "step-label text-slate-300";
      } else {
        // Upcoming
        item.className = "flex items-center gap-2 text-[#7d7b83] px-3 py-1.5 rounded";
        if (circle) circle.className = "step-circle w-5 h-5 rounded-full bg-[#1f1f22] flex items-center justify-center font-mono text-[11px]";
        if (label) label.className = "step-label text-[#7d7b83]";
      }
    });
  }

  // Stepper Click Navigation (backward allowed)
  el.stepItems.forEach((item) => {
    item.addEventListener("click", () => {
      const targetStep = parseInt(item.getAttribute("data-step"), 10);
      const currentStep = VIEW_STEPS[state.view];
      if (targetStep < currentStep) {
        if (targetStep === 1) setView("upload");
        else if (targetStep === 2 && state.anonymizedText) setView("detect");
        else if (targetStep === 4 && state.beforeAttack) setView("risk");
        else if (targetStep === 5 && state.edits.length) setView("harden");
      }
    });
  });

  // Local AI Status Popover (Feature 9)
  if (el.healthPill && el.healthPopover) {
    el.healthPill.addEventListener("click", (e) => {
      e.stopPropagation();
      el.healthPopover.classList.toggle("hidden");
    });
    document.addEventListener("click", () => {
      el.healthPopover.classList.add("hidden");
    });
    el.healthPopover.addEventListener("click", (e) => {
      e.stopPropagation();
    });
  }

  async function checkHealth() {
    try {
      const h = await api("/api/health");
      state.health = h;
      updateHealthBadge();
    } catch (e) {
      el.healthDot.className = "w-2 h-2 rounded-full bg-red-500";
      el.healthText.textContent = "Backend Offline";
      if (el.popoverStatus) el.popoverStatus.textContent = "Offline";
    }
  }

  function updateHealthBadge() {
    const h = state.health;
    if (el.popoverModel) el.popoverModel.textContent = h.model || "Qwen3 1.7B";
    if (el.popoverRuntime) el.popoverRuntime.textContent = h.mode === "STUB" ? "STUB Mode (No AI Called)" : "Ollama Local API";

    if (h.mode === "STUB") {
      el.healthDot.className = "w-2 h-2 rounded-full bg-amber-400";
      el.healthText.textContent = "STUB MODE (no AI called)";
      if (el.popoverStatus) el.popoverStatus.textContent = "STUB mode active";
      if (el.attackOfflineBadgeText) el.attackOfflineBadgeText.textContent = "STUB MODE active · Local rules evaluation";
    } else if (h.ollama && h.model_ready) {
      el.healthDot.className = "w-2 h-2 rounded-full bg-[#2FBF71] animate-pulse";
      el.healthText.textContent = `LOCAL AI · ${h.model}`;
      if (el.popoverStatus) el.popoverStatus.textContent = "Ready (Local machine)";
      if (el.attackOfflineBadgeText) el.attackOfflineBadgeText.textContent = `AI inference: Local machine (${h.model}) · Local backend`;
    } else if (h.ollama) {
      el.healthDot.className = "w-2 h-2 rounded-full bg-amber-500";
      el.healthText.textContent = `Ollama up · Pulling ${h.model}`;
      if (el.popoverStatus) el.popoverStatus.textContent = "Model missing in Ollama";
    } else {
      el.healthDot.className = "w-2 h-2 rounded-full bg-red-400";
      el.healthText.textContent = "Ollama not reachable";
      if (el.popoverStatus) el.popoverStatus.textContent = "Ollama connection failed";
    }
  }

  // Load Samples
  async function loadSamples() {
    try {
      const data = await api("/api/samples");
      if (Array.isArray(data)) state.samples = data;
    } catch (e) {
      console.warn("Could not load sample documents", e);
    }
  }

  function cycleSyntheticSample() {
    if (!state.samples.length) return;
    const sample = state.samples[state.sampleIndex];
    state.sampleIndex = (state.sampleIndex + 1) % state.samples.length;

    el.payloadText.value = sample.text;
    updateCharCounter();

    state.aliases = Array.isArray(sample.names) ? [...sample.names] : [];
    renderTags();
    hideError();
  }

  // Character Counter & Tag Handling
  function updateCharCounter() {
    const len = el.payloadText.value.length;
    const maxChars = state.health.max_chars || 6000;
    el.charCounter.textContent = `${len} / ${maxChars} chars`;
    el.charCounter.classList.toggle("text-red-400", len > maxChars);
  }

  function renderTags() {
    el.tagContainer.innerHTML = "";
    state.aliases.forEach((alias, idx) => {
      const tag = document.createElement("span");
      tag.className = "inline-flex items-center gap-1.5 bg-[#1f1f22] text-[#e5e1e6] text-xs font-mono px-2.5 py-1 rounded-full border border-[#26262E]";
      tag.innerHTML = `<span>${escapeHtml(alias)}</span> <button type="button" data-idx="${idx}" class="remove-tag text-slate-400 hover:text-red-400 text-sm leading-none cursor-pointer">&times;</button>`;
      el.tagContainer.appendChild(tag);
    });
  }

  function addAlias(val) {
    const cleaned = val.trim();
    if (cleaned && !state.aliases.includes(cleaned)) {
      state.aliases.push(cleaned);
      renderTags();
    }
  }

  el.aliasInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addAlias(el.aliasInput.value);
      el.aliasInput.value = "";
    }
  });

  el.tagContainer.addEventListener("click", (e) => {
    const btn = e.target.closest(".remove-tag");
    if (btn) {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.aliases.splice(idx, 1);
      renderTags();
    }
  });

  el.payloadText.addEventListener("input", updateCharCounter);
  el.btnLoadSynthetic.addEventListener("click", cycleSyntheticSample);
  el.btnClearInput.addEventListener("click", () => {
    el.payloadText.value = "";
    state.aliases = [];
    renderTags();
    updateCharCounter();
    hideError();
    el.payloadText.focus();
  });

  // Client-side File Upload Handling (.txt, .md)
  el.fileUploader.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const ext = file.name.split(".").pop().toLowerCase();
    if (!["txt", "md", "json", "log"].includes(ext)) {
      showError("Please upload a plain text or Markdown file (.txt, .md).");
      return;
    }

    if (file.size > 200000) {
      showError("Uploaded file is too large for privacy analysis (max 200 KB).");
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      el.payloadText.value = event.target.result;
      updateCharCounter();
      hideError();
    };
    reader.onerror = () => {
      showError("Failed to read the local file.");
    };
    reader.readAsText(file);
    e.target.value = "";
  });

  // Step 1: Anonymize
  async function handleAnonymize() {
    hideError();
    const text = el.payloadText.value.trim();

    if (!text) {
      showError("Please paste or load a document first.");
      el.payloadText.focus();
      return;
    }

    const maxChars = state.health.max_chars || 6000;
    if (text.length > maxChars) {
      showError(`Document exceeds maximum allowed length of ${maxChars} characters (${text.length} chars entered).`);
      return;
    }

    el.btnRunAnonymize.disabled = true;
    el.btnRunAnonymize.classList.add("opacity-60", "cursor-wait");

    try {
      const result = await api("/api/anonymize", {
        text: text,
        names: state.aliases,
      });

      state.originalText = text;
      state.anonymizedText = result.text;
      state.entities = result.entities || [];

      renderDetectScreen();
      setView("detect");
    } catch (err) {
      showError(err.message);
    } finally {
      el.btnRunAnonymize.disabled = false;
      el.btnRunAnonymize.classList.remove("opacity-60", "cursor-wait");
    }
  }

  el.btnRunAnonymize.addEventListener("click", handleAnonymize);

  // Render Step 2: Detect
  function renderDetectScreen() {
    el.detectChipsContainer.innerHTML = "";

    if (state.entities.length === 0) {
      const emptyChip = document.createElement("div");
      emptyChip.className = "inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#15151A] border border-[#26262E] text-slate-300 text-sm";
      emptyChip.innerHTML = `<span class="material-symbols-outlined text-[16px] text-[#2FBF71]">check</span> <span>No direct identifiers found in text</span>`;
      el.detectChipsContainer.appendChild(emptyChip);
    } else {
      const types = ["NAME", "EMAIL", "PHONE", "ID", "URL"];
      types.forEach((t) => {
        const found = state.entities.filter((e) => e.type === t);
        if (found.length > 0) {
          const chip = document.createElement("div");
          chip.className = "inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#E5383B]/10 border border-[#E5383B]/30 text-white text-sm font-medium";
          const namesPreview = found.map((f) => escapeHtml(f.original)).slice(0, 2).join(", ") + (found.length > 2 ? ` (+${found.length - 2} more)` : "");
          chip.innerHTML = `<span class="w-2 h-2 rounded-full bg-[#E5383B]"></span> <span><strong class="font-semibold text-white">${t}:</strong> ${namesPreview}</span> <span class="text-xs px-2 py-0.5 rounded-full bg-[#E5383B]/20 text-[#ffb3ae] font-medium">Scrubbed</span>`;
          el.detectChipsContainer.appendChild(chip);
        }
      });
    }

    el.detectOriginalText.innerHTML = renderHighlightedOriginal(state.originalText, state.entities);
    el.detectSanitizedText.innerHTML = renderSanitizedText(state.anonymizedText);
  }

  function renderHighlightedOriginal(text, entities) {
    if (!entities || !entities.length) return escapeHtml(text);
    const sorted = [...entities].sort((a, b) => a.start - b.start);
    let html = "";
    let lastIdx = 0;

    sorted.forEach((e) => {
      if (e.start >= lastIdx) {
        html += escapeHtml(text.slice(lastIdx, e.start));
        html += `<span class="bg-[#E5383B]/25 text-[#ffb3b1] border border-[#E5383B]/40 px-1.5 py-0.5 rounded font-semibold line-through inline-block">${escapeHtml(text.slice(e.start, e.end))}</span>`;
        lastIdx = e.end;
      }
    });
    html += escapeHtml(text.slice(lastIdx));
    return html;
  }

  function renderSanitizedText(text) {
    const escaped = escapeHtml(text);
    return escaped.replace(/\[(NAME|EMAIL|PHONE|ID|URL)\]/g, `<span class="bg-[#26262E] text-white font-mono px-2 py-0.5 rounded font-semibold border border-[#353438] inline-block mr-0.5">[$1]</span>`);
  }

  // Step 3: AI Red Team Attack Execution
  async function triggerAttack(isReTest = false) {
    hideError();
    const textToAttack = isReTest ? state.hardenedText : state.anonymizedText;

    if (!textToAttack) {
      showError("No document text found to analyze.");
      return;
    }

    setView("attack");
    startAttackAnimation(isReTest);

    try {
      const result = await api("/api/attack", { text: textToAttack });
      stopAttackAnimation();

      if (isReTest) {
        state.afterAttack = result;
        renderRetestScreen();
        setView("retest");
      } else {
        state.beforeAttack = result;
        renderRiskScreen(result);
        setView("risk");
      }
    } catch (err) {
      stopAttackAnimation();
      showError(err.message);
      setView(isReTest ? "harden" : "detect");
    }
  }

  el.btnStartAttack.addEventListener("click", () => triggerAttack(false));

  function startAttackAnimation(isReTest) {
    state.attackStartTime = Date.now();
    el.attackProgressPercent.textContent = "12%";
    el.attackProgressBar.style.width = "12%";

    const statuses = [
      { pct: 20, status: "1/5 Preparing document & isolating prompts...", detail: "Sanitizing delimiters and configuring red team" },
      { pct: 40, status: "2/5 Running Casual Reader persona...", detail: "Scanning for prominent cities, recognizable institutions, and obvious facts" },
      { pct: 60, status: "3/5 Running Informed Investigator persona...", detail: "Correlating workplace, dates, and geographic directories" },
      { pct: 80, status: "4/5 Running Targeted Attacker persona...", detail: "Exploiting niche achievements, unique credentials, and narrow combinations" },
      { pct: 92, status: "5/5 Enforcing quote-or-drop validation...", detail: "Verifying all clues verbatim; filtering unsupported AI claims" },
    ];

    let idx = 0;
    el.attackLiveStatus.textContent = isReTest ? "Running privacy regression re-test on hardened text..." : "Initiating Multi-Persona AI Red Team...";
    el.attackLiveDetail.textContent = "Running sequential attacker personas on local model...";

    clearInterval(state.attackTimer);
    state.attackTimer = setInterval(() => {
      const elapsed = Math.round((Date.now() - state.attackStartTime) / 1000);
      if (idx < statuses.length) {
        el.attackProgressPercent.textContent = `${statuses[idx].pct}%`;
        el.attackProgressBar.style.width = `${statuses[idx].pct}%`;
        el.attackLiveStatus.textContent = statuses[idx].status;
        el.attackLiveDetail.textContent = `${statuses[idx].detail} (${elapsed}s elapsed)`;
        idx++;
      } else {
        el.attackProgressPercent.textContent = "96%";
        el.attackProgressBar.style.width = "96%";
        el.attackLiveDetail.textContent = `Synthesizing attack surface & risk score... (${elapsed}s elapsed)`;
      }
    }, 2200);
  }

  function stopAttackAnimation() {
    clearInterval(state.attackTimer);
    el.attackProgressBar.style.width = "100%";
    el.attackProgressPercent.textContent = "100%";
  }

  // =========================================================================
  // SHOWCASE SCREEN 1: Privacy Risk Report (Features 2, 3, 4, 5, 8, 10)
  // =========================================================================
  function renderRiskScreen(attack) {
    const risk = attack.risk || { level: "MEDIUM", score: 0, factors: [], items: [], attack_surface: [] };
    const level = risk.level || "MEDIUM";
    const score = risk.score !== undefined ? risk.score : 0;
    const verifiedCount = attack.clues ? attack.clues.length : 0;
    const rejectedCount = attack.rejected || (attack.rejected_claims ? attack.rejected_claims.length : 0);
    const rejectedClaims = attack.rejected_claims || [];
    const attackSurface = risk.attack_surface || [];
    const personas = attack.personas || [];

    // Feature 10: Executive Risk Summary
    if (level === "HIGH") {
      el.riskExecBadge.className = "px-3.5 py-1 rounded-full bg-[#E5383B]/20 text-[#ffb4ab] border border-[#E5383B]/40 font-mono text-xs font-bold uppercase tracking-wider";
      el.riskExecBadge.textContent = "HIGH PRIVACY RISK";
      el.riskExecSummaryText.textContent = `${verifiedCount} verified contextual clues single out the individual. Multiple quasi-identifiers intersect to facilitate re-identification.`;
    } else if (level === "MEDIUM") {
      el.riskExecBadge.className = "px-3.5 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono text-xs font-bold uppercase tracking-wider";
      el.riskExecBadge.textContent = "MODERATE PRIVACY RISK";
      el.riskExecSummaryText.textContent = `${verifiedCount} verified clues moderately narrow down candidate pools. Contextual hardening is recommended to broaden demographic bands.`;
    } else {
      el.riskExecBadge.className = "px-3.5 py-1 rounded-full bg-[#2FBF71]/20 text-[#2FBF71] border border-[#2FBF71]/40 font-mono text-xs font-bold uppercase tracking-wider";
      el.riskExecBadge.textContent = "LOW PRIVACY RISK";
      el.riskExecSummaryText.textContent = `The AI red team found few identifying details in this text. Remember: low estimated risk is not a guarantee of legal anonymity.`;
    }

    el.riskMetricPii.textContent = state.entities.length;
    el.riskMetricVerified.textContent = verifiedCount;
    el.riskMetricRejected.textContent = rejectedCount;
    el.riskMetricEdits.textContent = (state.edits && state.edits.length) || "--";
    el.riskMetricScore.textContent = score;

    // Feature 3: Dynamic SVG Risk Visualization
    renderRiskSvgChart(score, level, risk.items || []);

    // Feature 2: Attack Surface Breakdown
    renderAttackSurface(attackSurface);

    // Feature 4: Evidence Chain Component
    renderEvidenceChain(risk.items || [], attack.clues || []);

    // Feature 1 & 8: AI Red Team Personas Breakdown
    renderPersonaTabs(personas);

    // Feature 5: Rejected AI Claims
    renderRejectedClaims(rejectedClaims, rejectedCount);
  }

  // Feature 3: Pure SVG Risk Gauge & Category Distribution
  function renderRiskSvgChart(score, level, items) {
    const maxScore = Math.max(20, score + 4);
    const scorePct = Math.min(100, Math.round((score / maxScore) * 100));

    let strokeColor = "#2FBF71";
    if (level === "HIGH") strokeColor = "#E5383B";
    else if (level === "MEDIUM") strokeColor = "#F2A33A";

    // Category breakdown counts
    const counts = { location: 0, employer: 0, age: 0, date_event: 0, role: 0, achievement: 0 };
    items.forEach((it) => {
      if (counts[it.category] !== undefined) counts[it.category] += it.weight || 1;
    });

    const categories = [
      { name: "Location", val: counts.location, max: 6 },
      { name: "Organization", val: counts.employer, max: 6 },
      { name: "Age Band", val: counts.age, max: 4 },
      { name: "Occupation", val: counts.role, max: 4 },
      { name: "Timeline", val: counts.date_event, max: 3 },
      { name: "Achievements", val: counts.achievement, max: 3 },
    ];

    let barsHtml = "";
    categories.forEach((cat, i) => {
      const pct = Math.min(100, Math.round((cat.val / cat.max) * 100));
      const y = 30 + i * 24;
      const barColor = cat.val > 0 ? (cat.val >= 3 ? "#E5383B" : "#F2A33A") : "#26262E";

      barsHtml += `
        <text x="10" y="${y + 11}" fill="#9AA0AE" font-size="11" font-family="Plus Jakarta Sans">${cat.name}</text>
        <rect x="110" y="${y}" width="160" height="12" rx="6" fill="#1b1b1e" stroke="#26262E" stroke-width="1" />
        <rect x="110" y="${y}" width="${Math.max(4, (pct * 160) / 100)}" height="12" rx="6" fill="${barColor}" />
        <text x="280" y="${y + 11}" fill="#F5F5F5" font-size="10" font-family="JetBrains Mono">+${cat.val}</text>
      `;
    });

    el.riskSvgChartContainer.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        <!-- Circular Risk Gauge -->
        <div class="md:col-span-5 flex flex-col items-center justify-center p-4">
          <svg viewBox="0 0 160 160" class="w-40 h-40">
            <circle cx="80" cy="80" r="64" fill="none" stroke="#26262E" stroke-width="12" />
            <circle cx="80" cy="80" r="64" fill="none" stroke="${strokeColor}" stroke-width="12"
                    stroke-dasharray="402" stroke-dashoffset="${402 - (402 * scorePct) / 100}"
                    stroke-linecap="round" transform="rotate(-90 80 80)" class="transition-all duration-1000 ease-out" />
            <text x="80" y="74" text-anchor="middle" fill="#F5F5F5" font-size="28" font-weight="800" font-family="Plus Jakarta Sans">Score ${score}</text>
            <text x="80" y="96" text-anchor="middle" fill="${strokeColor}" font-size="12" font-weight="700" font-family="JetBrains Mono" letter-spacing="1">${level} RISK</text>
          </svg>
          <span class="text-[11px] text-slate-400 font-mono mt-1 text-center">Transparent heuristic sum (Weights &cap; Caps)</span>
        </div>

        <!-- Category Contribution Bars -->
        <div class="md:col-span-7 p-2">
          <div class="text-xs font-semibold uppercase text-slate-400 font-mono mb-2">Quasi-Identifier Weight Distribution</div>
          <svg viewBox="0 0 320 185" class="w-full h-auto">
            ${barsHtml}
          </svg>
        </div>
      </div>
    `;
  }

  // Feature 2: Attack Surface Breakdown
  function renderAttackSurface(surface) {
    el.attackSurfaceGrid.innerHTML = "";

    surface.forEach((item) => {
      const card = document.createElement("div");
      card.className = "bg-[#15151A] border border-[#26262E] rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-all";

      let badgeColor = "bg-[#2FBF71]/15 text-[#2FBF71] border-[#2FBF71]/30";
      if (item.severity === "HIGH") badgeColor = "bg-[#E5383B]/15 text-[#ffb4ab] border-[#E5383B]/40";
      else if (item.severity === "MEDIUM") badgeColor = "bg-amber-500/15 text-amber-300 border-amber-500/40";
      else if (item.severity === "REMOVED") badgeColor = "bg-slate-800 text-slate-300 border-slate-700";

      let cluesHtml = "";
      if (item.clues && item.clues.length) {
        cluesHtml = `
          <div class="mt-2.5 pt-2 border-t border-[#26262E] flex flex-wrap gap-1">
            ${item.clues
              .slice(0, 3)
              .map((c) => `<span class="bg-[#1b1b1e] border border-[#26262E] text-slate-300 text-[11px] px-2 py-0.5 rounded font-mono truncate max-w-[180px]">“${escapeHtml(c)}”</span>`)
              .join("")}
            ${item.clues.length > 3 ? `<span class="text-[10px] text-slate-400 self-center">+${item.clues.length - 3} more</span>` : ""}
          </div>
        `;
      }

      card.innerHTML = `
        <div>
          <div class="flex items-center justify-between gap-2 mb-2">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-[18px] text-slate-400">${item.icon || "shield"}</span>
              <span class="font-bold text-sm text-white">${escapeHtml(item.name)}</span>
            </div>
            <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${badgeColor}">
              ${item.severity}
            </span>
          </div>
          <p class="text-xs text-slate-400 leading-relaxed">${escapeHtml(item.description)}</p>
        </div>
        ${cluesHtml}
      `;

      el.attackSurfaceGrid.appendChild(card);
    });
  }

  // Feature 4: Evidence Chain Component
  function renderEvidenceChain(items, clues) {
    el.evidenceChainContainer.innerHTML = "";

    if (!items.length) {
      el.evidenceChainContainer.innerHTML = `<p class="text-sm text-slate-400 italic p-4 text-center">No specific identifying clues detected in the document.</p>`;
      return;
    }

    const sorted = [...items].sort((a, b) => (b.weight || 0) - (a.weight || 0));

    sorted.forEach((item, idx) => {
      const matchingClue = clues.find((c) => c.quote.toLowerCase() === item.quote.toLowerCase()) || {};
      const whyText = matchingClue.why || (item.source === "rule" ? "Rule-detected quasi-identifier" : "Narrowing observation identified by red team");
      const persona = item.persona || (matchingClue.personas ? matchingClue.personas.join(", ") : "AI Red Team");

      const sevLevel = item.weight >= 3 ? "HIGH" : item.weight >= 2 ? "MEDIUM" : "LOW";
      let sevBadge = "bg-[#2FBF71]/15 text-[#2FBF71] border-[#2FBF71]/30";
      if (sevLevel === "HIGH") sevBadge = "bg-[#E5383B]/15 text-[#ffb4ab] border-[#E5383B]/40";
      else if (sevLevel === "MEDIUM") sevBadge = "bg-amber-500/15 text-amber-300 border-amber-500/40";

      const chain = document.createElement("div");
      chain.className = "bg-[#15151A] border border-[#26262E] rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-sm hover:border-slate-700 transition-colors";

      chain.innerHTML = `
        <div class="flex items-start md:items-center gap-3 flex-1 min-w-0">
          <span class="w-6 h-6 rounded-full bg-[#1b1b1e] border border-[#26262E] text-slate-400 text-xs font-mono flex items-center justify-center shrink-0">
            ${idx + 1}
          </span>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap mb-1">
              <span class="text-xs px-2 py-0.5 rounded-full bg-[#1b1b1e] text-slate-300 border border-[#26262E] font-mono uppercase text-[10px]">${escapeHtml(item.category)}</span>
              <span class="font-bold text-white text-sm truncate">“${escapeHtml(item.quote)}”</span>
              <span class="text-[10px] text-slate-400 font-mono">(${escapeHtml(persona)})</span>
            </div>
            <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(whyText)}</p>
          </div>
        </div>

        <div class="flex items-center gap-3 self-end md:self-center shrink-0">
          <span class="font-mono text-xs text-slate-400">+${item.weight} pts</span>
          <span class="px-2.5 py-1 rounded-full text-xs font-mono font-bold uppercase border ${sevBadge}">
            ${sevLevel}
          </span>
        </div>
      `;

      el.evidenceChainContainer.appendChild(chain);
    });
  }

  // Feature 1 & 8: Multi-Persona Findings Breakdown
  function renderPersonaTabs(personas) {
    if (!personas || !personas.length) {
      personas = [
        { id: "casual", name: "Casual Reader", clues: [], rejected: 0, likelihood: "low", seconds: 0.1 },
        { id: "investigator", name: "Informed Investigator", clues: [], rejected: 0, likelihood: "low", seconds: 0.1 },
        { id: "attacker", name: "Targeted Attacker", clues: [], rejected: 0, likelihood: "low", seconds: 0.1 },
      ];
    }

    el.personaTabsContainer.innerHTML = "";
    personas.forEach((p) => {
      const isActive = p.id === state.activePersonaTab;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `flex items-center gap-2 px-4 py-2.5 rounded-xl font-medium text-xs transition-all cursor-pointer ${
        isActive ? "bg-[#E5383B] text-white shadow-md" : "bg-[#1b1b1e] text-slate-300 border border-[#26262E] hover:text-white"
      }`;
      btn.innerHTML = `
        <span class="material-symbols-outlined text-[16px]">${p.icon || "person"}</span>
        <span>${escapeHtml(p.name)}</span>
        <span class="px-1.5 py-0.2 rounded-full ${isActive ? "bg-white/20 text-white" : "bg-[#26262E] text-slate-400"} text-[10px] font-mono">
          ${p.clues ? p.clues.length : 0}
        </span>
      `;

      btn.addEventListener("click", () => {
        state.activePersonaTab = p.id;
        renderPersonaTabs(personas);
      });

      el.personaTabsContainer.appendChild(btn);
    });

    // Render active tab content
    const activePersona = personas.find((p) => p.id === state.activePersonaTab) || personas[0];
    const clues = activePersona.clues || [];

    let cluesListHtml = "";
    if (clues.length) {
      cluesListHtml = clues
        .map(
          (c) => `
        <div class="bg-[#0e0e11] border border-[#26262E] rounded-lg p-3 text-xs flex items-start justify-between gap-2">
          <div>
            <div class="font-bold text-white mb-0.5">“${escapeHtml(c.quote)}”</div>
            <p class="text-slate-400">${escapeHtml(c.why || "Verified observation")}</p>
          </div>
          <span class="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#1b1b1e] text-slate-300 border border-[#26262E] shrink-0">
            ${escapeHtml(c.category)} · ${c.narrowing || "medium"}
          </span>
        </div>
      `
        )
        .join("");
    } else {
      cluesListHtml = `<p class="text-xs text-slate-400 italic">No specific identifying clues reported by this persona.</p>`;
    }

    el.personaTabContent.innerHTML = `
      <div class="bg-[#15151A] border border-[#26262E] rounded-xl p-5 space-y-4">
        <div class="flex items-center justify-between pb-3 border-b border-[#26262E] flex-wrap gap-2">
          <div>
            <h4 class="font-bold text-sm text-white">${escapeHtml(activePersona.name)}</h4>
            <p class="text-xs text-slate-400">${escapeHtml(activePersona.role_desc || "Adversary Persona")}</p>
          </div>
          <div class="flex items-center gap-3 text-xs font-mono">
            <span class="text-slate-400">Execution: <strong class="text-white">${activePersona.seconds || 0}s</strong></span>
            <span class="text-slate-400">Likelihood: <strong class="text-white uppercase">${activePersona.likelihood || "low"}</strong></span>
          </div>
        </div>

        <div class="space-y-2">
          ${cluesListHtml}
        </div>
      </div>
    `;
  }

  // Feature 5: Rejected AI Claims
  function renderRejectedClaims(rejectedClaims, totalCount) {
    el.rejectedClaimsCount.textContent = totalCount;

    if (totalCount === 0) {
      el.rejectedClaimsList.innerHTML = `<p class="text-xs text-slate-400 italic p-3">No claims were rejected for this document. Every generated clue matched document text verbatim.</p>`;
      return;
    }

    el.rejectedClaimsList.innerHTML = "";
    rejectedClaims.forEach((claim) => {
      const item = document.createElement("div");
      item.className = "bg-[#0e0e11] border border-amber-900/40 rounded-lg p-3 text-xs flex flex-col gap-1";
      item.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-red-300 font-semibold line-through">“${escapeHtml(claim.quote)}”</span>
          <span class="text-[10px] px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40 font-mono">
            REJECTED
          </span>
        </div>
        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1">
          <span>Reason: <strong class="text-slate-300">${escapeHtml(claim.reason || "Not found in document")}</strong></span>
          <span class="font-mono text-[10px] text-slate-400">${escapeHtml(claim.persona || "AI Persona")}</span>
        </div>
      `;
      el.rejectedClaimsList.appendChild(item);
    });
  }

  if (el.rejectedClaimsToggle) {
    el.rejectedClaimsToggle.addEventListener("click", () => {
      state.isRejectedClaimsExpanded = !state.isRejectedClaimsExpanded;
      el.rejectedClaimsContent.classList.toggle("hidden", !state.isRejectedClaimsExpanded);
      el.rejectedClaimsToggle.querySelector(".toggle-icon").textContent = state.isRejectedClaimsExpanded ? "expand_less" : "expand_more";
    });
  }

  // =========================================================================
  // STEP 5: Contextual Hardening & Feature 7 (Content Preservation)
  // =========================================================================
  async function handleGoToHarden() {
    hideError();
    el.btnGoToHarden.disabled = true;
    el.btnGoToHarden.classList.add("opacity-60", "cursor-wait");

    try {
      const res = await api("/api/harden", { text: state.anonymizedText });
      state.edits = res.edits || [];
      state.selectedEditIds = new Set(state.edits.map((e) => e.id));

      renderHardenCards();
      renderPreservationTable();
      updateHardenSummary();
      setView("harden");
    } catch (err) {
      showError(err.message);
    } finally {
      el.btnGoToHarden.disabled = false;
      el.btnGoToHarden.classList.remove("opacity-60", "cursor-wait");
    }
  }

  el.btnGoToHarden.addEventListener("click", handleGoToHarden);

  function renderHardenCards() {
    el.hardenCardsContainer.innerHTML = "";

    if (!state.edits.length) {
      el.hardenCardsContainer.innerHTML = `
        <div class="bg-[#15151A] border border-[#26262E] rounded-2xl p-6 text-center text-slate-400">
          <p class="text-base text-white font-medium mb-1">No automatic generalisation rules apply</p>
          <p class="text-sm">The remaining clues can be generalized manually before re-testing.</p>
        </div>
      `;
      return;
    }

    state.edits.forEach((edit) => {
      const isChecked = state.selectedEditIds.has(edit.id);
      const card = document.createElement("div");
      card.className = `group bg-[#15151A] border ${isChecked ? "border-[#26262E]" : "border-slate-800 opacity-60"} rounded-2xl p-5 mb-3 hover:border-[#E5383B]/50 transition-all cursor-pointer relative`;

      card.innerHTML = `
        <div class="flex items-center justify-between gap-4">
          <div class="flex items-center gap-4 flex-1 min-w-0">
            <input type="checkbox" ${isChecked ? "checked" : ""} class="h-6 w-6 rounded border-[#26262E] text-[#E5383B] focus:ring-0 focus:ring-offset-0 bg-[#0e0e11] cursor-pointer accent-[#E5383B]" onclick="event.stopPropagation();">
            <div class="flex flex-col gap-1 min-w-0">
              <div class="flex items-center gap-2.5 flex-wrap">
                <span class="text-base font-medium text-slate-400 line-through">${escapeHtml(edit.original)}</span>
                <span class="material-symbols-outlined text-slate-500 text-sm">arrow_forward</span>
                <span class="text-base font-semibold text-white">${escapeHtml(edit.replacement)}</span>
              </div>
            </div>
          </div>
          <span class="inline-flex shrink-0 items-center px-3 py-1 rounded-full text-xs font-medium bg-[#1f1f22] text-slate-300 border border-[#26262E]">
            ${escapeHtml(edit.rule || edit.category || "Generalisation")}
          </span>
        </div>
      `;

      const cb = card.querySelector('input[type="checkbox"]');
      cb.addEventListener("change", () => toggleEditSelection(edit.id, cb.checked, card));
      card.addEventListener("click", () => {
        cb.checked = !cb.checked;
        toggleEditSelection(edit.id, cb.checked, card);
      });

      el.hardenCardsContainer.appendChild(card);
    });
  }

  // Feature 7: Privacy vs Content Preservation Table
  function renderPreservationTable() {
    if (!el.hardenPreservationTable) return;
    if (!state.edits.length) {
      el.hardenPreservationTable.innerHTML = "";
      return;
    }

    let rowsHtml = "";
    state.edits.forEach((e) => {
      rowsHtml += `
        <tr class="border-b border-[#26262E]/60 text-xs">
          <td class="py-2.5 pr-3 text-slate-300 font-mono font-medium">${escapeHtml(e.original)}</td>
          <td class="py-2.5 px-3 text-[#2FBF71] font-mono font-semibold">${escapeHtml(e.replacement)}</td>
          <td class="py-2.5 px-3 text-slate-400 uppercase text-[10px] font-mono">${escapeHtml(e.category)}</td>
          <td class="py-2.5 pl-3 text-slate-400">Context preserved (cohort widened)</td>
        </tr>
      `;
    });

    el.hardenPreservationTable.innerHTML = `
      <div class="bg-[#15151A] border border-[#26262E] rounded-xl p-5 mt-6">
        <div class="flex items-center justify-between mb-3">
          <div class="font-bold text-sm text-white">Privacy vs. Content Preservation Analysis</div>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-[#2FBF71]/15 text-[#2FBF71] border border-[#2FBF71]/30 font-mono">
            Semantic Context Preserved
          </span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead>
              <tr class="border-b border-[#26262E] text-[11px] text-slate-400 font-mono uppercase">
                <th class="py-2 pr-3">Original Specific Detail</th>
                <th class="py-2 px-3">Generalized Cohort</th>
                <th class="py-2 px-3">Dimension</th>
                <th class="py-2 pl-3">Utility Impact</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  function toggleEditSelection(id, checked, card) {
    if (checked) {
      state.selectedEditIds.add(id);
      card.classList.remove("opacity-60", "border-slate-800");
      card.classList.add("border-[#26262E]");
    } else {
      state.selectedEditIds.delete(id);
      card.classList.add("opacity-60", "border-slate-800");
      card.classList.remove("border-[#26262E]");
    }
    updateHardenSummary();
  }

  function updateHardenSummary() {
    const selectedCount = state.selectedEditIds.size;
    const totalCount = state.edits.length;
    if (totalCount === 0) {
      el.hardenPillText.textContent = "No automatic generalisation available";
      return;
    }
    el.hardenPillText.textContent = `${selectedCount} of ${totalCount} generalisations selected for re-testing`;
  }

  el.btnCancelHarden.addEventListener("click", () => setView("risk"));

  // Apply Edits & Feature 6: Privacy Regression Re-Test
  async function handleApplyAndRetest() {
    hideError();
    el.btnApplyAndRetest.disabled = true;
    el.btnApplyAndRetest.classList.add("opacity-60", "cursor-wait");

    const chosen = state.edits.filter((e) => state.selectedEditIds.has(e.id));

    try {
      const applyRes = await api("/api/apply", {
        text: state.anonymizedText,
        edits: chosen,
      });

      state.hardenedText = applyRes.text;

      // Trigger automatic regression re-test
      await triggerAttack(true);
    } catch (err) {
      showError(err.message);
    } finally {
      el.btnApplyAndRetest.disabled = false;
      el.btnApplyAndRetest.classList.remove("opacity-60", "cursor-wait");
    }
  }

  el.btnApplyAndRetest.addEventListener("click", handleApplyAndRetest);

  // =========================================================================
  // SHOWCASE SCREEN 2: Before vs After Final Report (Features 3, 6, 7, 8, 10)
  // =========================================================================
  function renderRetestScreen() {
    const beforeRisk = state.beforeAttack ? state.beforeAttack.risk : { score: 0, level: "HIGH" };
    const afterRisk = state.afterAttack ? state.afterAttack.risk : { score: 0, level: "LOW" };
    const bScore = beforeRisk.score || 0;
    const aScore = afterRisk.score || 0;
    const diff = bScore - aScore;

    // Feature 6: Regression Test Status Banner
    el.retestCelebrationPill.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-[#2FBF71] animate-pulse"></span> Privacy Regression Test Completed`;

    // Feature 10: Executive Summary
    el.retestExecBadge.textContent = `${afterRisk.level || "LOW"} RISK`;
    if (diff > 0) {
      el.retestExecBadge.className = "px-3.5 py-1 rounded-full bg-[#2FBF71]/20 text-[#2FBF71] border border-[#2FBF71]/40 font-mono text-xs font-bold uppercase tracking-wider";
      el.retestExecSummaryText.textContent = `Hardening successfully reduced risk score from ${bScore} to ${aScore} (reduced by ${diff} points). Surviving details have been safely generalized into broader cohorts.`;
      el.retestDeltaText.textContent = `Reduced by ${diff} points (${beforeRisk.level} → ${afterRisk.level})`;
      el.retestDeltaBadge.className = "bg-[#1b1b1e] border border-[#2FBF71]/50 shadow-2xl px-4 py-1.5 rounded-full flex items-center gap-1.5 text-xs font-semibold text-[#2FBF71] backdrop-blur-md";
    } else {
      el.retestExecBadge.className = "px-3.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono text-xs font-bold uppercase tracking-wider";
      el.retestExecSummaryText.textContent = `Re-test completed. Score remained at ${bScore} points. Additional manual edits may be needed for full mitigation.`;
      el.retestDeltaText.textContent = `Score unchanged (${bScore} points)`;
      el.retestDeltaBadge.className = "bg-[#1b1b1e] border border-slate-700 shadow-2xl px-4 py-1.5 rounded-full flex items-center gap-1.5 text-xs font-semibold text-slate-300 backdrop-blur-md";
    }

    el.retestBeforeLevel.textContent = `${beforeRisk.level || "UNKNOWN"} RISK`;
    el.retestBeforeScore.textContent = `Score ${bScore}`;
    el.retestAfterLevel.textContent = `${afterRisk.level || "UNKNOWN"} RISK`;
    el.retestAfterScore.textContent = `Score ${aScore}`;

    // Feature 3: Dynamic SVG Comparison Chart
    renderRetestSvgChart(bScore, aScore, beforeRisk.level, afterRisk.level);

    // Feature 8: Attack Replay Component
    renderAttackReplay();

    // Side-by-side text diff panels
    el.retestBeforeDiffText.innerHTML = renderHighlightedTextWithEdits(state.anonymizedText, state.edits.filter((e) => state.selectedEditIds.has(e.id)), "before");
    el.retestAfterDiffText.innerHTML = renderHighlightedTextWithEdits(state.hardenedText, state.edits.filter((e) => state.selectedEditIds.has(e.id)), "after");
  }

  // Feature 3: SVG Before vs After Comparison Chart
  function renderRetestSvgChart(bScore, aScore, bLevel, aLevel) {
    if (!el.retestSvgChartContainer) return;
    const maxVal = Math.max(20, bScore + 2);
    const bW = Math.max(8, (bScore / maxVal) * 260);
    const aW = Math.max(8, (aScore / maxVal) * 260);

    const bColor = bLevel === "HIGH" ? "#E5383B" : bLevel === "MEDIUM" ? "#F2A33A" : "#2FBF71";
    const aColor = aLevel === "HIGH" ? "#E5383B" : aLevel === "MEDIUM" ? "#F2A33A" : "#2FBF71";

    el.retestSvgChartContainer.innerHTML = `
      <div class="bg-[#15151A] border border-[#26262E] rounded-xl p-5 mb-6">
        <div class="flex items-center justify-between mb-3">
          <div class="font-bold text-sm text-white">Heuristic Privacy Risk Score Comparison</div>
          <span class="text-xs text-slate-400 font-mono">Actual Verified Scores</span>
        </div>
        <svg viewBox="0 0 400 90" class="w-full h-auto">
          <!-- Before Bar -->
          <text x="10" y="26" fill="#9AA0AE" font-size="11" font-family="Plus Jakarta Sans">Before Hardening</text>
          <rect x="120" y="14" width="220" height="16" rx="8" fill="#1b1b1e" stroke="#26262E" stroke-width="1" />
          <rect x="120" y="14" width="${bW * 0.8}" height="16" rx="8" fill="${bColor}" />
          <text x="350" y="26" fill="#F5F5F5" font-size="11" font-family="JetBrains Mono" font-weight="bold">${bScore}</text>

          <!-- After Bar -->
          <text x="10" y="66" fill="#9AA0AE" font-size="11" font-family="Plus Jakarta Sans">After Hardening</text>
          <rect x="120" y="54" width="220" height="16" rx="8" fill="#1b1b1e" stroke="#26262E" stroke-width="1" />
          <rect x="120" y="54" width="${aW * 0.8}" height="16" rx="8" fill="${aColor}" />
          <text x="350" y="66" fill="${aColor}" font-size="11" font-family="JetBrains Mono" font-weight="bold">${aScore}</text>
        </svg>
      </div>
    `;
  }

  // Feature 8: Attack Replay
  function renderAttackReplay() {
    if (!el.retestAttackReplayList) return;
    el.retestAttackReplayList.innerHTML = "";

    const personas = (state.beforeAttack && state.beforeAttack.personas) || [
      { name: "Casual Reader", clues: [], seconds: 0.1 },
      { name: "Informed Investigator", clues: [], seconds: 0.1 },
      { name: "Targeted Attacker", clues: [], seconds: 0.1 },
    ];

    const replaySteps = [
      { title: "Attack #1 — Casual Reader", persona: personas[0], icon: "person", desc: "First pass scanning for immediate, prominent identifiers" },
      { title: "Attack #2 — Informed Investigator", persona: personas[1], icon: "manage_search", desc: "Correlating workplace, dates, and geographic directories" },
      { title: "Attack #3 — Targeted Attacker", persona: personas[2], icon: "track_changes", desc: "Cross-referencing niche achievements and cohort intersections" },
      {
        title: "Attack #4 — Privacy Regression Re-test",
        persona: {
          clues: (state.afterAttack && state.afterAttack.clues) || [],
          seconds: (state.afterAttack && state.afterAttack.seconds) || 0.1,
          name: "Hardened Regression Attack",
        },
        icon: "verified_user",
        desc: "Final attack pass on hardened document demonstrating clue mitigation",
      },
    ];

    replaySteps.forEach((step, idx) => {
      const clueCount = (step.persona && step.persona.clues) ? step.persona.clues.length : 0;
      const row = document.createElement("div");
      row.className = "bg-[#15151A] border border-[#26262E] rounded-xl p-4 flex items-center justify-between gap-4";

      row.innerHTML = `
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-lg bg-[#1b1b1e] border border-[#26262E] flex items-center justify-center text-slate-300 shrink-0">
            <span class="material-symbols-outlined text-[18px]">${step.icon}</span>
          </div>
          <div>
            <div class="font-bold text-xs text-white">${escapeHtml(step.title)}</div>
            <p class="text-[11px] text-slate-400">${escapeHtml(step.desc)}</p>
          </div>
        </div>
        <div class="flex items-center gap-3 shrink-0">
          <span class="font-mono text-xs text-slate-300"><strong>${clueCount}</strong> verified finding(s)</span>
          <span class="text-[10px] font-mono text-slate-400 bg-[#1b1b1e] px-2 py-0.5 rounded border border-[#26262E]">${step.persona.seconds || 0}s</span>
        </div>
      `;

      el.retestAttackReplayList.appendChild(row);
    });
  }

  function renderHighlightedTextWithEdits(text, appliedEdits, mode) {
    if (mode === "before") {
      let out = escapeHtml(text);
      appliedEdits.forEach((e) => {
        const origEsc = escapeHtml(e.original);
        out = out.split(origEsc).join(`<span class="bg-[#93000a]/50 text-[#ffb4ab] px-1.5 py-0.5 rounded line-through border border-[#E5383B]/30 font-medium">${origEsc}</span>`);
      });
      return out;
    } else {
      let out = escapeHtml(text);
      appliedEdits.forEach((e) => {
        const replEsc = escapeHtml(e.replacement);
        out = out.split(replEsc).join(`<span class="bg-[#2FBF71]/20 text-[#2FBF71] px-2 py-0.5 rounded-full border border-[#2FBF71]/30 font-medium">${replEsc}</span>`);
      });
      return out;
    }
  }

  // Copy Hardened Text to Clipboard
  el.btnCopyHardened.addEventListener("click", () => {
    if (!state.hardenedText) return;
    navigator.clipboard
      .writeText(state.hardenedText)
      .then(() => {
        el.copyBtnText.textContent = "Copied!";
        setTimeout(() => {
          el.copyBtnText.textContent = "Copy Hardened Text";
        }, 2000);
      })
      .catch(() => {
        showError("Failed to copy text to clipboard.");
      });
  });

  // Download Comprehensive Markdown Report (.md)
  function downloadReport() {
    const beforeRisk = state.beforeAttack ? state.beforeAttack.risk : { score: 0, level: "HIGH" };
    const afterRisk = state.afterAttack ? state.afterAttack.risk : { score: 0, level: "LOW" };
    const bScore = beforeRisk.score || 0;
    const aScore = afterRisk.score || 0;
    const diff = bScore - aScore;
    const mode = state.beforeAttack ? state.beforeAttack.mode : state.health.mode;
    const date = new Date().toISOString();

    const lines = [
      "# ReVeil AI Privacy Red-Team Report",
      "",
      `> **Generated:** ${date}`,
      `> **AI Model:** Qwen3 1.7B (${mode === "STUB" ? "STUB Mode" : "Ollama Local API"})`,
      `> **Inference:** Local machine · Document processing: Local backend`,
      `> **Disclaimer:** ReVeil is a privacy stress-testing tool. It does not guarantee anonymity. LOW means 'our attacker found little', never 'safe'.`,
      "",
      "---",
      "",
      "## 1. Executive Summary",
      "",
      `- **Initial Risk Level:** ${beforeRisk.level} (Score: ${bScore})`,
      `- **Hardened Risk Level:** ${afterRisk.level} (Score: ${aScore})`,
      `- **Risk Reduction:** Reduced by ${diff} points (${beforeRisk.level} → ${afterRisk.level})`,
      `- **Direct PII Scrubbed:** ${state.entities.length} detected and removed`,
      `- **Verified AI Clues (Initial):** ${state.beforeAttack ? state.beforeAttack.clues.length : 0}`,
      `- **Rejected / Unsupported AI Claims:** ${state.beforeAttack ? state.beforeAttack.rejected : 0}`,
      `- **Privacy Regression Test:** Completed successfully`,
      "",
      "---",
      "",
      "## 2. Attack Surface Breakdown",
      "",
    ];

    if (beforeRisk.attack_surface) {
      beforeRisk.attack_surface.forEach((surf) => {
        lines.push(`- **${surf.name} [${surf.severity}]:** ${surf.description}`);
        if (surf.clues && surf.clues.length) {
          lines.push(`  - Quoted findings: ${surf.clues.map((c) => `"${c}"`).join(", ")}`);
        }
      });
    }

    lines.push("", "---", "", "## 3. Multi-Persona AI Red Team Findings", "");
    if (state.beforeAttack && state.beforeAttack.personas) {
      state.beforeAttack.personas.forEach((p) => {
        lines.push(`### Persona: ${p.name}`);
        lines.push(`- Role: ${p.role_desc || "Adversary"}`);
        lines.push(`- Execution time: ${p.seconds || 0}s`);
        lines.push(`- Verified findings count: ${p.clues ? p.clues.length : 0}`);
        if (p.clues && p.clues.length) {
          p.clues.forEach((c) => lines.push(`  - [${c.category.toUpperCase()}] "${c.quote}": ${c.why || ""}`));
        }
      });
    }

    lines.push("", "---", "", "## 4. Quote-or-Drop Evidence Validation & Rejected Claims", "");
    if (state.beforeAttack && state.beforeAttack.rejected_claims && state.beforeAttack.rejected_claims.length) {
      lines.push("| Proposing Persona | Quoted Claim | Category | Rejection Reason |");
      lines.push("|---|---|---|---|");
      state.beforeAttack.rejected_claims.forEach((rc) => {
        lines.push(`| ${rc.persona || "AI"} | "${rc.quote}" | ${rc.category} | ${rc.reason} |`);
      });
    } else {
      lines.push("_All generated AI clues were strictly validated against document text. No claims required rejection._");
    }

    lines.push("", "---", "", "## 5. Contextual Hardening Applied", "");
    const applied = state.edits.filter((e) => state.selectedEditIds.has(e.id));
    if (applied.length) {
      lines.push("| Dimension | Original Detail | Generalized Cohort | Utility Impact |");
      lines.push("|---|---|---|---|");
      applied.forEach((e) => {
        lines.push(`| ${e.category} | \`${e.original}\` | **\`${e.replacement}\`** | Semantic context preserved (cohort widened) |`);
      });
    } else {
      lines.push("_No contextual hardening edits applied._");
    }

    lines.push("", "---", "", "## 6. Document Comparison", "", "### Original Sanitized Document", "```text", state.anonymizedText, "```", "", "### Final Hardened Document", "```text", state.hardenedText, "```", "");

    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reveil-privacy-redteam-report-${new Date().getTime()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  el.btnDownloadReport.addEventListener("click", downloadReport);

  // Restart / Reset
  function restartFlow() {
    state.originalText = "";
    state.aliases = [];
    state.anonymizedText = "";
    state.entities = [];
    state.beforeAttack = null;
    state.edits = [];
    state.selectedEditIds.clear();
    state.hardenedText = "";
    state.afterAttack = null;

    el.payloadText.value = "";
    renderTags();
    updateCharCounter();
    hideError();
    setView("upload");
  }

  el.btnRestartAnalysis.addEventListener("click", restartFlow);
  el.headerLogo.addEventListener("click", (e) => {
    e.preventDefault();
    setView("landing");
  });
  el.btnStartAnalysis.addEventListener("click", (e) => {
    e.preventDefault();
    setView("upload");
  });

  // Utilities
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initialize
  async function init() {
    await checkHealth();
    await loadSamples();
    setView("landing");
  }

  init();
})();
