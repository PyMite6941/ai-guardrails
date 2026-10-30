/*=============================================================================
  AI Guardrails — web config UI logic
  Talks to guardrail_server.py (same origin). Falls back to local-only edits
  + JSON download when the API is unreachable.
=============================================================================*/

const BASE = location.origin;
const CHECKS = [
  "canonicalize","container_breakout","prompt_injection","leakage","input_patterns","input_length",
  "output_patterns","output_length","harmful_content","pii_credentials","data_exfiltration",
  "disclaimers","system_prompt_leakage",
];
const DISCLAIMER_TOPICS = ["financial","legal","security","geopolitics"];

let currentPage = "default";
let policies = {};      // page -> policy object
let apiOk = false;
let csrfToken = null;   // CSRF token bound to the current session
let sessionToken = null; // current session token
let requires2fa = false; // whether 2FA verification is pending
let providers = [];      // available model providers
let currentProvider = null; // currently selected provider

const $ = (s) => document.querySelector(s);
const pagesEl = $("#pages");
const pageTitle = $("#pageTitle");
const statusEl = $("#status");
const connChip = $("#connChip");
const modelChip = $("#modelChip");
const btnSave = $("#btnSave");
const btnDownload = $("#btnDownload");
const btnRefresh = $("#btnRefresh");
const btnNew = $("#newPage");
const btnTest = $("#btnTest");
const testResult = $("#testResult");
const btnModel = $("#btnModel");
const modelCard = $("#modelCard");
const modelProviderSelect = $("#modelProvider");
const modelApiKeyInput = $("#modelApiKey");
const modelBaseUrlInput = $("#modelBaseUrl");
const modelNameInput = $("#modelName");
const modelEndpointInput = $("#modelEndpoint");
const apiKeyField = $("#apiKeyField");
const modelTestResult = $("#modelTestResult");
const btnAssistant = $("#btnAssistant");
const assistantCard = $("#assistantCard");
const assistantSetupResult = $("#assistantSetupResult");
const assistantActivityResult = $("#assistantActivityResult");
const assistantAuditLog = $("#assistantAuditLog");

function setStatus(msg, kind) {
  statusEl.textContent = msg;
  statusEl.className = "status " + (kind || "");
}

async function fetchJson(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...opts.headers };
  // Attach CSRF token on state-changing requests when we have one.
  if (csrfToken && opts.method && !/^GET$|^HEAD$|^OPTIONS$/i.test(opts.method || "")) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  // Attach session token header
  if (sessionToken) {
    headers["X-Session-Token"] = sessionToken;
  }
  try {
    const res = await fetch(BASE + path, {
      headers,
      ...opts,
    });
    // Capture CSRF token from response header (set by server on successful auth).
    const ct = res.headers.get("X-CSRF-Token");
    if (ct) csrfToken = ct;
    // Capture session token from Set-Cookie
    const setCookie = res.headers.get("Set-Cookie") || "";
    const m = setCookie.match(/session=([^;]+)/);
    if (m) sessionToken = m[1];
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

async function loadProviders() {
  const res = await fetchJson("/api/models");
  if (res.error) {
    if (modelChip) modelChip.textContent = "Model: error";
    if (modelChip) modelChip.className = "status-chip danger pulse";
    return;
  }
  providers = res.providers || [];
  renderProviders();
  loadSelectedModel();
}

function renderProviders() {
  if (!modelProviderSelect) return;
  modelProviderSelect.innerHTML = "";
  for (const p of providers) {
    const opt = document.createElement("option");
    opt.value = p.key;
    opt.textContent = p.name + (p.type === "cloud" ? " (cloud)" : " (local)");
    if (p.api_key_required && !p.api_key_configured) {
      opt.textContent += " — API key needed";
    }
    modelProviderSelect.appendChild(opt);
  }
  updateApiKeyField();
}

async function loadSelectedModel() {
  const res = await fetchJson("/api/models/selected");
  if (res.error) return;
  currentProvider = res.provider;
  const config = res.provider_config || {};
  if (currentProvider) {
    if (modelChip) {
      modelChip.textContent = "Model: " + currentProvider;
      modelChip.className = "status-chip ok pulse";
    }
    // Populate form
    if (modelProviderSelect && config.key) modelProviderSelect.value = config.key;
    if (modelBaseUrlInput && config.base_url) modelBaseUrlInput.value = config.base_url;
    if (modelNameInput && config.model) modelNameInput.value = config.model;
    if (modelEndpointInput && config.endpoint) modelEndpointInput.value = config.endpoint;
  } else {
    if (modelChip) {
      modelChip.textContent = "Model: not selected";
      modelChip.className = "status-chip warn";
    }
  }
  updateApiKeyField();
}

function updateApiKeyField() {
  const key = modelProviderSelect ? modelProviderSelect.value : "";
  const p = providers.find(pr => pr.key === key);
  if (apiKeyField && p && p.api_key_required) {
    apiKeyField.style.display = "block";
  } else if (apiKeyField) {
    apiKeyField.style.display = "none";
  }
}

function openModelCard() {
  if (modelCard) modelCard.classList.remove("hidden");
  loadProviders();
}

function closeModelCard() {
  if (modelCard) modelCard.classList.add("hidden");
  if (modelTestResult) modelTestResult.innerHTML = "";
}

async function applyModel() {
  const key = modelProviderSelect ? modelProviderSelect.value : "";
  const p = providers.find(pr => pr.key === key);
  if (!p) { alert("Please select a provider"); return; }

  const body = { provider: key };
  if (modelBaseUrlInput && modelBaseUrlInput.value) body.base_url = modelBaseUrlInput.value;
  if (modelNameInput && modelNameInput.value) body.model = modelNameInput.value;
  if (modelEndpointInput && modelEndpointInput.value) body.endpoint = modelEndpointInput.value;
  if (modelApiKeyInput && modelApiKeyInput.value) body.api_key = modelApiKeyInput.value;

  const res = await fetchJson("/api/models/select", {
    method: "POST", body: JSON.stringify(body),
  });
  if (res.error) { alert("Apply failed: " + res.error); return; }
  if (modelTestResult) modelTestResult.innerHTML = '<span style="color:var(--ok)">✔ Model set to ' + p.name + '</span>';
  setTimeout(() => { if (modelTestResult) modelTestResult.innerHTML = ""; }, 3000);
  closeModelCard();
  loadSelectedModel();
}

async function testModelConnection() {
  const key = modelProviderSelect ? modelProviderSelect.value : "";
  const p = providers.find(pr => pr.key === key);
  if (!p) { alert("Please select a provider"); return; }

  modelTestResult.innerHTML = "Testing connection…";
  const res = await fetchJson("/api/validate/input", {
    method: "POST", body: JSON.stringify({ page: "model-test", text: "hello", agent: "test" }),
  });
  if (res.error) {
    modelTestResult.innerHTML = '<span style="color:var(--danger)">Connection test failed: ' + res.error + '</span>';
  } else {
    modelTestResult.innerHTML = '<span style="color:var(--ok)">Connection OK — guardrail engine responding</span>';
  }
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>\"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));
}

window.DEFAULT_POLICY = {
  name: "default", version: "1.0.0",
  blocked_input_patterns: [],
  blocked_input_keywords: [],
  blocked_output_patterns: [],
  blocked_output_keywords: [],
  harmful_content_patterns: [],
  disclaimers: {},
  max_input_length: 4096, max_output_length: 8192,
  canonicalization_enabled: true, three_valued_monitoring: true,
  checks: CHECKS.slice(),
};

btnSave.onclick = savePolicy;
btnDownload.onclick = downloadPolicy;
btnRefresh.onclick = loadPages;
btnNew.onclick = addPage;
btnTest.onclick = testGuardrail;
btnModel.onclick = openModelCard;

// Wire up model form events
if (modelProviderSelect) modelProviderSelect.onchange = updateApiKeyField;
const btnApplyModel = document.getElementById("btnApplyModel");
if (btnApplyModel) btnApplyModel.onclick = applyModel;

loadPages();
setInterval(loadStats, 5000);
setInterval(loadEmergencyStatus, 5000);

// ── 2FA setup ────────────────────────────────────────────────────────────
async function setup2fa() {
  const res = await fetchJson("/api/auth/2fa/setup");
  if (res.error) { alert("2FA setup failed: " + res.error); return; }
  const dlg = document.createElement("div");
  dlg.style.position = "fixed";
  dlg.style.top = "0"; dlg.style.left = "0";
  dlg.style.width = "100%"; dlg.style.height = "100%";
  dlg.style.background = "rgba(0,0,0,0.8)";
  dlg.style.zIndex = "1000";
  dlg.style.display = "flex";
  dlg.style.flexDirection = "column";
  dlg.style.alignItems = "center";
  dlg.style.justifyContent = "center";
  dlg.style.color = "var(--text)";
  dlg.style.padding = "40px";
  dlg.innerHTML = '<div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:32px;max-width:500px;">' +
    '<h2 style="color:var(--accent);margin-top:0;">Enable 2FA (TOTP)</h2>' +
    '<p>Scan this QR code with Google Authenticator, Authy, or any TOTP app:</p>' +
    '<pre style="background:#0b0f19;border:1px solid var(--border);padding:12px;border-radius:8px;font-size:11px;word-break:break-all;">' + res.uri + '</pre>' +
    '<p style="color:var(--muted);font-size:11px;">Secret: <strong>' + res.secret + '</strong></p>' +
    '<p style="color:var(--danger);font-size:11px;"><strong>Backup codes (save these!):</strong><br>' + res.backup_codes.join(", ") + '</p>' +
    '<p style="color:var(--muted);font-size:11px;">Each backup code can be used once.</p>' +
    '<button class="btn primary" style="margin-top:16px;" onclick="this.closest(\'div\').remove()">I\'ve saved my codes</button>' +
    '</div>';
  document.body.appendChild(dlg);
}

async function check2faStatus() {
  const res = await fetchJson("/api/auth/2fa/status");
  if (res.error) return;
  const el = document.getElementById("btn2fa");
  if (el) {
    el.textContent = res["2fa_configured"] ? "2FA: Enabled" : "Set up 2FA";
    el.onclick = res["2fa_configured"] ? null : setup2fa;
  }
}

// ── Emergency override ───────────────────────────────────────────────────
async function emergencyAction(action) {
  if (!confirm("Emergency override: " + action.toUpperCase() + "\n\nThis will " + action + ". Continue?")) return;
  const res = await fetchJson("/api/emergency/" + action, { method: "POST" });
  if (res.error) { alert("Emergency action failed: " + res.error); return; }
  alert("Emergency " + action + " completed.");
  loadEmergencyStatus();
}

async function emergencyReenable() {
  const pw = prompt("Admin password:");
  if (!pw) return;
  let totp = prompt("TOTP code (or backup code):");
  if (!totp) return;
  const res = await fetchJson("/api/emergency/reenable", {
    method: "POST",
    body: JSON.stringify({ password: pw, totp_code: totp, backup_code: totp }),
  });
  if (res.error) { alert("Re-enable denied: " + res.error); return; }
  alert("System re-enabled. You can now restart the server.");
  loadEmergencyStatus();
}

async function loadEmergencyStatus() {
  const res = await fetchJson("/api/emergency/status");
  if (res.error) return;
  const el = document.getElementById("emergencyStatus");
  if (!el) return;
  const e = res.emergency || {};
  el.innerHTML = '<div class="stat"><div class="v">' + (e.containment ? "ACTIVE" : "off") + '</div><div class="l">Containment</div></div>' +
    '<div class="stat"><div class="v">' + (e.container_stopped ? "STOPPED" : "running") + '</div><div class="l">Containers</div></div>' +
    '<div class="stat"><div class="v">' + (e.logs_preserved ? "YES" : "no") + '</div><div class="l">Logs preserved</div></div>' +
    '<div class="stat"><div class="v">' + (e.shutdown ? "LOCKED" : "open") + '</div><div class="l">Full shutdown</div></div>';
}

// ── Assistant dashboard ───────────────────────────────────────────────
async function openAssistantCard() {
  assistantCard.classList.remove("hidden");
  assistantSetupStatus();
}

function closeAssistantCard() {
  assistantCard.classList.add("hidden");
}

async function assistantSetupStatus() {
  const res = await fetchJson("/api/assistant/setup");
  if (res.error) {
    assistantSetupResult.innerHTML = '<span style="color:var(--danger)">Setup check failed: ' + res.error + '</span>';
    return;
  }
  const s = res;
  const lines = [];
  lines.push('<span style="color:' + (s.password_configured ? "var(--ok)" : "var(--danger)") + '">' + (s.password_configured ? "✔" : "✘") + ' Password: ' + (s.password_configured ? "set" : "not set") + '</span>');
  lines.push('<span style="color:' + (s['2fa_configured'] ? "var(--ok)" : "var(--warn)") + '">' + (s['2fa_configured'] ? "✔" : "○") + ' 2FA: ' + (s['2fa_configured'] ? "enabled" : "not enabled") + '</span>');
  lines.push('<span style="color:' + (s.auth_configured ? "var(--ok)" : "var(--warn)") + '">' + (s.auth_configured ? "✔" : "○") + ' Auth: ' + (s.auth_configured ? "configured" : "not configured") + '</span>');
  lines.push('<span style="color:' + (s.emergency_locked ? "var(--danger)" : "var(--ok)") + '">' + (s.emergency_locked ? "🔒" : "🔓") + ' Emergency lock: ' + (s.emergency_locked ? "active" : "not active") + '</span>');
  lines.push('<span style="color:var(--text-muted)">Mode: ' + s.mode + '</span>');
  lines.push('<span style="color:var(--text-muted)">Providers available: ' + s.providers_available + '</span>');
  assistantSetupResult.innerHTML = lines.join('<br>');
}

async function assistantLoadActivity() {
  const res = await fetchJson("/api/assistant/activity");
  if (res.error) {
    assistantActivityResult.innerHTML = '<span style="color:var(--danger)">Activity load failed: ' + res.error + '</span>';
    return;
  }
  const lines = [];
  lines.push('<span style="color:var(--text-muted)">Audit entries: ' + res.audit_count + '</span>');
  lines.push('<span style="color:var(--text-muted)">Conversations: ' + res.risk_count + '</span>');
  if (res.risk_at_risk && res.risk_at_risk.length > 0) {
    lines.push('<span style="color:var(--danger)">⚠ At-risk conversations: ' + res.risk_at_risk.length + '</span>');
  } else {
    lines.push('<span style="color:var(--ok)">✔ No at-risk conversations</span>');
  }
  lines.push('<span style="color:var(--text-muted)">Canary: ' + (res.canary.consecutive_failures || 0) + ' consecutive failures</span>');
  lines.push('<span style="color:' + (res.integrity.ok ? "var(--ok)" : "var(--danger)") + ')">' + (res.integrity.ok ? "✔" : "✘") + ' Integrity: ' + (res.integrity.ok ? "ok" : "tampering detected") + '</span>');
  assistantActivityResult.innerHTML = lines.join('<br>');

  // Show recent audit log
  const logEl = document.getElementById("assistantAuditLog");
  if (logEl && res.audit && res.audit.length > 0) {
    logEl.innerHTML = res.audit.slice(0, 10).map(function(e) {
      return '<div style="margin-bottom:6px;"><span style="color:var(--muted);font-size:10px;">' + (e.ts || "") + '</span> <span style="color:var(--text-muted)">' + (e.kind || "event") + '</span>: ' + (e.content_preview || e.detail || "") + '</div>';
    }).join("");
  } else if (logEl) {
    logEl.innerHTML = '<span style="color:var(--text-muted)">No recent activity</span>';
  }
}

async function assistantLoadHealth() {
  const res = await fetchJson("/api/assistant/health");
  if (res.error) {
    assistantActivityResult.innerHTML = '<span style="color:var(--danger)">Health check failed: ' + res.error + '</span>';
    return;
  }
  const lines = [];
  lines.push('<span style="color:' + (res.status === "ok" ? "var(--ok)" : "var(--danger)") + ')">' + (res.status === "ok" ? "✔" : "✘") + ' System: ' + res.status + '</span>');
  lines.push('<span style="color:var(--text-muted)">Mode: ' + res.mode + '</span>');
  lines.push('<span style="color:' + (res['2fa_configured'] ? "var(--ok)" : "var(--warn)") + ')">' + (res['2fa_configured'] ? "✔" : "○") + ' 2FA: ' + (res['2fa_configured'] ? "enabled" : "not enabled") + '</span>');
  lines.push('<span style="color:' + (res.auth_configured ? "var(--ok)" : "var(--warn)") + ')">' + (res.auth_configured ? "✔" : "○") + ' Auth: ' + (res.auth_configured ? "configured" : "not configured") + '</span>');
  lines.push('<span style="color:' + (res.emergency_locked ? "var(--danger)" : "var(--ok)") + ')">' + (res.emergency_locked ? "🔒 Emergency locked" : "🔓 Not locked") + '</span>');
  lines.push('<span style="color:var(--text-muted)">At-risk conversations: ' + res.risk_at_risk_count + '</span>');
  assistantActivityResult.innerHTML = lines.join('<br>');
}

// Wire up assistant button
if (btnAssistant) btnAssistant.onclick = openAssistantCard;

