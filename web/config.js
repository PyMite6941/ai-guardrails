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

const $ = (s) => document.querySelector(s);
const pagesEl = $("#pages");
const pageTitle = $("#pageTitle");
const statusEl = $("#status");
const btnSave = $("#btnSave");
const btnDownload = $("#btnDownload");
const btnRefresh = $("#btnRefresh");
const btnNew = $("#newPage");
const btnTest = $("#btnTest");
const testResult = $("#testResult");

function setStatus(msg, kind) {
  statusEl.textContent = msg;
  statusEl.className = "status " + (kind || "");
}

async function fetchJson(path, opts = {}) {
  try {
    const res = await fetch(BASE + path, {
      headers: { "Content-Type": "application/json", ...opts.headers },
      ...opts,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

async function loadPages() {
  const data = await fetchJson("/api/policies");
  if (data.error) { setStatus("API unreachable — local mode", "err"); apiOk = false; renderLocal(); return; }
  apiOk = true;
  setStatus("API connected", "ok");
  const list = data.pages || [];
  if (!list.includes("default")) list.unshift("default");
  policies = {};
  pagesEl.innerHTML = "";
  for (const page of list) {
    const el = document.createElement("div");
    el.className = "page-item" + (page === currentPage ? " active" : "");
    el.innerHTML = `<span class="dot"></span>${escapeHtml(page)}`;
    el.onclick = () => loadPolicy(page);
    pagesEl.appendChild(el);
  }
  loadPolicy(currentPage);
}

function renderLocal() {
  const list = ["default", ...Object.keys(policies).filter(p => p !== "default")];
  pagesEl.innerHTML = "";
  for (const page of list) {
    const el = document.createElement("div");
    el.className = "page-item" + (page === currentPage ? " active" : "");
    el.innerHTML = `<span class="dot"></span>${escapeHtml(page)}`;
    el.onclick = () => loadPolicy(page);
    pagesEl.appendChild(el);
  }
  loadPolicy(currentPage);
}

async function loadPolicy(page) {
  currentPage = page;
  pageTitle.textContent = `${escapeHtml(page)} policy`;
  [...pagesEl.children].forEach(el => {
    el.classList.toggle("active", el.textContent.trim() === page);
  });
  setStatus("loading…", "");
  let policy;
  if (apiOk) {
    const data = await fetchJson(`/api/policies/${encodeURIComponent(page)}`);
    if (data.error) {
      policy = JSON.parse(JSON.stringify(window.DEFAULT_POLICY));
    } else {
      policy = data.policy || {};
    }
  } else {
    policy = policies[page] || JSON.parse(JSON.stringify(window.DEFAULT_POLICY));
  }
  policies[page] = policy;
  renderPolicy(policy);
  setStatus("loaded", "ok");
}

function renderPolicy(p) {
  const join = (arr) => (Array.isArray(arr) ? arr.join("\n") : "");
  $("#inPatterns").value = join(p.blocked_input_patterns);
  $("#inKeywords").value = join(p.blocked_input_keywords);
  $("#outPatterns").value = join(p.blocked_output_patterns);
  $("#outKeywords").value = join(p.blocked_output_keywords);
  $("#harmful").value = join(p.harmful_content_patterns);
  $("#maxInput").value = p.max_input_length ?? 4096;
  $("#maxOutput").value = p.max_output_length ?? 8192;
  $("#canonicalize").checked = p.canonicalization_enabled !== false;
  $("#threeValued").checked = p.three_valued_monitoring !== false;

  const dc = $("#disclaimers");
  dc.innerHTML = "";
  const disclaimers = p.disclaimers || {};
  for (const topic of DISCLAIMER_TOPICS) {
    const wrap = document.createElement("div");
    wrap.className = "disclaimer";
    wrap.innerHTML = `<div class="k">${topic}</div><textarea class="d">${escapeHtml(disclaimers[topic] || "")}</textarea>`;
    dc.appendChild(wrap);
  }

  const checksEl = $("#checks");
  checksEl.innerHTML = "";
  const enabled = new Set(p.checks || []);
  for (const c of CHECKS) {
    const lab = document.createElement("label");
    lab.className = "check";
    lab.innerHTML = `<input type="checkbox" value="${c}" ${enabled.has(c) ? "checked" : ""}> ${c}`;
    checksEl.appendChild(lab);
  }
}

function collectPolicy() {
  const lines = (id) => $(id).value.split("\n").map(s => s.trim()).filter(Boolean);
  const disclaimers = {};
  for (const topic of DISCLAIMER_TOPICS) {
    const val = $(`.d`).length ? "" : "";
  }
  // disclaimers are indexed by order in DISCLAIMER_TOPICS matching .d textareas
  const dTexts = document.querySelectorAll("#disclaimers .d");
  DISCLAIMER_TOPICS.forEach((topic, i) => { disclaimers[topic] = dTexts[i]?.value.trim() || ""; });

  const checks = Array.from($("#checks").querySelectorAll("input:checked")).map(i => i.value);
  return {
    name: currentPage,
    version: "1.0.0",
    description: `Per-page policy for ${escapeHtml(currentPage)}`,
    blocked_input_patterns: lines("#inPatterns"),
    blocked_input_keywords: lines("#inKeywords"),
    blocked_output_patterns: lines("#outPatterns"),
    blocked_output_keywords: lines("#outKeywords"),
    harmful_content_patterns: lines("#harmful"),
    disclaimers,
    max_input_length: parseInt($("#maxInput").value || "4096", 10) || 4096,
    max_output_length: parseInt($("#maxOutput").value || "8192", 10) || 8192,
    canonicalization_enabled: $("#canonicalize").checked,
    three_valued_monitoring: $("#threeValued").checked,
    checks,
  };
}

async function savePolicy() {
  const policy = collectPolicy();
  btnSave.disabled = true; btnSave.textContent = "Saving…";
  if (apiOk) {
    const res = await fetchJson(`/api/policies/${encodeURIComponent(currentPage)}`, {
      method: "PUT", body: JSON.stringify(policy),
    });
    if (res.error) { setStatus("Save failed: " + res.error, "err"); }
    else { setStatus(`Saved ${currentPage}`, "ok"); policies[currentPage] = policy; }
  } else {
    policies[currentPage] = policy;
    setStatus(`Saved locally: ${currentPage}`, "ok");
  }
  btnSave.disabled = false; btnSave.textContent = "Save policy";
}

async function downloadPolicy() {
  const policy = collectPolicy();
  const blob = new Blob([JSON.stringify(policy, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `ai-guardrails-${currentPage}.json`;
  a.click();
  URL.revokeObjectURL(url);
  setStatus(`Downloaded ${currentPage}.json`, "ok");
}

async function addPage() {
  const name = prompt("Page id (e.g. my-site.com or /chat):");
  if (!name || !name.trim()) return;
  const id = name.trim();
  if (policies[id]) { alert("Page already exists"); return; }
  policies[id] = JSON.parse(JSON.stringify(window.DEFAULT_POLICY));
  if (apiOk) {
    await fetchJson(`/api/policies/${encodeURIComponent(id)}`, {
      method: "PUT", body: JSON.stringify(policies[id]),
    });
  }
  loadPages();
  loadPolicy(id);
}

async function testGuardrail() {
  const kind = $("#testKind").value;
  const text = $("#testText").value;
  const agent = $("#testAgent").value || "assistant";
  if (!text.trim()) { alert("Enter text to validate"); return; }
  btnTest.disabled = true; btnTest.textContent = "Validating…";
  testResult.style.display = "none";
  try {
    const res = await fetchJson(`/api/validate/${kind}`, {
      method: "POST", body: JSON.stringify({ page: currentPage, text, agent }),
    });
    if (res.error) throw new Error(res.error);
    renderTestResult(res);
  } catch (e) {
    testResult.style.display = "block";
    testResult.className = "result blocked";
    testResult.textContent = "Test failed: " + e.message;
  } finally {
    btnTest.disabled = false; btnTest.textContent = "Validate";
  }
}

function renderTestResult(r) {
  testResult.style.display = "block";
  testResult.className = "result " + (r.safe ? "safe" : "blocked");
  const out = r.safe ? r.sanitized_output || r.sanitized_input : "";
  const lines = [
    `safe:      ${r.safe}`,
    `reason:    ${r.reason}`,
    `blocked_by:${r.blocked_by || "N/A"}`,
    `page:      ${r.page}`,
    `agent:     ${r.agent}`,
    `reported:  ${r.reported === true}`,
    "",
    out ? `--- sanitized ---\n${out}` : "",
    "",
    `--- checks ---`,
    ...Object.entries(r.checks || {}).map(([k, v]) => `  ${k}: ${v.safe ? "PASS" : "BLOCK"} — ${v.reason}`),
  ].filter(Boolean);
  testResult.textContent = lines.join("\n");
}

async function loadStats() {
  const data = await fetchJson("/api/stats");
  if (data.error) return;
  const s = $("#stats");
  s.innerHTML = "";
  const rows = [
    ["total", data.total], ["passed", data.passed], ["blocked", data.blocked],
    ["reported", data.reported], ["effectiveness", data.effectiveness + "%"],
  ];
  for (const [k, v] of rows) {
    const el = document.createElement("div");
    el.className = "stat";
    el.innerHTML = `<div class="v">${v}</div><div class="l">${k}</div>`;
    s.appendChild(el);
  }
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
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

loadPages();
setInterval(loadStats, 5000);
