/*=============================================================================
  AI Guardrails — Chat frontend
  ChatGPT-style agentic chat with full guardrail integration
=============================================================================*/

const BASE = location.origin;
let csrfToken = null;
let sessionToken = null;
let currentSessionId = null;
let providers = [];
let currentModel = 'ollama';
let agentMode = false;
let compressionLevel = 'light';
let guardrailTrace = [];

// ── DOM elements ──
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

const chatListEl = $("#chatList");
const messagesContainerEl = $("#messagesContainer");
const messageInputEl = $("#messageInput");
const btnSendEl = $("#btnSend");
const btnNewChatEl = $("#btnNewChat");
const modelSelectEl = $("#modelSelect");
const agentModeToggleEl = $("#agentModeToggle");
const chatTitleEl = $("#chatTitle");
const chatSubtitleEl = $("#chatSubtitle");
const typingIndicatorEl = $("#typingIndicator");
const guardrailPanelEl = $("#guardrailPanel");
const guardrailTraceEl = $("#guardrailTrace");
const btnCloseGuardrailEl = $("#btnCloseGuardrail");
const statusIndicatorEl = $("#statusIndicator");
const statusTextEl = $("#statusText");
const emptyStateEl = $(".empty-state");
const compressionLevelEl = $("#compressionLevel");
const thinkingOverlayEl = $("#thinkingOverlay");
const neuronNetworkEl = $("#neuronNetwork");

// ── Fetch wrapper ──
async function fetchJson(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...opts.headers };
  if (csrfToken && opts.method && !/^GET$|^HEAD$|^OPTIONS$/i.test(opts.method || "")) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  if (sessionToken) {
    headers["X-Session-Token"] = sessionToken;
  }
  try {
    const res = await fetch(BASE + path, { headers, ...opts });
    const ct = res.headers.get("X-CSRF-Token");
    if (ct) csrfToken = ct;
    const setCookie = res.headers.get("Set-Cookie") || "";
    const m = setCookie.match(/session=([^;]+)/);
    if (m) sessionToken = m[1];
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// ── Authentication ──
async function checkAuth() {
  const res = await fetchJson("/api/auth/session");
  if (res.error || !res.authenticated) {
    // Not authenticated — redirect to login
    window.location.pathname = "/login";
    return false;
  }
  sessionToken = res.session?.token || sessionToken;
  statusTextEl.textContent = "Authenticated";
  statusIndicatorEl.querySelector(".dot").style.background = "var(--accent)";
  return true;
}

// ── Sessions ──
async function loadSessions() {
  const res = await fetchJson("/api/chat/sessions");
  if (res.error) {
    chatListEl.innerHTML = `<div style="color:var(--danger);font-size:12px;padding:8px;">Failed to load sessions</div>`;
    return;
  }
  chatListEl.innerHTML = "";
  for (const s of res.sessions || []) {
    const item = document.createElement("div");
    item.className = `chat-item ${currentSessionId === s.id ? "active" : ""}`;
    item.innerHTML = `
      <div class="chat-item-dot"></div>
      <div class="chat-item-info">
        <div class="chat-item-title">${escapeHtml(s.title)}</div>
        <div class="chat-item-meta">${s.message_count} messages</div>
      </div>
    `;
    item.onclick = () => loadSession(s.id);
    chatListEl.appendChild(item);
  }
}

async function loadSession(sessionId, includeMessages = true) {
  currentSessionId = sessionId;
  const res = await fetchJson(`/api/chat/sessions/${sessionId}`, {
    headers: { "X-Include-Messages": includeMessages ? "true" : "false" }
  });
  if (res.error) {
    alert("Failed to load session: " + res.error);
    return;
  }
  chatTitleEl.textContent = res.title || "New Chat";
  currentModel = res.model || "ollama";
  agentMode = res.agent_mode || false;
  modelSelectEl.value = currentModel;
  agentModeToggleEl.checked = agentMode;
  chatSubtitleEl.textContent = `Agent mode: ${agentMode ? "on" : "off"} · Model: ${currentModel}`;
  updateAgentModeBadge();

  messagesContainerEl.innerHTML = "";
  if (res.messages && res.messages.length > 0) {
    emptyStateEl.style.display = "none";
    for (const m of res.messages) {
      appendMessage(m.role, m.content, m.tool_calls, m.tool_results, m.timestamp);
    }
    scrollToBottom();
  } else {
    emptyStateEl.style.display = "flex";
  }

  // Update active state in sidebar
  $$(".chat-item").forEach(el => {
    el.classList.toggle("active", el.onclick && el.dataset.id === sessionId);
  });
  // Mark active item
  const items = $$(".chat-item");
  items.forEach(el => {
    // Re-render click to set data-id
    if (!el.dataset.id) {
      el.dataset.id = sessionId;
    }
    el.classList.toggle("active", el.dataset.id === sessionId);
  });
}

async function createSession() {
  const title = prompt("Session title:", "New Chat");
  if (title === null) return;
  const res = await fetchJson("/api/chat/sessions", {
    method: "POST",
    body: JSON.stringify({ title, model: currentModel, agent_mode: agentMode })
  });
  if (res.error) {
    alert("Failed to create session: " + res.error);
    return;
  }
  await loadSessions();
  loadSession(res.id);
}

async function deleteSession(sessionId) {
  if (!confirm("Delete this conversation?")) return;
  const res = await fetchJson(`/api/chat/sessions/${sessionId}`, {
    method: "DELETE"
  });
  if (res.error) {
    alert("Failed to delete: " + res.error);
    return;
  }
  await loadSessions();
  if (currentSessionId === sessionId) {
    currentSessionId = null;
    messagesContainerEl.innerHTML = "";
    emptyStateEl.style.display = "flex";
    chatTitleEl.textContent = "New Chat";
  }
}

// ── Client-side secret stripping ─────────────────────────────────────────
// Strip API keys, tokens, passwords before they ever leave the browser.
// This is belt-and-suspenders: the server also strips, but client-side
// prevents secrets from touching the network at all.
const SECRET_PATTERNS = [
  // API keys
  [/\bsk-[A-Za-z0-9]{20,}/g, "[OPENAI_API_KEY]"],
  [/\bsk-ant-[A-Za-z0-9\-]{20,}/g, "[ANTHROPIC_API_KEY]"],
  [/\bsk-[A-Za-z0-9]{16,}/g, "[API_KEY]"],
  [/\b(ghp_[A-Za-z0-9]{36}|github_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9\-]{20,})\b/g, "[GITHUB_TOKEN]"],
  [/\bglpat-[A-Za-z0-9\-]{20,}/g, "[GITLAB_TOKEN]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[AWS_ACCESS_KEY_ID]"],
  [/\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g, "[STRIPE_KEY]"],
  [/\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}/g, "[SENDGRID_KEY]"],
  // Passwords / credentials
  [/\b(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|refresh_token|client_secret)\s*[:=]\s*['"]?\S{3,}['"]?/gi, "[REDACTED]"],
  [/\b(?:Authorization|authorization)\s*:\s*[A-Za-z0-9\-_ ]{10,}/gi, "Authorization: [REDACTED]"],
  // Private keys
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, "[PRIVATE_KEY_BLOCK]"],
  // Emails
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[EMAIL]"],
  // Private IPs
  [/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, "[PRIVATE_IP]"],
];

function stripSecretsClientSide(text) {
  let result = text;
  let strippedCount = 0;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    const matches = result.match(pattern);
    if (matches) strippedCount += matches.length;
    result = result.replace(pattern, replacement);
  }
  return { sanitized: result, secretsStripped: strippedCount };
}

// ── Thinking / Neuron Animations ──
function initNeuronNetwork() {
  if (!neuronNetworkEl) return;
  neuronNetworkEl.innerHTML = "";
  const rect = neuronNetworkEl.getBoundingClientRect();
  const w = rect.width || 300;
  const h = rect.height || 200;

  // Create neurons
  const neuronCount = 12;
  for (let i = 0; i < neuronCount; i++) {
    const n = document.createElement("div");
    n.className = "neuron";
    n.style.left = Math.random() * 80 + 10 + "%";
    n.style.top = Math.random() * 80 + 10 + "%";
    n.style.transitionDelay = Math.random() * 2 + "s";
    neuronNetworkEl.appendChild(n);
  }

  // Create synapses between random pairs
  const neurons = neuronNetworkEl.querySelectorAll(".neuron");
  for (let i = 0; i < 8; i++) {
    const s = document.createElement("div");
    s.className = "synapse";
    const a = neurons[Math.floor(Math.random() * neurons.length)];
    const b = neurons[Math.floor(Math.random() * neurons.length)];
    if (a === b) continue;
    const ax = parseFloat(a.style.left) * w / 100;
    const ay = parseFloat(a.style.top) * h / 100;
    const bx = parseFloat(b.style.left) * w / 100;
    const by = parseFloat(b.style.top) * h / 100;
    const length = Math.sqrt((bx - ax) ** 2 + (by - ay) ** 2);
    const angle = Math.atan2(by - ay, bx - ax) * 180 / Math.PI;
    s.style.left = ax + "px";
    s.style.top = ay + "px";
    s.style.width = length + "px";
    s.style.transform = `rotate(${angle}deg)`;
    s.style.transitionDelay = Math.random() * 2 + "s";
    neuronNetworkEl.appendChild(s);
  }
}

function showThinking() {
  if (thinkingOverlayEl) thinkingOverlayEl.classList.add("visible");
  if (neuronNetworkEl && neuronNetworkEl.children.length === 0) {
    initNeuronNetwork();
  }
}

function hideThinking() {
  if (thinkingOverlayEl) thinkingOverlayEl.classList.remove("visible");
}

// ── Messaging ──
async function sendMessage() {
  const text = messageInputEl.value.trim();
  if (!text || !currentSessionId) return;

  // ── Client-side secret stripping ──
  const { sanitized, secretsStripped } = stripSecretsClientSide(text);
  if (secretsStripped > 0) {
    showStatusMessage(`${secretsStripped} secret(s) stripped before sending`, "warn");
  }

  const compression = compressionLevelEl ? compressionLevelEl.value : "light";

  messageInputEl.value = "";
  messageInputEl.style.height = "auto";
  btnSendEl.disabled = true;

  // Append user message immediately (show sanitized version)
  const userMsg = appendMessage("user", sanitized);
  scrollToBottom();
  showTyping(true);
  showGuardrailPanel(false);
  showThinking();  // <-- Show thinking overlay with neuron animation

  const res = await fetchJson("/api/chat/message", {
    method: "POST",
    body: JSON.stringify({
      session_id: currentSessionId,
      text: sanitized,
      model: currentModel,
      agent_mode: agentMode,
      compression_level: compression,
    })
  });

  showTyping(false);
  hideThinking();  // <-- Hide thinking overlay when response arrives

  if (res.error) {
    appendMessage("assistant", `Error: ${res.error}`);
    scrollToBottom();
    btnSendEl.disabled = false;
    return;
  }

  // Update session info from response
  if (res.session_id) {
    currentSessionId = res.session_id;
  }

  // Show guardrail trace
  if (res.trace && res.trace.length > 0) {
    showGuardrailTrace(res.trace);
    showGuardrailPanel(true);
  }

  // ── Show privacy/compression info ──
  if (res.privacy) {
    const p = res.privacy;
    let infoParts = [];
    if (p.secrets_stripped > 0) {
      infoParts.push(`🔒 ${p.secrets_stripped} secret(s) stripped`);
    }
    const c = p.compression;
    if (c && c.tokens_saved > 0) {
      infoParts.push(`💾 ${c.tokens_saved} tokens saved (${c.savings_percent}%)`);
    }
    if (infoParts.length > 0) {
      appendPrivacyNotice(infoParts.join(" · "));
    }
  }

  // Append assistant response
  appendMessage("assistant", res.response);
  scrollToBottom();
  btnSendEl.disabled = false;
}

function appendPrivacyNotice(message) {
  const el = document.createElement("div");
  el.className = "privacy-notice";
  el.style.cssText = `
    font-size: 11px;
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 20px;
    background: rgba(16, 163, 127, 0.1);
    border: 1px solid rgba(16, 163, 127, 0.2);
    margin: 0 12px 12px 52px;
    display: inline-block;
    max-width: 700px;
  `;
  el.textContent = message;
  messagesContainerEl.appendChild(el);
  scrollToBottom();
}

function appendMessage(role, content, toolCalls, toolResults, timestamp) {
  const msgEl = document.createElement("div");
  msgEl.className = `message ${role}`;

  const avatar = role === "user" ? "U" : "A";
  const timeStr = timestamp ? new Date(timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";

  let html = `
    <div class="message-avatar ${role}">${avatar}</div>
    <div class="message-content">
      <div class="message-bubble ${role}">${escapeHtml(content)}</div>
  `;

  if (toolCalls && toolCalls.length > 0) {
    html += `<div class="tool-call">
      <div class="tool-call-header">🔧 Tool: ${escapeHtml(toolCalls[0].name)}</div>
      <div class="tool-call-content">${JSON.stringify(toolCalls[0].arguments || {}, null, 2)}</div>
    </div>`;
  }

  if (toolResults && toolResults.length > 0) {
    const result = toolResults[0];
    let resultHtml = `<div class="tool-call">
      <div class="tool-call-header">📋 Result</div>
      <div class="tool-call-content">`;
    if (result.blocked) {
      resultHtml += `<span style="color:var(--danger)">BLOCKED: ${escapeHtml(result.reason)}</span>`;
    } else if (result.error) {
      resultHtml += `<span style="color:var(--danger)">ERROR: ${escapeHtml(result.error)}</span>`;
    } else if (result.safe !== undefined) {
      resultHtml += `<span style="color:${result.safe ? 'var(--accent)' : 'var(--danger)'}">${
        result.safe ? '✓ SAFE' : '✗ BLOCKED'}</span>: ${escapeHtml(result.reason || '')}<br>`;
      if (result.sanitized) {
        resultHtml += `Sanitized: ${escapeHtml(result.sanitized)}`;
      }
    } else {
      resultHtml += escapeHtml(JSON.stringify(result, null, 2));
    }
    resultHtml += `</div></div>`;
    html += resultHtml;
  }

  html += `<div class="message-meta">
    <span class="tag">${role}</span>
    ${timeStr ? `<span>${timeStr}</span>` : ""}
  </div></div>`;

  msgEl.innerHTML = html;
  messagesContainerEl.appendChild(msgEl);
  return msgEl;
}

function insertPrompt(text) {
  messageInputEl.value = text;
  messageInputEl.focus();
  adjustTextarea(messageInputEl);
  btnSendEl.disabled = false;
}

// ── UI helpers ──
function showTyping(show) {
  typingIndicatorEl.classList.toggle("hidden", !show);
  if (show) scrollToBottom();
}

function adjustTextarea(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 160) + "px";
}

function scrollToBottom() {
  setTimeout(() => {
    messagesContainerEl.scrollTop = messagesContainerEl.scrollHeight;
  }, 50);
}

function showGuardrailPanel(show) {
  guardrailPanelEl.classList.toggle("hidden", !show);
}

function showGuardrailTrace(trace) {
  guardrailTraceEl.innerHTML = "";
  for (const entry of trace) {
    const div = document.createElement("div");
    div.className = "trace-entry";
    div.innerHTML = `
      <span class="step">${escapeHtml(entry.step)}</span>
      <div class="detail">${escapeHtml(JSON.stringify(entry.result, null, 2))}</div>
    `;
    guardrailTraceEl.appendChild(div);
  }
  guardrailTraceEl.scrollTop = guardrailTraceEl.scrollHeight;
}

function updateAgentModeBadge() {
  chatSubtitleEl.textContent = `Agent mode: ${agentMode ? "on" : "off"} · Model: ${currentModel}`;
}

function showStatusMessage(msg, kind) {
  const el = document.getElementById("statusText");
  const dot = document.getElementById("statusDot");
  if (el) el.textContent = msg;
  if (dot) dot.style.background = kind === "warn" ? "var(--warn)" : "var(--ok)";
  setTimeout(() => {
    if (el) el.textContent = "Authenticated";
    if (dot) dot.style.background = "var(--accent)";
  }, 3000);
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>\"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ── Providers ──
async function loadProviders() {
  const res = await fetchJson("/api/chat/tools");
  if (!res.error) {
    // Tools loaded — could display in a tools panel
  }
}

// ── Event listeners ──
document.addEventListener("DOMContentLoaded", async () => {
  // Check auth first
  const authed = await checkAuth();
  if (!authed) return;

  await loadSessions();
  await loadProviders();

  // New chat
  btnNewChatEl.onclick = createSession;

  // Send on button click
  btnSendEl.onclick = sendMessage;

  // Send on Enter (not Shift+Enter)
  messageInputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // Auto-resize textarea
  messageInputEl.addEventListener("input", () => {
    adjustTextarea(messageInputEl);
    btnSendEl.disabled = !messageInputEl.value.trim() || !currentSessionId;
  });

  // Model change
  modelSelectEl.onchange = (e) => {
    currentModel = e.target.value;
    chatSubtitleEl.textContent = `Agent mode: ${agentMode ? "on" : "off"} · Model: ${currentModel}`;
  };

  // Agent mode toggle
  agentModeToggleEl.onchange = (e) => {
    agentMode = e.target.checked;
    chatSubtitleEl.textContent = `Agent mode: ${agentMode ? "on" : "off"} · Model: ${currentModel}`;
    updateAgentModeBadge();
  };

  // Compression level change
  if (compressionLevelEl) {
    compressionLevelEl.onchange = (e) => {
      compressionLevel = e.target.value;
    };
  }

  // Close guardrail panel
  btnCloseGuardrailEl.onclick = () => showGuardrailPanel(false);

  // Load existing session from URL hash or create new
  const hash = location.hash.replace("#", "");
  if (hash) {
    loadSession(hash);
  } else {
    // Load most recent session or create one
    const res = fetchJson("/api/chat/sessions").then(sessionsRes => {
      if (!sessionsRes.error && sessionsRes.sessions && sessionsRes.sessions.length > 0) {
        loadSession(sessionsRes.sessions[0].id);
      } else {
        createSession();
      }
    });
  }

  // Initialize neuron network for thinking animation
  initNeuronNetwork();
});