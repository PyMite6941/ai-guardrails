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

// ── Messaging ──
async function sendMessage() {
  const text = messageInputEl.value.trim();
  if (!text || !currentSessionId) return;

  messageInputEl.value = "";
  messageInputEl.style.height = "auto";
  btnSendEl.disabled = true;

  // Append user message immediately
  const userMsg = appendMessage("user", text);
  scrollToBottom();
  showTyping(true);
  showGuardrailPanel(false);

  const res = await fetchJson("/api/chat/message", {
    method: "POST",
    body: JSON.stringify({
      session_id: currentSessionId,
      text,
      model: currentModel,
      agent_mode: agentMode,
    })
  });

  showTyping(false);

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

  // Append assistant response
  appendMessage("assistant", res.response);
  scrollToBottom();
  btnSendEl.disabled = false;
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

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, c => ({
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
});