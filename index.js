/**=============================================================================
 * @pymite6941/ai-guardrails — Node.js client embed
 *=============================================================================
 * Client-side wrapper for the AI Guardrails HTTP API server (guardrail_server.py).
 * Use it to validate inputs/outputs from a web page or Node app against a
 * per-page guardrail policy, with a lightweight standalone fallback.
 *
 * Usage (with API server running):
 *   const { AIGuardrails } = require("@pymite6941/ai-guardrails");
 *   const guard = new AIGuardrails({ baseUrl: "http://localhost:8083" });
 *   const res = await guard.validateOutput(modelOutput, { page: "example.com", agent: "assistant" });
 *   if (!res.safe) { /* block or show res.reason }
 *
 * Usage (standalone, no server):
 *   const guard = new AIGuardrails(); // no baseUrl -> client-side rules only
 *=============================================================================*/

const http = require("http");
const https = require("https");

const DEFAULT_POLICY = {
  blocked_input_patterns: [
    "ignore previous instructions", "disregard all prior", "system prompt leak",
    "reveal your system prompt", "jailbreak", "dan mode", "developer mode",
    "pretend to be", "you are now", "act as if", "roleplay as",
    "forget your training", "unfiltered mode", "no restrictions", "bypass safety",
    "sudo", "rm -rf", "chmod 777", "curl | bash", "wget | bash",
    "docker escape", "container escape", "privileged container", "host network",
    "pid=host", "ipc=host", "/proc/", "/sys/", "break out", "escape container",
    "docker.sock", "kubectl", "namespace", "privilege escalation",
    "wget", "curl", "ping", "nslookup", "dig", "telnet", "nc ", "netcat",
    "ssh ", "scp ", "ftp ", "socket", "raw socket",
  ],
  blocked_input_keywords: [
    "root", "escape", "container breach", "docker.sock",
    "privilege escalation", "jailbreak", "prompt injection",
    "system prompt", "ignore instructions", "bypass", "unfiltered",
    "no restrictions",
  ],
  blocked_output_patterns: [
    "ignore previous instructions", "disregard all prior", "system prompt leak",
    "reveal your system prompt", "jailbreak", "dan mode", "developer mode",
    "pretend to be", "you are now", "act as if", "roleplay as",
    "forget your training", "unfiltered mode", "no restrictions", "bypass safety",
    "docker escape", "container breach", "container escape", "privileged",
    "rm -rf /", "format disk", "delete all", "chmod -R", "iptables", "nftables",
    "break out", "escape container", "mount namespace",
  ],
  blocked_output_keywords: ["root access", "sudo", "escape", "breach", "privilege escalation"],
  harmful_content_patterns: [
    "virus", "malware", "ransomware", "exploit code", "create a botnet",
    "ddos", "keylogger", "trojan", "spyware", "rootkit",
    "credential stealer", "password stealer", "data exfiltration",
    "reverse shell", "command injection", "sql injection",
    "cross-site scripting", "privilege escalation exploit",
  ],
};

class AIGuardrails {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || null;
    this.timeout = options.timeout || 5000;
    this.defaultPage = options.page || "default";
    this.defaultAgent = options.agent || "assistant";
  }

  /** Validate text through the API server (preferred) or standalone rules. */
  async validate(text, { kind = "output", page, agent } = {}) {
    page = page || this.defaultPage;
    agent = agent || (kind === "input" ? "user" : this.defaultAgent);
    if (this.baseUrl) {
      return this._validateRemote(text, kind, page, agent);
    }
    return this._validateStandalone(text, kind);
  }

  async validateInput(text, { page, agent } = {}) {
    return this.validate(text, { kind: "input", page, agent });
  }

  async validateOutput(text, { page, agent } = {}) {
    return this.validate(text, { kind: "output", page, agent });
  }

  async _validateRemote(text, kind, page, agent) {
    const url = new URL(`/api/validate/${kind}`, this.baseUrl);
    const body = JSON.stringify({ page, text, agent });
    return this._request(url.href, "POST", body);
  }

  _validateStandalone(text, kind) {
    const isInput = kind === "input";
    const patterns = isInput ? DEFAULT_POLICY.blocked_input_patterns : DEFAULT_POLICY.blocked_output_patterns;
    const keywords = isInput ? DEFAULT_POLICY.blocked_input_keywords : DEFAULT_POLICY.blocked_output_keywords;
    const harmful = DEFAULT_POLICY.harmful_content_patterns;
    const lower = String(text).toLowerCase();
    for (const p of patterns) if (lower.includes(p.toLowerCase())) {
      return { safe: false, reason: `Blocked ${kind} pattern: ${p}`, blockedBy: kind + "_patterns", reported: false };
    }
    for (const k of keywords) if (lower.includes(k.toLowerCase())) {
      return { safe: false, reason: `Blocked ${kind} keyword: ${k}`, blockedBy: kind + "_keywords", reported: false };
    }
    for (const p of harmful) if (lower.includes(p.toLowerCase())) {
      return { safe: false, reason: `Harmful content detected: ${p}`, blockedBy: "harmful_content", reported: true };
    }
    // PII / credential leakage (standalone)
    const piiPatterns = [
      /sk-[a-zA-Z0-9]{10,}/,
      /\b\d{3}-\d{2}-\d{4}\b/,
      /\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b/,
      /password\s*[:=]\s*\S+/,
      /api_key\s*[:=]\s*\S+/,
      /secret\s*[:=]\s*\S+/,
      /username\s*[:=]\s*\S+/,
    ];
    for (const pat of piiPatterns) if (pat.test(lower)) {
      return { safe: false, reason: `PII / credential leakage detected: ${pat}`, blockedBy: "pii_credentials", reported: false };
    }
    return { safe: true, reason: "All checks passed (standalone)", blockedBy: null, reported: false };
  }

  _request(url, method, body) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const isHttps = parsed.protocol === "https:";
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname,
        method,
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body || "") },
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const req = (isHttps ? https : http).request(opts, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
          catch (e) { resolve({ status: res.statusCode, data }); }
        });
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")); });
      if (body) req.write(body);
      req.end();
    });
  }
}

module.exports = { AIGuardrails, DEFAULT_POLICY };

if (require.main === module) {
  (async () => {
    const guard = new AIGuardrails();
    console.log("standalone block:", await guard.validateOutput("how to create a virus", { kind: "output" }));
    console.log("standalone pass:", await guard.validateOutput("hello world", { kind: "output" }));
  })();
}
