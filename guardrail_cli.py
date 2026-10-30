#!/usr/bin/env python3
#=============================================================================
# guardrail_cli.py — AI Guardrails command-line control interface
#=============================================================================
# Modern, beginner-friendly CLI for controlling the AI Guardrails system.
# Uses color output and clear prompts. All commands also work via the web UI.
#
# Commands:
#   start [--host HOST] [--port PORT]   Start the API server
#   stop                                 Stop the API server
#   status                               Show system status
#   health [--port PORT]                 Check API health
#   password --set <pw>                  Set admin password (initial setup)
#   2fa setup                            Enable 2FA (shows QR URI + backup codes)
#   2fa status                           Show 2FA status
#   2fa disable                          Disable 2FA
#   emergency contain                    Stage 1: block ports + stop server
#   emergency container-stop             Stage 2: stop Docker containers
#   emergency logs-preserve              Stage 3: archive logs with SHA256
#   emergency shutdown                   Stage 4: full lock
#   emergency all                        All four stages
#   emergency reenable --pw <pw> --totp <code>  Re-enable with safety guards
#   emergency status                     Show emergency state
#   policies list                        List page policies
#   policies get <page>                  Get a page policy
#   validate input|output <page> <text>  Validate text through engine
#   kill-switch --reason <...>           Trigger kill switch
#   setup                                Interactive setup wizard (password + 2FA)
#=============================================================================

import json
import os
import sys
import subprocess
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardrail import GuardrailEngine
from guardrail_auth import (
    set_password, has_password,
    is_2fa_configured, enable_2fa, disable_2fa,
)
from guardrail_logging import get_logger
from guardrail_risk import get_tracker
from guardrail_canary import GuardrailCanary
from guardrail_modes import load_mode
from guardrail_models import (
    get_providers, get_provider, PROVIDERS, PROVIDER_API_KEY_ENV,
)

logger = get_logger("cli")

DIR = os.path.dirname(os.path.abspath(__file__))
PIDFILE = os.path.join(DIR, "logs", "guardrail_server.pid")
LOGFILE = os.path.join(DIR, "logs", "guardrail_server.run.log")

# ── Color helpers ──
USE_COLOR = sys.stdout.isatty()

def _color(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)

def c_ok(t):   return _color("32", "✔ " + str(t))
def c_err(t):  return _color("31", "✘ " + str(t))
def c_info(t): return _color("36", "→ " + str(t))
def c_warn(t): return _color("33", "⚠ " + str(t))
def c_dim(t):  return _color("2", str(t))
def c_bold(t): return _color("1", str(t))

def ok(msg):   print(c_ok(msg))
def err(msg):  print(c_err(msg))
def info(msg): print(c_info(msg))
def warn(msg): print(c_warn(msg))
def bold(msg): print(c_bold(msg))


def cmd_start(args):
    """Start the API server."""
    host = args.get("--host", "127.0.0.1")
    port = args.get("--port", "8083")
    env = os.environ.copy()
    env["GUARDRAIL_HOST"] = host
    env["GUARDRAIL_PORT"] = port

    if os.path.exists(PIDFILE):
        try:
            with open(PIDFILE) as f:
                pid = int(f.read().strip())
            if pid > 0 and os.path.exists(f"/proc/{pid}"):
                warn(f"Server already running (pid {pid})")
                return
        except (ValueError, FileNotFoundError):
            pass

    os.makedirs(os.path.join(DIR, "logs"), exist_ok=True)
    log_f = open(LOGFILE, "ab")
    proc = subprocess.Popen(
        [sys.executable, "guardrail_server.py"],
        env=env,
        cwd=DIR,
        stdout=log_f,
        stderr=subprocess.STDOUT,
    )
    with open(PIDFILE, "w") as f:
        f.write(str(proc.pid))

    import urllib.request
    for i in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
            ok(f"Server started (pid {proc.pid})")
            info(f"  Web UI:    http://{host}:{port}/")
            info(f"  API:       http://{host}:{port}/api/*")
            info(f"  Stop:      python3 guardrail_cli.py stop")
            return
        except Exception:
            time.sleep(0.5)
    err("Server did not become healthy. Check logs/guardrail_server.run.log")


def cmd_stop(args):
    """Stop the API server."""
    if not os.path.exists(PIDFILE):
        warn("No pidfile; server not tracked")
        return
    with open(PIDFILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 15)
        for _ in range(10):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.5)
        else:
            os.kill(pid, 9)
        ok(f"Stopped server (pid {pid})")
    except ProcessLookupError:
        warn("Server not running (stale pidfile)")
    finally:
        try:
            os.remove(PIDFILE)
        except FileNotFoundError:
            pass


def cmd_status(args):
    """Show system status."""
    engine = GuardrailEngine()
    stats = engine.get_stats()
    mode = load_mode()
    tracker = get_tracker()
    risk_states = tracker.all_states()
    canary = GuardrailCanary(engine=engine)

    bold("AI Guardrails — System Status")
    print()
    print(f"  Mode:           {c_bold(mode.value)}")
    pid = _get_pid()
    print(f"  Server:         {c_ok('running') if pid else c_err('stopped')}")
    print(f"  Total checks:   {stats['total']}")
    print(f"  Passed:         {c_ok(str(stats['passed']))}")
    print(f"  Blocked:        {c_err(str(stats['blocked']))}")
    print(f"  Effectiveness:  {stats['effectiveness']}%")
    print(f"  Pages:          {len(stats['by_page'])}")
    print(f"  2FA configured: {c_ok('yes') if is_2fa_configured() else c_warn('no')}")
    auth_configured = bool(os.environ.get('GUARDRAIL_ADMIN_PASSWORD') or os.environ.get('GUARDRAIL_API_KEY') or has_password())
    print(f"  Auth configured: {c_ok('yes') if auth_configured else c_warn('no')}")
    print()
    bold("Risk conversations")
    for r in risk_states:
        level_color = c_ok if r['level'] == 'low' else (c_warn if r['level'] in ('medium', 'high') else c_err)
        print(f"  {r['session_id']}::{r['page_id']}  level={level_color(r['level'])}  score={r['score']}  blocked={r['blocked_count']}")
    print()
    bold("Canary")
    cs = canary.get_state()
    print(f"  Last run:           {cs.get('last_run', 'never')}")
    print(f"  Consecutive failures: {cs.get('consecutive_failures', 0)}")


def cmd_health(args):
    """Check API health."""
    import urllib.request
    port = args.get("--port", "8083")
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=5)
        data = json.loads(resp.read())
        print(json.dumps(data, indent=2))
    except Exception as e:
        err(f"Health check failed: {e}")
        sys.exit(1)


def cmd_password(args):
    """Set admin password."""
    pw = args.get("--set")
    if not pw:
        err("Usage: guardrail_cli.py password --set <password>")
        sys.exit(1)
    try:
        result = set_password(pw)
        ok(result["message"])
    except ValueError as e:
        err(str(e))
        sys.exit(1)


def cmd_2fa(args):
    """2FA management."""
    sub = args.get("<sub>", "")
    if sub == "setup":
        if not has_password():
            err("Admin password must be set before enabling 2FA.")
            sys.exit(1)
        result = enable_2fa()
        ok(result["message"])
        print()
        bold("Secret key:")
        print(f"  {result['secret']}")
        bold("Backup codes (save these!):")
        print("  " + "  ".join(result["backup_codes"]))
        print()
        bold("OTPAuth URI (for QR code scanner):")
        print(f"  {result['uri']}")
    elif sub == "status":
        print(f"  2FA configured: {c_ok('yes') if is_2fa_configured() else c_warn('no')}")
        print(f"  2FA env enabled: {c_ok('yes') if os.environ.get('GUARDRAIL_2FA_ENABLED', 'false').lower() == 'true' else c_warn('no')}")
    elif sub == "disable":
        result = disable_2fa()
        ok(result["message"])
    else:
        err("Usage: guardrail_cli.py 2fa {setup|status|disable}")
        sys.exit(1)


def cmd_emergency(args):
    """Emergency override."""
    sub = args.get("<sub>", "")
    script = os.path.join(DIR, "scripts", "emergency-override.sh")
    valid = {"contain", "container-stop", "logs-preserve", "shutdown", "all", "status"}
    if sub == "reenable":
        pw = args.get("--pw", "")
        totp = args.get("--totp", "")
        backup = args.get("--backup", "")
        cmd_list = ["bash", script, "reenable"]
        if pw:
            cmd_list += ["--password", pw]
        if totp:
            cmd_list += ["--totp", totp]
        if backup:
            cmd_list += ["--backup", backup]
        result = subprocess.run(cmd_list, capture_output=True, text=True)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)
    elif sub in valid:
        result = subprocess.run(["bash", script, sub], capture_output=True, text=True)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)
    else:
        err("Usage: guardrail_cli.py emergency {contain|container-stop|logs-preserve|shutdown|all|reenable|status}")
        sys.exit(1)


def cmd_policies(args):
    """Policy management."""
    sub = args.get("<sub>", "")
    engine = GuardrailEngine()
    if sub == "list":
        pages = engine.list_pages()
        if not pages:
            warn("No pages configured")
        for p in pages:
            print(f"  {p}")
    elif sub == "get":
        page = args.get("<page>", "default")
        policy = engine.get_policy(page)
        print(json.dumps(policy.to_dict(), indent=2))
    else:
        err("Usage: guardrail_cli.py policies {list|get <page>}")
        sys.exit(1)


def cmd_validate(args):
    """Validate input or output."""
    kind = args.get("<kind>", "")
    page = args.get("<page>", "default")
    text = args.get("<text>", "")
    engine = GuardrailEngine()
    if kind == "input":
        result = engine.validate_input(text, page, "cli")
    elif kind == "output":
        result = engine.validate_output(text, page, "cli")
    else:
        err("Usage: guardrail_cli.py validate input|output <page> <text>")
        sys.exit(1)
    print(json.dumps(result, indent=2))


def cmd_kill_switch(args):
    """Trigger kill switch."""
    script = os.path.join(DIR, "scripts", "kill-switch.sh")
    reason = args.get("--reason", "CLI-triggered kill switch")
    result = subprocess.run(["bash", script, reason], capture_output=True, text=True)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    sys.exit(result.returncode)


def cmd_models(args):
    """Model provider selection."""
    sub = args.get("<sub>", "")
    if sub == "list":
        providers = get_providers()
        bold("Available Model Providers")
        print()
        for p in providers:
            key_color = c_ok(p["key"]) if p["api_key_configured"] or not p["api_key_required"] else c_warn(p["key"])
            type_tag = c_dim(f"[{p['type']}]")
            print(f"  {key_color} {type_tag}")
            print(f"    {p['name']} — {p['description']}")
            print(f"    Default: {p['default_model']} @ {p['default_base_url']}")
            if p["api_key_required"]:
                status = c_ok("key configured") if p["api_key_configured"] else c_warn("API key NOT set")
                print(f"    API key: {status}")
            print()
    elif sub == "select":
        provider_key = args.get("<provider>", "")
        if not provider_key:
            err("Usage: guardrail_cli.py models select <provider>")
            print()
            bold("Available providers:")
            for p in get_providers():
                print(f"  {p['key']} — {p['name']}")
            sys.exit(1)
        if provider_key not in PROVIDERS:
            err(f"Unknown provider: {provider_key}")
            sys.exit(1)
        provider = get_provider(provider_key)
        if provider and provider["api_key_required"]:
            env_name = PROVIDER_API_KEY_ENV.get(provider_key, "")
            if not os.environ.get(env_name, ""):
                err(f"API key required for {provider['name']}. Set {env_name} in .env or environment.")
                sys.exit(1)
        ok(f"Model provider set to {provider['name']} ({provider_key})")
        info("This selection applies to the current CLI session only.")
        info("For the web UI, select the provider in the Model panel after logging in.")
    elif sub == "status":
        from guardrail_models import get_session_provider
        # For CLI, show what's in environment
        bold("Current Model Configuration")
        print()
        for p in get_providers():
            env_name = PROVIDER_API_KEY_ENV.get(p["key"], "")
            key_set = bool(os.environ.get(env_name, "")) if p["api_key_required"] else True
            status = c_ok("✓") if key_set else c_warn("✗")
            print(f"  {status} {p['name']} ({p['key']})")
    else:
        err("Usage: guardrail_cli.py models {list|select <provider>|status}")
        sys.exit(1)


def _get_pid():
    if os.path.exists(PIDFILE):
        try:
            with open(PIDFILE) as f:
                return f.read().strip()
        except Exception:
            pass
    return None


def parse_args(argv):
    """Parse CLI arguments into a dict."""
    args = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--"):
            key = arg
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                args[key] = argv[i + 1]
                i += 2
            else:
                args[key] = "true"
                i += 1
        elif arg.startswith("<"):
            key = arg
            args[key] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
        else:
            args["<cmd>"] = arg
            i += 1
    return args


COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "status": cmd_status,
    "health": cmd_health,
    "password": cmd_password,
    "2fa": cmd_2fa,
    "emergency": cmd_emergency,
    "policies": cmd_policies,
    "validate": cmd_validate,
    "kill-switch": cmd_kill_switch,
    "models": cmd_models,
    "setup": None,  # handled inline below
}


def cmd_setup(args):
    """Interactive setup wizard."""
    bold("AI Guardrails — Setup Wizard")
    print()
    print("This wizard will help you set up your admin password and 2FA.")
    print("Every second counts in an emergency — take a moment to secure your system now.")
    print()

    # Step 1: Password
    bold("Step 1 — Admin password")
    print("Create a strong password for the web UI and API.")
    print("It is stored as a PBKDF2-HMAC-SHA256 hash — never in plain text.")
    print()
    while True:
        try:
            pw = input("  Enter password (min 8 chars, mixed case, digit, symbol): ").strip()
        except EOFError:
            err("\nSetup cancelled.")
            sys.exit(1)
        if len(pw) < 8:
            warn("  Password must be at least 8 characters.")
            continue
        if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            warn("  Use uppercase, lowercase, numbers, and a symbol.")
            continue
        break

    try:
        set_password(pw)
        ok("Password set successfully.")
    except ValueError as e:
        err(str(e))
        sys.exit(1)

    # Step 2: 2FA
    print()
    bold("Step 2 — Two-factor authentication (2FA)")
    print("Add a second layer of protection. Scan the QR code with Google Authenticator,")
    print("Authy, or any TOTP app. Save your backup codes — they cannot be recovered.")
    print()

    try:
        input("  Press Enter to generate 2FA...")
    except EOFError:
        err("\nSetup cancelled.")
        sys.exit(1)

    result = enable_2fa()
    ok(result["message"])
    print()
    bold("Secret key:")
    print(f"  {result['secret']}")
    bold("Backup codes (save these!):")
    print("  " + "  ".join(result["backup_codes"]))
    print()
    bold("OTPAuth URI (for QR code scanner):")
    print(f"  {result['uri']}")
    print()

    # Confirm backup codes saved
    while True:
        try:
            saved = input("  Have you saved your backup codes somewhere safe? (yes/no): ").strip().lower()
        except EOFError:
            err("\nSetup cancelled.")
            sys.exit(1)
        if saved in ("yes", "y"):
            break
        elif saved in ("no", "n"):
            warn("  Please save your backup codes before continuing.")
            continue
        else:
            warn("  Please answer yes or no.")
            continue

    ok("Setup complete!")
    print()
    info("Next steps:")
    print(f"  {c_bold('python3 guardrail_cli.py start')}    Start the API server")
    print(f"  {c_bold('python3 guardrail_cli.py status')}     Check system status")
    print(f"  Open http://127.0.0.1:8083/ in your browser for the web UI")

    # Step 3: Model provider configuration (local + cloud + custom domain)
    print()
    bold("Step 3 — Model Provider (AI model connection)")
    print("Connect an AI model for the outside monitor, classifier, and trusted model.")
    print("You can use a local provider (Ollama, etc.) or a cloud provider (Nebius,")
    print("Nemus/NVIDIA, OpenRouter, Groq, OpenAI) or your own domain.")
    print()
    try:
        use_model = input("  Configure a model provider now? (yes/no): ").strip().lower()
    except EOFError:
        err("\nSetup cancelled.")
        sys.exit(1)
    if use_model not in ("yes", "y"):
        info("  Skipped. You can add a model provider later via the web UI or CLI.")
        info("  Run: python3 guardrail_cli.py models list  (to see providers)")
        return

    # List available providers
    print()
    bold("Available providers:")
    providers = get_providers()
    for i, p in enumerate(providers, 1):
        key_status = ""
        if p["api_key_required"]:
            key_status = " [key configured]" if p["api_key_configured"] else " [API key needed]"
        print(f"  {i}. {p['name']} ({p['key']}) — {p['description']}{key_status}")
    print()

    # Get provider selection
    while True:
        try:
            choice = input("  Select provider number (or enter custom domain): ").strip()
        except EOFError:
            err("\nSetup cancelled.")
            sys.exit(1)
        if not choice:
            warn("  Please enter a provider number or domain.")
            continue
        break

    # Check if it's a number (provider index) or a custom domain
    provider_key = None
    custom_domain = None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(providers):
            provider_key = providers[idx]["key"]
        else:
            warn(f"  Invalid provider number. Please enter 1-{len(providers)}.")
            return
    except ValueError:
        # It's a custom domain
        custom_domain = choice
        # Validate the domain
        from guardrail_models import validate_model_base_url
        domain_validation = validate_model_base_url(custom_domain)
        if not domain_validation["valid"]:
            warn(f"  Invalid domain: {domain_validation['reason']}")
            info("  Example: https://models.yourdomain.com/v1/")
            return
        ok(f"  Domain validated: {domain_validation['domain']} ({domain_validation['scheme']})")
        if domain_validation["resolved_ips"]:
            info(f"  Resolved IPs: {{', '.join(domain_validation['resolved_ips'])}}")

    # Get API key if needed
    api_key = None
    if provider_key and get_provider(provider_key).get("api_key_required"):
        env_name = PROVIDER_API_KEY_ENV.get(provider_key, "")
        existing_key = os.environ.get(env_name, "")
        if existing_key:
            info(f"  API key already configured via {env_name}.")
            api_key = existing_key
        else:
            try:
                api_key = input(f"  Enter API key for {get_provider(provider_key)['name']}: ").strip()
            except EOFError:
                err("\nSetup cancelled.")
                sys.exit(1)
    elif custom_domain:
        try:
            api_key = input("  Enter API key for your domain (or leave blank if none): ").strip()
        except EOFError:
            err("\nSetup cancelled.")
            sys.exit(1)

    # Get model name
    try:
        model = input("  Enter model name (or press Enter for default): ").strip()
    except EOFError:
        err("\nSetup cancelled.")
        sys.exit(1)

    # Get endpoint
    try:
        endpoint = input("  Enter endpoint path (or press Enter for default): ").strip()
    except EOFError:
        err("\nSetup cancelled.")
        sys.exit(1)

    # Build configuration
    env_path = os.path.join(DIR, ".env")
    env_lines = []
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            env_lines = f.readlines()

    # Remove existing model-related lines
    keys_to_remove = [
        "GUARDRAIL_OUTSIDE_MODEL_BASE_URL=",
        "GUARDRAIL_OUTSIDE_MODEL_MODEL=",
        "GUARDRAIL_OUTSIDE_MODEL_ENDPOINT=",
        "GUARDRAIL_OUTSIDE_MODEL_API_KEY=",
        "GUARDRAIL_CUSTOM_DOMAIN_BASE_URL=",
        "GUARDRAIL_CUSTOM_DOMAIN_MODEL=",
        "GUARDRAIL_CUSTOM_DOMAIN_ENDPOINT=",
        "GUARDRAIL_CUSTOM_DOMAIN_API_KEY=",
    ]
    env_lines = [l for l in env_lines if not any(l.startswith(k) for k in keys_to_remove)]

    if custom_domain:
        # Custom domain configuration
        env_lines.append(f"GUARDRAIL_CUSTOM_DOMAIN_BASE_URL={custom_domain}\\n")
        env_lines.append(f"GUARDRAIL_CUSTOM_DOMAIN_MODEL={model or 'custom-model'}\\n")
        env_lines.append(f"GUARDRAIL_CUSTOM_DOMAIN_ENDPOINT={endpoint or 'chat/completions'}\\n")
        if api_key:
            env_lines.append(f"GUARDRAIL_CUSTOM_DOMAIN_API_KEY={api_key}\\n")
        ok(f"  Custom domain configured: {custom_domain}")
    elif provider_key:
        provider = get_provider(provider_key)
        provider_key_env = PROVIDER_API_KEY_ENV.get(provider_key, "")
        env_lines.append(f"GUARDRAIL_OUTSIDE_MODEL_BASE_URL={provider['default_base_url']}\\n")
        env_lines.append(f"GUARDRAIL_OUTSIDE_MODEL_MODEL={model or provider['default_model']}\\n")
        env_lines.append(f"GUARDRAIL_OUTSIDE_MODEL_ENDPOINT={endpoint or provider['default_endpoint']}\\n")
        if api_key:
            env_lines.append(f"{provider_key_env}={api_key}\\n")
        ok(f"  Provider configured: {provider['name']}")

    with open(env_path, "w") as f:
        f.writelines(env_lines)

    ok("Model provider saved to .env")
    info("  Source it before starting: source .env && python3 guardrail_cli.py start")
    info("  Then select the provider in the web UI under Model Provider settings.")



def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    rest = sys.argv[2:]

    if cmd not in COMMANDS and cmd != "setup":
        err(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

    args = parse_args(rest)
    args["<cmd>"] = cmd

    if cmd == "setup":
        cmd_setup(args)
        return

    # Handle subcommands (2fa setup, emergency contain, models select, etc.)
    if cmd in ("2fa", "emergency", "policies", "validate", "models"):
        if rest:
            args["<sub>"] = rest[0]
            if cmd == "validate" and len(rest) >= 2:
                args["<kind>"] = rest[0]
                args["<page>"] = rest[1] if len(rest) > 1 else "default"
                args["<text>"] = rest[2] if len(rest) > 2 else ""
            if cmd == "models" and len(rest) >= 2:
                args["<provider>"] = rest[1]

    COMMANDS[cmd](args)


if __name__ == "__main__":
    main()
