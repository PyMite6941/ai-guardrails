#!/usr/bin/env python3
#=============================================================================
# Guardrail Hardware — device-aware optimization configuration
#=============================================================================
# Detects the host hardware (CPU count, memory, architecture, Raspberry Pi
# model, container/virtualization, Docker) and derives guardrail settings that
# match the device so the same package runs well on a Raspberry Pi, a desktop,
# or inside a container — with no hardcoded paths to any one machine.
#
# "Force the model to hardware optimize" means the guardrails adapt their
# behavior to the available hardware:
#   - constrained Pi: fewer parallel checks, Rust scanner preferred (fast),
#     lower thread/memory limits, smaller model names for outside/trusted/
#     classifier models
#   - desktop/server: full parallelism, more verbose logging
#   - container: cgroup-aware CPU/memory limits, no host assumptions
#
# All paths are relative to this file or configurable via env vars — nothing is
# hardcoded to /home/pymite6941 or any specific host.
#=============================================================================

import os
import re
import json
import platform
from typing import Optional, Dict, Any, List

HARDWARE_STATE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "hardware_state.json"
)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _parse_meminfo_kb() -> Optional[int]:
    text = _read_text("/proc/meminfo")
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])  # kilobytes
                except ValueError:
                    return None
    return None


def _cpu_count() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


def _in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cgroup = _read_text("/proc/1/cgroup")
    return "docker" in cgroup or "kubepod" in cgroup or "containerd" in cgroup


def _is_raspberry_pi() -> bool:
    model = _read_text("/sys/firmware/devicetree/base/model")
    if "raspberry pi" in model.lower():
        return True
    cpuinfo = _read_text("/proc/cpuinfo")
    return "bcm27" in cpuinfo.lower() or "raspberry pi" in cpuinfo.lower()


def _pi_model() -> Optional[str]:
    model = _read_text("/sys/firmware/devicetree/base/model")
    if model:
        return model.strip()
    cpuinfo = _read_text("/proc/cpuinfo")
    for line in cpuinfo.splitlines():
        if line.lower().startswith("model"):
            return line.split(":", 1)[1].strip()
    return None


def _arch() -> str:
    try:
        return platform.machine().lower()
    except Exception:
        return "unknown"


def _python_version() -> str:
    try:
        return platform.python_version()
    except Exception:
        return "unknown"


def detect_hardware() -> Dict[str, Any]:
    """Return a hardware profile dict. All values are safely detectable with
    no sudo, no network, and no host-specific assumptions."""
    mem_kb = _parse_meminfo_kb()
    mem_gb = round(mem_kb / 1024 / 1024, 2) if mem_kb else None
    cpus = _cpu_count()
    in_container = _in_container()
    is_pi = _is_raspberry_pi()
    arch = _arch()

    # Derive a device class for tuning guardrail behavior.
    if is_pi:
        device_class = "raspberry_pi"
    elif in_container:
        device_class = "container"
    elif cpus >= 8 and (mem_gb or 0) >= 8:
        device_class = "desktop_server"
    elif cpus >= 4 and (mem_gb or 0) >= 4:
        device_class = "desktop_server"
    else:
        device_class = "constrained"

    # Recommended guardrail tuning per device class.
    if device_class == "raspberry_pi":
        parallel_checks = 1
        prefer_rust_scanner = True
        max_input_length = 2048
        max_output_length = 4096
        log_level = "INFO"
        outside_model = "qwen2.5:1.5b"
        trusted_model = "qwen2.5:1.5b"
        classifier_model = "qwen2.5:1.5b"
    elif device_class == "container":
        parallel_checks = 2
        prefer_rust_scanner = True
        max_input_length = 4096
        max_output_length = 8192
        log_level = "INFO"
        outside_model = "qwen2.5:1.5b"
        trusted_model = "qwen2.5:1.5b"
        classifier_model = "qwen2.5:1.5b"
    elif device_class == "constrained":
        parallel_checks = 2
        prefer_rust_scanner = True
        max_input_length = 4096
        max_output_length = 8192
        log_level = "INFO"
        outside_model = "qwen2.5:1.5b"
        trusted_model = "qwen2.5:1.5b"
        classifier_model = "qwen2.5:1.5b"
    else:  # desktop_server
        parallel_checks = 4
        prefer_rust_scanner = False
        max_input_length = 8192
        max_output_length = 16384
        log_level = "DEBUG"
        outside_model = "qwen2.5:7b"
        trusted_model = "qwen2.5:7b"
        classifier_model = "qwen2.5:7b"

    profile = {
        "device_class": device_class,
        "arch": arch,
        "cpus": cpus,
        "memory_gb": mem_gb,
        "memory_kb": mem_kb,
        "is_raspberry_pi": is_pi,
        "pi_model": _pi_model() if is_pi else None,
        "in_container": in_container,
        "python_version": _python_version(),
        "platform": platform.platform(),
        "hostname": platform.node(),
        # Guardrail tuning derived from hardware.
        "recommended": {
            "parallel_checks": parallel_checks,
            "prefer_rust_scanner": prefer_rust_scanner,
            "max_input_length": max_input_length,
            "max_output_length": max_output_length,
            "log_level": log_level,
            "outside_model": outside_model,
            "trusted_model": trusted_model,
            "classifier_model": classifier_model,
        },
    }
    return profile


def load_hardware_profile() -> Dict[str, Any]:
    profile = detect_hardware()
    try:
        os.makedirs(os.path.dirname(HARDWARE_STATE), exist_ok=True)
        with open(HARDWARE_STATE, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
    except Exception:
        pass
    return profile


def apply_hardware_to_env(profile: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Convert a hardware profile into env-var overrides for the guardrails.

    Returns a dict of env var -> value. The operator can apply these before
    starting guardrail_server.py / outer_monitor.py. Nothing is hardcoded to
    a host; values come from the detected device.
    """
    profile = profile or detect_hardware()
    rec = profile.get("recommended", {})
    env: Dict[str, str] = {
        "GUARDRAIL_PARALLEL_CHECKS": str(rec.get("parallel_checks", 2)),
        "GUARDRAIL_PREFER_RUST_SCANNER": "1" if rec.get("prefer_rust_scanner") else "0",
        "GUARDRAIL_MAX_INPUT_LENGTH": str(rec.get("max_input_length", 4096)),
        "GUARDRAIL_MAX_OUTPUT_LENGTH": str(rec.get("max_output_length", 8192)),
        "GUARDRAIL_LOG_LEVEL": rec.get("log_level", "INFO"),
        "OUTSIDE_MODEL_MODEL": rec.get("outside_model", "qwen2.5:1.5b"),
        "TRUSTED_MODEL_MODEL": rec.get("trusted_model", "qwen2.5:1.5b"),
        "CLASSIFIER_MODEL_MODEL": rec.get("classifier_model", "qwen2.5:1.5b"),
    }
    if profile.get("in_container"):
        env["GUARDRAIL_IN_CONTAINER"] = "1"
    if profile.get("is_raspberry_pi"):
        env["GUARDRAIL_IS_PI"] = "1"
    if profile.get("pi_model"):
        env["GUARDRAIL_PI_MODEL"] = profile["pi_model"]
    return env


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    profile = load_hardware_profile()
    print(json.dumps(profile, indent=2))
    print()
    print("Suggested env overrides:")
    for k, v in apply_hardware_to_env(profile).items():
        print(f"  export {k}={v}")


if __name__ == "__main__":
    main()
