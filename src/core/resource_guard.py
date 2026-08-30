# -*- coding: utf-8 -*-
"""
Resource Guard
==============
Auto-sizes safe LLM concurrency to whatever RAM is actually present on the
machine this is running on, and monitors live memory pressure so the app
degrades gracefully (warn, then refuse new work) instead of letting the OS
OOM-killer take down the whole stack (Postgres/Redis/API included) under
memory pressure.

Same code auto-scales correctly whether deployed on a 16GB customer box or a
32GB one -- no per-deployment manual tuning required. Every constant here can
still be overridden via env var for an operator who wants to hand-tune it.

Sizing is calibrated for the Gemma 4 E4B (Q4_K_M) model shipped with this app:
~5GB model weights + ~0.3GB embedding model + ~2.5GB OS/Postgres/Redis/API
baseline ~= 8GB fixed overhead, plus ~2.5GB KV cache per additional
full-context (131k token) concurrent slot. If a different model is swapped
in, override RESOURCE_GUARD_FIXED_OVERHEAD_GB / RESOURCE_GUARD_PER_SLOT_GB.
"""
import os

try:
    import psutil
except ImportError:
    psutil = None

# These must stay in sync with the -np auto-detection formula in llm_client.py:
# model_gb=4.0, slot_gb=0.5 — if you change one, change both.
FIXED_OVERHEAD_GB = float(os.environ.get("RESOURCE_GUARD_FIXED_OVERHEAD_GB", "4.5"))  # model(4GB) + OS/Postgres/Redis(0.5GB)
# Per-slot KV cost is DERIVED from the context each slot is given, not a flat
# figure. It used to be a hardcoded 0.5GB "per slot at -c 32768" -- correct only
# while the context stayed at that exact value. Raising the context with a flat
# constant would let this over-provision slots and OOM the box, so the same
# inputs docker/llm-entrypoint.sh uses are mirrored here (keep the two in sync).
# An explicit RESOURCE_GUARD_PER_SLOT_GB still wins, for hand-tuning.
MIN_CTX_PER_REQUEST = int(os.environ.get("MIN_CTX_PER_REQUEST", "16384"))
KV_GB_PER_1K_FP16 = float(os.environ.get("KV_GB_PER_1K_FP16", "0.12"))
_KV_BYTES_SCALE = 0.5 if os.environ.get("KV_QUANT", "1") == "1" else 1.0
_DERIVED_PER_SLOT_GB = (MIN_CTX_PER_REQUEST / 1024.0) * KV_GB_PER_1K_FP16 * _KV_BYTES_SCALE
PER_SLOT_GB = float(os.environ.get("RESOURCE_GUARD_PER_SLOT_GB", _DERIVED_PER_SLOT_GB))
SAFETY_MARGIN = float(os.environ.get("RESOURCE_GUARD_SAFETY_MARGIN", "0.85"))
MIN_SLOTS = 1

WARNING_AVAILABLE_PERCENT = float(os.environ.get("RESOURCE_GUARD_WARN_PERCENT", "2"))    # warn at <2% free
CRITICAL_AVAILABLE_PERCENT = float(os.environ.get("RESOURCE_GUARD_CRITICAL_PERCENT", "0.5"))  # block at <0.5% free
CRITICAL_ABSOLUTE_FLOOR_GB = float(os.environ.get("RESOURCE_GUARD_CRITICAL_FLOOR_GB", "0.10"))  # block if <0.10GB free


_CGROUP_V2_MAX = "/sys/fs/cgroup/memory.max"
_CGROUP_V2_CURRENT = "/sys/fs/cgroup/memory.current"
_CGROUP_V1_LIMIT = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
_CGROUP_V1_USAGE = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
# cgroup v1's "no limit" sentinel is a huge number, not a clean flag -- treat
# anything above this as "unlimited" and fall back to psutil's host reading.
_CGROUP_V1_UNLIMITED_THRESHOLD_BYTES = 1 << 62


def _cgroup_memory_limit_bytes():
    """Container memory limit (e.g. `docker run --memory`), if any is set.

    Matters because inside a container, psutil.virtual_memory() reports the
    HOST's total RAM, not this container's actual allowance -- if the
    operator capped the container below host RAM, sizing off the host figure
    would be dangerously optimistic. Returns None if no limit is set (native
    dev, or an uncapped container), in which case callers should fall back to
    psutil's host-level reading.
    """
    try:
        if os.path.exists(_CGROUP_V2_MAX):
            with open(_CGROUP_V2_MAX) as f:
                val = f.read().strip()
            if val != "max":
                return int(val)
            return None
        if os.path.exists(_CGROUP_V1_LIMIT):
            with open(_CGROUP_V1_LIMIT) as f:
                val = int(f.read().strip())
            if val < _CGROUP_V1_UNLIMITED_THRESHOLD_BYTES:
                return val
            return None
    except Exception:
        pass
    return None


def _cgroup_memory_usage_bytes():
    """Current memory usage *within this container*, if cgroup limits apply."""
    try:
        if os.path.exists(_CGROUP_V2_CURRENT):
            with open(_CGROUP_V2_CURRENT) as f:
                return int(f.read().strip())
        if os.path.exists(_CGROUP_V1_USAGE):
            with open(_CGROUP_V1_USAGE) as f:
                return int(f.read().strip())
    except Exception:
        pass
    return None


def _effective_total_and_available_bytes():
    """Resolves (total, available) bytes, preferring the container's cgroup
    limit over the host's full RAM when one is set. Returns (None, None) if
    neither cgroup nor psutil can answer.
    """
    cgroup_limit = _cgroup_memory_limit_bytes()

    host_total = None
    host_available = None
    if psutil is not None:
        try:
            vm = psutil.virtual_memory()
            host_total = vm.total
            host_available = vm.available
        except Exception:
            pass

    if cgroup_limit is not None:
        cgroup_usage = _cgroup_memory_usage_bytes()
        if cgroup_usage is not None:
            available = max(0, cgroup_limit - cgroup_usage)
            # A container's cgroup limit can technically exceed host RAM
            # (misconfigured or unset host-side limit) -- never report more
            # "total" than the host actually has, if that's known.
            total = min(cgroup_limit, host_total) if host_total else cgroup_limit
            return total, available

    return host_total, host_available


def detect_safe_concurrency_slots() -> int:
    """Auto-sizes safe concurrent LLM slot count from actual available RAM --
    this container's cgroup memory limit if one is set (Docker deployment),
    otherwise the host's total RAM (native dev).

    usable_gb = (total_ram * safety_margin) - fixed_overhead
    slots     = usable_gb // per_slot_cost, floored at MIN_SLOTS

    On a machine where memory stats can't be read at all, fails safe to
    MIN_SLOTS (1) rather than guessing high and risking an OOM crash.
    """
    total_bytes, _ = _effective_total_and_available_bytes()
    if total_bytes is None:
        return MIN_SLOTS

    total_gb = total_bytes / (1024 ** 3)
    usable_gb = (total_gb * SAFETY_MARGIN) - FIXED_OVERHEAD_GB
    if usable_gb <= 0:
        return MIN_SLOTS
    slots = int(usable_gb // PER_SLOT_GB)
    return max(MIN_SLOTS, slots)


def check_memory_pressure() -> dict:
    """Live memory-pressure check, called before starting new LLM work.

    Returns {"status": "OK" | "WARNING" | "CRITICAL", "available_gb": float,
    "available_percent": float, "reason": str|None}.

    OK       -> proceed normally.
    WARNING  -> proceed, but the caller should surface a visible warning.
    CRITICAL -> caller must refuse new work; already-running work should be
                allowed to finish rather than being killed outright.

    Prefers this container's cgroup memory limit/usage over the host's full
    RAM when one is set (Docker deployment) -- otherwise falls back to the
    host-level reading via psutil (native dev). If neither is available,
    fails OPEN (returns OK) rather than blocking every audit over a
    monitoring failure -- the caller is expected to log this distinctly from
    a genuine OK.
    """
    total_bytes, available_bytes = _effective_total_and_available_bytes()
    if total_bytes is None or available_bytes is None or total_bytes <= 0:
        return {
            "status": "OK", "available_gb": None, "available_percent": None,
            "reason": "memory stats unavailable -- resource guard disabled",
        }

    available_gb = available_bytes / (1024 ** 3)
    available_percent = 100.0 * available_bytes / total_bytes

    if available_percent < CRITICAL_AVAILABLE_PERCENT or available_gb < CRITICAL_ABSOLUTE_FLOOR_GB:
        return {
            "status": "CRITICAL",
            "available_gb": round(available_gb, 2),
            "available_percent": round(available_percent, 1),
            "reason": (
                f"Only {available_gb:.1f}GB RAM available ({available_percent:.0f}%). "
                f"System resources are critically low."
            ),
        }
    if available_percent < WARNING_AVAILABLE_PERCENT:
        return {
            "status": "WARNING",
            "available_gb": round(available_gb, 2),
            "available_percent": round(available_percent, 1),
            "reason": (
                f"Only {available_gb:.1f}GB RAM available ({available_percent:.0f}%). "
                f"System resources are getting tight."
            ),
        }
    return {
        "status": "OK",
        "available_gb": round(available_gb, 2),
        "available_percent": round(available_percent, 1),
        "reason": None,
    }
