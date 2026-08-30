import threading
from collections import defaultdict

def _get_bg_store():
    if not hasattr(_get_bg_store, "_instance"):
        _get_bg_store._instance = {
            "results": {},
            "running": set(),
            "progress": {},
            "lock": threading.Lock(),
            "summaries": {}
        }
    return _get_bg_store._instance

_bg_store = _get_bg_store()
_bg_results = _bg_store["results"]
_bg_running = _bg_store["running"]
_bg_lock = _bg_store["lock"]

# Stop flags: bg_key -> True means "please stop this scan"
_bg_stop_flags: dict = {}

# Per-auditor session tracking: auditor_id -> set of active session_ids
# Limits how many concurrent audits one auditor can run simultaneously.
# The resource guard (src/core/resource_guard.py) is the real RAM safety net --
# this exists to stop accidental pile-up (double-clicks, multiple tabs) rather
# than to be a hard resource budget, so it's kept low.
_auditor_sessions: dict = defaultdict(set)  # {auditor_id: {session_id, ...}}
MAX_AUDITS_PER_AUDITOR = int(__import__('os').environ.get("MAX_AUDITS_PER_AUDITOR", "2"))

# Global cap across ALL auditors combined -- was previously set as an env var
# in run_all.bat (MAX_CONCURRENT_AUDITS) but never actually read anywhere, so
# it did nothing. llama-server's own request queue (via --cont-batching) has
# no size limit of its own: past LLM_SLOTS truly-parallel slots, every
# further request just queues silently with growing wait times, and a
# client's own request timeout can fire before its turn ever comes. This is
# the real backstop -- reject the (LLM_SLOTS*2 + 1)th+ request at the API
# level with a clear "system busy" message instead of letting it queue
# indefinitely toward a confusing timeout. Default of 16 assumes 8 LLM_SLOTS
# (8 truly concurrent + 8 queued as buffer); adjust if LLM_SLOTS changes.
def _default_concurrent_audits() -> int:
    """Global audit cap, sized from the machine's PHYSICAL cores.

    A fixed 16 was a guess about the hardware, and on a small box it admits far
    more work than the machine can finish. Measured on a 4-physical-core host:
    three concurrent single-control Quick audits were all still running after 900
    seconds, having completed nothing, while one audit alone takes about five
    minutes. They were not stuck -- they were sharing four cores between three
    llama.cpp workers, so each ran several times slower.

    That is the failure this default exists to prevent, and it is worse than a
    refusal: every audit is admitted, the interface shows them all "running", and
    no result arrives. An honest "system at capacity" is better than a progress
    bar that never moves.

    Slots decide how many audits can START; cores decide whether they FINISH.
    Roughly one audit per two physical cores keeps each one responsive, floored
    at 2 (so a small box still allows a second audit) and capped at 16 (past that
    the model server's own batching, not this limit, is the constraint).

    MAX_CONCURRENT_AUDITS in the environment always wins -- an operator who has
    measured their own hardware should override this.
    """
    import os
    env = os.environ.get("MAX_CONCURRENT_AUDITS")
    if env and str(env).strip().isdigit():
        return int(env)
    try:
        import psutil
        physical = psutil.cpu_count(logical=False) or psutil.cpu_count() or 4
    except Exception:
        physical = os.cpu_count() or 4
    return max(2, min(16, physical // 2))


MAX_CONCURRENT_AUDITS = _default_concurrent_audits()
