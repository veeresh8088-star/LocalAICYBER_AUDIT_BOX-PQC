#!/bin/sh
# Single entrypoint for both LLM roles this app needs, selected via LLM_MODE
# so one built image serves both docker-compose services (completion + embed)
# instead of maintaining two near-identical Dockerfiles.
#
# LLM_MODE=completion (default): main generation server, port 11434.
#   -np (parallel slot count) auto-sizes to this container's actual available
#   RAM, mirroring the same formula src/core/resource_guard.py uses for the
#   app's own concurrency semaphore (see that file for the full explanation):
#   each slot is first given MIN_CTX_PER_REQUEST tokens (enough to hold a
#   real audit prompt), then as many such slots as RAM allows. Duplicated here in shell because
#   this is a separate container image with no Python app code to import
#   resource_guard.py from.
# LLM_MODE=embedding: embedding-only server, port 11435, nomic-embed-text.
#   No -np/context concerns here -- single-purpose, short requests.
#
# Reads cgroup memory limits first (this container's actual allowance, which
# may be less than host total RAM if the operator set --memory on it),
# falling back to /proc/meminfo (host total) if no cgroup limit is set.
#
# CPU thread count (-t) is auto-detected the same way (cgroup CPU quota
# first, falling back to the host's logical core count) -- LLM_THREADS and
# EMBED_THREADS previously had a hardcoded default of 4 regardless of the
# machine's actual core count, so a customer VM with 8, 16, or more vCPUs
# silently ran generation on a fraction of its real compute unless someone
# manually knew to override it. This makes "use everything available" the
# out-of-the-box default, matching how RAM/slot sizing already behaves,
# while still letting LLM_THREADS/EMBED_THREADS/LLM_CORES_OVERRIDE win
# explicitly for an operator who wants to reserve cores for something else.

LLM_MODE="${LLM_MODE:-completion}"

detect_total_mem_gb() {
    if [ -f /sys/fs/cgroup/memory.max ]; then
        limit=$(cat /sys/fs/cgroup/memory.max)
        if [ "$limit" != "max" ]; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
        if [ "$limit" -lt 1000000000000 ] 2>/dev/null; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    awk -v k="$kb" 'BEGIN { printf "%.2f", k / 1048576 }'
}

detect_cpu_cores() {
    # cgroup v2: "quota period" in microseconds, e.g. "800000 100000" == 8 cores.
    # "max" as the quota means uncapped -- fall through to the next check.
    if [ -f /sys/fs/cgroup/cpu.max ]; then
        read -r quota period < /sys/fs/cgroup/cpu.max
        if [ "$quota" != "max" ] && [ -n "$quota" ] && [ -n "$period" ] && [ "$period" -gt 0 ] 2>/dev/null; then
            cores=$(awk -v q="$quota" -v p="$period" 'BEGIN { c = int(q / p); if (c < 1) c = 1; print c }')
            echo "$cores"
            return
        fi
    fi
    # cgroup v1: cfs_quota_us / cfs_period_us. quota of -1 means uncapped.
    if [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] && [ -f /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        if [ "$quota" -gt 0 ] 2>/dev/null && [ "$period" -gt 0 ] 2>/dev/null; then
            cores=$(awk -v q="$quota" -v p="$period" 'BEGIN { c = int(q / p); if (c < 1) c = 1; print c }')
            echo "$cores"
            return
        fi
    fi
    # No cgroup CPU limit set -- use the host's actual logical core count.
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return
    fi
    grep -c ^processor /proc/cpuinfo
}

DETECTED_CORES=$(detect_cpu_cores)
if [ -z "$DETECTED_CORES" ] || [ "$DETECTED_CORES" -lt 1 ] 2>/dev/null; then
    DETECTED_CORES=4
fi
if [ -n "$LLM_CORES_OVERRIDE" ]; then
    DETECTED_CORES="$LLM_CORES_OVERRIDE"
fi

if [ "$LLM_MODE" = "embedding" ]; then
    EMBED_T="${EMBED_THREADS:-$DETECTED_CORES}"
    echo "[LLM ENTRYPOINT] Detected ${DETECTED_CORES} CPU core(s) -> using ${EMBED_T} thread(s) for the embedding server."
    echo "[LLM ENTRYPOINT] Starting embedding server (nomic-embed-text) on port 11435."
    exec /app/llama-server \
        --host 0.0.0.0 --port 11435 \
        -m /models/nomic-embed-text-v1.5.f16.gguf \
        -t "$EMBED_T" \
        --embedding
fi

# completion mode
# Keep these in sync with resource_guard.py (same MIN_CTX_PER_REQUEST /
# KV_GB_PER_1K_FP16 / KV_QUANT inputs) -- change one, change both.
FIXED_OVERHEAD_GB="${RESOURCE_GUARD_FIXED_OVERHEAD_GB:-4.5}"
SAFETY_MARGIN="${RESOURCE_GUARD_SAFETY_MARGIN:-0.85}"

# Sizing rule: give each slot a context that can actually hold a real audit
# prompt FIRST, then fit as many slots as RAM allows -- never the reverse.
#
# The previous formula maximised slot COUNT against a flat 0.5GB/slot guess
# and a hardcoded `-c 32768`. llama.cpp divides -c evenly across -np, so on a
# 24GB box that produced 8 slots of 32768/8 = 4096 tokens each -- too small to
# hold this app's generator prompt (~4k template) plus retrieved evidence.
# Prompts were silently trimmed and findings came out wrong. Confirmed on a
# customer deployment, whose /props reported {"n_ctx":4096,"total_slots":8}.
#
# MIN_CTX_PER_REQUEST is the floor a slot must offer to be useful, sized from
# the largest real control: ~11k tokens of evidence for a 40-chunk PDF (see
# config/retrieval_config.json) + ~4k prompt template + ~1.5k completion.
MIN_CTX_PER_REQUEST="${MIN_CTX_PER_REQUEST:-16384}"

# KV-cache cost expressed PER 1024 TOKENS so it scales with the context we
# actually ask for. The old PER_SLOT_GB was a flat per-slot figure pinned to
# `-c 32768`; raising the context while leaving it untouched would
# over-provision slots and OOM the box. Derived from that same calibration
# (0.5GB per 4096-token FP16 slot). MEASURE against your model and override
# rather than trusting this -- llama-server prints the real KV size at load.
KV_GB_PER_1K_FP16="${KV_GB_PER_1K_FP16:-0.12}"

# Upper bound on parallel slots, derived rather than fixed.
#
# This was a hardcoded 8, which is a statement about a machine rather than about
# this machine: it silently capped a 64-core server at 8 concurrent auditors no
# matter how much CPU and RAM it had, while on a small box the RAM bound below
# was doing all the work and the 8 never mattered. Neither case was described by
# the constant.
#
# Slots are bounded by the two things that actually constrain them:
#   * RAM   -- the KV cache each slot needs (applied in the SLOTS calculation)
#   * CPU   -- past one slot per core, concurrent requests are sharing cores and
#              each one simply runs proportionally slower, so more slots buy
#              queueing rather than throughput.
# This mirrors run_all.bat, which caps -np the same way. LLM_MAX_SLOTS still
# overrides for an operator who has measured their own hardware.
MAX_SLOTS="${LLM_MAX_SLOTS:-$DETECTED_CORES}"
if [ -z "$MAX_SLOTS" ] || [ "$MAX_SLOTS" -lt 1 ] 2>/dev/null; then
    MAX_SLOTS=2
fi

# Optional flags are probed against THIS build's own --help rather than
# assumed. The base image is an unpinned floating tag
# (ghcr.io/ggml-org/llama.cpp:server), so a flag present today can disappear
# tomorrow -- and an unknown flag makes llama-server exit at startup, which on
# a customer box takes the whole audit stack down. Probe first, then add.
HELP_TEXT="$(/app/llama-server --help 2>&1 || true)"

supports_flag() {
    printf '%s' "$HELP_TEXT" | grep -q -- "$1"
}

EXTRA_ARGS=""

# Unified KV cache: one shared buffer for all sequences, instead of -c split
# into -np fixed partitions. This is what lets a heavy control borrow tokens
# from idle slots -- the shared-pool behaviour this deployment is specified to
# have. Set KV_UNIFIED=0 to opt out.
if [ "${KV_UNIFIED:-1}" = "1" ] && supports_flag "--kv-unified"; then
    EXTRA_ARGS="$EXTRA_ARGS --kv-unified"
    KV_UNIFIED_ON="yes"
else
    KV_UNIFIED_ON="no"
fi

# 8-bit KV cache: halves KV RAM, which is what makes the larger per-slot
# context affordable. run_all.bat has always used this; this container never
# did, so the customer paid full FP16 price per slot. Set KV_QUANT=0 to opt out.
if [ "${KV_QUANT:-1}" = "1" ] && supports_flag "-ctk"; then
    EXTRA_ARGS="$EXTRA_ARGS -ctk q8_0 -ctv q8_0"
    KV_BYTES_SCALE="0.5"
    KV_QUANT_ON="yes"
else
    KV_BYTES_SCALE="1.0"
    KV_QUANT_ON="no"
fi

TOTAL_GB=$(detect_total_mem_gb)
GB_PER_SLOT=$(awk -v c="$MIN_CTX_PER_REQUEST" -v k="$KV_GB_PER_1K_FP16" -v s="$KV_BYTES_SCALE" '
    BEGIN { printf "%.4f", (c / 1024) * k * s }
')
SLOTS=$(awk -v t="$TOTAL_GB" -v o="$FIXED_OVERHEAD_GB" -v g="$GB_PER_SLOT" -v m="$SAFETY_MARGIN" -v max="$MAX_SLOTS" '
    BEGIN {
        usable = (t * m) - o
        if (g <= 0) g = 1
        slots = int(usable / g)
        if (slots < 1)    slots = 1
        if (slots > max)  slots = max
        print slots
    }
')

if [ -n "$LLM_SLOTS_OVERRIDE" ]; then
    SLOTS="$LLM_SLOTS_OVERRIDE"
    echo "[LLM ENTRYPOINT] LLM_SLOTS_OVERRIDE set -- using $SLOTS slots instead of auto-detection."
else
    # Name the binding constraint, so an operator can see at a glance whether
    # adding RAM or adding cores would raise concurrency on this machine.
    RAM_ONLY_SLOTS=$(awk -v t="$TOTAL_GB" -v o="$FIXED_OVERHEAD_GB" -v g="$GB_PER_SLOT" -v m="$SAFETY_MARGIN" '
        BEGIN { u=(t*m)-o; if (g<=0) g=1; s=int(u/g); if (s<1) s=1; print s }')
    if [ "$RAM_ONLY_SLOTS" -gt "$MAX_SLOTS" ] 2>/dev/null; then
        BOUND="CPU (${MAX_SLOTS} core(s); RAM alone would allow ${RAM_ONLY_SLOTS})"
    else
        BOUND="RAM (${TOTAL_GB}GB; ${MAX_SLOTS} core(s) available)"
    fi
    echo "[LLM ENTRYPOINT] Detected ${TOTAL_GB}GB and ${MAX_SLOTS} core(s), ~${GB_PER_SLOT}GB per ${MIN_CTX_PER_REQUEST}-token slot -> $SLOTS slot(s), bounded by $BOUND."
fi

# Total pool = slots x per-request floor. With --kv-unified this is one shared
# buffer any sequence can draw from, so an idle slot's tokens are reusable by a
# busy one; without it, llama.cpp partitions it back into per-slot regions of
# exactly MIN_CTX_PER_REQUEST each. Either way no slot drops below the floor.
TOTAL_CTX=$(( SLOTS * MIN_CTX_PER_REQUEST ))

LLM_T="${LLM_THREADS:-$DETECTED_CORES}"
echo "[LLM ENTRYPOINT] Detected ${DETECTED_CORES} CPU core(s) -> using ${LLM_T} thread(s) for the completion server."
echo "[LLM ENTRYPOINT] Context: -c ${TOTAL_CTX} across ${SLOTS} slot(s) = ${MIN_CTX_PER_REQUEST} tokens per request (kv_unified=${KV_UNIFIED_ON}, kv_8bit=${KV_QUANT_ON})."

# EXTRA_ARGS is deliberately unquoted: it carries multiple probed flags that
# must word-split into separate argv entries.
# shellcheck disable=SC2086
exec /app/llama-server \
    --host 0.0.0.0 --port 11434 \
    -m /models/google_gemma-4-E4B-it-Q4_K_M.gguf \
    -c "$TOTAL_CTX" -np "$SLOTS" \
    -t "$LLM_T" \
    -b 512 -ub 256 \
    --cont-batching \
    --flash-attn on \
    $EXTRA_ARGS
