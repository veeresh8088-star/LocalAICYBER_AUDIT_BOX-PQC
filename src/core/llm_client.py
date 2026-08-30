import os
import threading
import requests
import json
from src.core.port_pool import port_pool_manager

def in_docker():
    return os.path.exists('/.dockerenv')


# ── Round-Robin Load Balancer ─────────────────────────────────────────────────
# When LLM_HOSTS env var is set (e.g. "11434,11436"), requests are distributed
# across all configured LLM instances in a thread-safe round-robin fashion.
# Falls back to single OLLAMA_HOST when LLM_HOSTS is not set.
_rr_lock = threading.Lock()
_rr_index = 0

def _get_next_llm_host():
    """Returns the next LLM host URL in round-robin order."""
    global _rr_index
    hosts_env = os.environ.get("LLM_HOSTS", "").strip()
    if not hosts_env:
        # Single instance mode — use OLLAMA_HOST as before
        return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
    # Multi-instance mode — parse comma-separated ports or full URLs
    raw_hosts = [h.strip() for h in hosts_env.split(",") if h.strip()]
    hosts = []
    for h in raw_hosts:
        if h.isdigit():
            hosts.append(f"http://127.0.0.1:{h}")
        elif not h.startswith("http"):
            hosts.append(f"http://{h}")
        else:
            hosts.append(h)
    with _rr_lock:
        host = hosts[_rr_index % len(hosts)]
        _rr_index += 1
    return host

def get_llm_backend():
    """Returns llama.cpp as the sole, dedicated inference engine."""
    return "llama.cpp"

# ── Per-port lock for _ensure_llama_server_running() ──────────────────────────
_llm_start_locks_guard = threading.Lock()
_llm_start_locks = {}

def _get_llm_start_lock(port):
    """Returns (creating if needed) the threading.Lock for this port, so only one
    thread at a time attempts to auto-spawn llama-server.exe for that port."""
    with _llm_start_locks_guard:
        lock = _llm_start_locks.get(port)
        if lock is None:
            lock = threading.Lock()
            _llm_start_locks[port] = lock
        return lock

def _resolve_host(url=None, default_port=11434):
    """Resolves host URL."""
    if url is None:
        url = _get_next_llm_host() if default_port == 11434 else f"http://127.0.0.1:{default_port}"
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if ":" in url else f"http://{url}:{default_port}"
    return url

def _ensure_llama_server_running(port=11434):
    """Auto-detects if llama-server.exe on port 11434 (LLM) or 11435 (Embedding) is offline,
    and automatically spawns it in the background so the platform self-heals.

    Native/single-machine deployments only -- in Docker, the LLM lives in its
    own separate container (reached over the network as e.g. "llm:11434",
    never localhost) with its own lifecycle managed by that container's own
    entrypoint, not something this process could ever launch itself even in
    principle. Attempting it anyway used to always fail here (checking
    127.0.0.1, which nothing in the app container ever listens on) and log a
    scary-looking "could not locate llama-server.exe" line for what was
    usually just the LLM server being genuinely busy under concurrent load,
    not actually down.
    """
    import socket, subprocess, sys, time

    if in_docker():
        return False

    def _port_open():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except Exception:
            return False
        finally:
            s.close()

    if _port_open():
        return True  # Port is active & healthy!

    # Serialize server-spawn attempts per port. Previously this whole function ran
    # with zero synchronization: if the LLM server crashed mid-audit, every thread
    # with an in-flight call could observe the port closed at the same moment and
    # each independently spawn a competing llama-server.exe, each loading the
    # multi-GB model into RAM concurrently before the losers failed to bind the
    # port. The lock is per-port (not global) so 11434/LLM and 11435/embedding can
    # still be auto-started concurrently.
    lock = _get_llm_start_lock(port)
    with lock:
        # Re-check after acquiring the lock -- another thread may have already
        # finished starting the server while this one was waiting.
        if _port_open():
            return True

        print(f"[AUTO-START LLM] llama-server port {port} is offline. Auto-launching process...", flush=True)

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        llama_exe = None
        candidates = [
            r"C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe",
            os.path.join(base_dir, "llama-server.exe"),
            r"C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
        ]
        for c in candidates:
            if os.path.exists(c):
                llama_exe = c
                break

        if not llama_exe:
            print(f"[AUTO-START LLM] Could not locate llama-server.exe in candidates.", flush=True)
            return False

        # Auto-detect CPU cores at runtime — never hardcode a thread count.
        # llama-server gets all available logical cores, just like any other app.
        _cpu_threads = str(os.cpu_count() or 4)
        _physical_cores = max(1, (os.cpu_count() or 4))

        # Auto-detect parallel slots (-np) based on available RAM at startup.
        # With 8-bit KV cache (-ctk q8_0) and a 128k shared pool (-c 131072), each slot
        # consumes ~900 MB of KV-cache RAM. Slots are clamped to physical CPU core count
        # (one slot per core) so we never thrash the CPU with more parallel neural network
        # matrix computations than cores can handle simultaneously.
        try:
            import psutil as _psutil
            _avail_gb = _psutil.virtual_memory().available / (1024 ** 3)
            _model_gb = 5.0          # Gemma 4B Q4_K_M weight footprint in RAM
            _embed_gb = 0.3          # nomic-embed-text footprint in RAM
            _slot_gb  = 0.9          # ~900 MB KV-cache per slot (8-bit q8_0, 128k pool)
            _overhead_gb = _model_gb + _embed_gb + 2.5  # OS + FastAPI + Redis baseline
            _np = max(1, min(_physical_cores, int((_avail_gb - _overhead_gb) / _slot_gb)))
            print(f"[AUTO-START LLM] Detected {_avail_gb:.1f}GB free RAM, {_physical_cores} physical cores "
                  f"-> using -np {_np} parallel slots (8-bit KV cache, 128k shared pool)", flush=True)
        except Exception:
            _np = min(_physical_cores, 2)   # safe fallback if psutil unavailable
            print(f"[AUTO-START LLM] RAM detection unavailable -> using -np {_np} parallel slots (fallback)", flush=True)

        if port == 11434:
            model_path = os.path.join(base_dir, "google_gemma-4-E4B-it-Q4_K_M.gguf")
            # 128k fluid shared token pool, 8-bit KV-cache compression (halves RAM vs FP16),
            # flash attention, and continuous batching — matches run_all.bat/sh exactly.
            cmd = [
                llama_exe, "--port", "11434",
                "-m", model_path,
                "-c", "131072",
                "-np", str(_np),
                "-t", _cpu_threads,
                "-b", "2048",
                "-ub", "512",
                "--flash-attn", "on",
                "--cont-batching",
                "-ctk", "q8_0",
                "-ctv", "q8_0",
            ]
        else:
            model_path = os.path.join(base_dir, "nomic-embed-text-v1.5.f16.gguf")
            cmd = [llama_exe, "--port", "11435", "-m", model_path, "-t", _cpu_threads, "--embedding"]

        try:
            creation_flag = subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
            subprocess.Popen(cmd, creationflags=creation_flag)
            # Wait up to 25 seconds for model to load into RAM and accept HTTP requests
            for _ in range(25):
                time.sleep(1.0)
                try:
                    r_check = requests.get(f"http://127.0.0.1:{port}/health", timeout=1.5)
                    if r_check.status_code == 200:
                        print(f"[AUTO-START LLM] Successfully launched llama-server on port {port}!", flush=True)
                        return True
                except Exception:
                    pass
            print(f"[AUTO-START LLM] Server process started on port {port}, warming up...", flush=True)
            return True
        except Exception as e:
            print(f"[AUTO-START LLM] Auto-start error on port {port}: {e}", flush=True)
        return False

_real_num_ctx_cache = {}

# Conservative last resort when the server can't be asked. Deliberately small:
# under-reading the context trims evidence (visible, warned about), while
# over-reading it makes llama-server silently discard the overflow.
_FALLBACK_NUM_CTX = 4096


def get_real_num_ctx(host=None, timeout=10):
    """
    Real per-slot context size via llama-server's own /props endpoint --
    ground truth, not a guess. llama-server is started with -c 0 (auto-detect
    the model's native context) and -np <slots>, and divides the native
    context evenly across slots -- so the actual usable context per request
    is native_context / slots, which can be far smaller than the model's
    advertised full context (e.g. 5632 with 24 slots on a ~131k-context
    model), not a fixed 16384 as previously hardcoded here. That mismatch
    meant the token-budget calculator and its trim backstop (audit_chains.py)
    were both sizing prompts against a ceiling roughly 3x larger than any
    slot can actually hold.

    Cached per-host for the process lifetime -- this doesn't change while
    the server is running. LLM_NUM_CTX env var always wins if set (manual
    override for backends/setups this can't introspect). Falls back to a
    conservative 4096 if the query fails, so a monitoring hiccup degrades
    the budget rather than blocking an audit (same fail-open philosophy as
    resource_guard.py).
    """
    env_ctx = os.environ.get("LLM_NUM_CTX", "").strip()
    if env_ctx and env_ctx.isdigit():
        return int(env_ctx)

    resolved_host = host or _resolve_host()
    if resolved_host in _real_num_ctx_cache:
        return _real_num_ctx_cache[resolved_host]

    try:
        r = requests.get(f"{resolved_host}/props", timeout=timeout)
        if r.status_code == 200:
            n_ctx = r.json().get("default_generation_settings", {}).get("n_ctx")
            if isinstance(n_ctx, int) and n_ctx > 0:
                _real_num_ctx_cache[resolved_host] = n_ctx
                return n_ctx
    except Exception as e:
        print(f"[LLM CTX] /props query to {resolved_host} failed: {e}", flush=True)

    # Loud on purpose. Every prompt in the app is sized against whatever this
    # returns, so a silent fallback throttles all audits to 4096 tokens even
    # when the server offers far more -- and the only symptom is trimmed
    # evidence and wrong findings. The fallback path used to print nothing at
    # all, making that indistinguishable from a genuinely small slot. Cached
    # per host, so this warns once rather than on every control.
    print(
        f"[LLM CTX] WARNING: no usable per-slot n_ctx from {resolved_host}/props -- "
        f"falling back to {_FALLBACK_NUM_CTX}. If the server actually offers more, every "
        f"audit is being throttled to this figure. Set LLM_NUM_CTX to override, or check "
        f"whether this llama.cpp build still reports default_generation_settings.n_ctx.",
        flush=True
    )
    _real_num_ctx_cache[resolved_host] = _FALLBACK_NUM_CTX
    return _FALLBACK_NUM_CTX


def count_tokens(text, host=None, timeout=1.5):
    """
    Real token count via llama-server's own /tokenize endpoint -- ground truth,
    not an estimate. Falls back to a chars/4 approximation if the server is
    briefly unreachable, so a dynamic budget calculation never blocks an audit
    over a monitoring failure (same fail-open philosophy as resource_guard.py).
    """
    if not text:
        return 0
    try:
        url = f"{(host or _resolve_host())}/tokenize"
        r = requests.post(url, json={"content": text}, timeout=timeout)
        if r.status_code == 200:
            return len(r.json().get("tokens", []))
    except Exception:
        pass
    return len(text) // 4


def query_llm(prompt, model, format=None, num_ctx=16384, temperature=0.0, num_thread=None, timeout=None, stop=None, session_id=None, token_stats=None):
    """Sends a non-streaming prompt completion request exclusively to llama-server.exe."""
    # Only auto-compute when the caller genuinely didn't specify a timeout -- see
    # the matching comment in port_pool.py's acquire_control_slot() for why literal
    # 1800/600 are no longer treated as an "auto-compute this" sentinel.
    if timeout is None:
        try:
            from src.core.redis_metrics import get_live_metrics
            m = get_live_metrics()
            if m.get("redis_available"):
                active_cnt = max(1, len(m.get("active_sessions", [])))
            else:
                from src.core.bg_state import _bg_running
                active_cnt = max(1, len(_bg_running))
            timeout = max(600, active_cnt * 180)
        except Exception:
            timeout = 600

    # Two budgets, not one. Passing `timeout` to both the slot acquisition and the
    # HTTP request meant a request that waited a long time for a worker still had
    # its own full budget here, but the LangGraph wrapper above timed the pair
    # together -- so queue time came out of compute time and a request that would
    # have completed was killed. Waiting for a slot is a queueing problem with its
    # own, much shorter, deadline; the request itself keeps the full budget.
    _pool_timeout = int(os.environ.get("LLM_POOL_WAIT_TIMEOUT_SEC", "300"))
    with port_pool_manager.acquire_control_slot(session_id=session_id, timeout=_pool_timeout) as host:
        if "gemma" in model.lower():
            prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
        url = f"{host}/completion"
        stop_tokens = stop or ["<end_of_turn>", "<eos>", "<|im_end|>", "</s>", "</audit_finding>", "</gap_analysis>", "</vapt_finding>", "</finding>", "```"]

        def _complete(n_predict, prompt_text):
            payload = {
                "prompt": prompt_text,
                "temperature": temperature,
                "stream": False,
                "n_predict": n_predict,
                "stop": stop_tokens
            }
            if format == "json":
                payload["response_format"] = {"type": "json_object"}
            try:
                r = requests.post(url, json=payload, timeout=timeout)
                if r.status_code != 200:
                    try:
                        from src.core.bg_worker import log_system_event
                        log_system_event("LLM_HTTP_ERROR", "ERROR", f"LLM server returned HTTP {r.status_code}: {r.text[:200]}", session_id=session_id)
                    except Exception: pass
                    raise Exception(f"llama-server.exe error: HTTP {r.status_code} - {r.text}")
                return r.json()
            except requests.exceptions.Timeout as _to_err:
                # Must be caught BEFORE the broader ConnectionError/RequestException
                # clause below -- requests.exceptions.Timeout (which ReadTimeout
                # subclasses) is itself a RequestException, so with that clause
                # first, a plain "the LLM server is just busy under concurrent
                # load and hasn't answered yet" timeout was always being
                # misdiagnosed as a dead connection, triggering a pointless
                # local-process auto-start attempt instead of just logging the
                # (accurate, and often totally expected under load) timeout.
                try:
                    from src.core.bg_worker import log_system_event
                    log_system_event("LLM_REQUEST_TIMEOUT", "ERROR", f"LLM HTTP request timed out after {timeout}s", session_id=session_id)
                except Exception: pass
                raise
            except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as _conn_err:
                print(f"[LLM CLIENT] Connection error to {url}: {_conn_err}. Attempting auto-start...", flush=True)
                if _ensure_llama_server_running(11434):
                    r = requests.post(url, json=payload, timeout=timeout)
                    if r.status_code == 200:
                        return r.json()
                raise Exception(f"llama-server.exe connection error on {url}: {_conn_err}")

        result = _complete(1536, prompt)
        accumulated = result.get("content", "")
        total_prompt_toks = result.get("tokens_evaluated", 0)
        total_comp_toks = result.get("tokens_predicted", 0)

        # Continuation, not restart-from-scratch: on hitting the token cap, feed the
        # partial output back as part of the prompt so the model picks up exactly
        # where it stopped (same idea as Claude Code's own "continue" behavior on a
        # truncated response) instead of re-decoding the same tokens over again from
        # the original prompt. Capped at 2 continuation rounds so a model stuck
        # without ever emitting a stop token can't loop indefinitely.
        _continue_rounds = 0
        while result.get("stop_type") == "limit" and _continue_rounds < 2:
            _continue_rounds += 1
            if session_id:
                try:
                    from src.core.bg_state import _bg_store, _bg_lock
                    with _bg_lock:
                        _prev = _bg_store["progress"].get(session_id) or {}
                        _bg_store["progress"][session_id] = {
                            **_prev,
                            "warning": f"⚠️ Response hit the token limit — continuing generation (attempt {_continue_rounds})...",
                        }
                except Exception:
                    pass
            result = _complete(2048, prompt + accumulated)
            accumulated += result.get("content", "")
            total_prompt_toks += result.get("tokens_evaluated", 0)
            total_comp_toks += result.get("tokens_predicted", 0)

        if _continue_rounds and session_id:
            # Clear our own continuation notice once done (successfully or not) so it
            # doesn't linger on the next poll after this LLM call has already returned.
            try:
                from src.core.bg_state import _bg_store, _bg_lock
                with _bg_lock:
                    _prev = _bg_store["progress"].get(session_id) or {}
                    if str(_prev.get("warning", "")).startswith("⚠️ Response hit the token limit"):
                        _bg_store["progress"][session_id] = {**_prev, "warning": None}
            except Exception:
                pass

        if token_stats is not None:
            # Real counts from the server itself, summed across every continuation
            # round, not a character-count estimate.
            token_stats["prompt_tokens"] = total_prompt_toks
            token_stats["completion_tokens"] = total_comp_toks
            # Still cut off even after every continuation round -- tag it so the
            # caller (audit_chains.py) can give an honest "response was truncated,
            # re-run this control" message instead of the generic parse-failure
            # fallback, which otherwise looks identical to a real compliance gap.
            token_stats["truncated"] = (result.get("stop_type") == "limit")

        return accumulated.strip()

def query_llm_stream(prompt, model, num_ctx=16384, temperature=0.0, num_thread=None, session_id=None):
    """Generates streaming tokens from the dedicated llama-server.exe engine.
    Shares the same port_pool_manager slots as query_llm() instead of an independent,
    uncoordinated round-robin — otherwise a streaming and non-streaming call could
    collide on the same in-use slot."""
    with port_pool_manager.acquire_control_slot(session_id=session_id) as host:
        if "gemma" in model.lower():
            prompt = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
        url = f"{host}/completion"
        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "stream": True,
        }
        r = requests.post(url, json=payload, stream=True, timeout=300)
        if r.status_code != 200:
            raise Exception(f"llama-server.exe streaming error: HTTP {r.status_code} - {r.text}")

        for line in r.iter_lines():
            if line:
                decoded = line.decode("utf-8").strip()
                if decoded.startswith("data: "):
                    try:
                        data_json = json.loads(decoded[6:])
                        yield data_json.get("content", "")
                    except Exception:
                        pass

def get_embedding(text, model="nomic-embed-text"):
    """Fetches text embedding vector exclusively from the llama-server.exe embedding endpoint."""
    if not text or not str(text).strip():
        return None

    # Truncate text to 4000 chars to avoid overloading embedding server context
    text_sample = str(text)[:4000]

    host_env = os.environ.get("EMBEDDING_HOST") or os.environ.get("OLLAMA_HOST")
    host = _resolve_host(host_env, default_port=11435)
    embed_timeout = int(os.environ.get("EMBEDDING_TIMEOUT", "60"))

    # Query native llama-server /embedding endpoint
    url = f"{host}/embedding"
    try:
        r = requests.post(url, json={"content": text_sample}, timeout=embed_timeout)
        if r.status_code == 200:
            res_data = r.json()
            if isinstance(res_data, list):
                if res_data and isinstance(res_data[0], list):
                    return res_data[0]
                elif res_data and isinstance(res_data[0], dict):
                    return res_data[0].get("embedding") or res_data[0]
                return res_data
            elif isinstance(res_data, dict):
                emb = res_data.get("embedding")
                if emb:
                    if isinstance(emb, list) and len(emb) > 0 and isinstance(emb[0], list):
                        return emb[0]
                    return emb
    except Exception as e_emb:
        if not in_docker():
            print(f"[EMBEDDING RETRY] Connection error on {url}: {e_emb}. Attempting auto-start on 11435...", flush=True)
            _ensure_llama_server_running(11435)


    # Fallback to OpenAI-compatible /v1/embeddings on llama-server.exe
    try:
        url_v1 = f"{host}/v1/embeddings"
        r = requests.post(url_v1, json={"input": text_sample, "model": model}, timeout=embed_timeout)
        if r.status_code == 200:
            data = r.json().get("data")
            if data and isinstance(data, list) and len(data) > 0:
                emb = data[0].get("embedding")
                if isinstance(emb, list) and len(emb) > 0 and isinstance(emb[0], list):
                    return emb[0]
                return emb
    except Exception as e:
        print(f"[LLM CLIENT ERROR] Failed to query llama-server.exe embeddings: {e}")
    return None

