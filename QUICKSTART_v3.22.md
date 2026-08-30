# AICyberAuditBox v3.22 — Install & Upgrade

Offline deployment. Nothing in this release contacts the internet at runtime.

---

## 1. What you receive

| File | Size | Purpose |
|---|---|---|
| `aicyberauditbox-app-3.22.tar` | ~6.5 GB | Application image (API + frontend + audit engine) |
| `aicyberauditbox-3.22-companion.zip` | ~20 KB | Compose files, LLM entrypoint, this guide |

The LLM images are **not** re-shipped. The only change to them is one shell
script, which you relayer onto the images you already have — your model weights
and the pinned llama.cpp engine build stay exactly as they are.

---

## 2. Upgrade from v3.21

```bash
# 1 — stop the running stack
docker compose down

# 2 — load the new application image
docker load -i aicyberauditbox-app-3.22.tar

# 3 — unpack the companion archive over your deployment directory
unzip -o aicyberauditbox-3.22-companion.zip

# 4 — relayer the LLM images (seconds; no weights are copied)
docker build -f Dockerfile.llm.rebase \
  --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm:3.21 \
  -t aicyberauditbox-llm:3.22 .
docker build -f Dockerfile.llm.rebase \
  --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm-embed:3.21 \
  -t aicyberauditbox-llm-embed:3.22 .

# 5 — start
docker compose up -d
```

Your database, evidence files and completed audits are held in named volumes and
are not touched by this upgrade.

### Confirm the upgrade took

```bash
docker compose logs llm | grep "LLM ENTRYPOINT"
```

You should see the context line, which is new in this release:

```
[LLM ENTRYPOINT] Detected 16.00GB and 8 core(s), ~1.92GB per 32768-token slot
                 -> 4 slot(s), bounded by RAM (16.00GB; 8 core(s) available).
[LLM ENTRYPOINT] Context: -c 131072 across 4 slot(s) = 32768 tokens per request
                 (kv_unified=yes, kv_8bit=yes).
```

---

## 3. Sizing this release for your hardware

Slots are now derived from **both** RAM and CPU cores at startup — nothing is
hardcoded. Each slot is given 32,768 tokens, which is what a full 30-passage
retrieval needs.

```
RAM required  ≈  4.5 GB  +  (slots × 1.92 GB)
```

| Concurrent auditors | Slots | LLM container RAM |
|---|---|---|
| 2 | 4 | 12 GB |
| 5 | 7 | 18 GB |
| 10 | 12 | 28 GB |

**On a server with more than ~32 GB, set an explicit limit on the LLM
container.** Without one it sizes itself against the *whole host* and can crowd
out the application and database:

```yaml
  llm:
    mem_limit: 28g        # 10 concurrent auditors
```

CPU is the other bound. Roughly **one concurrent auditor per two physical
cores** keeps each audit responsive; below that they simply share cores and all
run proportionally slower.

---

## 4. Settings worth reviewing

All are optional — the defaults adapt to the machine. Set them only to override.

| Setting | Default | Effect |
|---|---|---|
| `MIN_CTX_PER_REQUEST` | `32768` | Tokens per request. Below ~29,000 a 30-passage retrieval is truncated. |
| `LLM_NUM_CTX` (app) | `32768` | **Must equal the above.** The app sizes prompts against this. |
| `LLM_MAX_SLOTS` | detected cores | Upper bound on parallel slots. |
| `LLM_SLOTS_OVERRIDE` | — | Pins the slot count outright. |
| `MAX_CONCURRENT_AUDITS` | cores ÷ 2 | Audits admitted before new ones are refused. |
| `max_file_size_mb` (app settings) | `100` | Per-file upload ceiling. |

---

## 5. Two behaviours to be aware of

**A control the engine could not evaluate is now reported as `NOT_EVALUATED`.**
Previously a timeout produced a NON_COMPLIANT finding, which was indistinguishable
from a genuine failure. It now states plainly that the control did not run and
should be re-run — it carries no severity and does not count toward your
compliance score.

**VAPT and PQC scans complete in seconds.** They use deterministic parsers and
make no model calls at all. Only ISO-family audits invoke the language model, and
those take minutes per control. A fast VAPT result is expected behaviour, not a
cached one.

---

## 6. Scanner formats

Upload scanner exports in their **native format** where possible.

| Tool | Preferred | Also accepted |
|---|---|---|
| Burp Suite | HTML export | PDF, text |
| Nessus | `.nessus` XML | HTML, text |
| Nmap | XML or console text | Screenshot (OCR) |
| Qualys / Trivy | CSV / JSON | — |
| PQC | `.conf`, `.yaml`, `.properties`, `.pem` | PDF, DOCX |

A **PDF printed from an HTML report** loses the document structure the parser
relies on, and carries the printing browser's header and footer into the text.
Both are handled, but the native export gives cleaner findings.

---

## 7. If something looks wrong

```bash
docker compose logs app  | grep -E "TOKEN BUDGET|RAG LOG"   # evidence selection
docker compose logs app  | grep -E "TIMEOUT|CAPACITY"       # capacity problems
docker compose logs llm  | grep "LLM ENTRYPOINT"            # sizing at startup
```

`[RAG LOG]` prints `total_chunks` (passages available) against `selected`
(passages sent). A large gap means the token budget is the constraint — raise
`MIN_CTX_PER_REQUEST`, and `LLM_NUM_CTX` with it.

The **Admin → System Log** view records timeouts, capacity shortfalls and blocked
uploads with the control and session they relate to.
