# AICyberAuditBox 3.22 — Offline Installation

A **self-contained, air-gapped install**. Every image ships in this bundle; the
machine never contacts a registry or the internet, during install or in use.

> Already running an earlier version? Use `QUICKSTART_v3.22.md` instead — it is a
> small upgrade delta. This guide is for a machine that has nothing installed.

---

## 1. What is in the box

**One file: `AICyberAuditBox-3.22-complete.tar` (~8 GB).** Extract it and it
becomes a folder holding everything:

| Inside the folder | Size | Contents |
|---|---|---|
| `aicyberauditbox-images-3.22.tar` | ~8 GB | **All five images in one file** — application, LLM and embedding servers (**model weights included**), PostgreSQL, Redis |
| `install.sh` / `install.bat` | — | Loads the images and starts the stack |
| `docker-compose.yml` | — | The stack definition, image-only (nothing is built on your server) |
| `INSTALL_v3.22.md` | — | This guide |

The two LLM tags share one file because they share their base layers and the
model weights — Docker stores those once rather than twice, which is why the
whole product fits in ~8 GB rather than ~14 GB.

---

## 2. Requirements

**An Intel or AMD (x86-64) CPU.** Every image is built `linux/amd64`. An ARM
server — AWS Graviton, Ampere, Apple Silicon — cannot run them natively, and the
QEMU emulation Docker falls back to is far too slow for LLM inference. Standard
Dell and HP rack servers are x86-64.

**Any OS that runs Docker** — Linux, Windows Server or macOS. Linux is the right
choice for a production box: containers run directly on the kernel, so the whole
machine's RAM is available. On Windows and macOS, Docker runs a Linux VM that
takes its own slice of memory first, and you have to raise that VM's memory limit
by hand before the LLM can open enough slots.

**Docker Engine 20.10+ with the Compose plugin** — install it from your own
offline media before starting; it is the one prerequisite this bundle cannot
carry. Nothing else is needed: no Python, no CUDA, no model download, no
registry access. Inference is CPU-only.

**Disk:** about 14 GB for the bundle plus 14 GB once the images are loaded —
allow **30 GB free**.

Sizing follows from how the LLM server allocates memory. Each concurrent request
holds a 32,768-token slot, and a slot costs about 1.92 GB of KV cache on top of
a 4.5 GB shared model footprint:

> **LLM container RAM ≈ 4.5 GB + (slots × 1.92 GB)**

| Concurrent auditors | Slots | LLM RAM | Total system RAM | Physical cores |
|---|---|---|---|---|
| 2–3 | 4 | ~12 GB | 16 GB | 8 |
| 5 | 8 | ~20 GB | 32 GB | 16 |
| **10** | **12** | **~28 GB** | **64 GB** | **24–32** |
| 20+ | 24 | ~51 GB | 96–128 GB | 64 |

Cores drive **latency**, RAM drives **how many can run at once**. Under-provision
cores and audits still complete, only slower; under-provision RAM and the LLM
cannot open enough slots, so auditors queue.

The container sizes itself at startup from the CPU and RAM it can actually see —
nothing is hardcoded, so the same bundle is correct on a laptop and on a 64-core
server.

---

## 3. Air-gapped operation

Verified on a container started with networking disabled entirely
(`--network none`): the OCR models, the embedding model, the LLM weights and
every Python package are baked into the images, and nothing is fetched at
first use. Licensing is validated locally and makes no outbound call.

Two things to know:

- **Keep the server clock roughly right.** Every login uses TOTP, which is
  derived from the current time. There is ±2.5 minutes of tolerance, but an
  air-gapped machine has no NTP, so a clock left to drift for months will
  eventually reject valid codes. Point it at an internal time source, or check
  it when you patch.
- **CVE reference links will not open.** Findings link to `nvd.nist.gov` for
  CVE detail. The finding itself — severity, CVSS, CWE, OWASP mapping,
  remediation — is generated on the box and complete without it; only the
  external hyperlink is inert.

The web UI loads no fonts, scripts or styles from the internet: everything is
served from the application container, so opening the dashboard generates no
outbound traffic for your network monitoring to flag.

---

## 4. Install

Copy the one file onto the server, extract it, and run the installer from
inside the folder it creates. The installer loads the images, starts the stack,
and waits until the application answers.

**Linux / macOS**

```sh
tar -xf AICyberAuditBox-3.22-complete.tar
cd AICyberAuditBox-3.22
chmod +x install.sh && ./install.sh
```

**Windows** (`tar` is built into Windows 10 and Server 2019 onward)

```bat
tar -xf AICyberAuditBox-3.22-complete.tar
cd AICyberAuditBox-3.22
install.bat
```

Expect 5–15 minutes, almost all of it loading the images. `docker load` prints
nothing at all while it works — that is normal, not a hang. When it finishes:

```
  Ready.  Open http://localhost:8000/
```

<details>
<summary>Manual steps, if you would rather not use the installer</summary>

```sh
docker load -i aicyberauditbox-images-3.22.tar
docker compose up -d
```

That is the whole install — one load, one up. The single images tar contains
all five images, so there is no ordering to get right.
</details>

---

## 5. Confirm it sized itself correctly

```sh
docker compose logs llm | grep "LLM ENTRYPOINT"
```

```
[LLM ENTRYPOINT] Detected 64.00GB and 32 core(s), ~1.92GB per 32768-token slot -> 12 slot(s), bounded by RAM (64.00GB; 32 core(s) available).
[LLM ENTRYPOINT] Detected 32 CPU core(s) -> using 32 thread(s) for the completion server.
[LLM ENTRYPOINT] Context: -c 393216 across 12 slot(s) = 32768 tokens per request (kv_unified=yes, kv_8bit=yes).
```

The line that matters is the last one: **32768 tokens per request**. That is the
per-request budget the app assumes. If it reads lower, the machine has less RAM
than the LLM container was expecting and evidence will be truncated before the
model sees it — give the container more RAM, or lower `LLM_MAX_SLOTS`.

---

## 6. On a server with more than ~32 GB, cap the LLM

When no limit is set, the container reads the **host's** total RAM and sizes
itself as though it owned the whole machine — which starves the app, database
and embedding server. Harmless on a laptop, not on a 96 GB server. In `docker-compose.yml`:

```yaml
  llm:
    mem_limit: 28g      # 10 concurrent auditors -> 12 slots
```

Leave the remainder for the app (~8 GB plus ~0.8 GB per active session),
Postgres and Redis.

---

## 7. Settings worth knowing

| Setting | Default | Meaning |
|---|---|---|
| `MIN_CTX_PER_REQUEST` (llm) | `32768` | Tokens each request may use. |
| `LLM_NUM_CTX` (app) | `32768` | **Must equal the above.** The app budgets prompts against it. |
| `LLM_MAX_SLOTS` | detected cores | Upper bound on parallel slots. |
| `LLM_SLOTS_OVERRIDE` | — | Pins the slot count outright. |
| `REQUIRE_POSTGRES` | `1` | Never silently fall back to container-local SQLite. |
| `JWT_SECRET` | auto-generated | A unique one is generated and persisted on first boot. |

Changing the context size means changing **both** `MIN_CTX_PER_REQUEST` and
`LLM_NUM_CTX` together. They are set in two places because the LLM server
reports the whole shared pool as every slot's size, so the app cannot detect the
real per-request share on its own.

---

## 8. First login

Open `http://localhost:8000/`. The first-boot administrator comes from
`ADMIN_DEFAULT_PASSWORD` and `ADMIN_TOTP_SECRET`; set both in the compose file
before first start, or register the first auditor through the UI. Every account
uses TOTP two-factor authentication — keep the secret shown at registration.

---

## 9. Day-to-day

```sh
docker compose ps        # what is running
docker compose logs app  # application log
docker compose restart   # restart everything
docker compose down      # stop (data is kept)
```

Audit data lives in the `pgdata` and `app_data` volumes and survives `down`,
restarts and upgrades. `down -v` **deletes** it — do not use it to restart.

---

## 10. If something is wrong

| Symptom | Cause and fix |
|---|---|
| App answers 502 / not reachable | The LLM is still loading weights on first start. Give it 2–3 minutes. |
| "per request" is below 32768 | Not enough RAM for the slot count. Add RAM or set `LLM_MAX_SLOTS` lower. |
| Audits queue instead of running | Slot count is the limit — see the sizing table in section 2. |
| Controls report a timeout | Cores are the limit. The finding says so explicitly rather than guessing a verdict. |
| Postgres connection refused | The database did not become healthy. `logs shakthidb`. |

Upload scanner exports in their **native format** (`.nessus`, Burp XML, Nmap
XML) rather than PDF printouts — parsers read structure, and a PDF export throws
most of it away.
