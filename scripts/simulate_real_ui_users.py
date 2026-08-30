#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real User Concurrent Upload & Audit Simulator
=============================================
Simulates 10 to 20 real users logging in, uploading real sample files of
varying sizes (5 MB, 10 MB, 20 MB, etc.), running audit controls in parallel,
and capturing per-file latency, CPU %, and GPU % metrics.

Usage:
  python scripts/simulate_real_ui_users.py --users 10 --base-url http://localhost:8000
  python scripts/simulate_real_ui_users.py --users 20 --base-url http://localhost:8000
"""

import os
import sys
import time
import glob
import random
import string
import csv
import threading
import argparse
import requests
import pyotp

# Try psutil for CPU monitoring
try:
    import psutil
except ImportError:
    psutil = None

def get_nvidia_gpu_metrics():
    """Queries nvidia-smi for current GPU util % and VRAM used."""
    import subprocess
    cmd = ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,power.draw,temperature.gpu", "--format=csv,noheader,nounits"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        parts = [p.strip() for p in res.stdout.strip().split(",")]
        if len(parts) >= 5:
            return {
                "gpu_util_pct": float(parts[0]),
                "vram_used_mb": float(parts[1]),
                "vram_total_mb": float(parts[2]),
                "power_w": float(parts[3]),
                "temp_c": float(parts[4])
            }
    except Exception:
        pass
    return {"gpu_util_pct": 0.0, "vram_used_mb": 0.0, "vram_total_mb": 0.0, "power_w": 0.0, "temp_c": 0.0}

def find_sample_files(base_dir, custom_docs_dir=None):
    """Finds sample files of various sizes in the project or a user-specified custom docs directory."""
    samples = []
    search_paths = []
    
    if custom_docs_dir and os.path.exists(custom_docs_dir):
        print(f"[DOCS DIR] Using custom documents directory: {custom_docs_dir}")
        search_paths.append(os.path.join(custom_docs_dir, "**", "*.*"))
    else:
        search_paths = [
            os.path.join(base_dir, "samples", "**", "*.*"),
            os.path.join(base_dir, "aa audit evidence samples", "**", "*.*"),
            os.path.join(base_dir, "pqc samples", "**", "*.*")
        ]
        
    for p in search_paths:
        for fpath in glob.glob(p, recursive=True):
            if os.path.isfile(fpath) and not fpath.endswith(".py") and not fpath.endswith(".tar"):
                sz_mb = os.path.getsize(fpath) / (1024.0 * 1024.0)
                if 0.01 <= sz_mb <= 500.0:
                    samples.append((fpath, sz_mb))
    return samples

def find_scoped_evidence_set(docs_dir, scope_excel=None):
    """Collects one Excel scope checklist plus the evidence files beside it.
    Automatically handles nested directories from docker cp.
    """
    if not docs_dir or not os.path.isdir(docs_dir):
        return None, []

    excel = scope_excel if (scope_excel and os.path.isfile(scope_excel)) else None
    evidence = []

    # Handle single nested directory created by docker cp
    entries = [e for e in os.listdir(docs_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(docs_dir, entries[0])):
        docs_dir = os.path.join(docs_dir, entries[0])

    for root, dirs, files in os.walk(docs_dir):
        for name in sorted(files):
            if name.startswith("~$"):
                continue
            fpath = os.path.join(root, name)
            low = name.lower()
            if low.endswith((".xlsx", ".xls")):
                if excel is None:
                    excel = fpath
                continue
            if low.endswith((".py", ".tar", ".gz", ".zip", ".md", ".csv")):
                continue
            evidence.append((fpath, os.path.getsize(fpath) / (1024.0 * 1024.0)))

    return excel, evidence



def run_user_simulation(user_idx, base_url, sample_file, file_size_mb, control_id, mode, results, lock,
                        evidence_files=None, scope_excel=None):
    """Simulates a single real user uploading a file and running an audit.

    Two modes:
      * Excel-scoped (evidence_files given): the user uploads the whole evidence
        set and drives the audit from the Excel checklist, exactly as the UI does
        -- POST /controls/parse-scope-excel, then /audit/start with the returned
        matched_sls + custom_evidence + custom_documents. This exercises the
        two-phase locked-file retrieval path that real audits use.
      * Random (default): one random file, one random control. Retained for
        raw-throughput testing, but it measures the standard retrieval path and
        pairs unrelated files with unrelated controls, so its findings columns
        are not meaningful.
    """
    suf = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    username = f"user_{user_idx}_{suf}@audit.com"
    password = "UserPass123!"
    api = f"{base_url}/api"
    
    scoped = bool(evidence_files)
    if scoped:
        _label = f"{len(evidence_files)} files (Excel-scoped)"
        _total_mb = sum(mb for _, mb in evidence_files)
    else:
        _label = os.path.basename(sample_file)
        _total_mb = file_size_mb

    user_record = {
        "user_id": user_idx,
        "username": username,
        "filename": _label,
        "file_size_mb": round(_total_mb, 2),
        "control_id": "Excel checklist" if scoped else control_id,
        "upload_latency_sec": 0.0,
        "audit_latency_sec": 0.0,
        "total_latency_sec": 0.0,
        "status": "FAILED",
        "compliance_result": "N/A",
        "compliant_count": 0,
        "non_compliant_count": 0,
        "policy_gap": "N/A",
        "evidence_gap": "N/A",
        "error": ""
    }

    t0 = time.time()
    try:
        # 1. Register
        r = requests.post(f"{api}/auth/register", json={"username": username, "password": password, "role": "auditor"}, timeout=30)
        r.raise_for_status()
        totp_secret = r.json()["totp_secret"]

        # 2. Login & OTP
        r = requests.post(f"{api}/auth/login", json={"username": username, "password": password}, timeout=30)
        r.raise_for_status()
        r_otp = requests.post(f"{api}/auth/verify-otp", json={"username": username, "otp_code": pyotp.TOTP(totp_secret).now()}, timeout=30)
        r_otp.raise_for_status()
        token = r_otp.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Create Session
        r_sess = requests.post(f"{api}/audit/sessions", data={"session_title": f"Audit User {user_idx}", "framework": "ISO 27001", "username": username}, headers=headers, timeout=30)
        r_sess.raise_for_status()
        session_id = r_sess.json()["session_id"]

        # 4. Upload File(s) (Timed)
        # /audit/upload takes `files: List[UploadFile]`, so the whole evidence set
        # goes up in one multipart request -- same as the browser does.
        t_up_start = time.time()
        if scoped:
            handles = []
            try:
                payload = []
                for fpath, _mb in evidence_files:
                    fh = open(fpath, "rb")
                    handles.append(fh)
                    payload.append(("files", (os.path.basename(fpath), fh, "application/octet-stream")))
                r_up = requests.post(
                    f"{api}/audit/upload",
                    data={"session_id": session_id, "is_auditor_uploaded": "true", "username": username},
                    files=payload, headers=headers, timeout=600
                )
            finally:
                for fh in handles:
                    fh.close()
        else:
            with open(sample_file, "rb") as f:
                r_up = requests.post(f"{api}/audit/upload", data={"session_id": session_id, "is_auditor_uploaded": "true", "username": username}, files={"files": (os.path.basename(sample_file), f, "application/octet-stream")}, headers=headers, timeout=120)
        r_up.raise_for_status()
        t_up_end = time.time()
        user_record["upload_latency_sec"] = round(t_up_end - t_up_start, 2)

        # 5. Start Audit (Timed)
        t_audit_start = time.time()
        if scoped:
            # Mirror the UI: parse the checklist first, then start the audit with the
            # controls it matched plus the per-control file locks it derived. Without
            # custom_evidence/custom_documents the backend runs standard retrieval
            # across every uploaded file instead of the locked-file two-phase path.
            with open(scope_excel, "rb") as xf:
                r_scope = requests.post(
                    f"{api}/controls/parse-scope-excel",
                    files={"file": (os.path.basename(scope_excel), xf,
                                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
                    headers=headers, timeout=120
                )
            r_scope.raise_for_status()
            scope_data = r_scope.json()
            matched_sls = scope_data.get("matched_sls") or []
            if not matched_sls:
                raise RuntimeError(
                    f"Excel checklist matched no controls: {scope_data.get('message') or scope_data}"
                )
            user_record["control_id"] = f"Excel: {len(matched_sls)} controls"
            start_payload = {
                "session_id": session_id,
                "selected_sls": matched_sls,
                "model_choice": "Gemma 4 (e4b)",
                "audit_mode": mode,
                "username": username,
                "custom_evidence": scope_data.get("custom_evidence"),
                "custom_documents": scope_data.get("custom_documents"),
            }
        else:
            start_payload = {"session_id": session_id, "selected_sls": [control_id], "model_choice": "Gemma 4 (e4b)", "audit_mode": mode, "username": username}
        # Retry audit start on 429 (system busy) with backoff — up to 20 attempts
        # so queued users wait for a slot instead of failing immediately.
        max_start_retries = 20
        for _attempt in range(max_start_retries):
            r_start = requests.post(f"{api}/audit/start", json=start_payload, headers=headers, timeout=60)
            if r_start.status_code == 429:
                wait_s = 30 + _attempt * 5
                print(f"  [QUEUE] User {user_idx}: system busy (429), retrying in {wait_s}s (attempt {_attempt+1}/{max_start_retries})...")
                time.sleep(wait_s)
                continue
            r_start.raise_for_status()
            break
        else:
            raise RuntimeError(f"Audit start failed after {max_start_retries} retries (429 capacity limit). Try reducing --users or raising MAX_CONCURRENT_AUDITS.")

        # 6. Poll for completion — unlimited polling (no time limit) until audit finishes
        last_stat = "processing"
        while True:
            try:
                r_stat = requests.get(f"{api}/audit/status/{session_id}", headers=headers, timeout=30)
                if r_stat.status_code == 200:
                    last_stat = r_stat.json().get("status")
                    if last_stat in ("completed", "failed"):
                        break
            except Exception as poll_err:
                pass
            time.sleep(5)

        t_audit_end = time.time()
        user_record["audit_latency_sec"] = round(t_audit_end - t_audit_start, 2)
        user_record["total_latency_sec"] = round(t_audit_end - t0, 2)
        user_record["status"] = "SUCCESS" if last_stat == "completed" else "FAILED"

        # 7. Fetch Actual Audit Findings (Compliance Result, Gaps, Status)
        if last_stat == "completed":
            try:
                r_find = requests.get(f"{api}/audit/findings?session_id={session_id}", headers=headers, timeout=30)
                if r_find.status_code == 200:
                    findings_data = r_find.json()
                    user_record["findings_count"] = len(findings_data)
                    comp_cnt = sum(1 for fd in findings_data if str(fd.get("final_result") or fd.get("status") or "").upper() == "COMPLIANT")
                    non_comp_cnt = sum(1 for fd in findings_data if str(fd.get("final_result") or fd.get("status") or "").upper() == "NON_COMPLIANT")
                    user_record["compliant_count"] = comp_cnt
                    user_record["non_compliant_count"] = non_comp_cnt

                    # Summarize gaps
                    first_finding = findings_data[0] if findings_data else {}
                    user_record["compliance_result"] = str(first_finding.get("final_result") or first_finding.get("status") or "COMPLIANT").upper()
                    user_record["policy_gap"] = str(first_finding.get("policy_gap") or "No policy gap identified.").strip()
                    user_record["evidence_gap"] = str(first_finding.get("evidence_gap") or "No evidence gap identified.").strip()
            except Exception as find_err:
                user_record["error"] += f" Findings fetch notice: {find_err}"
    except Exception as ex:
        user_record["error"] = str(ex)
        user_record["total_latency_sec"] = round(time.time() - t0, 2)

    with lock:
        results.append(user_record)
        print(f"  [{user_record['status']}] User {user_idx}: File '{user_record['filename']}' ({user_record['file_size_mb']} MB) -> Upload: {user_record['upload_latency_sec']}s | Audit: {user_record['audit_latency_sec']}s | Total: {user_record['total_latency_sec']}s")

def run_simulation(num_users, base_url, mode="Quick", docs_dir=None, hardware="gpu", scope_excel=None):
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Prefer the Excel-scoped path: if the documents directory holds a checklist,
    # every user runs that same real audit -- same evidence set, same controls --
    # which is what a production run actually looks like. Only fall back to the
    # random single-file pool when no checklist is present.
    scoped_excel, scoped_evidence = find_scoped_evidence_set(docs_dir, scope_excel)
    scoped = bool(scoped_excel and scoped_evidence)

    samples = []
    if not scoped:
        samples = find_sample_files(project_dir, custom_docs_dir=docs_dir)
        if not samples:
            print(f"[ERROR] No document files found in '{docs_dir or 'workspace'}' to simulate uploads.")
            sys.exit(1)

    print("=" * 80)
    print(f"  SIMULATING {num_users} REAL CONCURRENT USERS (UPLOADS + AUDITS)")
    print(f"  Target Server: {base_url} | Audit Mode: {mode} | Hardware Mode: {hardware.upper()}")
    if docs_dir:
        print(f"  Custom Documents Directory: {docs_dir}")
    if scoped:
        _tot = sum(mb for _, mb in scoped_evidence)
        print(f"  Scope Mode: EXCEL-SCOPED (two-phase locked-file retrieval)")
        print(f"  Checklist : {os.path.basename(scoped_excel)}")
        print(f"  Evidence  : {len(scoped_evidence)} file(s), {_tot:.2f} MB total -- every user uploads all of them")
        for fp, mb in scoped_evidence:
            print(f"              - {os.path.basename(fp)} ({mb:.2f} MB)")
    else:
        print(f"  Scope Mode: RANDOM SINGLE-FILE (standard retrieval, no checklist found)")
    print("=" * 80)

    # Monitor hardware concurrently
    system_metrics = []
    stop_monitoring = threading.Event()

    def hardware_monitor():
        while not stop_monitoring.is_set():
            gpu = get_nvidia_gpu_metrics()
            cpu_pct = psutil.cpu_percent(interval=1.0) if psutil else 0.0
            ram_gb = psutil.virtual_memory().used / 1e9 if psutil else 0.0
            system_metrics.append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cpu_util_pct": cpu_pct,
                "ram_used_gb": round(ram_gb, 2),
                "gpu_util_pct": gpu["gpu_util_pct"],
                "vram_used_mb": gpu["vram_used_mb"],
                "power_w": gpu["power_w"],
                "temp_c": gpu["temp_c"]
            })

    mon_thread = threading.Thread(target=hardware_monitor, daemon=True)
    mon_thread.start()

    # Launch concurrent user simulations
    results = []
    lock = threading.Lock()
    threads = []
    
    t_start_all = time.time()
    for i in range(1, num_users + 1):
        if scoped:
            sample_file, sz_mb, control_id = scoped_excel, 0.0, None
        else:
            sample_file, sz_mb = random.choice(samples)
            control_id = random.choice([64, 1, 17, 32])
        t = threading.Thread(
            target=run_user_simulation,
            args=(i, base_url, sample_file, sz_mb, control_id, mode, results, lock),
            kwargs={"evidence_files": scoped_evidence if scoped else None,
                    "scope_excel": scoped_excel if scoped else None},
        )
        threads.append(t)
        t.start()
        time.sleep(0.3)  # slight stagger matching real user click behavior

    for t in threads:
        t.join()

    stop_monitoring.set()
    total_elapsed = round(time.time() - t_start_all, 2)

    # Calculate statistics & write report
    hw_tag = hardware.lower()
    report_filename = f"real_user_simulation_{hw_tag}_{num_users}users_report.md"
    csv_filename = f"real_user_simulation_{hw_tag}_{num_users}users.csv"

    # Save CSV
    with open(csv_filename, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["user_id", "username", "filename", "file_size_mb", "control_id", "upload_latency_sec", "audit_latency_sec", "total_latency_sec", "status", "findings_count", "compliance_result", "compliant_count", "non_compliant_count", "policy_gap", "evidence_gap", "error"])
        w.writeheader()
        w.writerows(results)

    # Aggregates
    succ = [r for r in results if r["status"] == "SUCCESS"]
    avg_upload_lat = sum(r["upload_latency_sec"] for r in succ) / len(succ) if succ else 0.0
    avg_audit_lat = sum(r["audit_latency_sec"] for r in succ) / len(succ) if succ else 0.0
    avg_total_lat = sum(r["total_latency_sec"] for r in succ) / len(succ) if succ else 0.0

    tot_comp = sum(r.get("compliant_count", 0) for r in succ)
    tot_non_comp = sum(r.get("non_compliant_count", 0) for r in succ)

    avg_cpu = sum(m["cpu_util_pct"] for m in system_metrics) / len(system_metrics) if system_metrics else 0.0
    max_cpu = max(m["cpu_util_pct"] for m in system_metrics) if system_metrics else 0.0
    
    avg_gpu = sum(m["gpu_util_pct"] for m in system_metrics) / len(system_metrics) if system_metrics else 0.0
    max_gpu = max(m["gpu_util_pct"] for m in system_metrics) if system_metrics else 0.0

    max_vram_mb = max(m["vram_used_mb"] for m in system_metrics) if system_metrics else 0.0
    max_ram_gb = max(m["ram_used_gb"] for m in system_metrics) if system_metrics else 0.0

    report_content = f"""# Real User Simulation Performance & Audit Findings Report ({hardware.upper()} Mode - {num_users} Concurrent Users)

**Test Date**: {time.strftime("%Y-%m-%d %H:%M:%S")}
**Target Server**: {base_url}
**Hardware Mode Tested**: {hardware.upper()}
**Simulated Concurrent Users**: {num_users}
**Total Batch Execution Wall Time**: {total_elapsed}s

## 1. Concurrency & Audit Findings Summary

| Metric | Measured Value |
| :--- | :--- |
| **Successful Concurrent Runs** | **{len(succ)} / {num_users}** ({len(succ)/num_users*100:.1f}%) |
| **Total Compliant Findings Evaluated** | **{tot_comp}** |
| **Total Non-Compliant Gaps Identified** | **{tot_non_comp}** |
| **Average File Upload Latency** | **{avg_upload_lat:.2f} seconds** |
| **Average Audit Evaluation Latency** | **{avg_audit_lat:.2f} seconds** |
| **Average Total User Turnaround Time** | **{avg_total_lat:.2f} seconds** |

## 2. Hardware Resource Utilization ({hardware.upper()} Mode)

| Component | Average Utilization | Peak / Maximum Utilization |
| :--- | :--- | :--- |
| **CPU Utilization (Host)** | **{avg_cpu:.1f}%** | **{max_cpu:.1f}%** |
| **System RAM Footprint** | - | **{max_ram_gb:.2f} GB** |
| **GPU Utilization (NVIDIA)** | **{avg_gpu:.1f}%** | **{max_gpu:.1f}%** |
| **GPU VRAM Footprint** | - | **{max_vram_mb/1024.0:.2f} GB** ({max_vram_mb:.0f} MB) |

## 3. Detailed Per-User Audit Findings & Latency Breakdown

| User | Uploaded Evidence File | Size (MB) | Control | Compliance Status | Upload Latency | Audit Latency | Total Latency | Identified Policy / Evidence Gap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for r in results:
        res_str = f"**{r.get('compliance_result', 'COMPLIANT')}**"
        gap_str = r.get("evidence_gap") if r.get("evidence_gap") != "No evidence gap identified." else r.get("policy_gap", "No gap identified.")
        report_content += f"| User {r['user_id']} | `{r['filename']}` | {r['file_size_mb']} MB | Control {r['control_id']} | {res_str} | {r['upload_latency_sec']}s | {r['audit_latency_sec']}s | {r['total_latency_sec']}s | {gap_str} |\n"

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_content)

    print("\n" + "=" * 80)
    print(f"  [PASS] BENCHMARK COMPLETE FOR {hardware.upper()} MODE ({num_users} CONCURRENT USERS)")
    print(f"  Markdown Report Saved: {report_filename}")
    print(f"  Raw CSV Log Saved: {csv_filename}")
    print("=" * 80)
    print(report_content)

def main():
    parser = argparse.ArgumentParser(description="Simulate real users uploading files and running audits.")
    parser.add_argument("--users", type=int, default=10, help="Number of concurrent users (e.g. 10 or 20)")
    parser.add_argument("--base-url", type=str, default="http://localhost:8000", help="Deployed app URL")
    parser.add_argument("--mode", type=str, default="Quick", choices=["Quick", "Deep"], help="Audit evaluation mode")
    parser.add_argument("--docs-dir", type=str, default=None, help="Path to custom directory containing your test documents")
    parser.add_argument("--hardware", type=str, default="gpu", choices=["cpu", "gpu"], help="Hardware mode to label in report (cpu or gpu)")
    parser.add_argument("--scope-excel", type=str, default=None,
                        help="Excel scope checklist. Defaults to the single .xlsx found in --docs-dir; "
                             "when present, every user runs that Excel-scoped audit over the whole evidence set.")

    args = parser.parse_args()
    run_simulation(args.users, args.base_url, mode=args.mode, docs_dir=args.docs_dir,
                   hardware=args.hardware, scope_excel=args.scope_excel)

if __name__ == "__main__":
    main()
