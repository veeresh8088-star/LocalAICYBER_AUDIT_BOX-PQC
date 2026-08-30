# -*- coding: utf-8 -*-
"""
Run the COMPLETE Real Audit Pipeline (bg_worker.py -> LangGraph -> retrieval -> LLM -> validator)
using the actual real documents and real Excel checklist.
"""

import os
import sys
import io
import time
import json

sys.path.append(os.getcwd())

os.environ["RESOURCE_GUARD_CRITICAL_PERCENT"] = "2"
os.environ["RESOURCE_GUARD_CRITICAL_FLOOR_GB"] = "0.2"
os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:11434")
os.environ.setdefault("EMBEDDING_HOST", "http://127.0.0.1:11435")

from src.core.parsers.doc_parsers import extract_text
from src.core.excel_scoping_parser import parse_excel_scoping_checklist
from src.core.bg_worker import generate_ollama_findings, _build_controls_for_audit
from src.db.database import SessionLocal, force_master, AuditReport, Finding, ComplianceScore

print("=" * 80)
print("RUNNING COMPLETE LIVE AUDIT PIPELINE ON REAL DOCUMENTS")
print("=" * 80)

EVIDENCE_DIR = os.path.join(os.getcwd(), "aa audit evidence samples")
EXCEL_FILE = os.path.join(EVIDENCE_DIR, "Audit checklist and evidence files.xlsx")

files = os.listdir(EVIDENCE_DIR)
file_registry = {}
all_context_blocks = []

for fname in files:
    if fname.endswith(".xlsx"):
        continue
    fpath = os.path.join(EVIDENCE_DIR, fname)
    # The evidence folder contains a 'test_vapt samples' subdirectory; opening a
    # directory as a file raises, so skip anything that is not a regular file.
    if not os.path.isfile(fpath):
        continue
    with open(fpath, "rb") as f:
        f_bytes = f.read()
    f_obj = io.BytesIO(f_bytes)
    f_obj.name = fname
    text = extract_text(f_obj)
    file_registry[fname] = text
    all_context_blocks.append(f"=== FILE: {fname} ===\n{text}")

full_context_str = "\n\n".join(all_context_blocks)
print(f"[+] Loaded {len(file_registry)} real files into file registry (Total context: {len(full_context_str)} chars)")

# Parse real Excel checklist
checklist_items = parse_excel_scoping_checklist(EXCEL_FILE, uploaded_filenames=files)
custom_evidence = {"excel_items": checklist_items}
print(f"[+] Parsed {len(checklist_items)} rows from real Excel checklist into custom_evidence")

# Create test audit report in database
session_id = f"test_real_run_{int(time.time())}"
with force_master():
    db = SessionLocal()
    report = AuditReport(
        session_id=session_id,
        session_title="Real Audit Verification Session",
        created_by="test_auditor@organization.com",
        framework="ISO/IEC 27001:2022",
        status="In Progress"
    )
    db.add(report)
    db.commit()
    report_id = report.id
    db.close()

print(f"[+] Initialized live audit report in DB (session_id: {session_id}, report_id: {report_id})")

# Run the complete pipeline
start_t = time.time()
print("\n[+] Launching generate_ollama_findings()...")

res = generate_ollama_findings(
    context=full_context_str,
    file_names_list=list(file_registry.keys()),
    selected_sls=None,
    model_choice="Gemma 4 (e4b)",
    bg_key=session_id,
    checkpoint_session_id=session_id,
    audit_mode="Deep",
    custom_evidence=custom_evidence,
    file_registry=file_registry,
    username="Test Lead Auditor"
)

elapsed = time.time() - start_t
print(f"\n[+] generate_ollama_findings() completed in {elapsed:.2f}s")

if len(res) == 4:
    resolved_list, findings, all_results, _ = res
else:
    resolved_list, findings, all_results = res

print("\n" + "=" * 80)
print(f"LIVE PIPELINE EXECUTION RESULTS ({len(all_results)} controls evaluated)")
print("=" * 80)

for idx, f in enumerate(all_results, 1):
    cid = f.get("control_id") or f.get("control")
    status = f.get("status")
    ev_quote = f.get("evidence_snippet") or f.get("evidence_quote") or "None"
    rec = f.get("recommendation") or ""
    finding_txt = f.get("finding") or f.get("description") or ""
    
    print(f"\n[ROW {idx}] {cid}")
    print(f"  Status        : {status}")
    print(f"  Evidence Quote: {ev_quote[:200].replace(chr(10), ' ')}")
    print(f"  Finding       : {finding_txt[:150].replace(chr(10), ' ')}")
    print(f"  Recommendation: {rec[:150].replace(chr(10), ' ')}")

# Summary
comp_count = sum(1 for f in all_results if (f.get("status") or "").upper() == "COMPLIANT")
non_comp_count = len(all_results) - comp_count

print("\n" + "=" * 80)
print(f"PIPELINE SUMMARY: {comp_count} COMPLIANT, {non_comp_count} NON_COMPLIANT out of {len(all_results)} total")
print("=" * 80)
