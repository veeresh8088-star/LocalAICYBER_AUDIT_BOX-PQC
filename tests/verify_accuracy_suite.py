# -*- coding: utf-8 -*-
import sys
import re
import os
import time

sys.path.append(os.getcwd())

print("=" * 70)
print("COMPREHENSIVE AUDIT SYSTEM ACCURACY VERIFICATION SUITE")
print("=" * 70)

# -------------------------------------------------------------
# 1. SCOPING & DIRECT KEYWORD MAPPING ACCURACY
# -------------------------------------------------------------
print("\n[TEST 1] Testing Excel Scoping Direct Keyword Resolution...")
from src.core.controls_data import USE_CASES
from src.core.excel_scoping_parser import _resolve_control, _DIRECT_KEYWORD_CONTROL_MAP

use_cases = USE_CASES
total_direct = len(_DIRECT_KEYWORD_CONTROL_MAP)
correct_resolutions = 0
failed_resolutions = []

for keywords, target in _DIRECT_KEYWORD_CONTROL_MAP:
    for kw in keywords:
        sample_query = f"Please audit the organization regarding {kw} and verify evidence."
        res = _resolve_control(q_text=sample_query, use_cases=use_cases)
        target_cid = target.split(" ")[0]
        got_cid = res.get("control_id")
        if got_cid == target_cid:
            correct_resolutions += 1
        else:
            failed_resolutions.append((kw, target_cid, got_cid))

print(f"-> Direct Keyword Tests: {correct_resolutions} passed, {len(failed_resolutions)} failed.")
if failed_resolutions:
    for kw, exp, got in failed_resolutions[:10]:
        print(f"   FAIL: Query with [{kw}] expected {exp}, got {got}")
else:
    print("-> 100% Accuracy on Direct Keyword Map queries!")

# -------------------------------------------------------------
# 2. ALL 93 ISO CONTROLS RESOLUTION BY EXACT ID & NAME
# -------------------------------------------------------------
print("\n[TEST 2] Testing Exact ID & Label Resolution for all 93 ISO controls...")
# USE_CASES holds every framework, not just ISO: NIST CSF (GV./ID./PR./DE./RS./RC.),
# SOC 2 (CC*), DPDP, BCMS, XBOM and PQC all live here too. Excluding only "VAPT"
# swept 109 non-ISO entries into this test and reported them as ISO failures.
# Match the ISO 27001:2022 Annex A shape instead -- clause "<digits>.<digits> ".
iso_ucs = [uc for uc in USE_CASES if re.match(r"^\d+\.\d+ ", str(uc["use_case"]))]
id_pass = 0
id_fail = []

for uc in iso_ucs:
    cid = str(uc["use_case"]).split(" ")[0]
    cname = uc.get("label", "")
    
    # Query with ID
    res1 = _resolve_control(id_text=f"Audit check for {cid}", use_cases=use_cases)
    # Query with Control Full Label
    res2 = _resolve_control(name_text=cname, q_text=f"Does the organization have {cname}?", use_cases=use_cases)
    
    if res1.get("control_id") == cid and res2.get("control_id") == cid:
        id_pass += 1
    else:
        id_fail.append((cid, res1.get("control_id"), res2.get("control_id")))

print(f"-> Exact ID & Label Matching: {id_pass}/{len(iso_ucs)} ISO controls resolved accurately.")
if id_fail:
    for cid, r1, r2 in id_fail:
        print(f"   MISMATCH: {cid} -> by ID: {r1}, by Name: {r2}")

# -------------------------------------------------------------
# 3. VAPT 1..15 RESOLUTION
# -------------------------------------------------------------
print("\n[TEST 3] Testing VAPT 1..15 Resolution...")
vapt_ucs = [uc for uc in USE_CASES if str(uc["use_case"]).startswith("VAPT")]
vapt_pass = 0
for uc in vapt_ucs:
    cid = str(uc["use_case"]).split(" ")[0]
    res = _resolve_control(q_text=f"Review findings for {cid}", use_cases=use_cases)
    if res.get("control_id") == cid:
        vapt_pass += 1
print(f"-> VAPT ID Matching: {vapt_pass}/15 VAPT controls resolved accurately.")

# -------------------------------------------------------------
# 4. CONTENT_SIGNALS & AI AUTO-SCOPING RECALL
# -------------------------------------------------------------
print("\n[TEST 4] Testing Scoping Engine Document Type Signals & Umbrella Expansion...")
from src.ai.scoping_engine import detect_scope_and_controls, CONTENT_SIGNALS, DOC_TYPE_MAPPINGS

total_signals = sum(len(sigs) for sigs in CONTENT_SIGNALS.values())
print(f"-> Total Content Signal Keywords: {total_signals} across {len(CONTENT_SIGNALS)} categories")

umbrella_doc = "Master Information Security Policy (iProtect) document covering enterprise IT controls."
u_ctrls, _, u_cats, _ = detect_scope_and_controls(umbrella_doc, "master_policy.pdf")
print(f"-> Umbrella Policy Expansion: {len(u_cats)} categories, {len(u_ctrls)} controls detected")

# -------------------------------------------------------------
# 5. VALIDATOR DETERMINISTIC COMPLIANCE FORMULA VERIFICATION
# -------------------------------------------------------------
print("\n[TEST 5] Testing Deterministic Compliance Rule Enforcement in validator.py...")
from src.core.validator import validate_only

# Scenario A: Policy FOUND+COMPLIANT, Evidence FOUND+COMPLIANT -> COMPLIANT
finding_a = {
    "control_id": "8.5 Secure Authentication",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_quote": "Production authentication logs show Duo push approved for admin user id 4920 at 14:32:10 UTC.",
    "evidence_snippet": "Production authentication logs show Duo push approved for admin user id 4920 at 14:32:10 UTC.",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}
doc_text_a = "Information Security Standard: All systems require multi-factor authentication. Production authentication logs show Duo push approved for admin user id 4920 at 14:32:10 UTC."
res_a = validate_only(finding_a, doc_text_a, {"8.5": "Evidence showing configured multi-factor authentication systems and push notification logs."})
status_a = res_a.get("status")
print(f"-> Scenario A (Both Compliant + Grounded): Status = {status_a} (Expected COMPLIANT)")

# Scenario B: Policy FOUND+COMPLIANT, Evidence NOT_FOUND -> NON_COMPLIANT
finding_b = {
    "control_id": "8.5 Secure Authentication",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_quote": "NOT_FOUND",
    "evidence_snippet": "",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"  # LLM hallucinates COMPLIANT without evidence
}
doc_text_b = "Policy Requirement: Administrators must use MFA."
res_b = validate_only(finding_b, doc_text_b, {"8.5": "MFA configuration"})
status_b = res_b.get("status")
print(f"-> Scenario B (No Evidence - Overrides Hallucinated COMPLIANT): Status = {status_b} (Expected NON_COMPLIANT)")

print("\n" + "=" * 70)
print("ACCURACY VERIFICATION COMPLETE")
print("=" * 70)
