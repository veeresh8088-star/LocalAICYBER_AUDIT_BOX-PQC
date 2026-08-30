# -*- coding: utf-8 -*-
"""
Cross-framework control resolution.

Pure unit tests -- no LLM server, no database. Run with:

    pytest tests/test_framework_resolution.py -v

USE_CASES holds 217 controls across eight frameworks that share one resolver.
Two things must hold for every one of them:

  1. A control ID resolves to ITS OWN control. An Excel checklist whose only
     usable column is "Control ID" is a normal shape, and it must work.
  2. A control never resolves into a DIFFERENT framework. Auditing a NIST
     control against ISO 27001's text and expected evidence produces a finding
     about the wrong requirement, which is worse than no finding at all.

Both failed before `_CONTROL_ID_RE` was extended: it matched only "N.N" and
"VAPT-N", so ID lookup was dead for five frameworks and fuzzy name matching
silently took over -- sending NIST PR.AT to ISO 6.3 and RS.MA to ISO 5.24.
"""
import re
import collections

import pytest

from src.core.controls_data import USE_CASES
from src.core.excel_scoping_parser import _resolve_control, _resolve_control_by_id


def _framework_of(use_case: str) -> str:
    u = str(use_case or "")
    if u.startswith("VAPT"):
        return "VAPT"
    for prefix in ("PQC-", "XBOM-", "DPDP-", "BCMS-"):
        if u.startswith(prefix):
            return prefix.rstrip("-")
    if re.match(r"^CC\d", u):
        return "SOC2"
    if re.match(r"^(GV|ID|PR|DE|RS|RC)\.", u):
        return "NIST-CSF"
    if re.match(r"^\d+\.\d+ ", u):
        return "ISO27001"
    return "OTHER"


_ALL = [(str(uc["use_case"]).split(" ")[0], uc.get("label", "") or "", str(uc["use_case"]))
        for uc in USE_CASES]

_FRAMEWORKS = sorted({_framework_of(full) for _, _, full in _ALL})


def test_every_framework_is_represented():
    """Guards the parametrised tests below: if a framework is dropped from
    USE_CASES its coverage would vanish silently rather than fail."""
    assert set(_FRAMEWORKS) == {
        "BCMS", "DPDP", "ISO27001", "NIST-CSF", "PQC", "SOC2", "VAPT", "XBOM"
    }
    assert len(_ALL) == 217


@pytest.mark.parametrize("framework", _FRAMEWORKS)
def test_id_only_resolution(framework):
    """A checklist carrying only a Control-ID column must resolve every control.

    Was 1/15 for DPDP, 1/12 for PQC, 1/23 for XBOM, 1/4 for BCMS, 9/33 for SOC 2.
    """
    rows = [(cid, label, full) for cid, label, full in _ALL
            if _framework_of(full) == framework]
    failures = []
    for cid, _label, _full in rows:
        got = (_resolve_control(id_text=cid, use_cases=USE_CASES) or {}).get("control_id")
        if got != cid:
            failures.append((cid, got))
    assert not failures, f"{framework}: {len(failures)}/{len(rows)} unresolved -> {failures[:5]}"


@pytest.mark.parametrize("framework", _FRAMEWORKS)
def test_combined_resolution_never_crosses_frameworks(framework):
    """With id + name + question supplied -- the realistic Excel path -- a control
    must resolve to itself, and never into another framework."""
    rows = [(cid, label, full) for cid, label, full in _ALL
            if _framework_of(full) == framework]
    crossings = []
    for cid, label, _full in rows:
        got = (_resolve_control(id_text=cid, name_text=label, q_text=label,
                                use_cases=USE_CASES) or {}).get("control_id")
        if got != cid:
            got_fw = next((_framework_of(f) for c, _l, f in _ALL if c == got), "UNKNOWN")
            crossings.append((cid, got, got_fw))
    assert not crossings, f"{framework} mis-resolved: {crossings[:5]}"


def test_control_ids_are_unique():
    """Resolution is only meaningful if IDs identify a single control."""
    dupes = [cid for cid, n in collections.Counter(c for c, _, _ in _ALL).items() if n > 1]
    assert not dupes, f"duplicate control IDs: {dupes}"


@pytest.mark.parametrize("raw,expected_prefix", [
    ("DPDP-3", "DPDP-3"), ("dpdp 3", "DPDP-3"), ("DPDP - 3", "DPDP-3"),
    ("PQC-5", "PQC-5"), ("pqc5", "PQC-5"),
    ("XBOM-7", "XBOM-7"), ("BCMS-2", "BCMS-2"),
    ("VAPT-3", "VAPT-3"), ("vapt 3", "VAPT-3"),
])
def test_dashed_ids_normalise_to_canonical_form(raw, expected_prefix):
    """Sheets write these inconsistently -- "PQC-5", "pqc 5", "PQC5" all appear."""
    uc = _resolve_control_by_id(raw, USE_CASES)
    assert uc is not None, f"{raw!r} matched no control"
    assert str(uc["use_case"]).split(" ")[0] == expected_prefix


@pytest.mark.parametrize("cid", ["5.1", "8.17", "CC6.1", "GV.OC", "PR.AT", "RS.MA"])
def test_dotted_ids_resolve_exactly(cid):
    """PR.AT and RS.MA are the two that leaked into ISO before the fix."""
    uc = _resolve_control_by_id(cid, USE_CASES)
    assert uc is not None, f"{cid!r} matched no control"
    assert str(uc["use_case"]).split(" ")[0].upper() == cid.upper()


@pytest.mark.parametrize("question,expected", [
    ("Whether NTP is enabled", "8.17"),
    ("Whether NTP synchronized?", "8.17"),
    ("FRAUD ANALYTICS POLICY is available? Version and last updated date.", "5.1"),
    ("Whether multifactor authentification enabled or implemented?", "8.5"),
    ("How is the Authentication done?", "8.5"),
    ("Whether PAM user access evidence available?", "8.2"),
    ("CPU, memory and disk utilization", "8.6"),
    ("Whether log archival is done?", "5.33"),
])
def test_real_checklist_questions_still_resolve(question, expected):
    """The eight questions from the live customer checklist. Broadening the ID
    pattern must not pull a question-only row toward a different framework."""
    got = (_resolve_control(q_text=question, use_cases=USE_CASES) or {}).get("control_id")
    assert got == expected
