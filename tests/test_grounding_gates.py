# -*- coding: utf-8 -*-
"""
Grounding / contradiction gate regression suite.

Pure unit tests against src/core/validator.py -- no LLM server, no database, no
Redis. Run with:

    pytest tests/test_grounding_gates.py -v

Each test here corresponds to a defect found by executing the validator against
crafted evidence, not by reading it. The two directions matter equally:

  * A FALSE PASS (compliant verdict on failing evidence) hands the auditor a
    control that looks satisfied when it is not.
  * A FALSE FAILURE (non-compliant verdict on good evidence) buries a real pass
    in the gap list and destroys trust in the report.

Several fixes here trade against each other -- tightening the contradiction
check risks sinking correct findings -- so the "must still pass" cases below are
as load-bearing as the "must be blocked" ones. Keep both sides when editing.
"""
import io
import contextlib

from src.core.validator import (
    post_process,
    validate_only,
    check_grounding,
    check_reasoning_hallucination,
    map_new_schema_to_legacy,
)


class _Chunk:
    """Minimal stand-in for the DocumentChunk rows retrieval.py supplies."""

    def __init__(self, content, filename, chunk_id=1):
        self.id = chunk_id
        self.content = content
        self.filename = filename
        self.metadata_json = None


_BASE = {
    "confidence": 9,
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "policy_status": "NOT_REQUIRED",
    "policy_assessment": "NOT_APPLICABLE",
}


def _run(finding, doc, chunks):
    """post_process with its very chatty debug output suppressed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return post_process(dict(finding), doc, {}, db_chunks=chunks)


def _ground(finding, doc, chunks):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return validate_only(dict(finding), doc, {}, db_chunks=chunks)


# ── Contradiction between source and verdict ──────────────────────────────────

def test_failing_source_cannot_produce_compliant():
    """The headline defect: source says the control is off, verdict said COMPLIANT.

    The negative-proof scan used to read the model's own quote. A model that
    quoted selectively ("NTP enabled synchronized chronyd service") simply
    omitted every negation, so the guard saw a clean string and the deterministic
    layer computed COMPLIANT from inputs that all agreed.
    """
    doc = ("timedatectl status  NTP enabled: no  NTP synchronized: no  "
           "chronyd.service: inactive (dead)")
    out = _run({**_BASE,
                "control_id": "8.17 Clock Synchronization",
                "question": "8.17 Clock Synchronization - Whether NTP is enabled",
                "status": "COMPLIANT",
                "evidence_quote": "NTP enabled synchronized chronyd service time zone",
                "reasoning": "The system demonstrates NTP is enabled."},
               doc, [_Chunk(doc, "ntp.png")])

    assert out["status"] == "NON_COMPLIANT"
    assert out.get("contradiction_suspected") is True
    # Also routes back through reflection in audit_graph.should_continue().
    assert out.get("requires_human_review") is True


def test_unrelated_negation_does_not_sink_a_real_pass():
    """Guard against over-correction.

    expand_to_complete_sentence() widens a verified quote by up to ~450 chars, and
    terminal screenshots have no sentence punctuation -- so a correct
    "NTP enabled: yes" citation reliably drags in a neighbouring
    "IPv6 forwarding: disabled". A flat negation scan marked that NOT_SUPPORTED.
    """
    doc = ("timedatectl status  NTP enabled: yes  NTP synchronized: yes  "
           "Time zone: Asia/Kolkata  IPv6 forwarding: disabled  legacy telnet: disabled")
    out = _run({**_BASE,
                "control_id": "8.17 Clock Synchronization",
                "question": "8.17 Clock Synchronization - Whether NTP is enabled",
                "status": "COMPLIANT",
                "evidence_quote": "NTP enabled: yes  NTP synchronized: yes",
                "reasoning": "NTP is enabled and synchronized."},
               doc, [_Chunk(doc, "ntp_ok.png")])

    assert out["status"] == "COMPLIANT"


def test_control_expecting_disabled_is_not_inverted():
    """Polarity. "Whether Telnet is disabled" is CONFIRMED by the word "disabled".

    The flat indicator list marked exactly that evidence NOT_SUPPORTED, so such a
    control could never pass regardless of what was uploaded.
    """
    doc = "Service hardening report:  telnet: disabled   rsh: disabled   ftp: disabled"
    out = _run({**_BASE,
                "control_id": "8.20 Network Security",
                "question": "8.20 Network Security - Whether Telnet is disabled",
                "status": "COMPLIANT",
                "evidence_quote": "telnet: disabled   rsh: disabled   ftp: disabled",
                "reasoning": "Telnet is disabled as required."},
               doc, [_Chunk(doc, "hardening.png")])

    assert out["status"] == "COMPLIANT"


# ── Gate 3.5: image key-term overlap ─────────────────────────────────────────

def test_gate35_rejects_terms_scattered_across_a_long_document():
    """Terms must co-occur locally, not be scavenged from opposite ends of an OCR dump."""
    filler = " ".join(f"line{i} routine output value" for i in range(120))
    doc = ("NTP " + filler + " enabled " + filler + " synchronized " + filler
           + " configuration " + filler + " status")
    out = _ground({"control_id": "8.17 Clock Synchronization",
                   "status": "COMPLIANT",
                   "evidence_quote": "NTP enabled synchronized configuration status",
                   "confidence": 9},
                  doc, [_Chunk(doc, "long.png")])

    assert out["hallucination_check"] == "NOT_GROUNDED"


def test_gate35_still_tolerates_local_ocr_noise():
    """The OCR tolerance this gate exists for must survive the tightening."""
    doc = ("root@host ~# timedatectl  NTP enabled yes  NTP synchronized yes  "
           "RTC in local TZ no")
    out = _ground({"control_id": "8.17 Clock Synchronization",
                   "status": "COMPLIANT",
                   "evidence_quote": "NTP synchronized enabled timedatectl",
                   "confidence": 9},
                  doc, [_Chunk(doc, "ocr.png")])

    assert out["hallucination_check"] in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING")


# ── check_grounding ──────────────────────────────────────────────────────────

_DOC = "NTP enabled: yes NTP synchronized: yes RTC in local TZ: no"


def test_check_grounding_rejects_a_fabricated_tail():
    """Used to verify only evidence[:50], so anything after 50 chars was unchecked."""
    real_prefix = "NTP enabled: yes NTP synchronized: yes RTC in loc"
    fabricated = (real_prefix
                  + " and retention is 7 years approved by the CISO on 12-Mar-2024.")
    assert check_grounding(fabricated, _DOC) == "NOT_GROUNDED"


def test_check_grounding_accepts_a_genuine_quote():
    assert check_grounding("NTP enabled: yes", _DOC) == "GROUNDED"


# ── Reasoning hallucination detector ─────────────────────────────────────────

def test_hallucination_detector_flags_fabricated_claims():
    """Its skip-list held generic audit nouns ("control", "evidence", "policy"...),
    which appear in essentially every sentence -- so it skipped essentially
    everything and could not return a negative result on realistic input."""
    result = check_reasoning_hallucination(
        "The document states that backups run every 4 hours to an offsite vault. "
        "It also contains a signed approval from the Chief Information Security Officer.",
        _DOC,
    )
    assert result["clean"] is False
    assert len(result["flagged_phrases"]) >= 1


def test_hallucination_detector_spares_absence_claims():
    """You cannot ground "X is not present" by finding X, so absence claims are exempt.
    Without this every correct NON_COMPLIANT finding would be flagged."""
    result = check_reasoning_hallucination(
        "The uploaded document does not contain any backup retention schedule. "
        "No evidence of an approval record was found.",
        _DOC,
    )
    assert result["clean"] is True


# ── Finding description must not contradict its own verdict ──────────────────
#
# These exercise map_new_schema_to_legacy() directly. It returns early for a
# legacy-shaped finding ("evidence_quote" present, "justification" absent), so the
# gap fallback below is only reachable on the new-schema shape the generator
# actually emits -- an `evidence` list plus `justification`.

def test_compliant_finding_does_not_report_missing_evidence():
    """A COMPLIANT verdict described as "No documented evidence satisfying the
    control requirements" contradicts itself. The fallback fired whenever no gaps
    were listed, which is exactly the clean-pass case -- observed on a live run for
    controls quoting "NTP enabled: yes" and "Document Version: 1.0".
    """
    mapped = map_new_schema_to_legacy({
        "status": "COMPLIANT",
        "justification": "NTP is enabled and synchronized.",
        "evidence": [{"excerpt": "NTP enabled: yes"}],
        "missing_requirements": [],
        "business_impact": "",
    })
    assert "No documented evidence" not in str(mapped["gap_description"])
    assert "No gaps identified" in str(mapped["gap_description"])
    assert mapped["description"] == mapped["gap_description"]


def test_non_compliant_finding_keeps_the_absence_wording():
    """The original wording is correct for a genuine failure -- keep it there."""
    mapped = map_new_schema_to_legacy({
        "status": "NON_COMPLIANT",
        "justification": "Nothing relevant was located.",
        "evidence": [],
        "missing_requirements": [],
        "business_impact": "",
    })
    assert "No documented evidence" in str(mapped["gap_description"])


def test_reported_gaps_are_preserved_for_both_verdicts():
    """The fallback must not displace real gap content when the model supplied it."""
    mapped = map_new_schema_to_legacy({
        "status": "NON_COMPLIANT",
        "justification": "Partial.",
        "evidence": [{"excerpt": "something"}],
        "missing_requirements": ["Retention period is not stated"],
        "business_impact": "Regulatory exposure",
    })
    assert "Retention period is not stated" in mapped["gap_description"]
    assert "Regulatory exposure" in mapped["gap_description"]


# ── Excel scoping vs the clause-5/6/7 policy default ────────────────────────
#
# The evidence text below classifies as UNKNOWN rather than POLICY/PROCEDURE, so it
# lands in evidence_items. That matters: text classified as a procedure would land in
# policy_items and satisfy the policy requirement on its own, and the waiver under
# test would never be reached.

_ARCHIVE_DOC = ("Server_180 DB_Backup File Home Share View Cut New item Open Select all "
                "Copy path 2026-04-16 backup_2026_04_16.zip 4.2 GB archive volume")
_ARCHIVE_QUOTE = ("Server_180 DB_Backup File Home Share View Cut New item Open Select all "
                  "Copy path 2026-04-16 backup_2026_04_16.zip 4.2 GB")


def test_excel_scoped_evidence_only_control_can_pass():
    """5.33 is clause 5, so derive_policy_required() defaults it to needing a policy.
    The auditor's checklist scoped it to a single screenshot, which cannot contain
    one -- making the control unpassable regardless of what was uploaded. Excel
    scoping is the stronger statement of intent and overrides the blanket default.
    """
    out = _run({**_BASE,
                "control_id": "5.33 Protection of Records",
                "question": "5.33 Protection of Records - Whether log archival is done?",
                "status": "COMPLIANT",
                "evidence_quote": _ARCHIVE_QUOTE,
                "reasoning": "Archival is evidenced by the archive listing.",
                "locked_filenames": ["117_Log_Archived_AUA_Prod.jpg"]},
               _ARCHIVE_DOC, [_Chunk(_ARCHIVE_DOC, "117_Log_Archived_AUA_Prod.jpg")])

    assert out["status"] == "COMPLIANT"
    assert out.get("policy_requirement_waived") is True


def test_unscoped_clause5_control_still_requires_policy():
    """Without Excel scoping the clause default stands. This is the guard against
    the waiver leaking into ordinary, non-scoped runs."""
    out = _run({**_BASE,
                "control_id": "5.33 Protection of Records",
                "question": "5.33 Protection of Records - Whether log archival is done?",
                "status": "COMPLIANT",
                "evidence_quote": _ARCHIVE_QUOTE,
                "reasoning": "Archival is evidenced by the archive listing."},
               _ARCHIVE_DOC, [_Chunk(_ARCHIVE_DOC, "117_Log_Archived_AUA_Prod.jpg")])

    assert out["status"] == "NON_COMPLIANT"
    assert not out.get("policy_requirement_waived")


def test_scoped_control_explicitly_asking_for_a_policy_still_requires_one():
    """The waiver overrides only the blanket clause default. A question that
    literally asks for a policy document still demands one, scoped or not."""
    out = _run({**_BASE,
                "control_id": "5.1 Policies for Information Security",
                "question": "5.1 Policies for Information Security - Is an approved policy document available?",
                "status": "COMPLIANT",
                "evidence_quote": _ARCHIVE_QUOTE,
                "reasoning": "An artifact was located.",
                "locked_filenames": ["117_Log_Archived_AUA_Prod.jpg"]},
               _ARCHIVE_DOC, [_Chunk(_ARCHIVE_DOC, "117_Log_Archived_AUA_Prod.jpg")])

    assert out["status"] == "NON_COMPLIANT"
    assert not out.get("policy_requirement_waived")
