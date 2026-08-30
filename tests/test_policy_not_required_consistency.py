# -*- coding: utf-8 -*-
"""
A finding must not contradict itself about whether a policy was required.

    pytest tests/test_policy_not_required_consistency.py -v

Built from two findings in a real ISO 27001 run, both of which shipped like
this:

    Policy: Not Required
    Missing Requirements: A documented policy defining the retention period
                          and archival procedure for logs.

Both halves belong to the same finding and flatly contradict each other. 8.6
Capacity Management was worse still -- its recommendation read "no formal
policy statement was identified... Document a written policy" on a finding
whose header said a policy was not required.

The cause is ordering, not judgement. gap_description and recommendation are
built early in post_process from the LLM's own policy_status; the
deterministic layer only overrules that to NOT_REQUIRED about 900 lines later,
leaving the earlier text stale.

The verdict may well be correct in both cases -- backup folders are not a log
retention procedure. The stated REASON is what is wrong, and an auditee reading
the exported report spots it immediately. These tests pin the reconciliation,
and equally pin that a genuinely required policy still gets asked for.
"""
import pytest

from src.core.validator import (_drop_policy_demands, _split_requirements,
                                _rewrite_policy_recommendation)

# Verbatim from the 5.33 Protection of Records finding.
GAP_5_33 = ("Business Impact: Potential loss of historical data required for forensic "
            "investigation or compliance audits. | Missing Requirements: A documented "
            "policy defining the retention period and archival procedure for logs., "
            "Operational evidence demonstrating that logs are systematically archived "
            "according to defined procedures.")

# Verbatim from the 8.6 Capacity Management finding.
GAP_8_6 = ("Business Impact: Potential service degradation or performance bottlenecks "
           "due to unmonitored resource saturation. | Missing Requirements: Formal "
           "documented policy defining acceptable thresholds for CPU, memory, and disk "
           "utilization., Defined procedures for capacity review and remediation when "
           "thresholds are breached.")

REC_8_6 = ("Evidence of implementation was found but no formal policy statement was "
           "identified for 8.6 Capacity Management. Document a written policy or "
           "procedure that mandates this control requirement.")


# ── the contradiction is removed ─────────────────────────────────────────────

def test_the_policy_demand_is_dropped():
    out = _drop_policy_demands(GAP_5_33, "5.33 Protection of Records")
    assert "documented policy" not in out.lower()


def test_the_real_evidence_gap_survives():
    """Dropping the policy demand must not throw away the operational gap --
    that is the half that actually justifies the NON_COMPLIANT verdict."""
    out = _drop_policy_demands(GAP_5_33, "5.33")
    assert "systematically archived" in out


def test_business_impact_is_left_alone():
    """Business impact is a statement about consequence, not a demand for a
    document, so it is not the validator's business to edit it."""
    out = _drop_policy_demands(GAP_5_33, "5.33")
    assert "Potential loss of historical data" in out


def test_the_8_6_finding_reconciles_too():
    out = _drop_policy_demands(GAP_8_6, "8.6 Capacity Management")
    assert "documented policy" not in out.lower()
    assert "capacity review and remediation" in out
    assert "performance bottlenecks" in out


def test_the_recommendation_stops_asking_for_a_policy():
    """Asserted on intent, not on the substring.

    The replacement deliberately mentions a policy -- "a written policy is NOT
    required for this control" -- because saying so outright is what stops an
    auditor wondering whether the tool simply forgot. So the test checks that
    the text no longer INSTRUCTS anyone to write one.
    """
    out = _rewrite_policy_recommendation(REC_8_6, "8.6 Capacity Management")
    lower = out.lower()
    for demand in ("document a written policy", "document a policy",
                   "no formal policy statement was identified"):
        assert demand not in lower, f"still asking for a policy: {demand}"
    assert "not required" in lower
    assert "operational evidence" in lower


# ── and nothing else is disturbed ────────────────────────────────────────────

def test_a_gap_with_no_policy_demand_is_returned_unchanged():
    gap = ("Business Impact: Unauthorised access. | Missing Requirements: Evidence "
           "demonstrating periodic review of privileged accounts.")
    assert _drop_policy_demands(gap, "8.2") == gap


def test_a_recommendation_with_no_policy_demand_is_untouched():
    rec = "Upload the access review report covering the last quarter."
    assert _rewrite_policy_recommendation(rec, "8.2") == rec


def test_a_gap_with_no_missing_requirements_segment_is_untouched():
    gap = "Business Impact: Service degradation."
    assert _drop_policy_demands(gap, "8.6") == gap


@pytest.mark.parametrize("value", ["", None, "   "])
def test_empty_input_is_handled(value):
    assert _drop_policy_demands(value, "5.33") == ""
    assert _rewrite_policy_recommendation(value, "5.33") == ""


def test_an_all_policy_gap_still_says_something_useful():
    """If every listed requirement was a policy demand, the finding must not be
    left with an empty 'Missing Requirements:' label -- that reads as a bug to
    the auditor and says nothing to the auditee."""
    gap = "Missing Requirements: A documented policy defining retention."
    out = _drop_policy_demands(gap, "5.33 Protection of Records")
    assert "Missing Requirements:" not in out
    assert out.strip()
    assert "5.33 Protection of Records" in out


# ── the splitter the reconciliation depends on ───────────────────────────────

def test_requirements_split_on_sentence_boundaries_not_commas():
    """Individual requirements contain commas of their own -- "CPU, memory, and
    disk utilization" is one requirement, not three. Splitting on a bare comma
    would shred it and leave fragments in the report."""
    items = _split_requirements(
        " Formal documented policy defining acceptable thresholds for CPU, memory, and "
        "disk utilization., Defined procedures for capacity review.")
    assert len(items) == 2
    assert "CPU, memory, and disk utilization" in items[0]


def test_splitter_handles_a_single_requirement():
    assert len(_split_requirements("Just one requirement.")) == 1
