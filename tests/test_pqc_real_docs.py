# -*- coding: utf-8 -*-
"""
PQC pipeline against real configuration files and realistic edge cases.

Pure unit tests -- no LLM, no database. Run with:

    pytest tests/test_pqc_real_docs.py -v

tests/test_pqc_parser.py passed 43/43 while the comment-handling defect below was
live, because its fixtures do not include a migrated config. These exercise the
same code over real files in "pqc samples/" plus the config shapes a customer
mid-migration actually has.

The two failure directions matter equally:

  * A FALSE POSITIVE tells a customer their PQC-ready deployment is critically
    vulnerable, which destroys trust in the scan.
  * A FALSE NEGATIVE leaves genuinely quantum-vulnerable crypto unreported.
"""
import os
import glob

import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.pqc_parser import _is_comment_line

PQC_DIR = "pqc samples"

pytestmark = pytest.mark.skipif(
    not os.path.isdir(PQC_DIR), reason="pqc samples directory not present"
)


def _scan(content, filename="test.conf", framework="pqc"):
    findings, _ = parse_tool_file(filename, content, framework=framework)
    return findings


def _titles(findings):
    return [str(getattr(f, "title", "")) for f in findings]


# ── Commented-out crypto is not deployed crypto ──────────────────────────────

MIGRATED_CONFIG = """
# Legacy config, retained for reference only:
#   ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;
#   ssl_ecdh_curve secp384r1;
# Migrated to PQC on 2026-01-10.
ssl_ecdh_curve X25519MLKEM768;
ssl_protocols TLSv1.3;
"""


def test_commented_out_algorithms_are_not_reported():
    """A config that has already migrated -- classical ciphers left as commented
    reference, only X25519MLKEM768 active -- produced three actionable findings
    (RSA, ECC P-384, ECDHE) because the scan ran over the whole file."""
    findings = _scan(MIGRATED_CONFIG)
    assert findings == [] or not findings, (
        f"commented-out crypto reported as live: {_titles(findings)}"
    )


@pytest.mark.parametrize("line", [
    "# ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;",
    "   #   ssl_ecdh_curve secp384r1;",
    "// ssl_ciphers ECDHE-RSA",
    "; ssl_ciphers = ECDHE-RSA",
    "-- ssl_ciphers ECDHE-RSA",
    "<!-- ssl_ciphers ECDHE-RSA -->",
])
def test_comment_markers_are_recognised(line):
    assert _is_comment_line(line)


@pytest.mark.parametrize("line", [
    "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;  # legacy suite, still enabled",
    "ssl_ecdh_curve secp384r1;",
    "    ssl_protocols TLSv1.2 TLSv1.3;",
])
def test_live_directives_with_trailing_comments_are_still_assessed(line):
    """A trailing comment does not disable the directive -- it must still be scanned."""
    assert not _is_comment_line(line)


def test_trailing_comment_does_not_suppress_a_real_finding():
    """End-to-end guard for the case above."""
    findings = _scan("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;  # legacy, still enabled\n")
    assert findings, "a live directive with a trailing comment was skipped"


# ── Hybrid PQC must earn credit, not a finding ───────────────────────────────

def test_fully_pqc_ready_config_produces_no_actionable_findings():
    content = (
        "ssl_protocols TLSv1.3;\n"
        "ssl_ecdh_curve X25519MLKEM768;\n"
        "ssl_conf_command Groups X25519MLKEM768;\n"
        "signature_algorithms = ML-DSA-65;\n"
    )
    findings = _scan(content)
    assert not findings, f"PQC-ready config flagged as vulnerable: {_titles(findings)}"


def test_hybrid_group_is_not_reported_as_vulnerable():
    """'X25519MLKEM768' contains the substring 'X25519'. The fused hybrid group name
    must not be mistaken for the classical curve it embeds."""
    findings = _scan("ssl_ecdh_curve X25519MLKEM768;\n")
    joined = " ".join(_titles(findings)).lower()
    assert "curve25519" not in joined and "x25519" not in joined, joined


# ── Genuine vulnerabilities must still be found ──────────────────────────────

def test_classical_config_is_still_flagged():
    content = (
        "ssl_protocols TLSv1.2;\n"
        "ssl_ecdh_curve secp384r1;\n"
        "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"
    )
    findings = _scan(content)
    joined = " ".join(_titles(findings)).lower()
    assert findings, "genuinely quantum-vulnerable config produced no findings"
    assert "rsa" in joined
    assert any(k in joined for k in ("ecc", "p-384", "secp384r1"))


@pytest.mark.parametrize("path", sorted(
    p for p in glob.glob(os.path.join(PQC_DIR, "*")) if os.path.isfile(p)
))
def test_real_sample_configs_yield_findings_with_clean_titles(path):
    """Every real sample must produce findings, and no title may be a truncated
    fragment -- the failure mode that published a VAPT finding titled "SSL"."""
    content = open(path, "r", encoding="utf-8", errors="ignore").read()
    findings = _scan(content, filename=os.path.basename(path))
    assert findings, f"{os.path.basename(path)} produced no findings"
    for t in _titles(findings):
        assert len(t) > 8, f"suspiciously short title in {os.path.basename(path)}: {t!r}"
        assert not t.endswith(("(", "[", ",", "|", "-")), f"malformed title: {t!r}"


def test_severity_escalation_is_contextual_and_explained():
    """The same algorithm is HIGH in db.config and CRITICAL in the nginx config.
    That is correct -- nginx is internet-facing, which makes "harvest now, decrypt
    later" capture realistic -- but the finding has to say so, or the difference
    looks arbitrary to an auditor comparing two reports.

    Only algorithms whose severity actually moves are checked. RSA is CRITICAL on
    its own merits in both files and carries no escalation note.
    """
    db = os.path.join(PQC_DIR, "db.config")
    nginx = os.path.join(PQC_DIR, "nginx_intermediate.conf.txt")
    if not (os.path.isfile(db) and os.path.isfile(nginx)):
        pytest.skip("both sample configs required")

    def _by_algo(path):
        content = open(path, "r", encoding="utf-8", errors="ignore").read()
        out = {}
        for f in _scan(content, filename=os.path.basename(path)):
            title = str(getattr(f, "title", ""))
            for algo in ("ECDHE", "ECDSA"):
                if algo in title:
                    out[algo] = f
        return out

    internal, facing = _by_algo(db), _by_algo(nginx)
    shared = set(internal) & set(facing)
    assert shared, "expected ECDHE/ECDSA in both sample configs"

    for algo in sorted(shared):
        sev_internal = str(getattr(internal[algo], "severity", "")).upper()
        sev_facing = str(getattr(facing[algo], "severity", "")).upper()
        assert sev_internal == "HIGH", f"{algo} internal severity changed: {sev_internal}"
        assert sev_facing == "CRITICAL", f"{algo} internet-facing severity changed: {sev_facing}"
        desc = str(getattr(facing[algo], "description", "") or "").lower()
        assert "escalat" in desc, (
            f"{algo} was escalated to CRITICAL without saying why"
        )


# ── Framework isolation ──────────────────────────────────────────────────────

@pytest.mark.parametrize("path", sorted(
    p for p in glob.glob(os.path.join(PQC_DIR, "*")) if os.path.isfile(p)
))
def test_pqc_configs_do_not_leak_into_the_vapt_framework(path):
    """PQCParser must not claim files during a VAPT scan -- the mirror of the defect
    where it claimed a Nessus report and replaced its vulnerabilities."""
    content = open(path, "r", encoding="utf-8", errors="ignore").read()
    name = os.path.basename(path)
    assert _scan(content, filename=name, framework="pqc"), f"{name}: no PQC findings"
    assert not _scan(content, filename=name, framework="vapt"), (
        f"{name}: PQC config leaked into a VAPT scan"
    )
