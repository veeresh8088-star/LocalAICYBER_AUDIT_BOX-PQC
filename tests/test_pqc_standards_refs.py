# -*- coding: utf-8 -*-
"""
Standards references on PQC findings: impacted FIPS, NIST SP 800-53, and CVEs.

Pure unit tests -- no LLM, no database:

    pytest tests/test_pqc_standards_refs.py -v

From auditor review feedback on the PQC output:

  1. "NIST 53 PQC compliance standard"  -- findings carry no 800-53 reference.
  2. "CVE reference to be done"          -- the cve_list field was never populated.
  3. "Vuln Description should be more specific like NIST FIPS 203, 204, 205, 206
     which is impacted only to be mentioned" -- the remediation text listed every
     PQC standard on every finding, which tells the reader nothing.

The third is the one with a trap in it. FIPS 203-206 replace ASYMMETRIC
cryptography. A weak symmetric cipher or hash is not replaced by any of them --
Grover's algorithm only halves their strength, so the answer is a larger
parameter (AES-256, SHA-384+), not a new standard. Citing FIPS 203 on an RC4
finding would be exactly the vagueness the feedback is asking to remove, so
these tests assert the absence as carefully as the presence.
"""
import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.pqc_parser import _dh_group_cves


def _scan(content, filename="test.conf"):
    findings, _ = parse_tool_file(filename, content, framework="pqc")
    return findings


def _by_rule(findings, rule_id):
    """The finding produced by a specific ALGORITHM_RULES entry."""
    return next((f for f in findings if f.plugin_id == f"PQC-{rule_id}"), None)


# A config with enough crypto vocabulary to clear PQCParser.can_parse()'s
# keyword bar -- a one-line fixture is silently not claimed at all.
TLS_CONFIG = """
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve secp384r1;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA:RC4-MD5;
ssl_dhparam /etc/nginx/dhparam.pem;
default_bits = 2048
"""

IPSEC_CONFIG = """conn tunnel-a
  keyexchange = ikev2
  ike = aes256-sha256-{group}
  esp = aes256-sha256
  authby = psk
  leftcert = vpn.crt
"""


# ── CVE references: real ones only ───────────────────────────────────────────

@pytest.mark.parametrize("rule_id,expected", [
    ("md5",  ["CVE-2004-2761"]),
    ("des",  ["CVE-2016-2183"]),          # SWEET32
    ("rc4",  ["CVE-2013-2566", "CVE-2015-2808"]),
])
def test_classical_breaks_carry_their_published_cve(rule_id, expected):
    f = _by_rule(_scan(TLS_CONFIG), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    assert f.cve_list == expected


@pytest.mark.parametrize("rule_id", ["rsa-sized", "dhe", "ecdhe", "ecc-p384"])
def test_quantum_only_findings_carry_no_cve(rule_id):
    """There is no CVE for 'RSA-2048 will be broken by Shor's algorithm'.

    Inventing one would put a fabricated identifier into an audit report, which
    is worse than an empty column -- bg_worker already renders empty as
    'No CVE assigned'.
    """
    f = _by_rule(_scan(TLS_CONFIG), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    assert f.cve_list == [], f"fabricated CVE on a quantum-only finding: {f.cve_list}"


@pytest.mark.parametrize("group,expected", [
    ("DH Group 1",  ["CVE-2015-4000"]),   # 768-bit  -- Logjam
    ("DH Group 2",  ["CVE-2015-4000"]),   # 1024-bit -- Logjam
    ("DH Group 5",  []),                  # 1536-bit -- not Logjam
    ("DH Group 14", []),                  # 2048-bit -- not Logjam
    ("DH Group 18", []),                  # 8192-bit -- not Logjam
])
def test_logjam_is_cited_only_for_the_groups_it_actually_affects(group, expected):
    """Logjam is a 512/768/1024-bit weakness. Attaching it to DH Group 14 would
    be a false citation on a group that is classically fine and only quantum-
    vulnerable."""
    f = _by_rule(_scan(IPSEC_CONFIG.format(group=group), "ipsec.conf"), "dh-group")
    assert f is not None, f"dh-group rule did not fire for {group}"
    assert f.cve_list == expected


def test_dh_group_cve_helper_reads_the_group_number():
    assert _dh_group_cves("DH Group 2") == ["CVE-2015-4000"]
    assert _dh_group_cves("DH Group 14") == []
    assert _dh_group_cves("") == []


# ── Impacted FIPS: name one, not all four ────────────────────────────────────

_MARKER = "The applicable post-quantum replacement standard is"


@pytest.mark.parametrize("rule_id,must_say,must_not_say", [
    # Key establishment -> ML-KEM only. FIPS 204/205 are signature standards
    # and have no bearing on a key-exchange finding.
    ("dhe",   "FIPS 203", ["FIPS 204", "FIPS 205", "FIPS 206"]),
    ("ecdhe", "FIPS 203", ["FIPS 204", "FIPS 205", "FIPS 206"]),
])
def test_key_exchange_names_only_the_kem_standard(rule_id, must_say, must_not_say):
    f = _by_rule(_scan(TLS_CONFIG), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    tail = f.description[f.description.find(_MARKER):]
    assert must_say in tail, f"{rule_id} did not name {must_say}: {tail!r}"
    for wrong in must_not_say:
        assert wrong not in tail, f"{rule_id} also cited the irrelevant {wrong}"


@pytest.mark.parametrize("content,rule_id,must_say,must_not_say", [
    # X25519 only ever does key agreement; Ed25519 only ever signs. The generic
    # ECC category answer would name both standards, so these are rule-level
    # overrides -- and this is the test that keeps them honest.
    ("ssl_ecdh_curve X25519;\nssl_protocols TLSv1.3;\nssl_ciphers HIGH;\n",
     "ecc-x25519", "FIPS 203", ["FIPS 204"]),
    ("host_key_algorithms ssh-ed25519\nciphers aes256-ctr\nkex ecdh-sha2\n",
     "ecc-ed25519", "FIPS 204", ["FIPS 203"]),
])
def test_single_role_curves_name_only_their_own_standard(content, rule_id, must_say, must_not_say):
    f = _by_rule(_scan(content), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    tail = f.description[f.description.find(_MARKER):]
    assert must_say in tail, f"{rule_id} did not name {must_say}: {tail!r}"
    for wrong in must_not_say:
        assert wrong not in tail, f"{rule_id} also cited the irrelevant {wrong}"


@pytest.mark.parametrize("rule_id", ["md5", "des", "rc4"])
def test_symmetric_and_hash_findings_never_cite_a_pqc_standard(rule_id):
    """FIPS 203-206 replace asymmetric primitives. A broken hash or 64-bit block
    cipher is fixed by a bigger parameter, not by ML-KEM or ML-DSA."""
    f = _by_rule(_scan(TLS_CONFIG), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    for fips in ("FIPS 203", "FIPS 204", "FIPS 205", "FIPS 206"):
        assert fips not in f.description, (
            f"{rule_id} cited {fips}; that standard does not replace this primitive"
        )


def test_draft_fips_206_is_never_cited_as_a_target():
    """FN-DSA / FIPS 206 is still a draft. An audit finding must not point a
    customer at an unpublished standard as their remediation target."""
    for f in _scan(TLS_CONFIG):
        assert "FIPS 206" not in (f.description or ""), f.title
        assert "FIPS 206" not in (f.remediation or ""), f.title


def test_safe_findings_get_no_replacement_standard():
    """Nothing to migrate to when the algorithm is already quantum-safe."""
    content = ("ssl_ecdh_curve X25519MLKEM768;\nssl_protocols TLSv1.3;\n"
               "signature_algorithms = ML-DSA-65;\nssl_ciphers AES256-GCM-SHA384;\n")
    for f in _scan(content):
        if getattr(f, "quantum_status", "") == "SAFE":
            assert _MARKER not in (f.description or ""), f.title


# ── NIST SP 800-53 ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("rule_id,expected", [
    ("rsa-sized", "SC-12, SC-13"),          # key establishment + crypto protection
    ("dhe",       "SC-12, SC-13"),
    ("ecc-p384",  "SC-12, SC-13, SC-17"),   # + PKI certificates
    ("md5",       "SC-13"),
    ("rc4",       "SC-13, SC-28"),          # + protection at rest
])
def test_findings_carry_their_nist_80053_controls(rule_id, expected):
    f = _by_rule(_scan(TLS_CONFIG), rule_id)
    assert f is not None, f"rule {rule_id} did not fire"
    assert getattr(f, "nist_80053_controls", "") == expected


def test_every_pqc_finding_has_at_least_one_800_53_control():
    findings = _scan(TLS_CONFIG)
    assert findings
    for f in findings:
        assert getattr(f, "nist_80053_controls", ""), f"no 800-53 reference on {f.title!r}"


def test_the_field_stays_blank_for_non_pqc_parsers():
    """The column is additive -- a VAPT finding must not grow a PQC-only field."""
    nmap = ("Starting Nmap 7.94\nNmap scan report for 10.0.0.5\n"
            "PORT     STATE SERVICE\n80/tcp   open  http\n"
            "| http-vuln-cve2017-5638: CVE-2017-5638 Apache Struts RCE\n")
    findings, _ = parse_tool_file("scan.txt", nmap, framework="vapt")
    assert findings, "nmap fixture produced no findings"
    for f in findings:
        assert getattr(f, "nist_80053_controls", "") == ""
