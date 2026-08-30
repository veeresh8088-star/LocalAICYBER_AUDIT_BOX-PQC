# -*- coding: utf-8 -*-
"""
PQC parser accuracy tests.

Standalone script in the same style as tests/test_vapt_parsers.py -- run with:

    python tests/test_pqc_parser.py

Needs no LLM/DB stack. Covers the accuracy defects found in the Aug-2026 review:

  1. '\\bDSA\\b' matched the NIST PQC signature names (ML-DSA / SLH-DSA / FN-DSA),
     raising a false CRITICAL "quantum-vulnerable" on a *completed* migration.
  2. ECDHE -- the dominant quantum-vulnerable TLS key exchange -- matched no rule
     at all, so ECDHE-* suites were reported without their key exchange.
  3. Fused hybrid group names (X25519MLKEM768) matched no PQC rule, so a server
     that had already deployed hybrid PQC got no credit for it.
  4. Repeat hits of one algorithm on a single cipher-suite line produced one
     finding each, inflating P1/P2 counts.
  5. Config-presence rules were titled as algorithm detections even though their
     evidence is a file path, and fired even when PQC was demonstrably present.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.parsers.pqc_parser import PQCParser  # noqa: E402

_passed = 0
_failed = 0


def check(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"[PASS] {label}")
    else:
        _failed += 1
        print(f"[FAIL] {label}")


def scan(text, filename="probe.conf"):
    """Returns (all_findings, titles, statuses) for a snippet."""
    body = f"TLS certificate encryption configuration\n{text}\n"
    res = PQCParser().parse(filename, body)
    fs, extra = res if isinstance(res, tuple) else (res, None)
    allf = list(fs) + list(extra or [])
    return allf


def statuses_for(findings, needle):
    return {
        getattr(f, "quantum_status", "")
        for f in findings
        if needle.lower() in (getattr(f, "title", "") or "").lower()
    }


print("\n--- 1. NIST PQC signatures must never be flagged quantum-vulnerable ---")
for algo in ("ML-DSA-65", "SLH-DSA-SHA2-128s", "FN-DSA-512"):
    fs = scan(f"sig_algs = {algo}")
    vulns = [
        f for f in fs
        if getattr(f, "quantum_status", "") == "VULNERABLE"
    ]
    check(not vulns, f"{algo} produces no VULNERABLE finding")
    check(
        any(getattr(f, "quantum_status", "") == "SAFE" for f in fs),
        f"{algo} is recognized as quantum-SAFE",
    )

fs = scan("sig_algs = DSA")
check(
    "VULNERABLE" in statuses_for(fs, "DSA"),
    "plain DSA is still flagged VULNERABLE (fix must not over-correct)",
)

fs = scan("ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384;")
check(
    any("ECDSA" in (getattr(f, "title", "") or "") for f in fs),
    "ECDSA is still detected (not swallowed by the DSA lookbehind)",
)


print("\n--- 2. ECDHE key exchange must be detected ---")
fs = scan("ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;")
check(
    any("ECDHE" in (getattr(f, "title", "") or "") for f in fs),
    "ECDHE-* suite reports its key exchange",
)
check(
    "VULNERABLE" in statuses_for(fs, "ECDHE"),
    "ECDHE is classified quantum-VULNERABLE",
)


print("\n--- 3. Fused hybrid PQC group names must be credited as SAFE ---")
for group in ("X25519MLKEM768", "X25519Kyber768Draft00", "SecP256r1MLKEM768"):
    fs = scan(f"ssl_ecdh_curve {group};")
    check(
        any(getattr(f, "quantum_status", "") == "SAFE" for f in fs),
        f"{group} is recognized as quantum-SAFE",
    )

# A hybrid group offered alongside classical X25519 must report BOTH facts:
# the PQC group is present, and a classical downgrade path also exists.
fs = scan("ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;")
check(
    any(getattr(f, "quantum_status", "") == "SAFE" for f in fs),
    "hybrid + classical list still credits the hybrid group",
)
check(
    any(
        getattr(f, "quantum_status", "") == "VULNERABLE"
        and "25519" in (getattr(f, "title", "") or "")
        for f in fs
    ),
    "hybrid + classical list still flags the classical X25519 fallback",
)


print("\n--- 4. Repeated hits on one line collapse to a single finding ---")
LINE = (
    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;"
)
fs = scan(LINE, "nginx.conf")
for label in ("RSA (unspecified", "ECDSA", "ECDHE"):
    n = sum(1 for f in fs if label in (getattr(f, "title", "") or ""))
    check(n <= 1, f"'{label}' reported once, not {n} times, for one cipher list")

# Two DIFFERENT lines naming the same algorithm remain two findings.
fs = scan("ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\nfallback_ciphers ECDHE-RSA-AES128-GCM-SHA256;")
n_rsa = sum(1 for f in fs if "RSA (unspecified" in (getattr(f, "title", "") or ""))
check(n_rsa == 2, "the same algorithm on two different directives stays two findings")


print("\n--- 5. Config-presence rules: honest titles, and no self-contradiction ---")
DB_NO_PQC = (
    "[mysqld]\n"
    "ssl-cert = /path/to/signed_cert_plus_intermediates\n"
    "ssl-key = /path/to/private_key\n"
    "tls_version = TLSv1.3\n"
)
fs = scan(DB_NO_PQC, "sql.config")
gap_titles = [
    getattr(f, "title", "") for f in fs
    if "Database TLS" in (getattr(f, "title", "") or "")
]
check(bool(gap_titles), "a DB TLS config with no PQC still raises a readiness gap")
check(
    all(t.startswith("PQC Readiness Gap:") for t in gap_titles),
    "config-presence findings are titled as readiness gaps, not algorithm detections",
)
check(
    not any(
        "Algorithm Detected" in (getattr(f, "title", "") or "")
        and "Database TLS" in (getattr(f, "title", "") or "")
        for f in fs
    ),
    "a file path is never reported as a detected algorithm",
)

DB_WITH_PQC = DB_NO_PQC + "ssl_groups = X25519MLKEM768\n"
fs = scan(DB_WITH_PQC, "sql.config")
check(
    not any("Database TLS" in (getattr(f, "title", "") or "") for f in fs),
    "readiness gaps are suppressed once a PQC algorithm is present in the file",
)
check(
    any(getattr(f, "quantum_status", "") == "SAFE" for f in fs),
    "the PQC algorithm that caused the suppression is itself reported",
)


print("\n--- 5b. PQC found only by the extended OID/liboqs scan still counts ---")
# liboqs_algorithms.json carries no 'category' and no 'severity', so these two
# checks guard both the readiness-gap suppression and the severity default.
for kw in ("Kyber768", "FrodoKEM-640-AES"):
    fs = scan(DB_NO_PQC + f"oqs_alg = {kw}\n", "sql.config")
    check(
        not any("Database TLS" in (getattr(f, "title", "") or "") for f in fs),
        f"{kw} (extended scan only) suppresses the readiness gaps",
    )
    safe = [f for f in fs if getattr(f, "quantum_status", "") == "SAFE"]
    check(bool(safe), f"{kw} is reported as quantum-SAFE")
    check(
        all(getattr(f, "severity", "") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            for f in safe),
        f"{kw} is informational, never an actionable HIGH severity finding",
    )


print("\n--- 6. Exposure-driven severity escalation is explained, not silent ---")
EXTERNAL = (
    "server {\n  listen 443 ssl;\n  ssl_certificate /p/c;\n"
    "  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384;\n}\n"
)
fs = scan(EXTERNAL, "nginx.conf")
check(
    any(getattr(f, "exposure_context", "") == "EXTERNAL" for f in fs),
    "an internet-facing config is classified EXTERNAL",
)
# Only findings whose severity actually changed should carry the explanation --
# an already-CRITICAL or INFO finding is EXTERNAL too but was never escalated.
esc = [f for f in fs if getattr(f, "_pqc_severity_escalated", False)]
check(bool(esc), "at least one finding is escalated on an internet-facing asset")
check(
    all("internet-facing" in (getattr(f, "description", "") or "") for f in esc),
    "escalated findings say why their severity is higher",
)
check(
    all(
        "internet-facing" not in (getattr(f, "description", "") or "")
        for f in fs
        if not getattr(f, "_pqc_severity_escalated", False)
    ),
    "non-escalated findings do NOT claim an escalation",
)


print("\n--- 7. Real repo sample files still parse ---")
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for rel in ("pqc samples/nginx_intermediate.conf.txt",
            "pqc samples/db.config",
            "pqc samples/sql.config"):
    path = os.path.join(_root, rel.replace("/", os.sep))
    if not os.path.exists(path):
        print(f"[SKIP] {rel} not present")
        continue
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    fname = os.path.basename(path)
    p = PQCParser()
    check(p.can_parse(fname, text), f"{fname} is claimed by PQCParser")
    res = p.parse(fname, text)
    fs, _ = res if isinstance(res, tuple) else (res, None)
    check(len(fs) > 0, f"{fname} yields at least one actionable finding")
    titles = [getattr(f, "title", "") or "" for f in fs]
    check(
        len(titles) == len(set(titles)) or len(set(titles)) >= len(titles) - 0,
        f"{fname} has no exact duplicate finding titles",
    )


print("\n" + "=" * 70)
print(f"{_passed}/{_passed + _failed} checks passed")
print("=" * 70)
sys.exit(1 if _failed else 0)
