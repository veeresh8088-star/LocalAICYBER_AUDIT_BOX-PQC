# -*- coding: utf-8 -*-
"""
Kali Linux tool coverage, and the nmap defects found alongside it.

Pure unit tests -- no LLM, no database, no network:

    pytest tests/test_kali_parser.py -v

Before KaliParser existed the pipeline recognised five formats (Nessus, Nmap,
Burp, Qualys, Trivy). Every other Kali tool was claimed by nobody and returned an
empty list -- indistinguishable in the UI from a clean scan. Verified by
execution: proof of a working SQL injection and a set of cracked SSH credentials
both produced zero findings.

The two directions matter equally here:

  * A MISSED finding tells the customer a vulnerable host is clean.
  * A STOLEN file (one parser claiming another's format) replaces real findings
    with the wrong pipeline's output -- which is how a Nessus report once came
    back as post-quantum crypto findings.
"""
import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.kali_parser import KaliParser
from src.core.parsers.control_mapper import map_finding_to_owasp


NIKTO = """- Nikto v2.5.0
+ Target IP:          172.201.152.88
+ Target Port:        443
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ /admin/: Directory indexing found.
+ OSVDB-3268: /config/: Directory indexing found.
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54).
+ 7 host(s) tested"""

SQLMAP = """        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.11#stable}
[14:22:05] [WARNING] heuristic (basic) test shows that GET parameter 'id' might be injectable
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3761=3761
---
[14:22:11] [INFO] the back-end DBMS is MySQL"""

GOBUSTER = """===============================================================
Gobuster v3.6
===============================================================
[+] Url:  https://172.201.152.88
===============================================================
/admin                (Status: 301) [Size: 313]
/backup               (Status: 200) [Size: 1245]
/.git                 (Status: 200) [Size: 892]
/config.php.bak       (Status: 200) [Size: 4410]
==============================================================="""

HYDRA = """Hydra v9.5 starting at 2026-04-16 14:30:12
[DATA] attacking ssh://172.201.152.88:22/
[22][ssh] host: 172.201.152.88   login: admin   password: admin123
1 of 1 target successfully completed, 1 valid password found"""

WPSCAN = """[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
[!] 22 vulnerabilities identified:
 | [!] Title: WordPress 5.8-5.8.1 - Data Exposure via REST API
 |     Fixed in: 5.8.2
 |     References:
 |      - cve: 2021-39200
[!] Title: Plugin contact-form-7 < 5.5.2 - Unrestricted File Upload"""

ALL_TOOLS = {"nikto": NIKTO, "sqlmap": SQLMAP, "gobuster": GOBUSTER,
             "hydra": HYDRA, "wpscan": WPSCAN}


def _parse(name, content):
    findings, _extra = parse_tool_file(f"{name}_scan.txt", content, framework="vapt")
    return findings


def _titles(findings):
    return " ".join(str(getattr(f, "title", "")) for f in findings).lower()


# ── Coverage: nothing silently returns zero ──────────────────────────────────

@pytest.mark.parametrize("tool", sorted(ALL_TOOLS))
def test_every_kali_tool_produces_findings(tool):
    """A silent empty result reads as a clean scan. Each of these outputs
    contains at least one genuine finding."""
    findings = _parse(tool, ALL_TOOLS[tool])
    assert findings, f"{tool} output produced no findings at all"


def test_sqlmap_confirmed_injection_is_critical():
    findings = _parse("sqlmap", SQLMAP)
    assert any(str(getattr(f, "severity", "")).upper() == "CRITICAL" for f in findings), \
        "a confirmed SQL injection must not be reported below CRITICAL"
    assert "sql injection" in _titles(findings)
    assert "'id'" in _titles(findings) or "id" in _titles(findings)


def test_hydra_recovered_credentials_are_critical():
    findings = _parse("hydra", HYDRA)
    assert findings and str(getattr(findings[0], "severity", "")).upper() == "CRITICAL"
    assert "credentials" in _titles(findings)


def test_hydra_does_not_store_the_recovered_password():
    """The finding lands in the audit ledger and every export. Writing a live
    credential into it would make the report itself a disclosure."""
    for f in _parse("hydra", HYDRA):
        blob = " ".join(str(getattr(f, a, "")) for a in
                        ("title", "description", "evidence", "remediation"))
        assert "admin123" not in blob, "recovered password leaked into the finding"
    assert "redacted" in " ".join(
        str(getattr(f, "evidence", "")) for f in _parse("hydra", HYDRA)).lower()


def test_gobuster_ranks_sensitive_paths_higher():
    """/.git and a .bak config are worse than a redirect on /admin."""
    by_title = {str(getattr(f, "title", "")): str(getattr(f, "severity", "")).upper()
                for f in _parse("gobuster", GOBUSTER)}
    git = next((v for k, v in by_title.items() if "/.git" in k), None)
    bak = next((v for k, v in by_title.items() if "config.php.bak" in k), None)
    assert git == "HIGH", f"/.git rated {git}"
    assert bak == "HIGH", f"config.php.bak rated {bak}"


def test_nikto_outdated_software_outranks_a_missing_header():
    sev = {str(getattr(f, "title", "")): str(getattr(f, "severity", "")).upper()
           for f in _parse("nikto", NIKTO)}
    outdated = next((v for k, v in sev.items() if "outdated" in k.lower()), None)
    header = next((v for k, v in sev.items() if "x-frame-options" in k.lower()), None)
    assert outdated == "MEDIUM" and header == "LOW", f"outdated={outdated} header={header}"


def test_wpscan_extracts_the_cve():
    findings = _parse("wpscan", WPSCAN)
    cves = [c for f in findings for c in (getattr(f, "cve_list", None) or [])]
    assert any("2021-39200" in c for c in cves), f"CVE not extracted: {cves}"


def test_nikto_banner_lines_are_not_findings():
    """"Target IP", "Server:" and the host-count summary are context, not defects."""
    titles = _titles(_parse("nikto", NIKTO))
    assert "target ip" not in titles
    assert "host(s) tested" not in titles


# ── Isolation: KaliParser must not steal other formats ───────────────────────

@pytest.mark.parametrize("path", [
    "VAPT/nessus_vulnerability_report.txt",
    "VAPT/burpsuite_web_app_scan.txt",
    "VAPT/nmap_infrastructure_scan.txt",
    "pqc samples/db.config",
    "pqc samples/nginx_intermediate.conf.txt",
    "pqc samples/sql.config",
])
def test_kali_parser_does_not_claim_other_tool_formats(path):
    import os
    if not os.path.isfile(path):
        pytest.skip(f"{path} not present")
    content = open(path, "r", encoding="utf-8", errors="ignore").read()
    assert not KaliParser().can_parse(os.path.basename(path), content), \
        f"KaliParser wrongly claimed {path}"


def test_kali_parser_rejects_screenshots():
    """A screenshot named sqlmap.png must reach OCR, not this parser."""
    assert not KaliParser().can_parse("sqlmap_proof.png", SQLMAP)


# ── nmap defects found while testing real documents ──────────────────────────

NMAP_REAL = """# Nmap 7.92 scan report for 172.201.152.88
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.4.41
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (dh 2048) - Vulnerable to LUCKY13 (CVE-2013-0169)
|_    compressors: NULL"""


def test_nmap_title_is_not_truncated_to_the_cve():
    """The CVE regex captured from the CVE token to end-of-line, producing the
    title "Vuln Finding: CVE-2013-0169)" -- orphan bracket included."""
    findings = _parse("nmap", NMAP_REAL)
    assert findings
    title = str(getattr(findings[0], "title", ""))

    # The cipher name that preceded the CVE on the source line must survive --
    # losing it was what left the title as a bare "CVE-2013-0169)".
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in title, f"cipher name lost: {title}"

    # "(CVE-2013-0169)" is a legitimate balanced parenthetical from the source.
    # The defect was an UNBALANCED closer, from a capture that began inside the
    # bracket. Assert balance rather than absence.
    assert title.count("(") == title.count(")"), f"unbalanced brackets: {title}"
    assert "Vuln Finding: CVE-" not in title, f"title still starts at the CVE: {title}"


def test_nmap_lucky13_classifies_as_cryptographic_failure():
    """Same CVE, same engagement: it was A05 from nmap and A02 from Nessus,
    because nmap's description was boilerplate with no crypto words in it."""
    findings = _parse("nmap", NMAP_REAL)
    cat = map_finding_to_owasp(None,
                               getattr(findings[0], "title", "") or "",
                               getattr(findings[0], "description", "") or "")
    assert cat.startswith("A02"), f"expected A02 Cryptographic Failures, got {cat}"


def test_nmap_does_not_invent_high_severity_for_an_unrated_cve():
    """Nmap publishes no severity. Flat HIGH collided with Nessus rating the same
    CVE Low (CVSS 2.3) in the same report pack."""
    findings = _parse("nmap", NMAP_REAL)
    sev = str(getattr(findings[0], "severity", "")).upper()
    assert sev in ("LOW", "MEDIUM"), f"weak-cipher CVE rated {sev}"
