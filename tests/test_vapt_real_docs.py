# -*- coding: utf-8 -*-
"""
VAPT pipeline against the real scanner exports in VAPT/.

Pure unit tests -- no LLM, no database. Run with:

    pytest tests/test_vapt_real_docs.py -v

The existing tests/test_vapt_parsers.py uses synthetic fixtures and passed 14/14
while every defect below was live. These run the same code over the actual
customer-shaped documents, which is where they surfaced.

Each test corresponds to a defect found by executing the pipeline on those files:

  1. PQCParser claimed a Nessus report and replaced its vulnerabilities with
     post-quantum crypto findings.
  2. The OWASP mapper classified on the description, where attack-vector prose
     names other vulnerability classes.
  3. A title was cut at the first slash, publishing a finding called "SSL".
  4. Remediation sentences were emitted as HIGH severity findings.
"""
import os
import re

import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.control_mapper import map_finding_to_owasp
from src.core.parsers.burp_parser import _clean_poc_title, _is_non_finding_poc
from src.core.parsers.doc_parsers import extract_text

VAPT_DIR = "VAPT"
NESSUS = os.path.join(VAPT_DIR, "nessus_vulnerability_report.txt")
BURP = os.path.join(VAPT_DIR, "burpsuite_web_app_scan.txt")
NMAP = os.path.join(VAPT_DIR, "nmap_infrastructure_scan.txt")
WAVE = os.path.join(VAPT_DIR, "WAVE PTT 11.4 POC- Vuln & Penetration Test Report_ v0.1.docx")

pytestmark = pytest.mark.skipif(
    not os.path.isdir(VAPT_DIR), reason="VAPT sample directory not present"
)


def _parse(path, framework="vapt"):
    if path.lower().endswith((".docx", ".pdf")):
        content = extract_text(open(path, "rb"))
    else:
        content = open(path, "r", encoding="utf-8", errors="ignore").read()
    findings, _extra = parse_tool_file(os.path.basename(path), content, framework=framework)
    return findings


# ── 1. Framework isolation ───────────────────────────────────────────────────

def test_nessus_report_is_not_claimed_by_pqc_parser():
    """A file opening "Tenable Nessus Scan Report" was rejected by NessusParser and
    claimed by PQCParser, whose findings replaced the real vulnerabilities. The
    framework=="vapt" guard covered only the binary fast-path, so a plain-text
    export reached the ALL_PARSERS loop where PQCParser sits last."""
    findings = _parse(NESSUS)
    titles = " ".join(str(getattr(f, "title", "")) for f in findings).lower()

    assert findings, "the Nessus report produced no findings at all"
    assert "cbc-mode" not in titles, f"PQC findings leaked into a VAPT scan: {titles}"
    assert "deprecated algorithm" not in titles
    assert "strict transport security" in titles, (
        f"the report's real HSTS finding is missing: {titles}"
    )


def test_pqc_configs_still_parse_under_the_pqc_framework():
    """The isolation must not disable PQC scanning -- only stop it hijacking VAPT."""
    import glob
    configs = [p for p in sorted(glob.glob(os.path.join("pqc samples", "*")))
               if os.path.isfile(p)][:3]
    if not configs:
        pytest.skip("no pqc samples present")
    for path in configs:
        content = open(path, "r", encoding="utf-8", errors="ignore").read()
        name = os.path.basename(path)
        pqc_findings, _ = parse_tool_file(name, content, framework="pqc")
        vapt_findings, _ = parse_tool_file(name, content, framework="vapt")
        assert pqc_findings, f"{name}: PQC framework produced no findings"
        assert not vapt_findings, f"{name}: PQC config leaked into the VAPT framework"


# ── 2. OWASP classification ──────────────────────────────────────────────────

def test_owasp_ignores_attack_vector_prose_in_the_description():
    """The real Burp export's description reads "Attackers can steal these cookies
    via Cross-Site Scripting (XSS) or man-in-the-middle attacks" -- so searching
    title+description as one blob classified a cookie-flags finding as Injection."""
    category = map_finding_to_owasp(
        None,
        "Missing Secure/HttpOnly Flags on Session Cookies",
        "The web application sets session cookies without the 'Secure' and 'HttpOnly' "
        "flags. Attackers can steal these cookies via Cross-Site Scripting (XSS) or "
        "man-in-the-middle attacks.",
    )
    assert "A03" not in category, f"attack-vector prose still wins: {category}"
    assert category.startswith("A07"), category


def test_spelled_out_xss_is_classified_as_injection():
    """"xss" alone missed "Cross-site scripting (DOM-based)", which fell through to
    the A05 default -- so two XSS findings in one report got two categories."""
    assert map_finding_to_owasp(None, "Cross-site scripting (DOM-based) [WCSR]", "") \
        .startswith("A03")
    assert map_finding_to_owasp(None, "XSS vulnerability", "").startswith("A03")


def test_cwe_table_still_takes_precedence_when_present():
    """No real export here carries a CWE, but the table must still win when one does."""
    from src.core.parsers.control_mapper import CWE_TO_OWASP_MAP
    cwe, expected = next(iter(CWE_TO_OWASP_MAP.items()))
    assert map_finding_to_owasp(cwe, "totally unrelated title", "") == expected


def test_real_documents_classify_consistently():
    """Every XSS finding across the real reports must land in the same category."""
    findings = _parse(WAVE)
    xss = [f for f in findings
           if re.search(r"xss|cross-site scripting", str(getattr(f, "title", "")), re.I)]
    assert xss, "expected XSS findings in the WAVE report"
    categories = {
        map_finding_to_owasp(getattr(f, "cwe_id", None) or getattr(f, "cwe", None),
                             getattr(f, "title", "") or "",
                             getattr(f, "description", "") or "")
        for f in xss
    }
    assert len(categories) == 1, f"same vulnerability class split across {categories}"
    assert categories.pop().startswith("A03")


# ── 3. Title extraction ──────────────────────────────────────────────────────

def test_title_is_not_truncated_at_a_slash():
    """The title character class omitted "/", so "SSL/TLS CBC Cipher Suites Enabled
    (Lucky13)" was published as the three-character finding "SSL"."""
    titles = [str(getattr(f, "title", "")) for f in _parse(NESSUS)]
    assert "SSL" not in titles, "title truncated at the slash"
    assert any("SSL/TLS" in t for t in titles), titles


@pytest.mark.parametrize("raw,expected", [
    ("XSS vulnerability | High | No.", "XSS vulnerability"),
    ("Cross-site scripting (DOM-based) [WCSR] | Low ", "Cross-site scripting (DOM-based) [WCSR]"),
    ("SQL Injection( All Application exposed", "SQL Injection"),
    ("SQL injection prevention should be in place, S", "SQL injection prevention should be in place"),
])
def test_poc_titles_are_trimmed_of_table_columns(raw, expected):
    """doc_parsers flattens table rows to "cell | cell | cell", and the 60-char cap
    then cuts mid-word."""
    assert _clean_poc_title(raw) == expected


# ── 4. Remediation text must not become a finding ────────────────────────────

@pytest.mark.parametrize("text", [
    "SQL injection( All Application exposed API's are fixed) and",
    "SQL injection prevention should be in place, Session management",
    "XSS protection should be implemented to prevent attacks",
    "Cross-Site Scripting was not identified in this assessment",
])
def test_remediation_sentences_are_not_findings(text):
    assert _is_non_finding_poc(text), f"would be published as a HIGH finding: {text!r}"


@pytest.mark.parametrize("text", [
    "XSS vulnerability",
    "Cross-site scripting (DOM-based) [WCSR]",
    "SQL Injection in /api/login parameter id",
])
def test_genuine_findings_are_not_suppressed(text):
    """The guard against over-correction: real findings must survive."""
    assert not _is_non_finding_poc(text), f"real finding suppressed: {text!r}"


def test_no_remediation_sentence_survives_into_real_report_findings():
    """End-to-end on the real documents: no finding title may read as advice."""
    for path in (WAVE, NESSUS, BURP, NMAP):
        for f in _parse(path):
            title = str(getattr(f, "title", ""))
            assert not _is_non_finding_poc(title), (
                f"{os.path.basename(path)} published advice as a finding: {title!r}"
            )
