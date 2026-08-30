# -*- coding: utf-8 -*-
"""
Multi-Tool Vulnerability Ingestion Engine (Nessus, Nmap, BurpSuite, Qualys, Trivy, CSV, HTML)
"""
from typing import List, Tuple, Any
from .finding_schema import Finding
from .base_parser import BaseParser, is_image_file
from .control_mapper import map_finding_to_control, map_findings_list, map_pqc_findings_list
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .burp_parser import BurpParser
from .qualys_parser import QualysParser
from .trivy_parser import TrivyParser
from .kali_parser import KaliParser
from .pqc_parser import PQCParser, pqc_extract_text, _PQC_BINARY_EXTENSIONS

ALL_PARSERS = [
    NessusParser(),
    NmapParser(),
    BurpParser(),
    QualysParser(),
    TrivyParser(),
    # Kali console tools (nikto, sqlmap, gobuster, hydra, wpscan). Sits after the
    # structured-export parsers and before PQCParser: its signatures are specific
    # tool banners, so it will not steal a Nessus/Burp/Trivy export, but it must
    # get its chance before PQC's weak 2-keyword check claims the file.
    KaliParser(),
    # PQCParser goes LAST -- its can_parse() is a weak-signal (2+ keyword) check
    # like Nessus's own fallback path, so it must never steal a file that a more
    # specific structural-signature parser above would have claimed.
    PQCParser(),
]

def parse_tool_file(filename: str, content: str, framework: str = "") -> Tuple[List[Finding], Any]:
    """
    Auto-detects file type and dispatches to the appropriate security tool parser.

    Parameters
    ----------
    filename : str
        Name / path of the file being parsed.
    content : str
        Extracted text content of the file.
    framework : str, optional
        The active audit framework (e.g. "vapt", "pqc", "iso").  When set to
        "vapt" the PQC binary fast-path is **skipped** so nmap screenshots,
        Nessus PDFs, and other VAPT evidence files are never misrouted through
        PQCParser.  Empty string / None falls back to the old behaviour (tries
        PQCParser for any binary extension) for callers that have not been
        updated yet.

    Detection strategy (in order):
    1. If framework == "vapt": skip the PQC binary fast-path entirely.
       Images / PDFs are returned as [] so bg_worker's OCR path handles them.
    2. PDF / DOCX / image files with binary extensions are tried through
       PQCParser FIRST when framework is PQC (or unspecified).  If PQCParser
       finds PQC findings, return them directly.  Otherwise fall through.
    3. Image files NOT claimed by PQCParser are returned early with [] -- they
       are visual PoC evidence screenshots with no XML/HTML scanner structure.
    4. All other files are tried against ALL_PARSERS using content-signature
       detection.
    5. If no parser claims the file, NessusParser handles it as a fallback.

    Returns (actionable_findings, extra_info/inventory).
    """
    _fw = str(framework or "").strip().lower()
    _is_vapt_framework = _fw == "vapt"

    # ── Stage 1: Binary document fast-path (PDF / DOCX / images) ─────────────
    # Route to PQCParser FIRST for PQC-relevant binary formats ONLY when the
    # active framework is PQC (or unknown).  When the caller is running a VAPT
    # scan, skip this entire block -- nmap screenshots / Nessus PDFs / Burp
    # reports must never be misclassified as PQC findings simply because they
    # mention "TLS 1.0" or "RSA" in their OCR text.
    ext_lower = __import__('os').path.splitext(filename.lower())[1]
    if ext_lower in _PQC_BINARY_EXTENSIONS and not _is_vapt_framework:
        # Looked up by type rather than by position. `ALL_PARSERS[-1]` relied on
        # PQCParser staying last in the list; appending any parser would have
        # silently handed this fast-path to the wrong one, with no error.
        pqc_p = next((p for p in ALL_PARSERS if isinstance(p, PQCParser)), None)
        if pqc_p is not None and pqc_p.can_parse(filename, content):
            res = pqc_p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if findings:
                map_pqc_findings_list(findings)
                return findings, extra
        # PQCParser got nothing from this binary -- if it's an image, the
        # VAPT path handles it (OCR in bg_worker). If PDF/DOCX with no PQC
        # content, fall through to VAPT parsers below.
        if is_image_file(filename):
            # Images with no PQC content: route to caller for VAPT OCR.
            return [], None

    # ── Stage 2: Image fast-path for VAPT (non-PQC images) ───────────────────
    # Images with no binary-extension claim above are visual PoC screenshots.
    if is_image_file(filename):
        return [], None

    # ── Stage 3: Content-signature parser dispatch (text-based files) ────────
    #
    # The VAPT guard has to hold here too, not only on the binary fast-path above.
    # That earlier guard only covers _PQC_BINARY_EXTENSIONS, so a plain-text
    # scanner export skipped it entirely and fell into this loop, where PQCParser
    # sits last and claims anything mentioning cryptography. Confirmed on a real
    # file: VAPT/nessus_vulnerability_report.txt, which literally opens with
    # "Tenable Nessus Scan Report", was rejected by NessusParser.can_parse() and
    # claimed by PQCParser -- its HSTS and TLS vulnerabilities were replaced by
    # three duplicate "CBC-mode weak algorithm" PQC findings, and the Stage 3
    # NessusParser fallback below was never reached because the file had already
    # been claimed.
    #
    # Dropping PQCParser from the candidate list under the VAPT framework lets an
    # unclaimed scanner export reach that fallback, which is what it is for.
    _parsers = [
        p for p in ALL_PARSERS
        if not (_is_vapt_framework and p.__class__.__name__ == "PQCParser")
    ]
    for p in _parsers:
        if p.can_parse(filename, content):
            res = p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if not findings:
                print(
                    f"[VAPT PARSER WARNING] '{p.__class__.__name__}' recognized '{filename}' "
                    f"but extracted 0 findings. If this file genuinely contains vulnerabilities, "
                    f"the parser may not support this export's exact format/columns and needs review.",
                    flush=True
                )
            if findings:
                # PQCParser findings use the PQC-specific mapper (CIA, risk score,
                # per-algorithm remediation, OEM readiness, business priority).
                # All other parsers (Nessus, Burp, Nmap, Qualys, Trivy) use the
                # VAPT mapper. This is the gate that keeps the two pipelines separate.
                if p.__class__.__name__ == "PQCParser":
                    map_pqc_findings_list(findings)
                else:
                    map_findings_list(findings)
                return findings, extra

    # ── Stage 3: Fallback (general HTML/XML/PDF via NessusParser & BurpParser) ──
    findings, extra = NessusParser().parse(filename, content)
    if not findings:
        res_burp = BurpParser().parse(filename, content)
        findings, extra = res_burp if isinstance(res_burp, tuple) else (res_burp, None)
    if findings:
        map_findings_list(findings)
    return findings, extra

__all__ = [
    "Finding", "BaseParser", "is_image_file", "map_finding_to_control", "map_findings_list",
    "NessusParser", "NmapParser", "BurpParser", "QualysParser", "TrivyParser", "KaliParser", "PQCParser",
    "parse_tool_file", "pqc_extract_text",
]
