# -*- coding: utf-8 -*-
"""
Kali Linux tool output parser.

Covers the console/report output of the tools a Kali-based engagement actually
produces alongside nmap: nikto, sqlmap, gobuster/dirb/ffuf, hydra and wpscan.

Why this exists
---------------
Before this parser the pipeline recognised exactly five formats -- Nessus, Nmap,
Burp, Qualys, Trivy. Everything else was claimed by nobody and returned an empty
list. Verified by execution against realistic output from all five tools above:

    nikto      0 findings   (outdated Apache, directory indexing, missing headers)
    sqlmap     0 findings   (confirmed boolean-based blind SQL injection)
    gobuster   0 findings   (/.git and config.php.bak exposed)
    hydra      0 findings   (valid SSH credentials recovered: admin/admin123)
    wpscan     0 findings   (WordPress 5.8.1, 22 vulns, CVE-2021-39200)

An empty result is indistinguishable from a clean scan in the UI. Uploading proof
of a working SQL injection, or a cracked SSH login, and being told there is
nothing to report is the worst failure mode an audit tool has -- worse than a
crash, because nobody investigates a pass.

Detection is by content signature only, never filename, matching the convention
the other parsers follow (a screenshot named sqlmap.png must reach OCR, not this).
"""
import re
from typing import List, Tuple, Any

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding


# ── Signatures: banner/structure unique to each tool ────────────────────────
_SIGNATURES = {
    "nikto":    (re.compile(r'-\s*Nikto v[\d.]|nikto\.pl|OSVDB-\d+', re.IGNORECASE),),
    "sqlmap":   (re.compile(r'sqlmap identified the following injection point|\{[\d.]+#stable\}|starting @ .*sqlmap', re.IGNORECASE),
                 re.compile(r'\[INFO\]\s+(?:testing|the back-end DBMS)', re.IGNORECASE)),
    "gobuster": (re.compile(r'Gobuster v[\d.]|=+\s*\nGobuster', re.IGNORECASE),
                 re.compile(r'^/\S+\s+\(Status:\s*\d{3}\)', re.MULTILINE)),
    "hydra":    (re.compile(r'Hydra v[\d.]|hydra \(https?://', re.IGNORECASE),
                 re.compile(r'^\[\d+\]\[\w+\]\s+host:', re.MULTILINE | re.IGNORECASE)),
    "wpscan":   (re.compile(r'WPScan|wpscan\.com|WordPress version [\d.]+ identified', re.IGNORECASE),),
}

# HTTP statuses gobuster/dirb report that represent a real reachable resource.
_INTERESTING_STATUS = {"200", "201", "204", "301", "302", "307", "401", "403", "500"}

# Paths whose exposure is a finding in its own right, regardless of status.
_SENSITIVE_PATH_RE = re.compile(
    r'\.git|\.svn|\.env|\.bak|\.old|\.sql|\.zip|\.tar|backup|dump|config|'
    r'wp-config|id_rsa|\.ssh|admin|phpmyadmin|\.htpasswd',
    re.IGNORECASE,
)


def _detect_tool(content: str) -> str:
    """Return the tool name whose signature matches, or "" for none."""
    for tool, patterns in _SIGNATURES.items():
        if any(p.search(content) for p in patterns):
            return tool
    return ""


def _target_from(content: str) -> str:
    m = re.search(r'(?:Target IP|Target|Url|\[DATA\] attacking|host):\s*([^\s,\n]+)', content, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r'https?://[^\s,\n\'"]+', content)
    return m.group(0).strip() if m else "Target Host"


class KaliParser(BaseParser):
    """Parses console output from common Kali Linux assessment tools."""

    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        return bool(_detect_tool(content))

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        if not content:
            return [], None
        tool = _detect_tool(content)
        if not tool:
            return [], None

        target = _target_from(content)
        handler = {
            "nikto": self._parse_nikto,
            "sqlmap": self._parse_sqlmap,
            "gobuster": self._parse_gobuster,
            "hydra": self._parse_hydra,
            "wpscan": self._parse_wpscan,
        }[tool]

        findings = handler(content, target)

        # Collapse identical titles -- a directory brute-forcer in particular
        # reports the same class of exposure many times over.
        seen, deduped = set(), []
        for f in findings:
            key = (f.title, f.target)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped, None

    # ── nikto ───────────────────────────────────────────────────────────────
    def _parse_nikto(self, content: str, target: str) -> List[Finding]:
        out = []
        for line in content.splitlines():
            s = line.strip()
            if not s.startswith("+"):
                continue
            body = s.lstrip("+ ").strip()
            if not body or len(body) < 12:
                continue
            # Banner/summary lines carry no finding.
            if re.match(r'^(Target |Start Time|End Time|Server:|SSL Info|\d+ host\(s\) tested)', body, re.IGNORECASE):
                continue

            low = body.lower()
            if "outdated" in low or "appears to be out of date" in low:
                sev = "MEDIUM"
            elif "directory indexing" in low or "index of" in low:
                sev = "MEDIUM"
            elif "header is not present" in low or "header is not set" in low or "not defined" in low:
                sev = "LOW"
            elif re.search(r'\bOSVDB-\d+', body):
                sev = "MEDIUM"
            else:
                sev = "LOW"

            out.append(Finding(
                title=f"Nikto: {body[:110]}",
                severity=sev,
                target=target,
                description=f"Nikto web server scan finding against {target}: {body}",
                remediation="Review the affected web server configuration and apply the vendor's hardening guidance.",
                evidence=s,
                source_tool="Nikto",
            ))
        return out

    # ── sqlmap ──────────────────────────────────────────────────────────────
    def _parse_sqlmap(self, content: str, target: str) -> List[Finding]:
        out = []
        # A confirmed injection point is the headline result.
        for m in re.finditer(
            r'Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<method>[A-Z]+)\)(?P<body>.*?)(?=\nParameter:|\n---|\Z)',
            content, re.DOTALL | re.IGNORECASE,
        ):
            param, method = m.group("param"), m.group("method")
            body = m.group("body")
            types = re.findall(r'Type:\s*([^\n]+)', body)
            titles = re.findall(r'Title:\s*([^\n]+)', body)
            detail = (titles[0].strip() if titles else (types[0].strip() if types else "SQL injection"))
            dbms = re.search(r'back-end DBMS is ([^\n]+)', content, re.IGNORECASE)
            out.append(Finding(
                title=f"SQL Injection confirmed in {method} parameter '{param}' ({detail[:60]})",
                severity="CRITICAL",
                target=target,
                description=(
                    f"sqlmap confirmed an exploitable SQL injection in the {method} parameter "
                    f"'{param}' on {target}. Technique: {', '.join(t.strip() for t in types) or detail}."
                    + (f" Back-end DBMS: {dbms.group(1).strip()}." if dbms else "")
                ),
                remediation=(
                    "Replace dynamic SQL with parameterised queries or prepared statements, validate "
                    "and canonicalise input server-side, and grant the database account least privilege."
                ),
                evidence=body.strip()[:800],
                source_tool="sqlmap",
            ))

        # Heuristic warning with no confirmed point still warrants a finding.
        if not out:
            for m in re.finditer(
                r'(?:heuristic .*? shows that )?(?P<meth>GET|POST)\s+parameter\s+\'(?P<p>[^\']+)\'\s+(?:might be|is)\s+injectable',
                content, re.IGNORECASE,
            ):
                out.append(Finding(
                    title=f"Possible SQL Injection in {m.group('meth')} parameter '{m.group('p')}'",
                    severity="HIGH",
                    target=target,
                    description=(
                        f"sqlmap's heuristic check flagged the {m.group('meth')} parameter "
                        f"'{m.group('p')}' on {target} as potentially injectable. Not confirmed -- verify manually."
                    ),
                    remediation="Verify with a full sqlmap run; if confirmed, move the query to parameterised SQL.",
                    evidence=m.group(0),
                    source_tool="sqlmap",
                    confidence="Tentative",
                ))
        return out

    # ── gobuster / dirb / ffuf ──────────────────────────────────────────────
    def _parse_gobuster(self, content: str, target: str) -> List[Finding]:
        out = []
        for m in re.finditer(
            r'^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s*\[Size:\s*(?P<size>\d+)\])?',
            content, re.MULTILINE,
        ):
            path, status = m.group("path"), m.group("status")
            if status not in _INTERESTING_STATUS:
                continue
            sensitive = bool(_SENSITIVE_PATH_RE.search(path))
            if sensitive and status in ("200", "201"):
                sev = "HIGH"
            elif status in ("200", "201"):
                sev = "MEDIUM"
            elif status in ("401", "403"):
                sev = "LOW"
            else:
                sev = "LOW"
            out.append(Finding(
                title=f"Exposed path discovered: {path} (HTTP {status})",
                severity=sev,
                target=target,
                description=(
                    f"Directory brute-force against {target} found {path} responding with HTTP {status}"
                    + (f" ({m.group('size')} bytes)" if m.group("size") else "")
                    + (". The path name indicates potentially sensitive content." if sensitive else ".")
                ),
                remediation=(
                    "Remove or relocate the resource if it is not intended to be public, disable directory "
                    "listing, and restrict access at the web server or WAF."
                ),
                evidence=m.group(0).strip(),
                source_tool="Gobuster",
            ))
        return out

    # ── hydra ───────────────────────────────────────────────────────────────
    def _parse_hydra(self, content: str, target: str) -> List[Finding]:
        out = []
        for m in re.finditer(
            r'^\[(?P<port>\d+)\]\[(?P<svc>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<user>\S+)\s+password:\s*(?P<pw>\S+)',
            content, re.MULTILINE | re.IGNORECASE,
        ):
            svc, host, user, port = m.group("svc"), m.group("host"), m.group("user"), m.group("port")
            out.append(Finding(
                title=f"Valid credentials recovered by brute force: {svc} {user}@{host}:{port}",
                severity="CRITICAL",
                target=f"{host}:{port}",
                description=(
                    f"Hydra successfully authenticated to the {svc} service on {host}:{port} using the "
                    f"account '{user}'. The password was recovered by online brute force, meaning it is "
                    f"weak or default and the service has no effective rate limiting or lockout."
                ),
                remediation=(
                    "Rotate the credential immediately, enforce a strong password policy, enable account "
                    "lockout or rate limiting, restrict the service to trusted networks, and prefer key-based "
                    "authentication where the protocol supports it."
                ),
                # The recovered password is deliberately NOT stored -- this record ends up in
                # the audit ledger and exports, and writing a live credential into it would
                # turn the report itself into a disclosure.
                evidence=f"[{port}][{svc}] host: {host}   login: {user}   password: <redacted>",
                source_tool="Hydra",
                is_pii_exposed=True,
            ))
        return out

    # ── wpscan ──────────────────────────────────────────────────────────────
    def _parse_wpscan(self, content: str, target: str) -> List[Finding]:
        out = []

        m = re.search(r'WordPress version ([\d.]+) identified\s*\(([^)]*)\)', content, re.IGNORECASE)
        if m:
            version, note = m.group(1), m.group(2)
            insecure = "insecure" in note.lower() or "outdated" in note.lower()
            out.append(Finding(
                title=f"WordPress {version} identified ({note.strip()[:60]})",
                severity="HIGH" if insecure else "INFO",
                target=target,
                description=f"WPScan identified WordPress {version} on {target}. Scanner note: {note.strip()}.",
                remediation="Upgrade WordPress core to the current supported release.",
                evidence=m.group(0),
                source_tool="WPScan",
            ))

        for tm in re.finditer(r'Title:\s*([^\n]+)', content):
            title = tm.group(1).strip()
            if not title or len(title) < 8:
                continue
            window = content[tm.end():tm.end() + 400]
            cves = ["CVE-" + c for c in re.findall(r'cve:\s*([\d-]+)', window, re.IGNORECASE)]
            fixed = re.search(r'Fixed in:\s*([^\n]+)', window)
            out.append(Finding(
                title=f"WordPress vulnerability: {title[:100]}",
                severity="HIGH" if cves else "MEDIUM",
                cve_list=cves,
                target=target,
                description=(
                    f"WPScan reported '{title}' against {target}."
                    + (f" Fixed in {fixed.group(1).strip()}." if fixed else "")
                ),
                remediation=(
                    f"Update the affected component"
                    + (f" to {fixed.group(1).strip()} or later." if fixed else " to the latest release.")
                ),
                evidence=title,
                source_tool="WPScan",
            ))
        return out
