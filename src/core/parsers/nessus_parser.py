# -*- coding: utf-8 -*-
import re
from typing import List, Tuple, Any
from bs4 import BeautifulSoup
from .base_parser import BaseParser, is_image_file

# Prefer lxml for speed; fallback to html.parser if unavailable
try:
    import lxml  # noqa: F401
    _HTML_PARSER = "lxml"
    _XML_PARSER = "lxml-xml"
except ImportError:
    _HTML_PARSER = "html.parser"
    _XML_PARSER = "html.parser"
from .finding_schema import Finding
from .control_mapper import map_findings_list

_NESSUS_NUMERIC_SEVERITY = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}


class NessusParser(BaseParser):
    def _parse_native_xml(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """Parses native Nessus .nessus scan XML (<NessusClientData_v2><Report>
        <ReportHost><ReportItem>...). This is what Nessus itself produces when you
        save/export a scan -- see the docs at
        https://docs.tenable.com/nessus/Content/FileFormats.htm
        """
        soup = BeautifulSoup(content, _XML_PARSER)
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        def _child_text(item, tag_name):
            node = item.find(re.compile(rf'^{tag_name}$', re.IGNORECASE))
            return node.get_text(strip=True) if node else ""

        for host in soup.find_all(re.compile(r'^ReportHost$', re.IGNORECASE)):
            host_name = (host.get('name') or '').strip() or "Unknown Host"

            # Prefer the resolved host-ip tag over the (possibly hostname/FQDN) name attr
            host_ip = ""
            for tag in host.find_all(re.compile(r'^tag$', re.IGNORECASE)):
                if (tag.get('name') or '').lower() == 'host-ip':
                    host_ip = tag.get_text(strip=True)
                    break
            display_host = host_ip or host_name

            for item in host.find_all(re.compile(r'^ReportItem$', re.IGNORECASE)):
                plugin_id = (item.get('pluginID') or '').strip()
                title = (item.get('pluginName') or '').strip() or (f"Nessus Plugin {plugin_id}" if plugin_id else "Nessus Vulnerability Finding")
                port = (item.get('port') or '0').strip()
                svc = (item.get('svc_name') or '').strip()
                protocol = (item.get('protocol') or 'tcp').strip()

                risk_factor = _child_text(item, 'risk_factor')
                if risk_factor and risk_factor.lower() not in ("none", ""):
                    severity = "INFO" if risk_factor.lower() == "informational" else risk_factor.upper()
                else:
                    severity = _NESSUS_NUMERIC_SEVERITY.get((item.get('severity') or '0').strip(), "INFO")

                score_str = _child_text(item, 'cvss3_base_score') or _child_text(item, 'cvss_base_score')
                score = None
                if score_str:
                    try:
                        score = float(score_str)
                    except ValueError:
                        score = None

                vector = _child_text(item, 'cvss3_vector') or _child_text(item, 'cvss_vector')
                if vector and not vector.upper().startswith('CVSS:'):
                    vector = f"CVSS:3.0/{vector}"

                cves = sorted(set(
                    c.get_text(strip=True) for c in item.find_all(re.compile(r'^cve$', re.IGNORECASE))
                    if c.get_text(strip=True)
                ))

                desc = _child_text(item, 'description') or _child_text(item, 'synopsis')
                remed = _child_text(item, 'solution')
                evidence = _child_text(item, 'plugin_output') or desc[:500]

                if port and port != '0':
                    target = f"{display_host}:{port}/{protocol}" + (f" ({svc})" if svc and svc != "general" else "")
                else:
                    target = display_host

                finding = Finding(
                    plugin_id=plugin_id,
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=vector or None,
                    cve_list=cves,
                    description=desc,
                    remediation=remed,
                    target=target,
                    evidence=evidence,
                    source_tool="Nessus",
                )

                if finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

        return map_findings_list(actionable_findings), info_findings

    def can_parse(self, filename: str, content: str) -> bool:
        """Content-signature based detection — 0% filename keyword dependency.
        Rejects image files immediately, then inspects structural XML/text content
        that is exclusive to Nessus scan exports.
        """
        if not content:
            return False
        # Guard: reject image files regardless of their filename.
        if is_image_file(filename):
            return False
        # Primary: native .nessus XML format (NessusClientData_v2) or CSV/HTML exports.
        # Structural tags are exclusive to Nessus and cannot be confused with Nmap/Burp.
        # Scans the FULL content, not a fixed-size prefix -- a real 2.1MB Nessus-
        # shaped HTML export was found (during verification testing) to have its
        # actual signal content starting at character ~160,000, past a 100K
        # sample window, because a large embedded <style> block sits before it.
        sample = content.lower()
        # Structural XML tags are exclusive to real Nessus exports -- sufficient alone.
        if ("nessusclientdata_v2" in sample or "<reporthost" in sample
                or "<reportitem" in sample):
            return True
        # Product banners, equally exclusive and equally sufficient. A plain-text
        # export opening with "Tenable Nessus Scan Report" was rejected here and
        # claimed by PQCParser instead (on its crypto keywords); under the VAPT
        # framework, where PQC is excluded, it fell through to the Stage-3 fallback
        # and was parsed by BurpParser's regex. A Nessus report was being read by
        # the Burp parser. These strings cannot appear in an ISO policy document
        # the way "risk factor" can, so unlike the weak phrases below they need no
        # corroboration.
        if ("tenable nessus" in sample or "nessus scan report" in sample
                or "tenable.io" in sample or "tenable.sc" in sample):
            return True
        # Plain-English phrases are NOT exclusive to Nessus -- "risk factor" in
        # particular is common boilerplate in ordinary ISO 27001 risk-assessment
        # policy documents, which could get misrouted into VAPT parsing instead of
        # normal document ingestion on a single loose match. Require at least 2 of
        # these together before treating them as sufficient signal.
        weak_signal_count = sum((
            "risk factor" in sample,
            "vulnerabilities by plugin" in sample,
            "plugin output" in sample,
        ))
        if weak_signal_count >= 2:
            return True
        # .nessus extension is always a Nessus native scan file.
        if filename.lower().endswith(".nessus"):
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        # Native Nessus XML export (NessusClientData_v2 / <ReportHost>/<ReportItem>) --
        # the format Nessus itself produces when you save/export a scan. Distinct from
        # the HTML report-export format (div.section-wrapper) handled below, which was
        # previously the ONLY format this parser actually understood despite can_parse()
        # claiming to support any ".nessus" file -- a real scan silently produced 0
        # findings with no error shown anywhere.
        if "NessusClientData_v2" in content[:5000] or "<ReportItem" in content[:20000]:
            actionable, info = self._parse_native_xml(content)
            if actionable or info:
                return actionable, info
            # Malformed/empty native XML -- fall through to HTML parsing below as a
            # defensive last resort (harmless: it will also find nothing on real XML).

        soup = BeautifulSoup(content, _XML_PARSER if content.strip().startswith('<?xml') else _HTML_PARSER)
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        # 1. First check section-wrapper divs (Nessus HTML report exports like NOCPL_vu0k9r.html)
        wrappers = soup.find_all('div', class_='section-wrapper')
        if wrappers:
            for w in wrappers:
                txt = w.get_text()
                header = w.find_previous_sibling('div')
                h_text = header.get_text().strip() if header else ''
                
                m_header = re.search(r'(\d+)\s*\(\d+\)\s*-\s*(.+)', h_text)
                plugin_id = m_header.group(1).strip() if m_header else ''
                title = m_header.group(2).strip() if m_header else (h_text or "Nessus Vulnerability Finding")

                m_rf = re.search(r'Risk Factor\s*\n*\s*(Critical|High|Medium|Low|None|Informational)', txt, re.IGNORECASE)
                raw_sev = m_rf.group(1).strip() if m_rf else "INFO"
                if raw_sev.lower() in ("none", "informational"):
                    severity = "INFO"
                else:
                    severity = raw_sev.upper()

                m_cvss = re.search(r'CVSS\s*(?:v[32]\.0)?\s*Base\s*Score\s*:?\s*([\d\.]+)', txt, re.IGNORECASE)
                if not m_cvss:
                    m_cvss = re.search(r'CVSS\s*Score\s*:?\s*([\d\.]+)', txt, re.IGNORECASE)
                
                score = None
                if m_cvss:
                    try:
                        score = float(m_cvss.group(1))
                    except Exception:
                        score = None

                if score is None or score <= 0.0:
                    if raw_sev.upper() in ("CRITICAL", "P1"): score = 9.8
                    elif raw_sev.upper() in ("HIGH", "P2"): score = 8.0
                    elif raw_sev.upper() in ("MEDIUM", "P3"): score = 5.5
                    elif raw_sev.upper() in ("LOW", "P4"): score = 2.5
                    else: score = 0.0

                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                elif score > 0.0:
                    severity = "LOW"
                else:
                    severity = "INFO"

                m_vec = re.search(r'\(CVSS:3\.0/([^\)]+)\)', txt)
                cvss_vector = f"CVSS:3.0/{m_vec.group(1)}" if m_vec else None

                cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', txt, re.IGNORECASE))))

                desc = ""
                m_desc = re.search(r'Description\s*\n\s*(.*?)(?=\n\s*(?:See Also|Solution|Risk Factor|Plugin Information|Plugin Output|$))', txt, re.DOTALL)
                if m_desc:
                    desc = m_desc.group(1).strip()

                remed = ""
                m_sol = re.search(r'Solution\s*\n\s*(.*?)(?=\n\s*(?:Risk Factor|Plugin Information|Plugin Output|See Also|$))', txt, re.DOTALL)
                if m_sol:
                    remed = m_sol.group(1).strip()

                targets = []
                for h2 in w.find_all(['h2', 'h3']):
                    t_str = h2.get_text().strip()
                    # Try to match "IP / PORT / tcp" or "IP:PORT/tcp" (Nessus HTML format)
                    m_full = re.search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                        r'\s*[:/]\s*(\d{1,5})\s*[:/]\s*(tcp|udp)',
                        t_str, re.IGNORECASE
                    )
                    if m_full:
                        targets.append(f"{m_full.group(1)}:{m_full.group(2)}/{m_full.group(3).lower()}")
                    else:
                        m_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', t_str)
                        if m_ip:
                            targets.append(m_ip.group(1))

                t_host = ", ".join(sorted(list(set(targets)))) if targets else "Scoped Host Targets"

                # Extract Plugin Output for evidence
                evidence = ""
                m_out = re.search(r'Plugin Output\s*\n\s*(.*?)(?=\n\s*(?:Algorithm|Risk Factor|Plugin Information|CVSS|\Z))', txt, re.DOTALL)
                if m_out:
                    evidence = m_out.group(1).strip()
                else:
                    evidence = txt[:500]

                finding = Finding(
                    plugin_id=plugin_id,
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=cvss_vector,
                    cve_list=cves,
                    description=desc,
                    remediation=remed,
                    target=t_host,
                    evidence=evidence,
                    source_tool="Nessus"
                )

                if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

            if actionable_findings or info_findings:
                return map_findings_list(actionable_findings), info_findings

        # 2. Fallback to generic leaf div search
        for div in soup.find_all('div'):
            txt = div.get_text()
            if 'Risk Factor' in txt and 'Synopsis' in txt and 'Description' in txt:
                # Ensure this is a leaf plugin container div
                if any('Risk Factor' in child.get_text() and 'Synopsis' in child.get_text() for child in div.find_all('div', recursive=False)):
                    continue

                # Header div preceding this body div
                header = div.find_previous_sibling('div')
                h_text = header.get_text().strip() if header else ''
                
                # Extract plugin_id and title
                m_header = re.search(r'(\d+)\s*\(\d+\)\s*-\s*(.+)', h_text)
                plugin_id = m_header.group(1).strip() if m_header else ''
                title = m_header.group(2).strip() if m_header else (h_text or "Nessus Vulnerability Finding")

                # Extract Risk Factor / Severity
                m_rf = re.search(r'Risk Factor\s*\n*\s*(Critical|High|Medium|Low|None|Informational)', txt, re.IGNORECASE)
                raw_sev = m_rf.group(1).strip() if m_rf else "INFO"
                
                # Normalize severity
                if raw_sev.lower() == "none":
                    severity = "INFO"
                else:
                    severity = raw_sev.upper()

                # Extract CVSS Score & Vector
                m_cvss = re.search(r'CVSS v3\.0 Base Score\s*\n*\s*([\d\.]+)', txt)
                score = float(m_cvss.group(1)) if m_cvss else None

                m_vec = re.search(r'\(CVSS:3\.0/([^\)]+)\)', txt)
                cvss_vector = f"CVSS:3.0/{m_vec.group(1)}" if m_vec else None

                # Extract CVEs
                cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', txt, re.IGNORECASE))))

                # Extract Synopsis / Description
                desc = ""
                m_desc = re.search(r'Description\s*\n\s*(.*?)(?=\n\s*(?:See Also|Solution|Risk Factor|Plugin Information|Plugin Output|$))', txt, re.DOTALL)
                if m_desc:
                    desc = m_desc.group(1).strip()

                # Extract Solution / Remediation
                remed = ""
                m_sol = re.search(r'Solution\s*\n\s*(.*?)(?=\n\s*(?:Risk Factor|Plugin Information|Plugin Output|See Also|$))', txt, re.DOTALL)
                if m_sol:
                    remed = m_sol.group(1).strip()

                # Extract target IP + port + protocol from Plugin Output
                targets = []
                m_out = re.search(r'Plugin Output\s*\n\s*(.*?)(?=\n\s*(?:Algorithm|Risk Factor|$))', txt, re.DOTALL)
                if m_out:
                    evidence = m_out.group(1).strip()[:1500]
                    # Try "IP:PORT/tcp" or "IP / PORT / tcp" patterns first
                    full_hits = re.findall(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                        r'[:\s/]+(\d{1,5})\s*[:/]\s*(tcp|udp)',
                        evidence, re.IGNORECASE
                    )
                    if full_hits:
                        for ip, port, proto in full_hits:
                            targets.append(f"{ip}:{port}/{proto.lower()}")
                    else:
                        # Fallback: extract standalone IPs
                        ip_hits = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', evidence)
                        if ip_hits:
                            targets = list(set(ip_hits))
                        # Also try "port 443/tcp" pattern to append port to IP
                        if ip_hits:
                            port_hits = re.findall(r'[Pp]ort\s+(\d{1,5})/(tcp|udp)', evidence)
                            if port_hits and targets:
                                targets = [f"{t}:{port_hits[0][0]}/{port_hits[0][1].lower()}" for t in targets]

                target_str = ", ".join(sorted(set(targets))) if targets else "Scoped Target Systems"

                finding = Finding(
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=cvss_vector,
                    cve_list=cves,
                    target=target_str,
                    description=desc,
                    remediation=remed,
                    evidence=evidence,
                    plugin_id=plugin_id,
                    source_tool="Nessus"
                )

                if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

        # Apply central VAPT control mapping
        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        if actionable_findings or info_findings:
            return actionable_findings, info_findings

        # Last resort: plain-text fallback (PDF/DOCX-extracted or pasted report text
        # with no HTML structure at all -- the two paths above both require actual
        # <div> elements, which text extraction from a PDF/DOCX export doesn't produce).
        return self._parse_plaintext(content)

    def _parse_plaintext_table(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """Parses a vulnerability table that text extraction has flattened to one
        cell per line.

        PDF and DOCX extraction does not preserve table structure -- a four-column
        row arrives as four consecutive lines. The recurring unit is therefore:

            <plugin id>          numeric, 4-7 digits
            <vulnerability name> free text, usually carrying a CVE
            <severity>           Critical | High | Medium | Low | Info
            <control ref>        optional, e.g. "8.8 Tech Vuln Mgmt"

        Anchored on that ordering rather than on column headings, since the header
        row is itself flattened and its wording varies between exports.
        """
        actionable: List[Finding] = []
        info: List[Finding] = []

        row_re = re.compile(
            r'^[ \t]*(?P<pid>\d{4,7})[ \t]*\n'
            r'[ \t]*(?P<name>\S[^\n]{6,180}?)[ \t]*\n'
            r'[ \t]*(?P<sev>Critical|High|Medium|Low|Info(?:rmational)?|None)[ \t]*(?:\n|$)'
            r'(?:[ \t]*(?P<ctrl>[A-Z]?[\d.]+[^\n]{0,60})[ \t]*(?:\n|$))?',
            re.MULTILINE | re.IGNORECASE,
        )

        for m in row_re.finditer(content):
            name = m.group("name").strip()
            # A row whose "name" is itself a severity or a bare number is a header
            # or a misaligned read, not a finding.
            if re.fullmatch(r'(?i)(critical|high|medium|low|info\w*|none|[\d.\s]+)', name):
                continue
            raw_sev = m.group("sev").upper()
            score = {"CRITICAL": 9.8, "HIGH": 8.0, "MEDIUM": 5.5,
                     "LOW": 2.5}.get(raw_sev, 0.0)
            severity = ("INFO" if raw_sev.startswith("INFO") or raw_sev == "NONE"
                        else "CRITICAL" if score >= 9.0
                        else "HIGH" if score >= 7.0
                        else "MEDIUM" if score >= 4.0 else "LOW")
            cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', name, re.IGNORECASE)))
            ctrl = (m.group("ctrl") or "").strip()

            f = Finding(
                title=name,
                severity=severity,
                severity_score=score,
                confidence="Firm",
                cve_list=cves,
                target="Scoped Host Targets",
                description=name,
                remediation="",
                evidence=(f"Plugin ID:   {m.group('pid')}\n"
                          f"Severity:    {raw_sev}\n"
                          + (f"Reference:   {ctrl}\n" if ctrl else "")
                          + f"Source:      tabular scan report"),
                plugin_id=m.group("pid"),
                source_tool="Nessus",
            )
            (info if severity == "INFO" else actionable).append(f)

        return actionable, info

    def _parse_plaintext_summary(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """Parses the numbered, inline-labelled Nessus summary export.

        Blocks are delimited by a "<n>. <Title>" heading and carry their fields as
        "Label: value" lines. Severity is taken from the report's own statement --
        including the CVSS score it prints in parentheses -- rather than inferred,
        since the export states both explicitly.
        """
        actionable: List[Finding] = []
        info: List[Finding] = []

        heads = list(re.finditer(r'^\s*(\d{1,3})\.\s+(?P<title>\S.*?)\s*$', content, re.MULTILINE))
        # A numbered list alone is not a Nessus report; require the field labels
        # this format always carries, so ordinary numbered prose is not consumed.
        if not heads or not re.search(r'^\s*Severity\s*:', content, re.MULTILINE | re.IGNORECASE):
            return [], []

        for i, h in enumerate(heads):
            title = h.group("title").strip()
            body = content[h.end(): heads[i + 1].start() if i + 1 < len(heads) else len(content)]

            m_sev = re.search(r'Severity\s*:\s*(Critical|High|Medium|Low|None|Info(?:rmational)?)', body, re.IGNORECASE)
            if not m_sev:
                continue
            raw_sev = m_sev.group(1).upper()

            m_score = re.search(r'CVSS[^\d]{0,12}([\d]+\.?\d*)', body, re.IGNORECASE)
            score = None
            if m_score:
                try:
                    score = float(m_score.group(1))
                except ValueError:
                    score = None
            if score is None:
                score = {"CRITICAL": 9.8, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5}.get(raw_sev, 0.0)

            severity = ("INFO" if raw_sev.startswith("INFO") or raw_sev == "NONE"
                        else "CRITICAL" if score >= 9.0
                        else "HIGH" if score >= 7.0
                        else "MEDIUM" if score >= 4.0
                        else "LOW" if score > 0 else "INFO")

            def _field(label):
                m = re.search(rf'{label}\s*:\s*(.+?)(?=\n\s*(?:Severity|Description|Port|Recommendation|Solution|Plugin|CVE|References)\s*:|\n\s*\d{{1,3}}\.\s+\S|\Z)',
                              body, re.IGNORECASE | re.DOTALL)
                return m.group(1).strip() if m else ""

            desc = _field("Description")
            remed = _field("Recommendation") or _field("Solution")
            port = _field("Port")
            cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', body, re.IGNORECASE)))

            f = Finding(
                title=title,
                severity=severity,
                severity_score=score,
                confidence="Firm",
                cve_list=cves,
                target=port or "Scoped Host Targets",
                description=desc or title,
                remediation=remed,
                evidence=(body.strip()[:800]) or title,
                plugin_id=f"nessus-text-{i + 1}",
                source_tool="Nessus",
            )
            (info if severity == "INFO" else actionable).append(f)

        return actionable, info

    def _parse_plaintext(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """Parses Nessus report text with no HTML/XML structure -- e.g. text extracted
        from a PDF or DOCX export of a Nessus report, or a plain-text paste of one.
        Reuses the exact same field-extraction regexes as the HTML div-based path
        above, but splits the document into per-finding blocks using the heading text
        pattern ("80336 (1) - PHP Multiple Vulnerabilities") instead of HTML div
        boundaries, since extracted PDF/DOCX text carries no div structure to split on.
        """
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        header_re = re.compile(r'^(\d+)\s*\(\d+\)\s*-\s*(.+)$', re.MULTILINE)
        headers = list(header_re.finditer(content))
        if not headers:
            # Second plain-text shape: the human-readable summary export, which
            # numbers findings sequentially and labels fields inline rather than
            # using plugin-ID headings:
            #     1. Missing HTTP Strict Transport Security (HSTS) Header
            #     Severity: Low (CVSS 2.3)
            #     Description: ...
            #     Port: 80/tcp, 443/tcp
            #     Recommendation: ...
            # This returned nothing, so a report opening "Tenable Nessus Scan Report"
            # fell through the dispatch to BurpParser's regex and its findings were
            # published to the customer attributed to the wrong scanner.
            found, info = self._parse_plaintext_summary(content)
            if found or info:
                return found, info
            # Third shape: a vulnerability TABLE flattened by PDF/DOCX text
            # extraction into one value per line. Real customer report:
            #     Plugin ID / Vulnerability Name / Severity / ISO Control
            #     189421
            #     OpenSSH 7.2p1 Remote Code Execution (CVE-2024-6387)
            #     CRITICAL
            #     8.8 Tech Vuln Mgmt
            # Three genuine findings, two of them CRITICAL/HIGH with a CVE, were
            # extracted as zero because neither shape above matches a table.
            return self._parse_plaintext_table(content)

        for idx, h in enumerate(headers):
            plugin_id = h.group(1).strip()
            title = h.group(2).strip()
            block_start = h.end()
            block_end = headers[idx + 1].start() if idx + 1 < len(headers) else len(content)
            txt = content[block_start:block_end]

            m_rf = re.search(r'Risk Factor\s*\n*\s*(Critical|High|Medium|Low|None|Informational)', txt, re.IGNORECASE)
            raw_sev = m_rf.group(1).strip() if m_rf else "INFO"
            severity = "INFO" if raw_sev.lower() in ("none", "informational") else raw_sev.upper()

            m_cvss = re.search(r'CVSS\s*(?:v[32]\.0)?\s*Base\s*Score\s*:?\s*([\d\.]+)', txt, re.IGNORECASE)
            if not m_cvss:
                m_cvss = re.search(r'CVSS\s*Score\s*:?\s*([\d\.]+)', txt, re.IGNORECASE)
            score = None
            if m_cvss:
                try:
                    score = float(m_cvss.group(1))
                except Exception:
                    score = None
            if score is None or score <= 0.0:
                if raw_sev.upper() in ("CRITICAL", "P1"): score = 9.8
                elif raw_sev.upper() in ("HIGH", "P2"): score = 8.0
                elif raw_sev.upper() in ("MEDIUM", "P3"): score = 5.5
                elif raw_sev.upper() in ("LOW", "P4"): score = 2.5
                else: score = 0.0

            if score >= 9.0: severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            elif score > 0.0: severity = "LOW"
            else: severity = "INFO"

            m_vec = re.search(r'\(CVSS:3\.0/([^\)]+)\)', txt)
            cvss_vector = f"CVSS:3.0/{m_vec.group(1)}" if m_vec else None

            cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', txt, re.IGNORECASE))))

            desc = ""
            m_desc = re.search(r'Description\s*\n\s*(.*?)(?=\n\s*(?:See Also|Solution|Risk Factor|Plugin Information|Plugin Output|$))', txt, re.DOTALL)
            if m_desc:
                desc = m_desc.group(1).strip()

            remed = ""
            m_sol = re.search(r'Solution\s*\n\s*(.*?)(?=\n\s*(?:Risk Factor|Plugin Information|Plugin Output|See Also|$))', txt, re.DOTALL)
            if m_sol:
                remed = m_sol.group(1).strip()

            targets = []
            full_hits = re.findall(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:/]\s*(\d{1,5})\s*[:/]\s*(tcp|udp)',
                txt, re.IGNORECASE
            )
            if full_hits:
                for ip, port, proto in full_hits:
                    targets.append(f"{ip}:{port}/{proto.lower()}")
            else:
                ip_hits = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', txt)
                targets = sorted(set(ip_hits))
            t_host = ", ".join(sorted(set(targets))) if targets else "Scoped Host Targets"

            evidence = ""
            m_out = re.search(r'Plugin Output\s*\n\s*(.*?)(?=\n\s*(?:Algorithm|Risk Factor|Plugin Information|CVSS|\Z))', txt, re.DOTALL)
            if m_out:
                evidence = m_out.group(1).strip()[:1500]
            else:
                evidence = txt.strip()[:500]

            finding = Finding(
                plugin_id=plugin_id,
                title=title,
                severity=severity,
                severity_score=score,
                cvss_vector=cvss_vector,
                cve_list=cves,
                description=desc,
                remediation=remed,
                target=t_host,
                evidence=evidence,
                source_tool="Nessus"
            )

            if finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable_findings.append(finding)
            else:
                info_findings.append(finding)

        return map_findings_list(actionable_findings), info_findings
