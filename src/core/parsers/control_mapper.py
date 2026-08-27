# -*- coding: utf-8 -*-
import re
from typing import List, Optional
from .finding_schema import Finding

# Official Published MITRE CWE to OWASP Top 10 (2021) Deterministic Lookup Table
CWE_TO_OWASP_MAP = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-285": "A01:2021 Broken Access Control",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-862": "A01:2021 Broken Access Control",
    "CWE-863": "A01:2021 Broken Access Control",
    
    # A02:2021 - Cryptographic Failures
    "CWE-259": "A02:2021 Cryptographic Failures",
    "CWE-326": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-331": "A02:2021 Cryptographic Failures",

    # A03:2021 - Injection
    "CWE-79": "A03:2021 Injection", # XSS
    "CWE-89": "A03:2021 Injection", # SQLi
    "CWE-77": "A03:2021 Injection", # Command Injection
    "CWE-78": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",

    # A04:2021 - Insecure Design
    "CWE-209": "A04:2021 Insecure Design",
    "CWE-522": "A04:2021 Insecure Design",

    # A05:2021 - Security Misconfiguration
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-200": "A05:2021 Security Misconfiguration",
    "CWE-693": "A05:2021 Security Misconfiguration",

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-937": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",

    # A07:2021 - Identification and Authentication Failures
    "CWE-287": "A07:2021 Identification & Auth Failures",
    "CWE-384": "A07:2021 Identification & Auth Failures",
    "CWE-798": "A07:2021 Identification & Auth Failures",

    # A08:2021 - Software and Data Integrity Failures
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-829": "A08:2021 Software and Data Integrity Failures",

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-778": "A09:2021 Security Logging & Monitoring Failures",
    "CWE-117": "A09:2021 Security Logging & Monitoring Failures",

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021 Server-Side Request Forgery (SSRF)",
}

def get_dedup_key(title: str, target: str, cve_list: Optional[List[str]] = None, plugin_id: Optional[str] = None) -> str:
    """
    CVE-First, Plugin-ID-fallback, Title-last Deduplication Strategy.
    Prevents accidentally merging distinct vulnerabilities (e.g. Notepad++ < 8.8.2 vs < 8.9.2).
    """
    t_clean = (target or "").strip().lower()
    if cve_list and len(cve_list) > 0:
        cve_str = ",".join(sorted([str(c).upper().strip() for c in cve_list if c]))
        if cve_str:
            return f"cve:{cve_str}|target:{t_clean}"
    if plugin_id and str(plugin_id).strip():
        return f"plugin:{str(plugin_id).strip()}|target:{t_clean}"
    return f"title:{(title or '').strip().lower()}|target:{t_clean}"

def map_finding_to_owasp(cwe_id: Optional[str], title: str, desc: str) -> str:
    """
    100% Deterministic OWASP Top 10 Mapper via static CWE tables.
    """
    if cwe_id:
        cwe_clean = f"CWE-{re.sub(r'[^0-9]', '', str(cwe_id))}"
        if cwe_clean in CWE_TO_OWASP_MAP:
            return CWE_TO_OWASP_MAP[cwe_clean]
            
    combined = f"{(title or '').lower()} {(desc or '').lower()}"
    if any(k in combined for k in ("xss", "sqli", "sql injection", "command injection", "ldap injection")):
        return "A03:2021 Injection"
    if any(k in combined for k in ("access control", "privilege escalation", "directory traversal", "cors", "idor")):
        return "A01:2021 Broken Access Control"
    if any(k in combined for k in ("weak cipher", "ssl", "tls", "plaintext", "unencrypted", "hsts")):
        return "A02:2021 Cryptographic Failures"
    if any(k in combined for k in ("outdated", "end of life", "eol", "unpatched")):
        return "A06:2021 Vulnerable and Outdated Components"
    if any(k in combined for k in ("auth", "password", "session", "credential", "jwt")):
        return "A07:2021 Identification & Auth Failures"
    if any(k in combined for k in ("ssrf", "server-side request forgery")):
        return "A10:2021 Server-Side Request Forgery (SSRF)"
        
    return "A05:2021 Security Misconfiguration"

def map_finding_to_control(finding: Finding) -> str:
    """
    Centralized 100% Deterministic VAPT control mapper.
    Assigns a VAPT control ID (VAPT-1 .. VAPT-15) based on finding metadata,
    title, CVEs, and description. ZERO LLM dependency for category mapping.
    """
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    ev_lower = (finding.evidence or "").lower()
    combined = f"{title_lower} {desc_lower} {ev_lower}"

    # 1. Specific technical vulnerability classifications
    if any(k in combined for k in ("rce", "remote code execution", "directory traversal", "winrar", "buffer overflow")):
        return "VAPT-5"

    if any(k in combined for k in ("privilege escalation", "privesc", "uac bypass", "sudo")):
        return "VAPT-7"

    if any(k in combined for k in ("weak cipher", "ssl", "tls", "rc4", "3des", "cbc", "plaintext", "unencrypted", "default credentials", "default password")):
        return "VAPT-14"

    if any(k in combined for k in ("web", "http", "https", "xss", "sqli", "csrf", "hsts", "cookie", "apache", "nginx", "iis", "owasp")):
        return "VAPT-4"

    if any(k in combined for k in ("patch", "outdated", "update required", "installed version", "fixed version", "end of life", "eol")):
        return "VAPT-12"

    if any(k in combined for k in ("api", "rest", "graphql", "jwt", "swagger", "openapi")):
        return "VAPT-10"

    if any(k in combined for k in ("wireless", "wifi", "wpa", "802.11", "bluetooth")):
        return "VAPT-9"

    if any(k in combined for k in ("phishing", "spf", "dkim", "dmarc", "social engineering")):
        return "VAPT-8"

    if any(k in combined for k in ("reconnaissance", "osint", "whois", "dns zone")):
        return "VAPT-2"

    if any(k in combined for k in ("firewall", "segmentation", "filtered port")):
        return "VAPT-13"

    # Default fallback for network scanner findings
    return "VAPT-3"


def map_finding_to_pqc_control(finding: Finding) -> str:
    """
    Centralized 100% Deterministic PQC (Post-Quantum Cryptography Readiness)
    control mapper. Assigns a PQC control ID (PQC-1 .. PQC-12) based on finding
    title/description/evidence keywords. ZERO LLM dependency.

    Separate from map_finding_to_control() (VAPT-1..15-specific) -- PQC findings
    must never be routed through that function or they'd get mis-mapped to
    VAPT control IDs. Only PQC-1..PQC-9 (technical evidence controls) are
    reachable from a scanned finding here; PQC-10/11/12 are governance/
    process controls (remediation tracker, migration roadmap, final CBOM/QBOM
    sign-off) that a raw algorithm detection can't determine on its own --
    same as how several VAPT-* process controls (VAPT-1, VAPT-8, VAPT-15, etc.)
    are never reached by map_finding_to_control() either.
    """
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    ev_lower = (finding.evidence or "").lower()
    combined = f"{title_lower} {desc_lower} {ev_lower}"

    # Narrower/more specific categories are checked before the broad TLS/SSL
    # bucket, mirroring map_finding_to_control()'s own "specific before generic"
    # ordering -- otherwise an SSH or IPSec finding that happens to also mention
    # "TLS" in passing would get bucketed under the generic TLS/SSL control.
    if any(k in combined for k in ("ssh", "sshd", "openssh")):
        return "PQC-3"

    if any(k in combined for k in ("ipsec", "vpn", " ike ", "ikev1", "ikev2", "phase 1", "phase 2", "phase1", "phase2")):
        return "PQC-4"

    if any(k in combined for k in ("certificate", "x.509", "x509", "pki", "csr", "certificate authority", " ca ")):
        return "PQC-5"

    if any(k in combined for k in ("database", "tde", "transparent data encryption", "db encryption", "at-rest", "at rest", "data at rest")):
        return "PQC-6"

    if any(k in combined for k in ("library", "dependency", "package", "sdk", "openssl version", "crypto library", "cryptographic library")):
        return "PQC-7"

    if any(k in combined for k in ("hsm", "kms", "key management", "key vault", "keystore", "key store")):
        return "PQC-8"

    if any(k in combined for k in ("code signing", "code-signing", "firmware signing", "firmware", "authenticode")):
        return "PQC-9"

    if any(k in combined for k in ("tls", "ssl", "cipher suite", "https", "handshake")):
        return "PQC-2"

    # Default fallback: cryptographic asset inventory
    return "PQC-1"


# ══════════════════════════════════════════════════════════════════════════════
# RISK CATEGORY TAXONOMY  (100% offline — static deterministic lookup)
# ══════════════════════════════════════════════════════════════════════════════

# Maps OWASP Top 10 codes to human-readable risk categories
_OWASP_TO_CATEGORY = {
    "A01": "Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Authentication Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging & Monitoring",
    "A10": "SSRF",
}

def map_finding_to_risk_category(finding: Finding) -> str:
    """
    Maps a Finding to a human-readable Risk Category using:
    1. CWE → OWASP Top 10 static lookup
    2. Title/description keyword fallback
    Returns a category string like 'Injection', 'Access Control', etc.
    100% offline — no network calls.
    """
    # Try CWE-based OWASP mapping first
    cwe_id = None
    # Extract CWE from CVE list or evidence
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()} {(finding.evidence or '').lower()}"
    cwe_match = re.search(r'CWE-(\d+)', combined, re.IGNORECASE)
    if cwe_match:
        cwe_id = cwe_match.group(0).upper()

    if cwe_id:
        owasp = CWE_TO_OWASP_MAP.get(cwe_id, "")
        if owasp:
            # Extract A0x prefix to map to category
            code = owasp[:3]
            if code in _OWASP_TO_CATEGORY:
                return _OWASP_TO_CATEGORY[code]

    # Use the existing OWASP mapper as fallback
    owasp_str = map_finding_to_owasp(cwe_id, finding.title, finding.description)
    if owasp_str:
        code = owasp_str[:3]
        if code in _OWASP_TO_CATEGORY:
            return _OWASP_TO_CATEGORY[code]

    # Final keyword-based fallback
    if any(k in combined for k in ("xss", "sqli", "sql injection", "command injection", "ldap injection", "scripting", "injection")):
        return "Injection"
    if any(k in combined for k in ("access control", "privilege escalation", "directory traversal", "cors", "idor", "unauthorized")):
        return "Access Control"
    if any(k in combined for k in ("weak cipher", "ssl", "tls", "plaintext", "unencrypted", "hsts", "crypto")):
        return "Cryptographic Failures"
    if any(k in combined for k in ("auth", "password", "session", "credential", "jwt", "login")):
        return "Authentication Failures"
    if any(k in combined for k in ("ssrf", "server-side request forgery")):
        return "SSRF"
    if any(k in combined for k in ("patch", "update", "outdated", "eol", "end of life")):
        return "Vulnerable Components"
    if any(k in combined for k in ("network", "port", "tcp", "udp", "firewall", "nmap", "open port")):
        return "Network Security"
    if any(k in combined for k in ("log", "monitoring", "audit trail")):
        return "Logging & Monitoring"

    return "Security Misconfiguration"



# ══════════════════════════════════════════════════════════════════════════════
# CIA IMPACT & PII EXPOSURE EVALUATOR  (100% offline — regex-based)
# ══════════════════════════════════════════════════════════════════════════════

# PII / sensitive data patterns for the "⚠ PII EXPOSURE DETECTED" report flag.
# Deliberately does NOT include IPv4 -- a VAPT finding's target host IP is the
# report's actual content, not personally-identifying data, and every finding
# mentions one; flagging on it made the badge fire on ~100% of findings and
# stop carrying any signal. Matches the same IP-is-not-PII call already made
# for VAPT export redaction (src/core/report_exporter.py, redact_pii(redact_ip=False)).
_PII_PATTERNS = [
    # Email: require word chars on both sides of '@', exclude crypto algo identifiers
    # (e.g. sntrup761x25519-sha512@openssh.com is a KEX algo name, not a personal email).
    # Guard: must start with >=2 plain word chars (letters/digits only before any special),
    # and the local part must NOT look like a crypto/hash string (all-hex or digit+hyphen heavy).
    re.compile(
        r'(?<![\w@])'
        r'(?!(?:[0-9a-f]{8,}|[\w\d]+-sha[0-9]+|sntrup|mlkem|kyber|dilithium|sphincs|falcon)[^\s]*@)'
        r'[a-zA-Z0-9][\w.+\-]{1,}@[\w\-]+\.(?:[a-zA-Z]{2,})',
        re.IGNORECASE
    ),   # Email (with crypto-algo false-positive guard)
    re.compile(r'(?:password|passwd|pwd|secret|api[_\-]?key|token|credential|private[_\-]?key)\s*[:=]\s*\S+', re.IGNORECASE),  # Credentials
    re.compile(r'(?:ssn|social\s+security|credit\s+card|card\s+number|pan\s+number|aadhaar)', re.IGNORECASE),  # PII identifiers
]

def evaluate_cia_and_pii_impact(finding: Finding) -> tuple:
    """
    Evaluates CIA (Confidentiality, Integrity, Availability) impact and
    PII exposure for a Finding based on its content.
    Returns (cia_impact_str, is_pii_exposed).
    100% offline — uses local regex patterns only.
    """
    combined = f"{finding.title or ''} {finding.description or ''} {finding.evidence or ''} {finding.remediation or ''}"

    # ── PII Exposure Detection ──
    # PQC-Scan findings come from configuration files (TLS/SSH/IPSec config exports)
    # that never contain personal data -- skip PII detection to avoid false positives
    # (e.g. SSH KEX algo strings like sntrup761x25519-sha512@openssh.com matching email regex).
    is_pii = False
    if getattr(finding, "source_tool", "") != "PQC-Scan":
        for pattern in _PII_PATTERNS:
            if pattern.search(combined):
                is_pii = True
                break

    # ── CIA Impact Assessment ──
    combined_lower = combined.lower()
    c_impact = "NONE"
    i_impact = "NONE"
    a_impact = "NONE"

    # ── PQC / Quantum-specific CIA override ──────────────────────────────────
    # ONLY applied when the finding actually came from the PQC scanner
    # (source_tool == "PQC-Scan") OR already has quantum_status set.
    # Must NOT fire on ISO/VAPT findings that merely mention "RSA" or "ECDSA"
    # in evidence -- those use the generic CIA logic below.
    # Rationale: quantum-vulnerable algorithms break confidentiality (HNDL: harvest
    # now, decrypt later) and integrity (signature forgery). Availability is not
    # directly impacted by algorithm weakness alone.
    _is_pqc_finding = (
        getattr(finding, "source_tool", "") == "PQC-Scan"
        or bool(getattr(finding, "quantum_status", ""))
    )
    if _is_pqc_finding:
        c_impact = "HIGH"   # HNDL: data captured today decrypted post-Q-day
        i_impact = "HIGH"   # Signature forgery: ECC/RSA signatures are breakable
        # a_impact stays NONE — algorithm weakness alone doesn't cause DoS

    # Confidentiality indicators (generic — only applied if not already set by PQC block)
    if c_impact == "NONE":
        if is_pii or any(k in combined_lower for k in (
            "information disclosure", "data leak", "sensitive", "credential",
            "password", "token", "private key", "directory listing",
            "source code", "backup file", "database dump", "pii"
        )):
            c_impact = "HIGH"
        elif any(k in combined_lower for k in (
            "version disclosure", "banner", "stack trace", "error message",
            "server header", "configuration"
        )):
            c_impact = "MEDIUM"

    # Integrity indicators (generic — only applied if not already set by PQC block)
    if i_impact == "NONE":
        if any(k in combined_lower for k in (
            "injection", "sqli", "xss", "csrf", "command injection",
            "code execution", "rce", "file upload", "deserialization"
        )):
            i_impact = "HIGH"
        elif any(k in combined_lower for k in (
            "open redirect", "clickjacking", "header injection"
        )):
            i_impact = "MEDIUM"

    # Availability indicators
    if any(k in combined_lower for k in (
        "denial of service", "dos", "ddos", "buffer overflow",
        "resource exhaustion", "crash", "memory corruption"
    )):
        a_impact = "HIGH"
    elif any(k in combined_lower for k in (
        "rate limit", "timeout", "slow"
    )):
        a_impact = "MEDIUM"

    if is_pii:
        c_impact = "Confidential (High - PII Data Present)"
    cia_str = f"C:{c_impact} | I:{i_impact} | A:{a_impact}"
    return cia_str, is_pii


# ══════════════════════════════════════════════════════════════════════════════
# ACTIONABLE DEVELOPER REMEDIATION ENGINE  (100% offline — template-based)
# ══════════════════════════════════════════════════════════════════════════════

_REMEDIATION_TEMPLATES = {
    "sql injection": "Use parameterized queries (prepared statements) instead of string concatenation. Example: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`. Apply input validation and use an ORM where possible.",
    "sqli": "Use parameterized queries (prepared statements) instead of string concatenation. Apply input validation and use an ORM where possible.",
    "cross-site scripting": "Encode all user-supplied output using context-aware encoding (HTML entity, JavaScript, URL encoding). Implement Content-Security-Policy (CSP) headers. Use frameworks with auto-escaping (React, Angular).",
    "xss": "Encode all user-supplied output using context-aware encoding. Implement Content-Security-Policy (CSP) headers.",
    "csrf": "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing requests. Set `SameSite=Strict` or `SameSite=Lax` on session cookies.",
    "hsts": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses. Ensure all resources load over HTTPS.",
    "ssl": "Upgrade to TLS 1.2+ minimum. Disable SSLv3, TLS 1.0, TLS 1.1. Use strong cipher suites (AES-GCM, ChaCha20). Renew expired certificates.",
    "tls": "Upgrade to TLS 1.2+ minimum. Disable weak protocols and cipher suites. Configure perfect forward secrecy (ECDHE).",
    "weak cipher": "Disable RC4, DES, 3DES, and CBC-mode ciphers. Configure server to prefer AES-256-GCM or ChaCha20-Poly1305.",
    "outdated": "Update the affected software/library to the latest stable version. Establish a patch management policy with regular update cycles.",
    "end of life": "Migrate to a supported version of the software immediately. Unsupported software receives no security patches.",
    "open redirect": "Validate and whitelist redirect URLs against a list of allowed domains. Never pass user-controlled URLs directly to redirect functions.",
    "directory traversal": "Sanitize file path inputs. Use a whitelist of allowed file paths. Never use user input directly in file system operations.",
    "command injection": "Avoid passing user input to shell commands. Use language-specific safe APIs (e.g., `subprocess.run()` with `shell=False`). Apply strict input validation.",
    "rce": "Patch the vulnerable component immediately. Isolate the affected service using network segmentation. Apply least-privilege execution context.",
    "default credentials": "Change all default usernames and passwords before deployment. Implement strong password policies and credential rotation.",
    "missing security headers": "Add security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy`, `Referrer-Policy: strict-origin-when-cross-origin`.",
    "clickjacking": "Set `X-Frame-Options: DENY` or `SAMEORIGIN`. Implement `Content-Security-Policy: frame-ancestors 'none'`.",
    "information disclosure": "Remove verbose error messages from production. Disable server version banners. Remove unnecessary HTTP response headers.",
    "ssrf": "Validate and whitelist allowed URLs/IP ranges. Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x). Use a dedicated egress proxy.",
    "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON) instead of native object serialization. Implement integrity checks.",
    "file upload": "Validate file types using content inspection (magic bytes), not just extensions. Store uploads outside the web root. Set size limits and scan for malware.",
    "privilege escalation": "Apply principle of least privilege. Validate authorization on every privileged action server-side. Use role-based access control (RBAC).",
    "brute force": "Implement account lockout or rate limiting after failed attempts. Use CAPTCHA. Enforce strong password policies and multi-factor authentication.",
    "path traversal": "Sanitize file path inputs. Use a whitelist of allowed file paths. Never use user input directly in file system operations.",
    "session fixation": "Regenerate the session ID immediately after login and on every privilege change. Never accept a session ID supplied by the client before authentication.",
    "cors": "Restrict `Access-Control-Allow-Origin` to an explicit whitelist of trusted domains. Never reflect the request's `Origin` header or use a wildcard (`*`) alongside `Access-Control-Allow-Credentials: true`.",
    "self-signed": "Replace the self-signed certificate with one issued by a trusted Certificate Authority. Configure automatic renewal (e.g. via ACME/Let's Encrypt) to prevent future expiry.",
    "self signed": "Replace the self-signed certificate with one issued by a trusted Certificate Authority. Configure automatic renewal (e.g. via ACME/Let's Encrypt) to prevent future expiry.",
    "md5": "Replace MD5/SHA-1 with a modern hashing algorithm (SHA-256 or better) for integrity checks, and a dedicated password-hashing function (bcrypt, scrypt, or Argon2) for credential storage.",
    "sha1": "Replace MD5/SHA-1 with a modern hashing algorithm (SHA-256 or better) for integrity checks, and a dedicated password-hashing function (bcrypt, scrypt, or Argon2) for credential storage.",
    "request smuggling": "Ensure front-end proxy and back-end server agree on request framing (Content-Length vs. Transfer-Encoding). Disable support for ambiguous/duplicate headers at the proxy layer.",
    "directory listing": "Disable directory browsing/auto-indexing at the web server configuration level (e.g. `Options -Indexes` in Apache, `autoindex off` in nginx).",
    "index of": "Disable directory browsing/auto-indexing at the web server configuration level (e.g. `Options -Indexes` in Apache, `autoindex off` in nginx).",
    "xml external entity": "Disable external entity and DTD processing in the XML parser (e.g. `XMLConstants.FEATURE_SECURE_PROCESSING` in Java, `resolve_entities=False` in lxml). Prefer a data format that doesn't support entities (JSON) where possible.",
    "xxe": "Disable external entity and DTD processing in the XML parser. Prefer a data format that doesn't support entities (JSON) where possible.",
    "insecure direct object reference": "Enforce server-side authorization checks on every object reference (verify the requesting user owns/may access the specific record ID), not just authentication. Use indirect reference maps or UUIDs instead of predictable sequential IDs.",
    "idor": "Enforce server-side authorization checks on every object reference, not just authentication. Use indirect reference maps or UUIDs instead of predictable sequential IDs.",
    "cleartext": "Enforce TLS for this service/protocol; disable the unencrypted listener entirely if a secure alternative exists (e.g. FTPS/SFTP instead of FTP, HTTPS instead of HTTP).",
    "unencrypted": "Enforce TLS for this service/protocol; disable the unencrypted listener entirely if a secure alternative exists.",
    "rate limit": "Implement request throttling per user/IP (e.g. token-bucket or sliding-window) on this endpoint, with a clear `429 Too Many Requests` response and `Retry-After` header.",
}

def get_actionable_remediation(finding: Finding) -> str:
    """
    Returns developer-actionable remediation guidance based on finding title/description.
    Uses a deterministic local template dictionary — 100% offline, no LLM required.

    When no template matches, this used to just return the scanner's own remediation
    text verbatim -- which made the exported report's "Developer Actionable Mitigation
    Steps" section silently disappear for that finding (report_exporter.py only shows
    it when the actionable text differs from the raw recommendation), since duplicating
    the same text under two headings has no display value. Any finding whose vulnerability
    type isn't one of the ~35 hardcoded keywords above -- a large share of real Nessus/
    Qualys CVE-based findings -- was getting no developer-specific guidance at all. Now
    builds a genuinely more actionable, structured fallback instead of parroting the
    scanner text back.
    """
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()}"

    # ── PQC findings bypass the VAPT keyword templates entirely ───────────────
    # Without this guard, short keys like 'ssl' and 'tls' match PQC database/
    # TLS findings first, returning generic VAPT guidance ("Upgrade to TLS 1.2+")
    # instead of the correct PQC-specific actionable steps.
    _title_low = (finding.title or "").lower()
    _is_pqc = (
        (finding.category or "").upper() in (
            "PQC", "POST-QUANTUM CRYPTOGRAPHY",
            "ELLIPTIC CURVE CRYPTOGRAPHY (ECC)", "ASYMMETRIC ENCRYPTION (RSA)"
        )
        or (finding.control_id or "").upper().startswith("PQC")
        or bool(getattr(finding, "quantum_status", ""))
    )

    # Check each template key against combined text. Word-boundary matched, not plain
    # substring containment -- a bare `key in combined` check let short keys like "rce"
    # match inside unrelated words (enfoRCEd, souRCE, resouRCE, divoRCE...), handing out
    # wrong/irrelevant remediation guidance for findings that had nothing to do with
    # remote code execution.
    if not _is_pqc:
        for key, guidance in _REMEDIATION_TEMPLATES.items():
            if re.search(rf'\b{re.escape(key)}\b', combined):
                return guidance

    # No keyword template matched.
    cve_ref = finding.cve_list[0] if finding.cve_list else None
    base_remed = (finding.remediation or "").strip()

    # ── PQC findings: return a SHORT, genuinely distinct developer action list ──
    # The full multi-step remediation is already in finding.recommendation.
    # Repeating it here (with "Apply the fix: " prefix) makes both sections
    # look identical -- no value. Instead emit a concise per-algorithm action.
    # (_title_low and _is_pqc are set at the top of this function.)
    if _is_pqc:
        # Pick the shortest meaningful dev action by algorithm class
        if "rsa" in _title_low:
            return (
                "1. Audit all RSA key usages in this asset (TLS cert, SSH, JWT, S/MIME). "
                "2. Disable static-RSA cipher suites — keep only ECDHE-* (PFS) as interim. "
                "3. Re-issue the TLS certificate as ECDSA P-256 (short-term) or ML-DSA-65/FIPS-204 (post-quantum). "
                "4. Re-run the PQC scanner after each change to confirm the finding is resolved."
            )
        if "ecdsa" in _title_low:
            return (
                "1. Replace ECDSA TLS/SSH certificates with ML-DSA (FIPS 204) once your CA supports it. "
                "2. Interim: add X25519MLKEM768 to ssl_ecdh_curve to harden the key-exchange layer now. "
                "3. Migrate JWT / code-signing keys to ML-DSA-44 or ML-DSA-65. "
                "4. Re-run the PQC scanner after migration to confirm."
            )
        if "x25519" in _title_low or "curve25519" in _title_low:
            return (
                "1. Set ssl_ecdh_curve X25519MLKEM768:X25519; in NGINX — one config change enables hybrid PQC. "
                "2. For SSH: add sntrup761x25519-sha512@openssh.com to KexAlgorithms in sshd_config (OpenSSH 9.0+). "
                "3. Re-run the PQC scanner to confirm X25519MLKEM768 is detected as the active KEM."
            )
        if "secp384" in _title_low or "ecc" in _title_low or "elliptic" in _title_low:
            return (
                "1. Replace secp384r1 with X25519MLKEM768 hybrid in ssl_ecdh_curve — works with current OpenSSL 3.x. "
                "2. Plan certificate re-issuance to ML-DSA-65 (FIPS 204) once your CA supports PQC hybrids. "
                "3. Re-run the PQC scanner after each change to confirm no classical-only curves remain."
            )
        if "database" in _title_low or "mysql" in _title_low or "ssl cert" in _title_low or "ssl key" in _title_low or "sql" in _title_low:
            return (
                "1. Set tls_ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 in my.cnf. "
                "2. Set tls_version = TLSv1.3 and remove TLSv1.2 if still listed. "
                "3. Apply network compensating controls (private VPC, mTLS) while awaiting PQC-capable DB engine. "
                "4. Re-run the PQC scanner after config change to confirm TLS hardening is in effect."
            )
        if "tls" in _title_low or "protocol" in _title_low:
            return (
                "1. Add X25519MLKEM768 as the first entry in ssl_ecdh_curve for hybrid PQC key exchange. "
                "2. Ensure tls_version = TLSv1.3 only — disable TLSv1.2 if the client population allows. "
                "3. Re-run the PQC scanner to confirm ML-KEM hybrid is active in the TLS handshake."
            )
        # Generic PQC fallback
        return (
            "1. Identify the specific algorithm in use and its role (key exchange, signature, or encryption). "
            "2. Replace with the NIST-selected post-quantum equivalent: ML-KEM (FIPS 203) for key exchange, "
            "ML-DSA (FIPS 204) for signatures, SLH-DSA (FIPS 205) as alternative signature scheme. "
            "3. Re-run the PQC scanner after migration to confirm the finding is resolved."
        )

    # ── VAPT / CVE-based findings: structured actionable fallback ─────────────
    if cve_ref:
        fix_step = f"Apply the vendor-supplied patch addressing {cve_ref} for the affected component."
    elif base_remed:
        fix_step = f"Apply the fix: {base_remed}"
    else:
        fix_step = f"Apply the vendor-recommended fix for '{finding.title or 'this finding'}'."

    steps = [fix_step, "Verify the fix by re-running the scan against the affected target after remediation."]
    if not cve_ref and not base_remed:
        steps.append("If no vendor patch is available yet, apply compensating controls (network segmentation, a WAF rule, or disabling the affected service) until one is released.")

    return " ".join(steps)


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED ENRICHMENT PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def map_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    Centralized mapper helper that enriches a list of Findings in-place:
    1. Assigns control_id (VAPT-1..VAPT-15)
    2. Assigns risk category (Access Control, Injection, etc.)
    3. Evaluates CIA impact & PII exposure
    4. Generates actionable developer remediation
    All operations are 100% offline and deterministic.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_control(f)
        if not f.category:
            f.category = map_finding_to_risk_category(f)
        if not f.cia_impact:
            cia_str, is_pii = evaluate_cia_and_pii_impact(f)
            f.cia_impact = cia_str
            f.is_pii_exposed = is_pii
        if not f.remediation_actionable:
            f.remediation_actionable = get_actionable_remediation(f)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# PQC RISK SCORING  (Enhancement A -- CIA + HNDL Risk Scoring, 100% offline)
# ══════════════════════════════════════════════════════════════════════════════

def _cia_letter_score(cia_impact: str, letter: str) -> int:
    """Extracts one component's rating out of the 'C:HIGH | I:MEDIUM | A:NONE'
    -style cia_impact string produced by evaluate_cia_and_pii_impact() and maps
    it to a 1-5 score: HIGH -> 5, MEDIUM -> 3, NONE/blank/unrecognized -> 1.
    Substring-matched (not exact-equality) so the PII-exposure variant of the
    confidentiality value -- 'Confidential (High - PII Data Present)' -- still
    resolves to HIGH/5."""
    if not cia_impact:
        return 1
    for part in cia_impact.split("|"):
        part = part.strip()
        if part.upper().startswith(f"{letter}:"):
            val = part.split(":", 1)[1].strip().upper()
            if "HIGH" in val:
                return 5
            if "MEDIUM" in val:
                return 3
            return 1
    return 1


_BUSINESS_PRIORITY_CIA = {
    "CRITICAL": (5, 5, 4),
    "HIGH": (4, 4, 3),
    "MEDIUM": (3, 2, 2),
    "LOW": (2, 1, 1),
}


def _pqc_cia_scores(finding: Finding) -> "tuple":
    """
    C/I/A scores (1-5 each) for PQC risk scoring.

    The shared evaluate_cia_and_pii_impact() (via _cia_letter_score above) was
    built for VAPT findings and keys off text like "password"/"credential"/
    "injection" -- vocabulary that essentially never appears in a PQC finding's
    evidence ("Certificate : RSA2048"), so every PQC finding silently floored
    at C=I=A=1/NONE regardless of how critical the asset actually is.

    Instead, C/I/A for a PQC finding is driven by the asset's business
    criticality (finding.business_priority, Enhancement B) -- this also
    matches how the source RFP's own worked examples score CIA per business
    system, not per algorithm ("Internet Banking Portal": C=5/I=5/A=4;
    "Internal HR Portal": C=3/I=2/A=2 -- both reproduced exactly by this
    table for CRITICAL/MEDIUM respectively).

    Falls back to the shared VAPT-style keyword scorer (floored at a small
    baseline) only when the asset didn't match any business-priority keyword,
    so an unclassified asset isn't scored as zero-impact, and a genuine
    keyword hit (e.g. "credential") in that fallback still counts.
    """
    bp = (finding.business_priority or "").strip().upper()
    if bp in _BUSINESS_PRIORITY_CIA:
        return _BUSINESS_PRIORITY_CIA[bp]
    c = _cia_letter_score(finding.cia_impact, "C")
    i = _cia_letter_score(finding.cia_impact, "I")
    a = _cia_letter_score(finding.cia_impact, "A")
    return (max(c, 2), max(i, 2), max(a, 1))


def _hndl_score(exposure_context: str, quantum_status: str) -> int:
    """Harvest-Now-Decrypt-Later exposure factor (1-5), derived from
    exposure_context + quantum_status per the fixed lookup table below."""
    exp = (exposure_context or "").strip().upper()
    qs = (quantum_status or "").strip().upper()
    if exp == "EXTERNAL" and qs == "VULNERABLE":
        return 5
    if exp == "EXTERNAL" and qs == "WEAK":
        return 4
    if exp == "INTERNAL" and qs == "VULNERABLE":
        return 3
    if exp == "EXTERNAL" and qs == "SAFE":
        return 2
    if exp == "INTERNAL" and qs == "WEAK":
        return 2
    return 1


def _qv_score(quantum_status: str) -> int:
    """Quantum Vulnerability factor (1-5): VULNERABLE -> 5, WEAK -> 3,
    SAFE/blank -> 1."""
    qs = (quantum_status or "").strip().upper()
    if qs == "VULNERABLE":
        return 5
    if qs == "WEAK":
        return 3
    return 1


def compute_pqc_risk_score(finding: Finding) -> "tuple":
    """
    AICyberAuditBox PQC Risk Scoring Methodology
    ─────────────────────────────────────────────
    This tool's own defined, deterministic risk-scoring formula for PQC
    findings -- a weighted sum of 5 factors, each scored 1-5. It is NOT a
    reverse-engineered external standard (not CVSS, not FAIR, not any
    published PQC risk framework); it exists purely to give auditors a
    consistent 0-100 composite score to sort/prioritize PQC findings by.

        C    (Confidentiality impact) -- from finding.business_priority (see _pqc_cia_scores)
        I    (Integrity impact)       -- from finding.business_priority (see _pqc_cia_scores)
        A    (Availability impact)    -- from finding.business_priority (see _pqc_cia_scores)
        HNDL (Harvest-Now-Decrypt-Later exposure) -- from exposure_context + quantum_status
        QV   (Quantum Vulnerability)  -- from quantum_status

        risk_score = round((C + I + A + HNDL + QV) / 25 * 100)

    Banding: >= 80 -> CRITICAL, 60-79 -> HIGH, 40-59 -> MEDIUM, < 40 -> LOW.

    NOTE: requires finding.business_priority to already be set (classify_business_priority()
    must run before this in map_pqc_findings_list() -- it does, see call order below).

    Returns (risk_score: int, risk_band: str). 100% offline, deterministic --
    no LLM involvement.
    """
    c, i, a = _pqc_cia_scores(finding)
    hndl = _hndl_score(finding.exposure_context, finding.quantum_status)
    qv = _qv_score(finding.quantum_status)

    risk_score = round((c + i + a + hndl + qv) / 25 * 100)

    if risk_score >= 80:
        risk_band = "CRITICAL"
    elif risk_score >= 60:
        risk_band = "HIGH"
    elif risk_score >= 40:
        risk_band = "MEDIUM"
    else:
        risk_band = "LOW"

    return risk_score, risk_band


# ══════════════════════════════════════════════════════════════════════════════
# BUSINESS PRIORITY CLASSIFICATION  (Enhancement B -- 100% offline, keyword-based)
# ══════════════════════════════════════════════════════════════════════════════

# Ordered CRITICAL -> LOW so the most severe matching bucket wins when an
# asset description happens to contain keywords from more than one bucket
# (same "specific/severe checked first" convention as map_finding_to_control()
# and map_finding_to_pqc_control() above).
_BUSINESS_PRIORITY_BUCKETS = [
    ("CRITICAL", (
        "internet banking", "mobile banking", "core banking", "pki", "root ca",
        "vpn gateway", "payment switch", "payment", "swift", "atm",
    )),
    ("HIGH", (
        "api gateway", "api ", "load balancer", "firewall", "database",
        "oracle db", "customer data",
    )),
    ("MEDIUM", (
        "internal", "intranet", "hr portal", "employee", "erp",
    )),
    ("LOW", (
        "archive", "backup", "test environment", "sandbox", "staging",
    )),
]


def classify_business_priority(finding: Finding) -> str:
    """
    Deterministic business-criticality classification (Enhancement B) for a
    PQC finding's asset, based on keyword buckets matched against the asset's
    known context text. Searches (in order of richness):
      1. asset_category  -- already classified by _classify_asset_category()
         e.g. 'Load Balancer' -> HIGH, 'PKI / HSM' -> CRITICAL
      2. asset_name / target -- filename fallback from _find_asset_context()
      3. title -- algorithm name (last resort)
    Same style as map_finding_to_risk_category(): fixed ordered keyword lookup,
    100% offline. Returns "" when nothing matches -- never forces a guess.
    """
    # Build combined text: asset_category first (most reliable signal),
    # then asset_name / target, then title as last resort.
    combined = " ".join(filter(None, [
        getattr(finding, "asset_category", "") or "",
        finding.asset_name or "",
        finding.target or "",
        finding.title or "",
    ])).lower()
    for band, keywords in _BUSINESS_PRIORITY_BUCKETS:
        if any(kw in combined for kw in keywords):
            return band
    return ""


def map_pqc_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    PQC-specific variant of map_findings_list(): identical enrichment (risk
    category, CIA impact/PII, actionable remediation), but assigns control_id
    via map_finding_to_pqc_control() (PQC-1..PQC-12) instead of
    map_finding_to_control() (VAPT-1..15) -- called from pqc_parser.py so PQC
    findings never get mis-mapped to a VAPT control ID.

    Idempotent like map_findings_list(): every assignment is guarded by
    `if not f.<field>`, so a later generic map_findings_list() re-pass (e.g.
    parsers/__init__.py's parse_tool_file()) is a no-op for anything already
    set here -- the PQC-specific control_id survives.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_pqc_control(f)
        if not f.category:
            f.category = map_finding_to_risk_category(f)
        if not f.cia_impact:
            cia_str, is_pii = evaluate_cia_and_pii_impact(f)
            f.cia_impact = cia_str
            f.is_pii_exposed = is_pii
        if not f.remediation_actionable:
            f.remediation_actionable = get_actionable_remediation(f)
        # Enhancement B: business priority classification -- must run BEFORE
        # Enhancement A below, since compute_pqc_risk_score()'s C/I/A factors
        # are now derived from finding.business_priority (see _pqc_cia_scores).
        if not f.business_priority:
            f.business_priority = classify_business_priority(f)
        # Enhancement A: CIA + HNDL PQC risk score. Only computed for actual
        # problems (VULNERABLE/WEAK) -- a SAFE finding (e.g. AES-256) sitting
        # on a business-critical system would otherwise inherit that system's
        # high C/I/A weighting and surface a misleading "68/HIGH" risk score
        # for an algorithm that needs no remediation at all. Same reasoning
        # that already routes SAFE findings to info_findings (not actionable)
        # in pqc_parser.py. Guarded on risk_score is None for idempotency.
        if f.quantum_status in ("VULNERABLE", "WEAK") and f.risk_score is None:
            f.risk_score, f.risk_band = compute_pqc_risk_score(f)
    return findings
