import os
import math
import io
import sys
import time
import json
import uuid
import threading
from datetime import datetime, timezone
from src.db.database import (
    SessionLocal,
    User,
    AuditReport,
    EvidenceFile,
    Finding,
    ComplianceScore,
    AuditCheckpoint,
    AuditTrail,
    SystemEvent,
    force_master,
    get_all_custom_controls
)

def _safe_float(value, default=0.0):
    """Best-effort float. Parser scores arrive as float, str or None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _detect_physical_cores():
    """Physical core count, or None when it can't be determined.

    Physical rather than logical on purpose: llama.cpp gains nothing from SMT on
    this workload, so a logical count would overstate the machine's real capacity
    in the capacity message and recommend too few cores.
    """
    try:
        import psutil
        return psutil.cpu_count(logical=False) or psutil.cpu_count()
    except Exception:
        try:
            return os.cpu_count()
        except Exception:
            return None


def _count_active_sessions():
    """Concurrent audits at this moment, from Redis with an in-memory fallback."""
    try:
        from src.core.redis_metrics import get_running_session_count
        return get_running_session_count()
    except Exception:
        try:
            from src.core.bg_state import _bg_running
            return len(_bg_running)
        except Exception:
            return 1


def log_system_event(event_type, severity, details, session_id=None, actor="System"):
    """Logs an audit error/warning/event into SystemEvent for the Privacy-Safe System Log Trail.

    Default actor is "System", not a specific person -- most callers that omit
    `actor` are logging system-initiated events (LLM timeouts, malware blocks,
    port-lock failures, background thread exceptions), not a real user's
    action, so attributing them to one specific hardcoded email was both
    misleading and a minor accuracy/privacy issue in the admin log trail.
    """
    for attempt in range(3):
        try:
            with force_master():
                db = SessionLocal()
                try:
                    db.add(SystemEvent(
                        event_type=event_type,
                        severity=severity,
                        actor=actor or "System",
                        session_id=session_id or "System",
                        meta=details
                    ))
                    db.commit()
                    return
                finally:
                    db.close()
        except Exception as _e:
            if attempt == 2:
                print(f"[SYSTEM EVENT LOG ERROR] {_e}", flush=True)
            time.sleep(0.15)
from src.core.controls_data import USE_CASES
from src.core.control_keywords import CONTROL_KEYWORDS
from src.core.input_guardrail import scan_document
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags
from src.ai.audit_graph import audit_graph
from src.core.token_tracker import record_token_metrics
from src.core import redis_metrics as _rm


_CUSTOM_USE_CASES_CACHE = []
_CUSTOM_UC_CACHE_TS = 0
BACKEND_NAME = "Ollama"

# ── GLOBAL TOPIC → ISO CONTROL MAPPING TABLE ─────────────────────────────
TOPIC_CONTROL_MAP = {
    # ── Authentication & Identity ─────────────────────────────────────────────
    "multi-factor authentication": ["8.5", "5.17", "5.16"],
    "mfa": ["8.5", "5.17"], "otp": ["8.5", "5.17"], "2fa": ["8.5", "5.17"],
    "two-factor": ["8.5", "5.17"], "password": ["8.5", "5.17"],
    "authentication": ["8.5", "5.17", "5.15"], "authentication process": ["8.5", "5.17"],
    "authentication information": ["5.17"], "identity management": ["5.16", "5.15"],
    "iam": ["5.16", "5.15", "8.2", "5.18"], "idam": ["5.16", "5.15", "8.2", "5.18"],
    "single sign-on": ["8.5", "5.16"], "sso": ["8.5", "5.16"],
    "user provisioning": ["5.16", "5.18"], "account lifecycle": ["5.16", "5.18"],
    "joiner leaver": ["5.16", "5.18", "6.5"],

    # ── Privileged Access / PAM ───────────────────────────────────────────────
    "privileged access": ["8.2", "5.15", "5.18"], "pam": ["8.2", "5.15", "5.18"],
    "pim": ["8.2", "5.15"], "admin access": ["8.2", "5.18"],
    "root access": ["8.2", "5.18"], "role based access": ["5.15", "5.18", "8.2"],
    "rbac": ["5.15", "5.18"], "access rights": ["5.18", "5.15"],
    "access control": ["5.15", "5.18", "8.3"], "access management": ["5.15", "5.18"],
    "least privilege": ["5.18", "8.3"], "need to know": ["5.18", "8.3"],
    "access restriction": ["8.3", "5.18"],

    # ── Monitoring & Logging ──────────────────────────────────────────────────
    # NOTE: 7.4 (Physical Security Monitoring / CCTV) and 5.22 (Monitoring of SUPPLIER
    # Services specifically) were previously attached to every "monitoring" keyword here
    # just because their control names contain the word "monitoring" -- neither has
    # anything to do with system/cloud/log monitoring. Removed; 8.16 (Monitoring
    # Activities) is the correct general-purpose match for this keyword family.
    "monitoring": ["8.16"], "cloudwatch": ["8.16"],
    "aws cloudwatch": ["8.16", "5.23"], "cloud monitoring": ["8.16", "5.23"],
    "siem": ["8.16", "8.15"], "alerting": ["8.16", "5.25"],
    "logging": ["8.15", "8.16", "5.28"], "log management": ["8.15", "5.28"],
    "log archival": ["8.15", "5.28"], "log archive": ["8.15", "5.28"],
    "archived log": ["8.15", "5.28"], "audit log": ["8.15", "5.28"],
    "prod log": ["8.15", "5.28"], "syslog": ["8.15"], "event logs": ["8.15"],
    "log retention": ["8.15", "5.33"],
    "collection of evidence": ["5.28"], "evidence collection": ["5.28"],

    # ── NTP / Clock ───────────────────────────────────────────────────────────
    "ntp": ["8.17"], "ntp server": ["8.17"], "clock synchronization": ["8.17"],
    "clock sync": ["8.17"], "ntp clock sync": ["8.17"],
    "time sync": ["8.17"], "time server": ["8.17"], "timestamp": ["8.17"],

    # ── Cloud Services ────────────────────────────────────────────────────────
    "cloud": ["5.23", "8.16"], "aws": ["5.23", "8.16"], "azure": ["5.23"], "gcp": ["5.23"],
    "cloud services": ["5.23"], "cloud security": ["5.23"],
    "saas": ["5.23"], "iaas": ["5.23"], "paas": ["5.23"],

    # ── Network Security ──────────────────────────────────────────────────────
    "network security": ["8.20", "8.21", "8.22"], "firewall": ["8.20", "VAPT-13"],
    "network segmentation": ["8.22", "VAPT-13"], "vlan": ["8.22"],
    "dmz": ["8.22"], "micro segmentation": ["8.22"],
    "vpn": ["6.7", "8.20"], "remote working": ["6.7"], "remote access": ["6.7", "8.20"],
    "network services": ["8.21"], "api gateway": ["8.21"],
    "web filtering": ["8.23"], "url filtering": ["8.23"], "proxy": ["8.23"],
    "content filter": ["8.23"], "internet filtering": ["8.23"],

    # ── Vulnerability & Patch ─────────────────────────────────────────────────
    "vulnerability": ["8.8", "VAPT-11"], "patch": ["VAPT-12", "8.8"],
    "patch management": ["VAPT-12", "8.8"], "vulnerability scan": ["8.8", "VAPT-3"],
    "penetration test": ["VAPT-5", "VAPT-6", "8.29"],
    "pentest": ["VAPT-5", "VAPT-6"], "vapt": ["VAPT-5", "VAPT-6", "8.29"],

    # ── Operations & Procedures ───────────────────────────────────────────────
    "operating procedures": ["5.37"], "documented procedures": ["5.37"],
    "sop": ["5.37"], "operational procedure": ["5.37"],
    "standard operating procedure": ["5.37"],

    # ── Policy & Governance ───────────────────────────────────────────────────
    "information security policy": ["5.1"], "isms policy": ["5.1"],
    "security policy": ["5.1"], "iprotect": ["5.1"], "isms": ["5.1"],
    "roles and responsibilities": ["5.2"], "isms roles": ["5.2"],
    "security roles": ["5.2"], "responsibility assignment": ["5.2"],
    "segregation of duties": ["5.3"], "separation of duties": ["5.3"],
    "dual control": ["5.3"], "four eyes principle": ["5.3"],
    "management commitment": ["5.4"], "management responsibilities": ["5.4"],
    "senior management": ["5.4"], "executive sponsor": ["5.4"],
    "contact with authorities": ["5.5"], "law enforcement": ["5.5"],
    "regulatory body": ["5.5"], "government contact": ["5.5"],
    "special interest group": ["5.6"], "isac": ["5.6"], "industry group": ["5.6"],
    "security forum": ["5.6"],

    # ── Threat Intelligence ───────────────────────────────────────────────────
    "threat intelligence": ["5.7"], "threat feed": ["5.7"], "cti": ["5.7"],
    "threat data": ["5.7"], "ioc": ["5.7"], "indicators of compromise": ["5.7"],

    # ── Project & SDLC Governance ─────────────────────────────────────────────
    "project security": ["5.8"], "sdlc governance": ["5.8"], "project risk": ["5.8"],
    "security in projects": ["5.8"], "project management": ["5.8"],

    # ── Asset Management ──────────────────────────────────────────────────────
    "asset inventory": ["5.9"], "asset register": ["5.9"], "asset management": ["5.9"],
    "acceptable use": ["5.10"], "aup": ["5.10"], "usage policy": ["5.10"],
    "return of assets": ["5.11"], "asset return": ["5.11"], "equipment return": ["5.11"],
    "data classification": ["5.12"], "information classification": ["5.12"],
    "classification scheme": ["5.12"], "sensitivity label": ["5.12"],
    "data labelling": ["5.13"], "information labelling": ["5.13"], "document marking": ["5.13"],
    "information transfer": ["5.14"], "data transfer": ["5.14"],
    "file transfer": ["5.14"], "email security": ["5.14"], "secure ftp": ["5.14"], "sftp protocol": ["5.14"],

    # ── Supplier / Third Party ────────────────────────────────────────────────
    "supplier": ["5.19", "5.21", "5.22"], "vendor": ["5.19", "5.21", "5.22"],
    "third party": ["5.19", "5.22"], "supplier security": ["5.19", "5.21", "5.22"],
    "supplier relationship": ["5.19"], "vendor relationship": ["5.19"],
    "supplier agreement": ["5.20"], "vendor contract": ["5.20"],
    "third party contract": ["5.20"], "outsourcing agreement": ["5.20"],
    "ict supply chain": ["5.21"], "supply chain security": ["5.21"],
    "supply chain risk": ["5.21"], "hardware supply": ["5.21"],
    "supplier monitoring": ["5.22"], "vendor monitoring": ["5.22"],
    "third party review": ["5.22"], "supplier audit": ["5.22"],

    # ── Incident Management ───────────────────────────────────────────────────
    "incident": ["5.24", "5.25", "5.26"], "incident response": ["5.24", "5.25"],
    "security incident": ["5.24"], "incident management": ["5.24", "5.25"],
    "incident assessment": ["5.25"], "incident triage": ["5.25"],
    "event decision": ["5.25"], "incident classification": ["5.25"],
    "incident handling": ["5.26"], "containment": ["5.26"], "eradication": ["5.26"],
    "recovery response": ["5.26"],
    "lessons learned": ["5.27"], "post incident review": ["5.27"],
    "learning from incidents": ["5.27"], "incident debrief": ["5.27"],
    "forensic": ["5.28"], "digital forensic": ["5.28"],
    "chain of custody": ["5.28"], "evidence forensic": ["5.28"],

    # ── Business Continuity ───────────────────────────────────────────────────
    "business continuity": ["5.29", "5.30"], "bcp": ["5.29", "5.30"],
    "disaster recovery": ["5.29", "5.30"], "dr": ["5.29", "5.30"],
    "ict continuity": ["5.30"], "ict readiness": ["5.30"], "it continuity": ["5.30"],
    "backup": ["8.13"], "data backup": ["8.13"], "backup policy": ["8.13"],
    "system redundancy": ["8.14"], "failover mechanism": ["8.14"], "high availability setup": ["8.14"],

    # ── Compliance & Legal ────────────────────────────────────────────────────
    "legal requirement": ["5.31"], "statutory requirement": ["5.31"],
    "regulatory requirement": ["5.31"], "contractual requirement": ["5.31"],
    "compliance obligation": ["5.31"], "regulatory": ["5.31"],
    "intellectual property": ["5.32"], "copyright": ["5.32"],
    "software license": ["5.32"], "license management": ["5.32"], "ip rights": ["5.32"],
    "log retention policy": ["5.33"], "records retention": ["5.33"], "record management": ["5.33"],
    "gdpr": ["5.34"], "pii": ["5.34"], "personal data": ["5.34"],
    "privacy": ["5.34"], "data privacy": ["5.34"],
    "independent review": ["5.35"], "internal audit": ["5.35"], "isms review": ["5.35"],
    "external audit": ["5.35"],
    "compliance check": ["5.36"], "policy compliance": ["5.36"],
    "compliance review": ["5.36"], "standards compliance": ["5.36"],
    # ── HR & Personnel ────────────────────────────────────────────────────────
    # FIXED: was mapped to 5.1 (wrong); screening/onboarding are 6.1 people controls
    "background check": ["6.1"], "screening": ["6.1"], "pre-employment": ["6.1"],
    "onboarding": ["6.1"], "hr security": ["6.1"],
    "employment terms": ["6.2"], "terms of employment": ["6.2"],
    "employment contract": ["6.2"], "offer letter": ["6.2"],
    "security awareness": ["6.3"], "awareness training": ["6.3"],
    "staff training": ["6.3"], "phishing awareness": ["6.3"], "e-learning": ["6.3"],
    "disciplinary": ["6.4"], "misconduct": ["6.4"], "policy violation": ["6.4"],
    "termination": ["6.5"], "offboarding": ["6.5"], "exit process": ["6.5"],
    "leaver": ["6.5"], "resignation": ["6.5"], "dismissal": ["6.5"],
    "nda": ["6.6"], "non-disclosure": ["6.6"], "confidentiality agreement": ["6.6"],
    "remote work": ["6.7"], "work from home": ["6.7"], "wfh": ["6.7"],
    "telework": ["6.7"], "home working": ["6.7"], "vpn policy": ["6.7"],
    "security event reporting": ["6.8"], "event reporting": ["6.8"],
    "how to report": ["6.8"], "staff reporting": ["6.8"],

    # ── Physical Security ─────────────────────────────────────────────────────
    "physical security": ["7.1", "7.2", "7.4"], "visitor": ["7.2"],
    "visitor log": ["7.2"], "cctv": ["7.4"], "badge": ["7.2"],
    "physical access": ["7.1", "7.2"],
    "physical entry": ["7.2"], "entry control": ["7.2"],
    "door access": ["7.2"], "turnstile": ["7.2"],
    "secure office": ["7.3"], "secure room": ["7.3"], "server room": ["7.3"],
    "data center access": ["7.3"],
    "physical monitoring": ["7.4"], "camera surveillance": ["7.4"],
    "security camera": ["7.4"], "video surveillance": ["7.4"],
    "environmental threat": ["7.5"], "flood protection": ["7.5"], "fire protection": ["7.5"],
    "power protection": ["7.5"], "uninterruptible power": ["7.5", "7.11"],
    "secure area": ["7.6"], "restricted area": ["7.6"],
    "clean desk policy": ["7.7"], "clear screen policy": ["7.7"], "unattended workstation": ["7.7"],
    "equipment siting": ["7.8"], "rack security": ["7.8"],
    "assets off-premises": ["7.9"], "remote equipment": ["7.9"], "equipment offsite": ["7.9"],
    "storage media": ["7.10"], "removable media": ["7.10"], "usb": ["7.10"],
    "media handling": ["7.10"], "removable storage": ["7.10"],
    "supporting utilities": ["7.11"], "power supply failure": ["7.11"], "backup generator": ["7.11"],
    "utility failure": ["7.11"],
    "cabling": ["7.12"], "cable security": ["7.12"], "network cabling": ["7.12"],
    "structured cabling": ["7.12"],
    "equipment maintenance": ["7.13"], "maintenance schedule": ["7.13"],
    "hardware maintenance": ["7.13"], "preventive maintenance": ["7.13"],
    "secure disposal": ["7.14"], "equipment disposal": ["7.14"],
    "data destruction": ["7.14"], "disk wipe": ["7.14"],
    "degauss": ["7.14"], "decommission": ["7.14"],

    # ── Endpoint & Device ─────────────────────────────────────────────────────
    "endpoint": ["8.1"], "user endpoint": ["8.1"], "laptop policy": ["8.1"],
    "mobile device": ["8.1"], "mdm": ["8.1"], "byod": ["8.1"],
    "endpoint security": ["8.1"],

    # ── Source Code ───────────────────────────────────────────────────────────
    "software development": ["8.25", "8.28"], "sdlc": ["8.25", "8.28"],
    "secure coding": ["8.28"], "code review": ["8.28"],
    "source code": ["8.4", "8.28"], "code repository": ["8.4"],
    "git access": ["8.4"], "github": ["8.4"], "gitlab": ["8.4"],

    # ── Malware & Configuration ───────────────────────────────────────────────
    "antivirus": ["8.7"], "anti-malware": ["8.7"], "edr": ["8.7"],
    "malware": ["8.7"], "av policy": ["8.7"],
    "configuration management": ["8.9"], "hardening": ["8.9"],
    "cmdb": ["8.9"], "baseline configuration": ["8.9"],

    # ── Data Management ───────────────────────────────────────────────────────
    "data deletion": ["8.10"], "information deletion": ["8.10"],
    "secure erase": ["8.10"], "data wiping": ["8.10"],
    "data masking": ["8.11"], "anonymization": ["8.11"], "pseudonymization": ["8.11"],
    "dlp": ["8.12"], "data leakage prevention": ["8.12"],
    "data loss prevention": ["8.12"], "data exfiltration": ["8.12"],

    # ── Capacity & Utilities ──────────────────────────────────────────────────
    "api security": ["8.26"], "fraud analytics": ["8.26"],
    "capacity": ["8.6"], "cpu": ["8.6"], "memory": ["8.6"],
    "disk utilization": ["8.6"],
    "privileged utility": ["8.18"], "admin tools": ["8.18"],
    "utility programs": ["8.18"], "system utilities": ["8.18"],
    "software installation": ["8.19"], "approved software": ["8.19"],
    "application whitelist": ["8.19"], "install policy": ["8.19"],

    # ── Cryptography & Key Management ─────────────────────────────────────────
    "encryption": ["8.24"], "cryptography": ["8.24"],
    "kms": ["8.24"], "ssl": ["8.24"], "tls": ["8.24"], "key management": ["8.24"],

    # ── Risk Assessment ───────────────────────────────────────────────────────
    # FIXED: was mapped to 5.12 (Classification) which is wrong; risk assessment = 5.1, 5.7
    "risk assessment": ["5.1", "5.7", "5.8"],
    "risk management": ["5.1", "5.7"], "risk": ["5.1", "5.7"],
    "risk register": ["5.1", "5.7"], "risk treatment": ["5.1", "5.7"],
    "residual risk": ["5.1", "5.7"], "risk appetite": ["5.1", "5.7"],

    # ── Secure Development ────────────────────────────────────────────────────
    "secure development": ["8.25"], "secure development lifecycle": ["8.25"],
    "application security": ["8.26"], "security requirements": ["8.26"],
    "secure architecture": ["8.27"], "security architecture": ["8.27"],
    "engineering principles": ["8.27"], "security by design": ["8.27"],
    "security testing": ["8.29"], "acceptance testing": ["8.29"],
    "outsourced development": ["8.30"], "third party development": ["8.30"],
    "separation of environments": ["8.31"], "dev test prod": ["8.31"],
    "staging environment": ["8.31"], "non-production": ["8.31"],
    "change management": ["8.32"], "change control": ["8.32"],
    "change request": ["8.32"], "change advisory board": ["8.32"], "change approval process": ["8.32"],
    "test data": ["8.33"], "test information": ["8.33"],
    "production data in test": ["8.33"], "sanitised test data": ["8.33"],
    "audit testing": ["8.34"], "audit tools": ["8.34"], "audit environment": ["8.34"],
}

def log_dev_latency(message: str):
    """Appends performance and execution log entries for developer latency tracking."""
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/audit_run_latency.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        pass

def _resolve_llm_model(model_choice):
    """Map UI model name to LLM model identifier."""
    MODEL_MAP = {
        "Gemma 4 (e4b)": "gemma4:e4b",
        "Gemma 4 (2b)": "gemma-2-2b-it",
    }
    if model_choice in MODEL_MAP:
        return MODEL_MAP[model_choice]
    if "12B" in model_choice:
        return "gemma4:12b"
    if "e4b" in model_choice or "4B" in model_choice:
        return "gemma4:e4b"
    if "Gemma" in model_choice or "9B" in model_choice or "2B" in model_choice:
        return "gemma2:9b"
    return "qwen2.5:7b"

def _load_custom_use_cases(force: bool = False) -> list:
    global _CUSTOM_USE_CASES_CACHE, _CUSTOM_UC_CACHE_TS
    now = time.time()
    if not force and (now - _CUSTOM_UC_CACHE_TS) < 60 and _CUSTOM_USE_CASES_CACHE:
        return _CUSTOM_USE_CASES_CACHE

    try:
        rows = get_all_custom_controls(active_only=True)
    except Exception:
        return []

    custom_ucs = []
    for idx, row in enumerate(rows):
        sl = 10000 + idx
        name = row["control_name"]
        cid = row["control_id"]
        desc = row["description"] or name
        cat = row["category"]
        framework = row.get("framework") or "ISO 27001"
        kws = ", ".join(row["keywords"]) if row["keywords"] else name

        custom_ucs.append({
            "sl": sl,
            # "standard" drives real backend behavior (audit_chains.py's is_vapt
            # check swaps in CVSS-style VAPT prompting/severity when this is
            # "VAPT" -- same mechanism the 15 built-in VAPT-* controls use).
            # "category" drives frontend framework-picker filtering (app.js
            # cat.includes("VAPT")/"DPDP"/"SOC"/"BCMS"/"X-BOM" checks) and is
            # already set to a matching "<Framework> Framework Controls" string
            # by api_create_control for non-ISO frameworks, so both stay in sync.
            "standard": framework,
            "category": cat,
            "label": f"{name} ({cid}) [Custom]",
            "icon": "🔧",
            "use_case": name,
            "expected": f"Evidence of compliance with {name}. {desc}",
            "format": "PDF",
            "prompt_hint": (
                f"Verify compliance against the custom control: {name} ({cid}). "
                f"Category: {cat}. "
                f"Description: {desc}. "
                f"Relevant keywords: {kws}. "
                f"Check whether the uploaded documents demonstrate that this control "
                f"has been implemented, documented, and is being followed."
            ),
            "scope_tags": [cat],
            "severity": "MEDIUM",
            "finding": f"No documented evidence found for custom control {cid} ({name}).",
            "recommendation": (
                f"Establish, document, and implement procedures to satisfy "
                f"the custom control {cid} ({name})."
            ),
            "_is_custom": True,
            # Raw curated keywords (structured, not just flattened into prompt_hint text
            # above) so _build_controls_for_audit() can turn them into real retrieval
            # scoring weights instead of leaving retrieval.py's keyword scorer blind to them.
            "keywords": row["keywords"] or [],
        })

    _CUSTOM_USE_CASES_CACHE = custom_ucs
    _CUSTOM_UC_CACHE_TS = now
    return custom_ucs

def _get_expected_evidence(uc, custom_evidence=None):
    if custom_evidence is not None:
        return custom_evidence.get(uc["use_case"], uc["expected"])
    return uc["expected"]

def _build_controls_for_audit(selected_sls=None, custom_evidence=None):
    if custom_evidence is not None and isinstance(custom_evidence, dict) and "excel_items" in custom_evidence:
        excel_items = custom_evidence["excel_items"]
        if excel_items and isinstance(excel_items, list):
            controls = []
            for item in excel_items:
                ctrl_id = item.get("control_id", "UNKNOWN")
                # control_label is the official ISO name resolved by excel_scoping_parser
                # (e.g. "5.15 Access Control"), not the raw checklist question. Without it,
                # "control" ends up as just "5.15 — <question text>", and the UI's header
                # renderer strips everything after " — " assuming what's left is a real
                # name — leaving a bare "5.15" with no control name shown at all.
                ctrl_full_label = item.get("control_label") or ctrl_id
                q_text = item.get("requirement_question") or item.get("question") or ctrl_full_label
                q_source = item.get("requirement_question_source") or ("excel" if item.get("requirement_question") else "framework")
                q_status = item.get("requirement_question_status") or ("RESOLVED" if q_text else "UNRESOLVED")
                files = item.get("files") or item.get("raw_file_refs") or []
                files_str = ", ".join(files) if isinstance(files, list) else str(files)
                primary_file = files[0] if (files and isinstance(files, list) and len(files) > 0) else files_str

                # Role-split file lists, when the sheet has separately named
                # Policy/Evidence columns (both empty for a generic "File name"
                # column) -- carried through so the LLM can be told which locked
                # file(s) the auditor intended as policy proof vs evidence proof,
                # instead of re-deriving the split blind from undifferentiated text.
                policy_files = item.get("policy_files") or []
                evidence_files = item.get("evidence_files") or []

                controls.append({
                    "control": f"{ctrl_full_label} — {q_text}",
                    "control_id": ctrl_full_label,
                    "label": f"{ctrl_full_label} — {q_text}",
                    "requirement_question": q_text,
                    "requirement_question_source": q_source,
                    "requirement_question_status": q_status,
                    "row_index": item.get("row_index"),
                    "expected": item.get("expected_evidence") or q_text,
                    "prompt_hint": item.get("prompt_hint") or f"Evaluate evidence for: {q_text}",
                    "severity": item.get("severity", "MEDIUM"),
                    "standard": "ISO 27001",
                    "recommendation": f"Establish, document, and implement procedures to satisfy {ctrl_full_label}.",
                    "evidence_location": primary_file,
                    "evidence_source_file": primary_file,
                    # Full file list for THIS row (not just the first one) — used by the
                    # scoping block below to lock retrieval to every file actually listed
                    # against this row, not only file[0], when a single row names multiple.
                    "evidence_source_files_all": files_str,
                    "policy_source_files_all": ", ".join(policy_files) if policy_files else "",
                    "evidence_only_source_files_all": ", ".join(evidence_files) if evidence_files else "",
                })
            return controls

    all_ucs = list(USE_CASES) + _load_custom_use_cases()
    controls = []
    seen_controls = set()
    for uc in all_ucs:
        ctrl_id = uc["use_case"]
        if ctrl_id in seen_controls:
            continue
        if selected_sls is None or uc["sl"] in selected_sls:
            seen_controls.add(ctrl_id)
            # Custom controls carry real auditor-curated keywords (weighted highest, 2.5,
            # since a human picked them) via _load_custom_use_cases(); standard controls
            # use the deterministically pre-generated CONTROL_KEYWORDS lookup. Either way,
            # retrieval.py's keyword scorer previously always fell back to empty here.
            if uc.get("_is_custom") and uc.get("keywords"):
                kw_weights = {kw: 2.5 for kw in uc["keywords"]}
            else:
                kw_weights = CONTROL_KEYWORDS.get(ctrl_id, {})
            controls.append({
                "control": ctrl_id,
                "label": uc["label"],
                "expected": _get_expected_evidence(uc, custom_evidence),
                "prompt_hint": uc["prompt_hint"],
                "severity": uc.get("severity", "MEDIUM"),
                "standard": uc.get("standard", ""),
                "recommendation": uc.get("recommendation", ""),
                "keywords": kw_weights,
            })
    return controls


def get_num_ctx(model_name: str) -> int:
    """Per-request context, read from the running server rather than guessed.

    This used to be a hardcoded table whose e4b branch returned 32768, with the
    comment "server runs -c 32768 -> full 32k context available per request".
    That comment was wrong: llama.cpp divides -c evenly across -np slots, so the
    real per-request figure is -c/-np. On a customer box running 8 slots it was
    4096, not 32768 -- and because retrieval.py already sized prompts against
    the true value via get_real_num_ctx(), the two halves of the same pipeline
    disagreed by 8x. Ask the server; it knows, and it is the same source
    audit_chains.py::get_num_ctx already uses.
    """
    try:
        from src.core.llm_client import get_real_num_ctx
        return get_real_num_ctx()
    except Exception as e:
        # This used to be a pure lookup table that could not fail. It now asks
        # the server, so keep a floor: a context-summary call is not worth
        # aborting an audit over.
        print(f"[LLM CTX] get_num_ctx fell back to 4096 for {model_name!r}: {e}", flush=True)
        return 4096

def _generate_context_summary(context, llm_model):
    """Generates a brief document scope summary using the configured LLM backend.
    Routes through query_llm() so it correctly uses llama.cpp or Ollama.
    Hard timeout of 15s — skips gracefully if LLM is unresponsive."""
    import re
    files = re.split(r'--- FILE: (.*?) ---', context)
    sample_text = ""
    if len(files) > 1:
        for idx in range(1, len(files), 2):
            fname = files[idx]
            fcontent = files[idx+1] if idx+1 < len(files) else ""
            sample_text += f"FILE: {fname}\n{fcontent.strip()[:1000]}\n\n"
    else:
        sample_text = context[:8000]

    sample_text = sample_text[:8000]   # Keep prompt short for fast response

    summary_prompt = f"""You are a forensic compliance auditor assistant.
Analyze the following document beginning text and extract its overall scope:
1. What is the main purpose of this document?
2. What are the key topics it covers?
3. What does it explicitly state it does NOT cover (exclusions)?

Keep your response brief, under 150 words.

--- START DOCUMENT TEXT ---
{sample_text}
--- END DOCUMENT TEXT ---

Output:"""

    try:
        from src.core.llm_client import query_llm
        # Use query_llm which correctly routes to llama.cpp or Ollama
        summary = query_llm(
            prompt=summary_prompt,
            model=llm_model,
            num_ctx=get_num_ctx(llm_model),
            temperature=0.0,
            timeout=1800   # 1800s (30 mins) timeout for 3-pass LLM reasoning, OCR, and multi-user queueing



        )
        return summary if summary.strip() else "Document scope summary unavailable."
    except Exception as e:
        print(f"[CONTEXT SUMMARY] Skipped (LLM unavailable or timeout): {e}", flush=True)
        return "Document scope summary unavailable (LLM not ready)."

def _checkpoint_create(session_id, bg_key, ai_model, selected_sls, file_names, context_str, total_controls, batch_size):
    with force_master():
        db = SessionLocal()
        try:
            # Only discard checkpoints for THIS session — other sessions' checkpoints stay intact
            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).update({AuditCheckpoint.status: "discarded"}, synchronize_session=False)

            db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id
            ).delete(synchronize_session=False)

            chk = AuditCheckpoint(
                session_id=session_id,
                bg_key=bg_key,
                ai_model=ai_model,
                selected_sls_json=json.dumps(list(selected_sls)),
                file_names_json=json.dumps(file_names),
                context_text=context_str,
                total_controls=total_controls,
                completed_batches=0,
                batch_size=batch_size,
                partial_results_json="[]",
                status="in_progress",
            )
            db.add(chk)
            db.commit()
            chk_id = chk.id
            return chk_id
        except Exception as e:
            print(f"[checkpoint] Failed to create checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def _checkpoint_update(session_id, completed_batches, all_results_so_far):
    """Legacy batch-level checkpoint update — kept for compatibility."""
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "paused"])
            ).first()
            if chk:
                chk.completed_batches = completed_batches
                chk.partial_results_json = json.dumps(all_results_so_far)
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to update checkpoint: {e}", flush=True)
        finally:
            db.close()

def _checkpoint_update_per_control(session_id, control_id, all_results_so_far):
    """
    Per-control granular checkpoint.
    Called after EVERY single control is evaluated (~3ms overhead).
    Saves:
      - completed_controls: integer count
      - completed_control_ids_json: JSON list of control IDs already done
      - partial_results_json: full results so far (for resume)
    On resume, any control whose ID is in completed_control_ids_json is SKIPPED.
    """
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "paused"])
            ).first()
            if chk:
                # Parse existing completed IDs and add new one
                try:
                    done_ids = json.loads(chk.completed_control_ids_json or "[]")
                except Exception:
                    done_ids = []
                if control_id and control_id not in done_ids:
                    done_ids.append(control_id)
                chk.completed_controls = len(done_ids)
                chk.completed_control_ids_json = json.dumps(done_ids)
                chk.partial_results_json = json.dumps(all_results_so_far)
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
                print(
                    f"[CHECKPOINT] Control '{control_id}' saved "
                    f"({len(done_ids)}/{chk.total_controls} done)",
                    flush=True
                )
        except Exception as e:
            print(f"[checkpoint] Per-control update failed for '{control_id}': {e}", flush=True)
        finally:
            db.close()


def _checkpoint_finish(session_id, status="completed"):
    with force_master():
        db = SessionLocal()
        try:
            chk = db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).first()
            if chk:
                chk.status = status
                chk.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            print(f"[checkpoint] Failed to finish checkpoint: {e}", flush=True)
        finally:
            db.close()

def get_resumable_checkpoint(session_id):
    # force_master() for read-after-write consistency -- this is checked right after
    # a checkpoint write (crash detection on restart), and without pinning to master
    # a lagging replica read could report "nothing to resume" even though the
    # checkpoint was just committed, defeating the one scenario this exists for.
    with force_master():
        db = SessionLocal()
        try:
            return db.query(AuditCheckpoint).filter(
                AuditCheckpoint.session_id == session_id,
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).order_by(AuditCheckpoint.created_at.desc()).first()
        except Exception as e:
            print(f"[checkpoint] Failed to get checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def get_global_resumable_checkpoint():
    with force_master():
        db = SessionLocal()
        try:
            return db.query(AuditCheckpoint).filter(
                AuditCheckpoint.status.in_(["in_progress", "failed", "paused", "interrupted"])
            ).order_by(AuditCheckpoint.created_at.desc()).first()
        except Exception as e:
            print(f"[checkpoint] Failed to get global checkpoint: {e}", flush=True)
            return None
        finally:
            db.close()

def generate_ollama_findings(context, file_names_list, selected_sls, model_choice, bg_key=None, batch_size=None, checkpoint_session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None, already_done_ids=None, username=None):
    os.environ["RAG_RERANK_MODE"] = "quick" if "quick" in str(audit_mode).lower() else "deep"
    llm_model = _resolve_llm_model(model_choice)
    controls = _build_controls_for_audit(selected_sls, custom_evidence)
    scanned_files_str = ", ".join(file_names_list) if file_names_list else "None"

    # Resolved once and threaded into every control's graph state below, so
    # retrieval can scope document_chunks reads/writes to THIS session's own
    # report_id -- without it, two sessions uploading identically-named files
    # collide in the shared, session-agnostic document_chunks table (see
    # save_document_chunks / _vec_native_search).
    report_id_for_retrieval = None
    if checkpoint_session_id:
        try:
            with force_master():
                _rid_session = SessionLocal()
                _rid_report = _rid_session.query(AuditReport).filter(
                    AuditReport.session_id == checkpoint_session_id
                ).first()
                report_id_for_retrieval = _rid_report.id if _rid_report else None
                _rid_session.close()
        except Exception as _rid_err:
            print(f"[REPORT ID RESOLVE] Failed to resolve report_id for {checkpoint_session_id}: {_rid_err}", flush=True)

    # ── On RESUME: restore already-completed results from checkpoint and skip those controls ──
    _already_done_set = set(already_done_ids or [])
    if _already_done_set:
        print(
            f"[RESUME] Skipping {len(_already_done_set)} already-completed controls: {sorted(_already_done_set)}",
            flush=True
        )

    # ── SCOPING MODE DETERMINATION & ISOLATION ─────────────────────────────
    # Mode 1: EXCEL UPLOAD SCOPE (custom_evidence provided from uploaded Excel checklist)
    # Mode 2: CUSTOM / MANUAL SCOPE (user manually selected specific subset of controls < 30)
    # Mode 3: AI AUTO-SCOPING (full control pool scan; runs Evidence-First topic pre-filter)
    is_excel_scope = custom_evidence is not None
    is_manual_scope = (selected_sls is not None and len(selected_sls) < 30)

    is_auto_scoping = (not is_excel_scope) and (not is_manual_scope) and (
        "auto" in str(audit_mode).lower() or 
        "scope" in str(audit_mode).lower() or 
        selected_sls is None or 
        len(controls) >= 30
    )

    filtered_controls = []
    out_of_scope_results = []

    if is_auto_scoping:
        import re
        from src.core.llm_client import query_llm

        def _extract_topics_llm(file_names_list, context_text):
            """Extract security topics from evidence using LLM (file names + per-file snippets)."""
            file_summaries = []
            chunks = context_text.split("\n\n") if context_text else []
            fnames = file_names_list or []
            for i, fname in enumerate(fnames):
                snippet = (chunks[i][:300] if i < len(chunks) else "").replace("\n", " ").strip()
                file_summaries.append(f"FILE: {fname}\nCONTENT: {snippet}")
            files_block = "\n\n".join(file_summaries) if file_summaries else context_text[:2000]

            prompt = f"""You are a security auditor assistant. Below are evidence files for an ISO 27001 audit.
Extract the specific security topics these files cover.
Rules:
- Return ONLY a JSON array of short topic strings (1-4 words each)
- Cover ALL files listed
- Focus on: authentication, access control, logging, NTP/clock, cloud, backup, encryption, fraud, monitoring
- Maximum 20 topics, no duplicates
- No explanation, just the JSON array

Evidence Files:
{files_block}

Return format: ["topic1", "topic2", ...]"""

            try:
                response = query_llm(
                    prompt, model=llm_model, num_ctx=4096, temperature=0.0, timeout=1800,


                    stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"]
                )
                if not response:
                    return []
                match = re.search(r'\[.*?\]', response, re.DOTALL)
                if match:
                    topics = __import__("json").loads(match.group())
                    return [t.lower().strip() for t in topics if isinstance(t, str)]
                lines = [l.strip().strip('"\'').strip('-').strip() for l in response.splitlines() if l.strip()]
                return [l.lower() for l in lines if 2 < len(l) < 60 and not l.startswith('{')]
            except Exception as e:
                print(f"[AI AUTO-SCOPE] LLM topic extraction failed: {e}", flush=True)
                return []

        def _ctrl_prefix(ctrl_str):
            parts = ctrl_str.strip().split()
            return parts[0] if parts else ctrl_str

        print(f"[AI AUTO-SCOPE] Starting Evidence-First scoping for {len(controls)} controls...", flush=True)
        topics = _extract_topics_llm(file_names_list, context or "")

        if topics:
            print(f"[AI AUTO-SCOPE] LLM extracted topics: {topics}", flush=True)
            matched_ids = set()
            for topic in topics:
                for key, ctrl_ids in TOPIC_CONTROL_MAP.items():
                    if key in topic or topic in key:
                        matched_ids.update(ctrl_ids)

            for c in controls:
                prefix = _ctrl_prefix(c["control"])
                if prefix in matched_ids:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": 0, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"AI Evidence-First Scoping: topics {topics} did not match this control.",
                        "source_files": scanned_files_str,
                    })
            print(f"[AI AUTO-SCOPE] Evidence-First filtered {len(controls)} -> {len(filtered_controls)} controls.", flush=True)

            if not filtered_controls:
                print(f"[AI AUTO-SCOPE] WARNING: 0 controls matched map. Running keyword fallback.", flush=True)
                stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
                full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
                out_of_scope_results = []
                for c in controls:
                    combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                    phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                    phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                    single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                    score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                    if score >= 3:
                        filtered_controls.append(c)
                    else:
                        out_of_scope_results.append({
                            "control_id": c["control"], "control": c["label"],
                            "relevance_score": score, "evidence_found": "Not Relevant",
                            "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                            "finding": "Control does not apply to this document scope",
                            "recommendation": "",
                            "reasoning": f"Safety net keyword fallback: score {score} < 3.",
                            "source_files": scanned_files_str,
                        })
                print(f"[AI AUTO-SCOPE] Safety net keyword: {len(filtered_controls)} controls matched.", flush=True)
        else:
            print(f"[AI AUTO-SCOPE] LLM unavailable — using keyword fallback.", flush=True)
            import re
            stopwords = {"whether","is","are","the","and","for","with","available","enabled","done","used","audit","evidence","check","system","information","security","management","policies","policy","shall","should","must","will","has","have","been","that","this","also","from","into","their","which","data","user","users","access","control","controls","process","processes","document","documents","record","records","activity","activities","include","including","ensure","required","requirement","requirements","related","relevant","review","reviews","update","updates","implement","implementation","define","defined","maintain","maintained","establish","established","appropriate","effective","internal","external","based","provide","provided","all","each","other","any","not","only","such","may","its","use","organization","asset","assets","risk","risks","measure","measures","protect","protection"}
            full_text = (str(context or "") + " " + " ".join(file_names_list or [])).lower()
            for c in controls:
                combined = (c.get("label","") + " " + c.get("expected","") + " " + c.get("prompt_hint","")).lower()
                phrases = re.findall(r'\b[a-z]{5,}(?:\s+[a-z]{4,}){1,3}\b', combined)
                phrases = [p for p in phrases if not any(w in stopwords for w in p.split())]
                single_kw = [w for w in set(re.findall(r'\b[a-z]{7,}\b', combined)) if w not in stopwords]
                score = sum(3 for p in phrases if p in full_text) + sum(1 for w in single_kw if w in full_text)
                if score >= 5:
                    filtered_controls.append(c)
                else:
                    out_of_scope_results.append({
                        "control_id": c["control"], "control": c["label"],
                        "relevance_score": score, "evidence_found": "Not Relevant",
                        "evidence_snippet": "", "status": "Out of Scope", "severity": "N/A",
                        "finding": "Control does not apply to this document scope",
                        "recommendation": "",
                        "reasoning": f"Keyword fallback: score {score} below threshold 5.",
                        "source_files": scanned_files_str,
                    })

        if filtered_controls:
            print(f"[AI AUTO-SCOPE] Final: {len(filtered_controls)} controls will be audited by LLM.", flush=True)
            controls = filtered_controls
            all_results = out_of_scope_results
        else:
            print(f"[AI AUTO-SCOPE] ULTIMATE SAFETY NET: All filters returned 0 — auditing ALL {len(controls)} controls.", flush=True)
            all_results = []
    else:
        print(f"[MANUAL/EXCEL SCOPE] Auditing all {len(controls)} controls selected by user/Excel checklist without auto-scoping pre-filter.", flush=True)
        all_results = []





    if not controls:
        all_results = []
        for uc in USE_CASES:
            all_results.append({
                "control_id": uc["use_case"],
                "control": uc["label"],
                "relevance_score": 0,
                "evidence_found": "Not Relevant",
                "evidence_snippet": "",
                "status": "Out of Scope",
                "severity": "N/A",
                "finding": "Control does not apply to this document type",
                "recommendation": "",
                "reasoning": "Control is out of scope for the detected document type.",
                "source_files": scanned_files_str,
            })
        return [], all_results

    # NOTE: all_results was already seeded above (out_of_scope_results from
    # AI Auto-Scoping, or [] for manual/Excel scope) -- do NOT reset it here.
    # A bare `all_results = []` used to sit at this exact spot and silently
    # discarded every "Out of Scope" finding the evidence-first pre-filter
    # had just computed, so they never reached the final report/checkpoint.
    # ── RESUME: restore already-completed results from the checkpoint ─────────
    # Without this, resuming correctly SKIPS re-running already-done controls
    # (see _already_done_set below) but their prior results were never re-added
    # to all_results, so the final saved report only ever contained controls
    # processed after the resume point -- the pre-crash work vanished from the
    # output even though it was never actually lost from the checkpoint itself.
    if already_done_ids and checkpoint_session_id:
        try:
            with force_master():
                _resume_session = SessionLocal()
                _resume_chk = (
                    _resume_session.query(AuditCheckpoint)
                    .filter(AuditCheckpoint.session_id == checkpoint_session_id)
                    .order_by(AuditCheckpoint.created_at.desc())
                    .first()
                )
                _resume_session.close()
            if _resume_chk and _resume_chk.partial_results_json:
                restored = json.loads(_resume_chk.partial_results_json)
                if isinstance(restored, list):
                    all_results = restored
                    print(
                        f"[RESUME] Restored {len(all_results)} already-completed result(s) "
                        f"from checkpoint for session {checkpoint_session_id}.",
                        flush=True
                    )
        except Exception as e:
            print(f"[RESUME] Failed to restore partial results from checkpoint: {e}", flush=True)
    total = len(controls)
    overall_start_time = time.time()
    _audit_real_prompt_toks = 0
    _audit_real_comp_toks = 0

    # ── Busy-system notice (warning only, never blocks) ────────────────────────
    # Measured directly: 2 concurrent audits on a 12-core machine ran ~1.7-2x
    # slower each (still genuinely parallel, not queued -- see
    # qa/checkpointing/test_concurrent_sessions.py). At 2+ already running,
    # tell the auditor to expect a slower run instead of leaving them guessing
    # why it's taking longer than usual.
    try:
        from src.core.redis_metrics import get_running_session_count
        _running_now = get_running_session_count()
    except Exception:
        _running_now = 0
    # _running_now includes this audit itself (session_start() already ran for
    # it before this point), so "other" audits = _running_now - 1.
    _other_running = max(0, _running_now - 1)
    _busy_warning = (
        f"⚠️ System is busy — {_other_running} other audit(s) running, this may take longer than usual."
        if _other_running >= 1 else None
    )

    msg = f"[AUDIT START] Starting LangGraph ISO 27001 Audit for {total} controls (Model: {model_choice}, Mode: {audit_mode})"
    print(f"\n[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    log_dev_latency(msg)

    # Generate context summary
    summary_text = _generate_context_summary(context, llm_model)

    # ── Universal Pre-Ingest for Top 6 RAG Vector Retrieval across ALL Scoping Modes (Manual, AI Auto-Scoping, Excel) ──
    if file_registry:
        for fname, ftext in file_registry.items():
            if fname and ftext:
                try:
                    save_document_chunks(fname, ftext, report_id=report_id_for_retrieval)
                except Exception as _e_ingest:
                    print(f"[RAG INGEST WARNING] Pre-ingest for '{fname}' failed: {_e_ingest}", flush=True)

    was_resource_paused = False

    for idx, c in enumerate(controls):
        # ── STOP FLAG CHECK ─────────────────────────────────────────────
        if _bg_stop_flags.get(bg_key) or (checkpoint_session_id and _bg_stop_flags.get(checkpoint_session_id)):

            print(f"[AUDIT STOPPED] User requested stop at control {idx + 1}/{total}. Exiting early.", flush=True)
            break
        # ────────────────────────────────────────────────────────────────


        # ── RESOURCE GUARD: stop gracefully (not crash) if RAM gets critical ──
        # Checked every control, not just at audit start — a long-running audit
        # can outlive the memory conditions it started under (other processes,
        # other concurrent audits). Already-completed controls stay checkpointed;
        # the rest can be resumed later via the existing resume-checkpoint path.
        from src.core.resource_guard import check_memory_pressure
        _mem = check_memory_pressure()
        if _mem["status"] == "CRITICAL":
            print(f"[RESOURCE GUARD] CRITICAL memory pressure at control {idx + 1}/{total}: {_mem['reason']} Stopping audit gracefully.", flush=True)
            was_resource_paused = True
            if bg_key:
                with _bg_lock:
                    _bg_store["progress"][bg_key] = {
                        "text": f"Paused: system resources critically low ({_mem['available_gb']}GB RAM available). "
                                f"Completed {idx}/{total} controls — resume once resources free up.",
                        "percent": int((idx / total) * 100),
                        "resource_status": "CRITICAL",
                    }
            break
        # ────────────────────────────────────────────────────────────────

        # ── PER-CONTROL RESUME: skip controls already saved in checkpoint ─
        _ctrl_id_str = c.get("control", "")
        if _ctrl_id_str in _already_done_set:
            print(
                f"[RESUME SKIP] Control {idx + 1}/{total}: '{_ctrl_id_str}' already completed — skipping.",
                flush=True
            )
            # Update progress bar so UI shows correct % even for skipped controls
            if bg_key:
                pct = int(((idx + 1) / total) * 100)
                with _bg_lock:
                    _bg_store["progress"][bg_key] = {
                        "text": f"Resuming: {idx + 1}/{total} controls (skipping already done)...",
                        "percent": pct
                    }
            continue
        # ─────────────────────────────────────────────────────────────────

        control_start_time = time.time()
        c_label = c.get("label") or c.get("control")
        start_msg = f"-> Running Control {idx + 1}/{total}: {c['control']} ({c_label})"
        print(f"[{time.strftime('%H:%M:%S')}]   {start_msg}", flush=True)
        log_dev_latency(f"[{idx + 1}/{total}] {start_msg}")


        # ── Upstream 4-Tier Scoping Priority ──────────────────────────────────
        # Tier 1: Explicit Manual / Excel file assignment (Authoritative — use ONLY assigned files)
        # Tier 2: Deterministic Control ID / Topic mapping (Match 8.17, 8.2, 5.15 against filenames)
        # Tier 3: Semantic Keyword matching fallback
        # Tier 4: Still no match → control_file_names = [] (NEVER fall back to all session files)
        control_context = context
        control_file_names = []
        target_evidence_files = []   # Track which specific evidence files this control maps to
        matched_policy_files = []    # Locked files that came from a Policy-named column
        matched_evidence_only_files = []  # Locked files that came from an Evidence-only column
        excel_no_evidence_mapped = False
        # Why the scope was blocked, when it was. Defaults to the plain
        # "nothing mapped" case; ambiguity sets its own so the auditor is told the
        # checklist is the problem rather than the evidence.
        excel_scope_block_reason = None

        def _extract_canonical_id(s):
            if not s: return ""
            import re as _re
            match = _re.search(r'\b([0-9]+\.[0-9]+)\b', str(s))
            if match:
                return match.group(1)
            num = _re.sub(r'[^0-9\.]', '', str(s)).strip('.')
            return num

        def _match_control_key(c_id, docs_source):
            if not c_id or not docs_source: return None
            if c_id in docs_source: return docs_source[c_id]
            cid_canon = _extract_canonical_id(c_id)
            if cid_canon:
                for k, v in docs_source.items():
                    if _extract_canonical_id(k) == cid_canon:
                        return v
            import re
            def _clean(s): return re.sub(r'[^a-z0-9]', '', str(s).lower())
            clean_cid = _clean(c_id)
            if clean_cid:
                for k, v in docs_source.items():
                    clean_k = _clean(k)
                    if clean_k and (clean_cid in clean_k or clean_k in clean_cid):
                        return v
            return None

        def _norm_question_text(q):
            if not q: return ""
            import re as _re
            s = _re.sub(r'[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]', '-', str(q))
            s = _re.sub(r'[^a-zA-Z0-9\s]', ' ', s.lower())
            return ' '.join(s.split())

        def _match_excel_row(c, excel_items, cid_canon):
            if not isinstance(excel_items, list) or not excel_items:
                return None, False

            c_row_idx = c.get("row_index")
            # Priority 1: Exact row identity / row_index
            if c_row_idx is not None:
                for item in excel_items:
                    if item.get("row_index") == c_row_idx:
                        return item, False

            if not cid_canon:
                return None, False

            # Candidates matching canonical ID
            candidates = []
            for item in excel_items:
                item_cid = _extract_canonical_id(item.get("control_id") or item.get("control_label") or item.get("question"))
                if item_cid and item_cid == cid_canon:
                    candidates.append(item)

            if not candidates:
                return None, False

            # Priority 2: Canonical Control ID + normalized exact question match
            c_q_norm = _norm_question_text(c.get("requirement_question") or c.get("question") or c.get("control"))
            if c_q_norm:
                for item in candidates:
                    item_q_norm = _norm_question_text(item.get("requirement_question") or item.get("question") or item.get("control_label"))
                    if item_q_norm and (c_q_norm == item_q_norm or c_q_norm in item_q_norm or item_q_norm in c_q_norm):
                        return item, False

            # Priority 3: Unique canonical control ID (exactly 1 candidate row)
            if len(candidates) == 1:
                return candidates[0], False

            # Priority 4: Ambiguity failure — multiple rows with no unique question/row match
            print(f"[SCOPING AMBIGUITY] Multiple Excel rows match control ID '{cid_canon}' but no unique row/question match was found.", flush=True)
            return None, True

        def _norm_fn(s):
            if not s: return ""
            base = os.path.basename(str(s))
            s_no_ext = os.path.splitext(base)[0]
            import re as _re
            return _re.sub(r'[^a-z0-9]', '', s_no_ext.lower())

        def _match_refs(refs_list):
            out = []
            for ref in refs_list:
                ref_str = str(ref or "").strip()
                if not ref_str:
                    continue
                norm_ref = _norm_fn(ref_str)
                if not norm_ref:
                    continue
                exact_hit = next((fname for fname in file_names_list if _norm_fn(fname) == norm_ref), None)
                if exact_hit:
                    if exact_hit not in out:
                        out.append(exact_hit)
                    continue
                # Bidirectional substring match -- checking only "is the citation a
                # substring of the real filename" missed real, common citations
                # where the Excel cell has a trailing copy/version marker the
                # actual uploaded (and sanitized) filename doesn't, e.g. Excel
                # cites "...Organizational Controls(5).docx" but the real
                # uploaded file is "...Organizational_Controls.docx" -- the
                # citation's normalized form is then LONGER than the real
                # filename's (extra "5"), so it can never be "in" the shorter
                # string. Confirmed on a real end-to-end run where this caused
                # every control's file scope to resolve empty and silently
                # skip retrieval/LLM entirely for all of them, not just one.
                # excel_scoping_parser.py's _match_filenames already checks
                # both directions; this mirrors that fix here.
                sub_hits = [
                    fname for fname in file_names_list
                    if _norm_fn(fname) and (norm_ref in _norm_fn(fname) or _norm_fn(fname) in norm_ref)
                ]
                if sub_hits:
                    for fname in sub_hits:
                        if fname not in out:
                            out.append(fname)
                else:
                    print(f"[SCOPING WARNING] Referenced file '{ref_str}' for control '{c.get('control')}' was not found among uploaded files.", flush=True)
            return out

        # Collect Tier 1 explicit file references with role provenance
        raw_tier1_policy_refs = []
        raw_tier1_evidence_refs = []
        raw_tier1_generic_refs = []

        cid_canon = _extract_canonical_id(c.get("control_id") or c.get("control"))

        # Diagnostic logs for scoping mapping investigation
        avail_cd_keys = list(custom_docs.keys()) if (custom_docs and isinstance(custom_docs, dict)) else []
        avail_ce_keys = list(custom_evidence.keys()) if (custom_evidence and isinstance(custom_evidence, dict)) else []
        print(f"[SCOPING MAP DEBUG] canonical_id={cid_canon}", flush=True)
        print(f"[SCOPING MAP DEBUG] available_custom_docs_keys={avail_cd_keys}", flush=True)
        print(f"[SCOPING MAP DEBUG] available_custom_evidence_keys={avail_ce_keys}", flush=True)

        is_excel_mode = False
        matched_excel_row = None
        is_ambiguous = False
        if isinstance(custom_evidence, dict) and "excel_items" in custom_evidence and isinstance(custom_evidence["excel_items"], list):
            is_excel_mode = True
            matched_excel_row, is_ambiguous = _match_excel_row(c, custom_evidence["excel_items"], cid_canon)

        if matched_excel_row:
            matched_key_str = matched_excel_row.get("control_id") or matched_excel_row.get("control_label") or cid_canon
            row_idx_val = matched_excel_row.get("row_index")
            q_val = matched_excel_row.get("requirement_question") or matched_excel_row.get("question")
            p_files = matched_excel_row.get("policy_files") or matched_excel_row.get("raw_policy_files") or []
            e_files = matched_excel_row.get("evidence_files") or matched_excel_row.get("raw_evidence_files") or []
            g_files = matched_excel_row.get("files") or matched_excel_row.get("raw_file_refs") or []

            print(f"[SCOPING MAP DEBUG] control={c.get('control')}", flush=True)
            print(f"[SCOPING MAP DEBUG] matched_row_index={row_idx_val}", flush=True)
            print(f"[SCOPING MAP DEBUG] matched_question={q_val}", flush=True)
            print(f"[SCOPING MAP DEBUG] files={g_files or e_files or p_files}", flush=True)

            if p_files:
                p_list = p_files if isinstance(p_files, list) else [r.strip() for r in str(p_files).split(",") if r.strip()]
                for ref in p_list:
                    ref_s = str(ref).strip()
                    if ref_s and ref_s not in raw_tier1_policy_refs:
                        raw_tier1_policy_refs.append(ref_s)

            if e_files:
                e_list = e_files if isinstance(e_files, list) else [r.strip() for r in str(e_files).split(",") if r.strip()]
                for ref in e_list:
                    ref_s = str(ref).strip()
                    if ref_s and ref_s not in raw_tier1_evidence_refs:
                        raw_tier1_evidence_refs.append(ref_s)

            if not raw_tier1_policy_refs and not raw_tier1_evidence_refs and g_files:
                g_list = g_files if isinstance(g_files, list) else [r.strip() for r in str(g_files).split(",") if r.strip()]
                for ref in g_list:
                    ref_s = str(ref).strip()
                    if ref_s and ref_s not in raw_tier1_generic_refs:
                        raw_tier1_generic_refs.append(ref_s)
        elif not is_excel_mode:
            # Manual / Custom scoping from custom_docs ONLY when not in Excel mode
            if c.get("policy_source_files_all"):
                raw_tier1_policy_refs.extend([r.strip() for r in str(c["policy_source_files_all"]).split(",") if r.strip()])
            if c.get("evidence_only_source_files_all"):
                raw_tier1_evidence_refs.extend([r.strip() for r in str(c["evidence_only_source_files_all"]).split(",") if r.strip()])
            if not raw_tier1_policy_refs and not raw_tier1_evidence_refs:
                row_files_str = c.get("evidence_source_files_all") or c.get("evidence_source_file")
                if row_files_str:
                    raw_tier1_generic_refs.extend([r.strip() for r in str(row_files_str).split(",") if r.strip()])

            docs_source = custom_docs if custom_docs is not None else {}
            matched_custom_key = None
            if docs_source:
                matched_custom_val = _match_control_key(c.get("control"), docs_source) or _match_control_key(c.get("control_id"), docs_source)
                if matched_custom_val:
                    matched_custom_key = matched_custom_val
                    print(f"[SCOPING MAP DEBUG] matched_custom_docs_val={matched_custom_val}", flush=True)
                    if isinstance(matched_custom_val, list):
                        for v in matched_custom_val:
                            raw_tier1_generic_refs.extend([r.strip() for r in str(v).split(",") if r.strip()])
                    else:
                        raw_tier1_generic_refs.extend([r.strip() for r in str(matched_custom_val).split(",") if r.strip()])

        print(f"[SCOPING DEBUG] control: '{c.get('control')}', canonical_id: '{cid_canon}', policy_refs: {raw_tier1_policy_refs}, evidence_refs: {raw_tier1_evidence_refs}, generic_refs: {raw_tier1_generic_refs}, session_files: {file_names_list}", flush=True)

        has_tier1_explicit_assignment = bool(raw_tier1_policy_refs or raw_tier1_evidence_refs or raw_tier1_generic_refs)

        # Ambiguity must STOP the cascade, not fall through it.
        #
        # _match_excel_row() already detects the case where several checklist rows
        # share a control ID and none can be tied to this control -- it returns
        # (None, True) and logs [SCOPING AMBIGUITY]. But `is_ambiguous` was then
        # never read. With no row matched, no Tier 1 refs were collected, so the
        # condition below was False and Tier 2/3 ran, ending at the "no
        # filename/keyword match" fallback that hands the control EVERY uploaded
        # file. The control was audited against evidence belonging to other rows'
        # questions -- precisely the cross-row bleed Excel scoping exists to stop,
        # and the loudest possible failure turned into the widest possible scope.
        #
        # An unmapped control reported as such is honest; one silently audited
        # against everything is not.
        if is_excel_mode and is_ambiguous and not has_tier1_explicit_assignment:
            control_file_names = []
            target_evidence_files = []
            excel_no_evidence_mapped = True
            excel_scope_block_reason = (
                f"Ambiguous checklist scope: multiple rows share control ID "
                f"'{cid_canon}' and none could be matched to this question. No files were "
                f"assigned, to avoid auditing this control against another row's evidence. "
                f"Give each row a distinct question or control ID and re-run."
            )
            control_context = ""
            print(
                f"[CONTROL FILE SCOPE] {c['control']}: scope left EMPTY -- multiple checklist "
                f"rows share this control ID and none matched uniquely. Refusing to borrow "
                f"another row's files.",
                flush=True
            )
        elif has_tier1_explicit_assignment:
            # ── Tier 1: Explicit File Assignment (AUTHORITATIVE) ──────────────
            matched_policy_files = _match_refs(raw_tier1_policy_refs)
            matched_evidence_only_files = _match_refs(raw_tier1_evidence_refs)
            matched_generic_files = _match_refs(raw_tier1_generic_refs)

            # Combine assigned files without duplicates, preserving order
            combined_tier1 = []
            for f in matched_policy_files + matched_evidence_only_files + matched_generic_files:
                if f not in combined_tier1:
                    combined_tier1.append(f)

            control_file_names = combined_tier1
            target_evidence_files = matched_evidence_only_files if matched_evidence_only_files else (matched_generic_files if matched_generic_files else control_file_names)

            reg_source = file_registry if file_registry is not None else {}
            if control_file_names:
                matched_texts = [reg_source.get(fname, "") for fname in control_file_names if reg_source.get(fname)]
                if matched_texts:
                    control_context = "\n\n".join(matched_texts)
            else:
                # Tier 1 was defined but 0 referenced files resolved -> STOP with empty scope & no evidence flag
                excel_no_evidence_mapped = True
                control_context = ""

            # STOP CASCADE: Tier 1 explicit assignment was defined, so NEVER run Tier 2/3 fallbacks!
        else:
            # ── Tier 2 & Tier 3 Fallbacks (when NO Tier 1 explicit assignment exists at all) ──
            ctrl_id_clean = c.get("control", "").lower().strip()
            ctrl_id_raw = str(c.get("control_id") or "").lower().strip()

            short_id = cid_canon.lower()

            import re as _re_tier2
            tier2_matched = []
            for fname in file_names_list:
                fname_clean = fname.lower()
                # Word-boundary matched, not a bare substring check -- confirmed on
                # a real audit run: VAPT-1's canonical short_id ("1", a bare digit)
                # matched inside "NOCPL_y71934.html" purely because a "1" happened
                # to appear in an unrelated number, authorizing a file that had
                # nothing to do with VAPT-1. "_"/"-" (common filename separators)
                # are normalized to spaces first so a real dotted ID like "8.17"
                # still matches "8.17_Clock_Sync.jpg" -- the literal "." inside the
                # ID itself is kept and escaped, since it's meaningful there, not a
                # separator to strip.
                fname_norm = _re_tier2.sub(r'[_\-]', ' ', fname_clean)
                if short_id and _re_tier2.search(r'\b' + _re_tier2.escape(short_id) + r'\b', fname_norm):
                    tier2_matched.append(fname)
                elif ctrl_id_raw and _re_tier2.search(r'\b' + _re_tier2.escape(ctrl_id_raw) + r'\b', fname_norm):
                    tier2_matched.append(fname)

            if tier2_matched:
                control_file_names = tier2_matched
            else:
                # Tier 3: Semantic keyword matching fallback
                import re as _re_tier3  # local import: this scope doesn't reliably have
                # module-level `re` bound (this file's other `import re` calls are
                # conditional/nested elsewhere), so import it directly here instead
                # of relying on another branch having already run first.
                ctrl_keywords = [k.lower() for k in (c.get("keywords") or {}).keys()]
                tier3_matched = []
                for fname in file_names_list:
                    fname_clean = fname.lower()
                    # Word-boundary matched on a separator-normalized filename, not a
                    # bare substring check -- the same class of bug found in
                    # classify_content_and_modality (validator.py): a bare
                    # "kw in fname_clean" check let a keyword like "log" or "port"
                    # match inside an unrelated filename ("employee_catalog.pdf",
                    # "IT_support_ticket.docx"), authorizing the wrong file for a
                    # control. Plain \b alone isn't enough here, though -- regex
                    # treats "_" as a word character, so \bword\b would ALSO miss a
                    # real match like "access" in "access_control_log.txt" (no
                    # boundary between "access" and the following "_"). Normalizing
                    # "_"/"-"/"." to spaces first fixes both directions: real
                    # underscore-separated filename tokens still match, embedded
                    # substrings inside a longer contiguous word still don't.
                    fname_norm = _re_tier3.sub(r'[_\-.]', ' ', fname_clean)
                    if any(_re_tier3.search(r'\b' + _re_tier3.escape(kw) + r'\b', fname_norm) for kw in ctrl_keywords if len(kw) >= 3):
                        tier3_matched.append(fname)
                if tier3_matched:
                    control_file_names = tier3_matched
                else:
                    # Tier 4: no filename/keyword match. Previously this meant NO
                    # authorized files at all (control_file_names = []) -- which
                    # skipped retrieval entirely (_retrieve_rag_context short-circuits
                    # to an empty context when file_names_list is empty), so the LLM
                    # got nothing to evaluate even when real, relevant evidence was
                    # sitting in an uploaded file the whole time. Confirmed on a real
                    # audit run: CONTROL_KEYWORDS had zero entries for several controls
                    # (VAPT-2, VAPT-5, VAPT-6, and this is equally true for ISO
                    # controls run without an Excel checklist), so Tier 2/3 could never
                    # match regardless of what was actually in the uploaded files --
                    # while OTHER controls only "worked" by filename coincidence
                    # (Tier 2 matching a control's canonical ID against an unrelated
                    # digit inside a filename).
                    #
                    # Falling back to the full file list here is safe, not a return to
                    # "blindly dump everything" -- _retrieve_rag_context still does its
                    # own content-based relevance filtering (vector similarity + cross-
                    # encoder reranking, verified directly to correctly select and
                    # attribute the right chunks) on whatever file list it's given. This
                    # tier only decided which files retrieval was ALLOWED to search, not
                    # what got shown to the LLM -- so this fallback restores retrieval's
                    # own content search as the deciding factor instead of a brittle
                    # filename/keyword pre-filter with incomplete keyword coverage.
                    control_file_names = list(file_names_list)
                    print(
                        f"[CONTROL FILE SCOPE] {c['control']}: no filename/keyword match -- "
                        f"falling back to content-based search across all {len(file_names_list)} "
                        f"uploaded file(s) instead of skipping retrieval entirely.",
                        flush=True
                    )

        print(f"[CONTROL FILE SCOPE] {c['control']}: {control_file_names}", flush=True)
        if matched_policy_files:
            print(f"[POLICY FILE SCOPE] {c['control']}: {matched_policy_files}", flush=True)
        if matched_evidence_only_files:
            print(f"[EVIDENCE FILE SCOPE] {c['control']}: {matched_evidence_only_files}", flush=True)

        # Assemble graph inputs mapping exactly to LangGraph AuditState schema
        state_input = {
            "control_id": c["control"],
            "control_label": c["label"],
            "expected_evidence": c["expected"],
            "prompt_hint": c["prompt_hint"],
            "severity": c["severity"],
            "standard": c.get("standard", "ISO 27001:2022"),
            "recommendation": c.get("recommendation", ""),
            "keywords": c.get("keywords") or {},

            # Context & Config
            "document_text": control_context,
            "file_names_list": control_file_names,
            "llm_model": llm_model,
            "summary_text": summary_text,
            "report_id": report_id_for_retrieval,

            # State tracking
            "retrieved_context": "",
            "draft_finding": None,
            "validation_error": None,
            "retry_count": 0,
            "final_finding": None,
            "token_stats": {},

            # Progress tracking
            "bg_key": bg_key,
            "control_idx": idx,
            "total_controls": total,
            "audit_mode": audit_mode,
            "file_registry": file_registry or {},

            # ── Two-Phase Excel Scoping: pass locked_filenames if scoping is active ──
            # locked_filenames restricts Phase 1 retrieval to ONLY the matched file(s) --
            # this is the actual SQL-level filter in _retrieve_rag_context, not just a
            # prompt hint, and bool(locked_filenames) is also what decides whether
            # generate_node uses the Excel-judge-only prompt vs the standard one. So
            # this must stay [] for Tier 2/3 (keyword/ID-matched, no explicit Excel
            # assignment) exactly as before -- only fix the Tier-1 case, where it was
            # target_evidence_files (evidence-only). When a checklist row has separate
            # Policy-column and Evidence-column files, that silently excluded the
            # policy file's content from ever being retrieved -- the LLM then only had
            # a filename hint ("the policy file is X") with no way to actually read X,
            # despite AGENTS.md's column_source_hint guidance requiring the LLM to
            # verify the real content, not just trust the hint. control_file_names is
            # the deduped union of policy+evidence+generic refs (see combined_tier1
            # above), so using it here for Tier 1 keeps both files readable.
            # checklist_question is the original Excel audit check question text.
            "locked_filenames": (control_file_names if has_tier1_explicit_assignment else target_evidence_files) or [],
            "checklist_question": c.get("checklist_question") or c["label"],
            # Which of the locked files (if any) came from a Policy-named vs an
            # Evidence-named column on the sheet -- lets generate_node tell the LLM
            # the auditor's own intent instead of re-deriving the split blind.
            "policy_locked_filenames": matched_policy_files,
            "evidence_locked_filenames": matched_evidence_only_files,
        }
        
        if excel_no_evidence_mapped:
            # No retrieval, no LLM call -- there's nothing to search or evaluate.
            # Deterministic NON_COMPLIANT-for-human-review, matching the same
            # convention already used elsewhere for a genuine "evidence not found"
            # LLM result, but without spending 10-45 minutes of LLM time (and
            # without the risk of the LLM being handed unrelated session files)
            # to arrive at the same place.
            ctrl_duration = time.time() - control_start_time
            _no_evidence_msg = excel_scope_block_reason or "No evidence file was mapped to this control in the uploaded Excel checklist."
            result = {
                "control_id": c["control"],
                "control_label": c["label"],
                "control": c["control"],
                "status": "NON_COMPLIANT",
                "severity": c.get("severity", "MEDIUM"),
                "finding": _no_evidence_msg,
                "description": _no_evidence_msg,
                "gap_detected": _no_evidence_msg,
                "evidence_found": "NOT_FOUND",
                "evidence_snippet": "",
                "source_files": "",
                "evidence_location": "",
                "recommendation": f"Map and upload evidence for {c['label']} in the audit checklist, then re-run this control.",
                "reasoning": (
                    "This checklist row had no evidence file mapped to it, so no retrieval or "
                    "LLM evaluation was performed -- flagged for human review instead of "
                    "searching other, unrelated files in this session."
                ),
                "policy_status": "NOT_FOUND",
                "policy_assessment": "NON_COMPLIANT",
                "evidence_status": "NOT_FOUND",
                "evidence_assessment": "NON_COMPLIANT",
                "final_result": "NON_COMPLIANT",
                "final_reason": _no_evidence_msg,
            }
            all_results.append(result)
            print(f"[{time.strftime('%H:%M:%S')}] [CONTROL EVALUATED] {c['control']} ({c['label']}) | Status: NON_COMPLIANT (no evidence mapped -- retrieval/LLM skipped) | Latency: {ctrl_duration:.1f}s | Tokens Used: 0", flush=True)
            log_dev_latency(f"[{idx + 1}/{total}] [NO EVIDENCE MAPPED] Control {c['control']} {c['label']} -- retrieval/LLM skipped ({ctrl_duration:.2f}s)")
        else:
            try:
                # Invoke LangGraph
                state_output = audit_graph.invoke(state_input)
                result = state_output.get("final_finding")
                if result:
                    # ── Excel Scoping Safety Gate (Phase 2 final correction) ─────────────
                    # Overrides N/A evidence and wrong-file citations structurally.
                    if target_evidence_files:
                        try:
                            from src.core.validator import apply_excel_scoping_safety_gate
                            retrieved_ctx = state_output.get("retrieved_context", "")
                            result = apply_excel_scoping_safety_gate(
                                finding=result,
                                locked_filenames=target_evidence_files,
                                retrieved_context=retrieved_ctx,
                                checklist_question=c.get("checklist_question") or c["label"]
                            )
                        except Exception as _sg_err:
                            print(f"[SAFETY GATE ERROR] {_sg_err}", flush=True)

                    # ── Evidence provenance fix ───────────────────────────────────────
                    # BUG FIX: source_files must ALWAYS reflect the Excel-mapped file.
                    # Previously: only overrode source_files when it was empty, allowing
                    # the validator to write the WRONG file (e.g. MFA doc for Capacity
                    # Management) when a fallback-pool search happened.
                    # Fix: if Excel strictly mapped this control to specific files, ALWAYS
                    # set source_files to those mapped files — ignore whatever the validator
                    # may have written from searching the wrong-pool fallback.
                    if target_evidence_files:
                        # Excel scoping is active → enforce the mapped file unconditionally.
                        result["source_files"] = ", ".join(target_evidence_files)
                    else:
                        # No Excel scoping → use whatever the validator set (or leave empty).
                        existing_src = result.get("source_files") or ""
                        if not existing_src.strip():
                            result["source_files"] = ""
                    all_results.append(result)
                ctrl_duration = time.time() - control_start_time
                res_status = result.get("status", "Unknown") if result else "None"

                c_mins = int(ctrl_duration // 60)
                c_secs = round(ctrl_duration % 60, 1)
                c_lat_str = f"{c_mins}m {c_secs}s" if c_mins > 0 else f"0m {c_secs}s"

                _real_token_stats = state_output.get("token_stats") or {}
                ctrl_p_toks = _real_token_stats.get("prompt_tokens", 0)
                ctrl_c_toks = _real_token_stats.get("completion_tokens", 0)
                ctrl_t_toks = ctrl_p_toks + ctrl_c_toks
                _audit_real_prompt_toks += ctrl_p_toks
                _audit_real_comp_toks += ctrl_c_toks

                print(f"[{time.strftime('%H:%M:%S')}] [CONTROL EVALUATED] {c['control']} ({c['label']}) | Status: {res_status} | Latency: {c_lat_str} ({ctrl_duration:.1f}s) | Tokens Used: {ctrl_t_toks:,} (Prompt: {ctrl_p_toks:,}, Completion: {ctrl_c_toks:,})", flush=True)
                log_dev_latency(f"[{idx + 1}/{total}] [SUCCESS] Control {c['control']} {c['label']} completed in {ctrl_duration:.2f}s ({c_lat_str}) | Tokens: {ctrl_t_toks:,}")
                # ── Redis: push per-control metrics live ─────────────────────────
                try:
                    _rm.push_control_metrics(
                        session_id=checkpoint_session_id or bg_key,
                        prompt_tokens=ctrl_p_toks,
                        comp_tokens=ctrl_c_toks,
                        latency_sec=ctrl_duration
                    )
                except Exception as _rpm_err:
                    pass  # Redis write failures never break an audit
            except Exception as e:
                print(f"[AUDIT ERROR] Error evaluating control {c['control']}: {e}", flush=True)
                log_dev_latency(f"ERROR: Control {c['control']} failed: {e}")
                # ── Redis: push error signal ─────────────────────────────────────
                try:
                    _rm.push_error(session_id=checkpoint_session_id or bg_key)
                except Exception:
                    pass

        # ── PER-CONTROL CHECKPOINT ─────────────────────────────────────────────
        # Save after EVERY control (~3ms). On crash, at most 1 control is re-run.
        if checkpoint_session_id:
            _checkpoint_update_per_control(
                checkpoint_session_id,
                c.get("control", ""),
                all_results
            )

        # Update progress bar
        if bg_key:
            pct = int(((idx + 1) / total) * 100)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {
                    "text": f"Scanning: {idx + 1}/{total} controls...",
                    "percent": pct,
                    "warning": _busy_warning,
                }

        # Legacy batch checkpoint for backward compat (kept but superseded by per-control)
        if checkpoint_session_id and batch_size and (idx + 1) % batch_size == 0:
            completed_batches = (idx + 1) // batch_size
            _checkpoint_update(checkpoint_session_id, completed_batches, all_results)


    resolved_list = [r["control_id"] for r in all_results if (r.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
    findings_list = [r for r in all_results if (r.get("status") or "").upper() not in ("COMPLIANT", "ACCEPTED", "PASS")]
    
    total_audit_time = time.time() - overall_start_time
    tot_mins = int(total_audit_time // 60)
    tot_secs = round(total_audit_time % 60, 1)
    tot_lat_str = f"{tot_mins}m {tot_secs}s" if tot_mins > 0 else f"0m {tot_secs}s"

    end_msg = f"[AUDIT COMPLETE] Evaluated {total} controls in {tot_lat_str} ({total_audit_time:.1f}s). Compliant: {len(resolved_list)}, Gaps: {len(findings_list)}"
    print(f"[{time.strftime('%H:%M:%S')}] {end_msg}\n", flush=True)
    log_dev_latency(end_msg)

    # ── Capacity report: name the hardware when controls could not be evaluated ──
    # A timeout used to leave the auditor with a finding that read like any other.
    # Counting them at the end turns an invisible degradation into a specific,
    # actionable statement about the machine -- every figure below is already known
    # at this point, so the recommendation costs nothing to produce.
    try:
        _not_evaluated = [
            r for r in (all_results or [])
            if str((r or {}).get("status") or (r or {}).get("final_result") or "").upper() == "NOT_EVALUATED"
        ]
        if _not_evaluated:
            _cores = _detect_physical_cores()
            _active = max(1, _count_active_sessions())
            # Cores needed to bring the average control inside the 10-minute target
            # at the concurrency actually observed, from the measured per-control
            # wall time. Halved-utilisation assumption is deliberate: it reports the
            # figure that also leaves the headroom the deployment was sized for.
            _avg_ctrl_sec = (total_audit_time / max(1, total)) or 0
            _needed = None
            if _cores and _avg_ctrl_sec > 0:
                _needed = int(math.ceil((_cores * _avg_ctrl_sec) / 600.0 / 2.0) * 2)
            _cap_msg = (
                f"{len(_not_evaluated)} of {total} controls could not be evaluated "
                f"(analysis engine timeout) with {_active} audit(s) running."
            )
            if _cores and _needed and _needed > _cores:
                _cap_msg += (
                    f" This server has {_cores} CPU core(s); approximately {_needed} "
                    f"are needed to evaluate every control at this concurrency."
                )
            elif _cores:
                _cap_msg += f" This server has {_cores} CPU core(s)."
            _cap_msg += " Re-run the affected controls."
            print(f"[CAPACITY] {_cap_msg}", flush=True)
            log_system_event("CAPACITY_SHORTFALL", "WARNING", _cap_msg,
                             session_id=checkpoint_session_id or bg_key or "System")
            if bg_key:
                with _bg_lock:
                    _prev = _bg_store["progress"].get(bg_key) or {}
                    _bg_store["progress"][bg_key] = {**_prev, "warning": f"⚠️ {_cap_msg}"}
    except Exception as _cap_err:
        print(f"[CAPACITY] Summary skipped (non-fatal): {_cap_err}", flush=True)

    # Record benchmark metrics for Excel tracker & Terminal Summary Box
    try:
        from src.core.token_tracker import record_token_metrics
        text_chars = len(str(context or ""))
        total_file_bytes = 0
        file_details = []
        file_types_summary = {}

        if file_registry:
            for fname, fmeta in file_registry.items():
                sz = 0
                txt_c = 0
                if isinstance(fmeta, dict):
                    sz = fmeta.get("size_bytes", 0)
                    txt_c = len(fmeta.get("text", ""))
                elif isinstance(fmeta, str):
                    txt_c = len(fmeta)
                    sz = max(512, txt_c * 2)

                total_file_bytes += sz
                ext = os.path.splitext(str(fname))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1
                file_details.append({
                    "name": fname,
                    "ext": ext,
                    "size_bytes": sz,
                    "size_kb": round(sz / 1024, 1),
                    "char_count": txt_c
                })

        if not file_types_summary and file_names_list:
            for fn in file_names_list:
                ext = os.path.splitext(str(fn))[1].lower().replace('.', '') or 'doc'
                file_types_summary[ext] = file_types_summary.get(ext, 0) + 1

        if total_file_bytes == 0:
            total_file_bytes = max(1024, text_chars * 2)

        cpu_cores_cnt = os.cpu_count() or 4

        prompt_toks = _audit_real_prompt_toks
        comp_toks = _audit_real_comp_toks
        tot_tokens_all = prompt_toks + comp_toks
        avg_tokens_ctrl = round(tot_tokens_all / max(1, total), 1)

        avg_lat_sec = total_audit_time / max(1, total)
        avg_mins = int(avg_lat_sec // 60)
        avg_secs = round(avg_lat_sec % 60, 1)
        avg_lat_str = f"{avg_mins}m {avg_secs}s" if avg_mins > 0 else f"0m {avg_secs}s"
        
        mode_str = str(audit_mode).lower()
        if "excel" in mode_str or "manual" in mode_str:
            scoping_label = "Excel / Manual Scoping"
        elif "auto" in mode_str or "quick" in mode_str:
            scoping_label = "AI Auto-Scoping"
        else:
            scoping_label = "Excel / Manual Scoping"

        record_token_metrics(
            session_id=checkpoint_session_id or bg_key or "SESSION-LATEST",
            scoping_mode=scoping_label,
            file_names=file_names_list or ["Uploaded Evidence Documents"],
            total_file_size_bytes=total_file_bytes,
            extracted_text_chars=text_chars,
            controls_count=total,
            prompt_tokens=prompt_toks,
            completion_tokens=comp_toks,
            total_latency_sec=total_audit_time,
            compliant_count=len(resolved_list),
            non_compliant_count=len(findings_list),
            out_of_scope_count=len(out_of_scope_results) if 'out_of_scope_results' in locals() else 0,
            folder_name="Audit Evidence Package",
            cpu_cores=cpu_cores_cnt,
            file_details=file_details,
            file_types_summary=file_types_summary
        )

        total_files_cnt = len(file_names_list) if file_names_list else 0
        file_size_mb = round(total_file_bytes / (1024 * 1024), 2)
        file_size_kb = round(total_file_bytes / 1024, 1)
        total_text_chunks = len([c for c in str(context or "").split("\n\n") if len(c.strip()) > 20])
        if total_text_chunks == 0:
            total_text_chunks = max(1, int(text_chars / 500))

        file_types_str = ", ".join([f"{ext.upper()}: {cnt}" for ext, cnt in file_types_summary.items()]) if file_types_summary else "N/A"
        # Previously: getattr(locals().get("req", None), "auditor_username", None) or
        # os.environ.get("CURRENT_AUDITOR", "rk1@gmail.com") -- this function has no
        # local named "req" and CURRENT_AUDITOR is never set anywhere in the codebase,
        # so that always evaluated to the literal hardcoded fallback regardless of who
        # actually ran the audit. `username` is now a real parameter threaded down from
        # the authenticated request (api_start_audit -> _run_ollama_bg -> here).
        auditor_user = username or "Unknown Auditor"

        summary_box = f"""====================================================================================
 • Session ID                      : {checkpoint_session_id or bg_key or 'SESSION-LATEST'}
 • Auditor Username                : {auditor_user}
 • Scoping Detection Mode          : {scoping_label}
 • System CPU Hardware Specs       : {cpu_cores_cnt} Logical CPU Cores
 • Total Evidence Files Count      : {total_files_cnt} Files
 • File Extensions Breakdown       : {file_types_str}
 • Total Evidence File Size        : {file_size_mb} MB ({file_size_kb:,} KB)
 • Total Text Chunks Analyzed      : {total_text_chunks} Chunks ({text_chars:,} Chars)
 • Total Controls Evaluated        : {total}
 • Compliant Controls              : {len(resolved_list)}
 • Non-Compliant Gaps              : {len(findings_list)}
 • Prompt Input Tokens             : {prompt_toks:,} Tokens
 • Completion Output Tokens        : {comp_toks:,} Tokens
 • Total Audit Tokens Used         : {tot_tokens_all:,} Tokens
 • Average Tokens per Control      : {avg_tokens_ctrl:,} Tokens/Control
 • Overall Audit Latency           : {tot_lat_str} ({total_audit_time:.1f} seconds)
 • Average Latency per Control     : {avg_lat_str} ({avg_lat_sec:.1f} seconds/control)
====================================================================================
"""
        print("\n" + summary_box, flush=True)
        log_dev_latency(summary_box)

        # Write audit completion metrics to SystemEvent for Privacy-Safe Log Trail
        log_system_event(
            "AUDIT_COMPLETED", "INFO",
            f"Audit completed: {total} controls evaluated, "
            f"{len(resolved_list)} compliant, {len(findings_list)} non-compliant | "
            f"Tokens: {tot_tokens_all:,} (prompt: {prompt_toks:,}, completion: {comp_toks:,}) | "
            f"Latency: {tot_lat_str} | Files: {total_files_cnt} ({file_size_mb} MB) | "
            f"Scoping: {scoping_label}",
            session_id=checkpoint_session_id or bg_key,
            actor=auditor_user
        )

    except Exception as _bm_err:
        print(f"[BENCHMARK ERROR] Failed to record token metrics: {_bm_err}", flush=True)

    # ── Redis: mark session as done / paused ─────────────────────────────────
    try:
        _rm.session_done(session_id=checkpoint_session_id or bg_key, status="paused" if was_resource_paused else "done")
    except Exception:
        pass

    return resolved_list, findings_list, all_results, was_resource_paused

# No concurrency queue — audits run freely without waiting in line.
# The resource guard's check_memory_pressure() (called in /audit/start before
# this thread is even spawned) is the only gate: it refuses new audits when
# RAM is genuinely critically low (< 8% available), preventing OOM crashes.
# Without --mlock, the OS manages memory like a normal app (swap to disk when
# tight), so queuing is unnecessary — worst case is slower, never a crash.

def _run_ollama_bg(bg_key, files_data, selected_sls_copy, ai_model, session_id=None, audit_mode="Deep", custom_docs=None, custom_evidence=None, file_registry=None, already_done_ids=None, username=None):
    print(f"[_run_ollama_bg] Starting thread for key {bg_key} with model {ai_model}...", flush=True)
    _sid = session_id or bg_key
    try:


        # ── Pre-flight: verify LLM server is reachable (3s timeout) ──────────
        import os as _os
        import requests as _req
        from src.core.llm_client import get_llm_backend, _resolve_host, _ensure_llama_server_running
        _backend = get_llm_backend()
        _is_llamacpp = _backend in ("llama.cpp", "llamacpp")
        _llm_host = _resolve_host()
        _health_url = f"{_llm_host}/health" if _is_llamacpp else f"{_llm_host}/api/tags"
        _healthy = False
        try:
            _hr = _req.get(_health_url, timeout=3)
            if _hr.status_code in (200, 201):
                _healthy = True
                print(f"[_run_ollama_bg] LLM server health check OK ({_health_url}): {_hr.status_code}", flush=True)
        except Exception:
            pass

        if not _healthy and _is_llamacpp:
            _ensure_llama_server_running(11434)
            try:
                _hr = _req.get(_health_url, timeout=5)
                if _hr.status_code in (200, 201):
                    _healthy = True
                    print(f"[_run_ollama_bg] LLM server self-healed and online ({_health_url}): {_hr.status_code}", flush=True)
            except Exception:
                pass

        if not _healthy:
            _backend_label = "llama.cpp" if _is_llamacpp else "Ollama"
            _err_msg = (
                f"Cannot connect to {_backend_label} server at {_llm_host}. "
                "Please start the service before running audits."
            )
            print(f"[_run_ollama_bg ERROR] {_err_msg}", flush=True)
            log_system_event("LLM_OFFLINE_ERROR", "ERROR", _err_msg, session_id=_sid)
            with _bg_lock:
                _bg_store["progress"][bg_key] = {"text": f"Error: {_backend_label} offline", "percent": 0}
            _checkpoint_finish(_sid, "failed")
            return

        print(f"[_run_ollama_bg] Pipeline executing for session {_sid}...", flush=True)
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": "🔍 Scanning file security...",
                "percent": 0
            }

        # Resolved once here and reused below -- scopes this session's chunk
        # ingestion so a same-named file uploaded under a different session
        # never collides with (deletes/overwrites) this session's own chunks.
        _report_id_for_ingest = None
        try:
            with force_master():
                _rid_session2 = SessionLocal()
                _rid_report2 = _rid_session2.query(AuditReport).filter(
                    AuditReport.session_id == _sid
                ).first()
                _report_id_for_ingest = _rid_report2.id if _rid_report2 else None
                _rid_session2.close()
        except Exception as _rid_err2:
            print(f"[REPORT ID RESOLVE] Failed to resolve report_id for {_sid}: {_rid_err2}", flush=True)

        ctx = ""
        file_names_list = []
        if file_registry is None:
            file_registry = {}
        for f_data in files_data:
            name = f_data["name"]
            file_bytes = f_data["bytes"]
            f_like = io.BytesIO(file_bytes)
            f_like.name = name
            # Full 4-layer scan — text is already extracted at this point (unlike the
            # upload-time scan), so Layer 4 (null-byte/oversized text) is also covered.
            is_clean, reason = scan_document(name, file_bytes, f_data.get("text") or "")
            if not is_clean:
                print(f"[_run_ollama_bg] Security alert! Malware scan failed for file {name}: {reason}", flush=True)
                log_system_event("MALWARE_BLOCKED", "CRITICAL", f"File blocked by security scan: {name} ({reason})", session_id=_sid)
                with _bg_lock:
                    _bg_results[bg_key] = {"error": f"🚨 SECURITY ALERT: '{name}' BLOCKED! {reason}"}
                    _bg_store["progress"].pop(bg_key, None)
                _checkpoint_finish(_sid, "failed")
                return

            text = f_data.get("text")
            if not text:
                text = extract_text(f_like)
                f_data["text"] = text
            file_registry[name] = text

            ctx += f"--- FILE: {name} ---\n{text}\n\n"
            save_document_chunks(name, text, report_id=_report_id_for_ingest)
            file_names_list.append(name)
        context_str = ctx.strip()

        # ── Redis: register session as started ───────────────────────────────
        try:
            _total_file_bytes_pre = sum(
                f_data.get("size_bytes", max(512, len(f_data.get("text", "")) * 2))
                for f_data in files_data
            )
            _file_mb_pre = round(_total_file_bytes_pre / (1024 * 1024), 3)
            _auditor_pre = username or "Unknown Auditor"
            _rm.session_start(
                session_id=_sid,
                auditor=_auditor_pre,
                files_count=len(file_names_list),
                file_mb=_file_mb_pre
            )
        except Exception as _rs_err:
            print(f"[Redis session_start ignored] {_rs_err}", flush=True)

        # Update scanned files to "Reviewing" in database
        try:
            with force_master():
                db_write = SessionLocal()
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Processing"}, synchronize_session=False)
                db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE] Failed to update active files status to Reviewing: {e}", flush=True)

        # Was len(selected_sls_copy) -- the count of unique selected control IDs.
        # In Excel-scoping mode, one control ID can span multiple checklist rows
        # (e.g. two separate questions both filed under "8.5"), and the audit
        # loop (inside generate_ollama_findings) iterates per ROW via
        # _build_controls_for_audit(), not per unique control ID. Using the
        # unique-ID count here instead produced checkpoint displays like
        # "(7/6 done)" once more rows than the stated total had completed.
        # Purely a display value -- never used in any resume/completion
        # decision -- but confusing and worth matching reality. Re-derives the
        # same list generate_ollama_findings will build (cheap: no LLM calls,
        # just dict construction) so the two totals agree.
        # PERF: Build controls list once and take its len -- previously called
        # _build_controls_for_audit() a second time here solely for the count,
        # rebuilding the entire list just to get a display number.
        _controls_for_count = _build_controls_for_audit(selected_sls_copy, custom_evidence)
        _total_ctrl_count = len(_controls_for_count)
        _batch_sz = 1 if ("7B" in ai_model or "8B" in ai_model or "9B" in ai_model or "Escalation" in ai_model) else 4

        # On fresh start: create a new checkpoint.
        # On RESUME (already_done_ids provided): the checkpoint already exists — skip re-creation.
        _is_resume = bool(already_done_ids)
        if not _is_resume:
            _checkpoint_create(
                _sid, bg_key, ai_model,
                selected_sls_copy, file_names_list, context_str,
                _total_ctrl_count, _batch_sz
            )
        else:
            print(
                f"[RESUME] Checkpoint exists — skipping _checkpoint_create, "
                f"resuming from {len(already_done_ids)} already-done controls.",
                flush=True
            )

        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"Scanning controls with {ai_model.split(' - ')[0]}...",
                "percent": 0
            }

        res = generate_ollama_findings(
            context_str, file_names_list, selected_sls_copy, ai_model, bg_key=bg_key,
            checkpoint_session_id=_sid, audit_mode=audit_mode,
            custom_docs=custom_docs, custom_evidence=custom_evidence, file_registry=file_registry,
            already_done_ids=already_done_ids or [], username=username
        )
        if len(res) == 4:
            resolved_combined, findings_combined, all_results_combined, is_resource_paused = res
        else:
            resolved_combined, findings_combined, all_results_combined = res
            is_resource_paused = False

        resolved_mapping = {}
        for ctrl in resolved_combined:
            resolved_mapping[ctrl] = file_names_list
        for finding in findings_combined:
            finding["status"] = finding.get("status", "Non-Compliant")
            finding["comment"] = ""
            finding["editing"] = False
            
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": findings_combined,
                "resolved_list": resolved_combined,
                "resolved_count": len(resolved_mapping),
                "resolved_controls": set(resolved_mapping.keys()),
                "context": context_str
            }

        # Update scanned files to "Completed" and save results in database
        try:
            with force_master():
                db_write = SessionLocal()
                
                # 1. Update Evidence File statuses
                db_write.query(EvidenceFile).filter(
                    EvidenceFile.filename.in_(file_names_list)
                ).update({EvidenceFile.status: "Completed"}, synchronize_session=False)
                
                # 2. Retrieve report and insert findings (auto-create report if missing so findings are ALWAYS saved)
                report = db_write.query(AuditReport).filter(AuditReport.session_id == _sid).first()
                if not report:
                    report = AuditReport(
                        session_id=_sid,
                        session_title=f"Audit Scan {_sid[:14]}",
                        framework="ISO/IEC 27001:2022",
                        status="Pending Review"
                    )
                    db_write.add(report)
                    db_write.flush()


                # Clear existing findings for this report
                db_write.query(Finding).filter(Finding.report_id == report.id).delete()
                for f in all_results_combined:
                    f_desc = f.get("description") or f.get("finding") or f.get("gap_detected") or f.get("reasoning") or "Evaluated against ISO 27001 / VAPT compliance standards."
                    f_status = f.get("status", "Non-Compliant")
                    is_comp = (f_status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")
                    f_recom = f.get("recommendation") or f.get("remediation") or (f"Maintain current documented policies and verification procedures for {f.get('control_id')}." if is_comp else f"Establish formal policy documentation, access controls, and logging evidence for {f.get('control_id')}.")

                    ev_loc = f.get("evidence_location") or f.get("evidence_source_file") or f.get("source_file") or ""
                    src_files = f.get("source_files") or ""

                    if not ev_loc and src_files:
                        ev_loc = src_files.split(",")[0].strip()

                    # If evidence location is a child image file, include parent document name
                    if ev_loc and src_files and ev_loc != src_files:
                        if ev_loc.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")) and src_files not in ev_loc:
                            ev_loc = f"{src_files} ({ev_loc})"

                    raw_cid = str(f.get("control_id") or "")
                    raw_cname = str(f.get("control_label") or f.get("control") or raw_cid)

                    db_write.add(Finding(
                        report_id=report.id,
                        control_id=raw_cid[:98] if raw_cid else "ISO_CONTROL",
                        control_name=raw_cname[:198] if raw_cname else "ISO Control",
                        severity="N/A" if is_comp else f.get("severity", "N/A"),
                        description=f_desc,
                        gap_detected=f_desc,
                        relevance_score=f.get("relevance_score", 0),
                        evidence_found=f.get("evidence_found", ""),
                        evidence_snippet=f.get("evidence_snippet", ""),
                        evidence_location=ev_loc,
                        evidence_source_file=ev_loc,
                        recommendation=f_recom,
                        reasoning=f.get("reasoning") or f_desc or "",
                        status="COMPLIANT" if is_comp else f_status,
                        policy_present=f.get("policy_present") or ("Compliant" if is_comp else "No"),
                        evidence_present=f.get("evidence_present") or ("Compliant" if is_comp else "No"),
                        source_files=f.get("source_files", ""),
                        # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7)
                        policy_status=f.get("policy_status"),
                        policy_assessment=f.get("policy_assessment"),
                        policy_name=f.get("policy_name"),
                        policy_version=f.get("policy_version"),
                        policy_clause=f.get("policy_clause"),
                        policy_effective_date=f.get("policy_effective_date"),
                        policy_review_date=f.get("policy_review_date"),
                        policy_expiry_date=f.get("policy_expiry_date"),
                        policy_validity=f.get("policy_validity"),
                        policy_finding=f.get("policy_finding"),
                        policy_gap=f.get("policy_gap"),
                        evidence_status=f.get("evidence_status"),
                        evidence_assessment=f.get("evidence_assessment"),
                        evidence_date=f.get("evidence_date"),
                        evidence_freshness=f.get("evidence_freshness"),
                        evidence_finding=f.get("evidence_finding"),
                        evidence_gap=f.get("evidence_gap"),
                        evidence_relevance=f.get("evidence_relevance"),
                        final_result=f.get("final_result"),
                        final_reason=f.get("final_reason"),
                        policy_snippet=f.get("policy_snippet"),
                        operational_evidence_snippet=f.get("operational_evidence_snippet"),
                        requirements_total=f.get("requirements_total"),
                        requirements_supported=f.get("requirements_supported"),
                        requirements_partial=f.get("requirements_partial"),
                        requirements_not_supported=f.get("requirements_not_supported"),
                        requirements_coverage_json=f.get("requirements_coverage_json"),
                        likelihood=f.get("likelihood"),
                        impact=f.get("impact"),
                        risk_level=f.get("risk_level"),
                        risk_rationale=f.get("risk_rationale"),
                        policy_items_json=f.get("policy_items_json") if "policy_items_json" in f else "[]",
                        evidence_items_json=f.get("evidence_items_json") if "evidence_items_json" in f else "[]",
                        requirement_question=f.get("requirement_question"),
                        policy_required=f.get("policy_required"),
                        # requires_human_review/review_note are computed throughout validator.py
                        # (grounding failures, potential-evidence-found heuristic, the NON_COMPLIANT-
                        # vs-"no gap identified" consistency guard, etc.) but were never read here --
                        # every one of those flags was silently dropped at save time and could never
                        # reach the auditor UI, regardless of which validator rule set it.
                        requires_human_review=bool(f.get("requires_human_review") or False),
                        review_note=f.get("review_note") or "",
                    ))

                # 3. Calculate score and update ComplianceScore
                db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                in_scope = [f for f in all_results_combined if f.get("status")]
                compliant = [f for f in in_scope if (f.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
                score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                db_write.add(ComplianceScore(
                    report_id=report.id,
                    framework=report.framework,
                    score_percent=score_pct
                ))
                
                report.status = "Pending Review"
                # Commit and close INSIDE force_master() so writes go to the primary
                db_write.commit()
                db_write.close()

        except Exception as e:
            print(f"[PIPELINE] Failed to save findings and complete files update: {e}", flush=True)
            
        _checkpoint_finish(_sid, "paused" if is_resource_paused else "completed")
    except Exception as e:
        print(f"[_run_ollama_bg] Exception raised in background thread: {str(e)}", flush=True)
        log_system_event("AUDIT_EXCEPTION", "CRITICAL", f"Background audit thread exception: {str(e)}", session_id=_sid)
        with _bg_lock:
            _bg_results[bg_key] = {"error": f"Error contacting {BACKEND_NAME}: {str(e)}"}
        _checkpoint_finish(_sid, "failed")
    finally:
        with _bg_lock:
            _bg_running.discard(bg_key)
            _bg_store["progress"].pop(bg_key, None)
            _bg_stop_flags.pop(bg_key, None)  # Clear stop flag on thread exit

def _run_fast_technical_vapt_bg(bg_key, files_data, selected_sls, file_registry=None, framework=""):
    # `framework` decides which parser family parse_tool_file() is allowed to use.
    # It used to be absent entirely, so every call below passed the literal "vapt"
    # -- including calls made for a PQC session, since PQC is a technical-mode scan
    # and routes through this same function. parse_tool_file() removes PQCParser
    # from its candidate list and skips the PQC binary fast-path whenever the
    # framework is "vapt", so a PQC scan could not produce a single PQC finding:
    # the parser was unreachable from the only code path that reaches it.
    _fw_upper = str(framework or "").upper()
    _dispatch_framework = "pqc" if "PQC" in _fw_upper else "vapt"
    all_findings = []
    resolved_ctrls = set()
    _seen_dedup_keys = set()
    try:
        from src.core.parsers import parse_tool_file, map_finding_to_control
        # Aliased to avoid colliding with the module-level `Finding` import (the
        # SQLAlchemy DB model, from src.db.database at the top of this file) -- the
        # OCR-fallback finding construction below needs the parsers' plain dataclass
        # (title/evidence/control_id/etc.), not the ORM model, which has none of
        # those columns and raises "invalid keyword argument" if constructed with them.
        from src.core.parsers.finding_schema import Finding as ParsedFinding

        # Pre-seed dedup keys from whatever this session already saved in a PREVIOUS
        # run -- without this, re-running a scan on the same session (e.g. after
        # uploading more evidence) re-inserted every finding from files that were
        # already scanned before, since in-memory dedup alone only sees the current run.
        try:
            with force_master():
                _db_seed = SessionLocal()
                _existing_report = _db_seed.query(AuditReport).filter(AuditReport.session_id == bg_key).first()
                if _existing_report:
                    _existing_keys = _db_seed.query(Finding.dedup_key).filter(
                        Finding.report_id == _existing_report.id,
                        Finding.dedup_key.isnot(None)
                    ).all()
                    for (_ek,) in _existing_keys:
                        if _ek:
                            _seen_dedup_keys.add(_ek)
                _db_seed.close()
        except Exception as _seed_err:
            print(f"[VAPT DEDUP] Failed to pre-seed existing dedup keys: {_seed_err}", flush=True)

        for fd in files_data:
            fname = fd.get("name", "")
            ftext = fd.get("text", "")
            fname_lower = fname.lower()
            if not ftext and fd.get("bytes"):
                fbytes = fd.get("bytes")
                if fname_lower.endswith((".html", ".htm", ".xml", ".csv", ".json", ".txt")):
                    try:
                        ftext = fbytes.decode("utf-8", errors="ignore")
                    except Exception:
                        ftext = ""
                elif fname_lower.endswith(".pdf"):
                    # Fast native PDF text extraction first
                    try:
                        import io
                        from pypdf import PdfReader
                        reader = PdfReader(io.BytesIO(fbytes))
                        pages_text = [page.extract_text() or "" for page in reader.pages]
                        ftext = "\n".join(pages_text).strip()
                    except Exception:
                        ftext = ""
                    # Fall back to extract_text (hybrid OCR) if sparse/scanned
                    if not ftext or len(ftext.strip()) < 50:
                        try:
                            import io
                            buf = io.BytesIO(fbytes)
                            buf.name = fname
                            ftext = extract_text(buf)
                        except Exception:
                            pass
                elif fname_lower.endswith((".docx", ".doc", ".pptx", ".ppt", ".xlsx", ".xls", ".zip",
                                            ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif")):
                    # Images MUST go through extract_text()'s OCR path here, not the generic
                    # decode() branch below -- decoding raw PNG/JPG binary as UTF-8 with
                    # errors="ignore" silently "succeeds" (garbage but non-empty, e.g. 12KB+ of
                    # noise from a ~20KB screenshot), which made the OCR-fallback logic further
                    # down think it already had real text and skip calling extract_text() at
                    # all (it only OCRs when this initial decode comes back empty) -- so every
                    # screenshot silently produced zero findings instead of being OCR'd.
                    try:
                        import io
                        buf = io.BytesIO(fbytes)
                        buf.name = fname
                        ftext = extract_text(buf)
                    except Exception:
                        ftext = ""
                else:
                    try:
                        ftext = fbytes.decode("utf-8", errors="ignore")
                    except Exception:
                        ftext = ""

            reg_text = (file_registry or {}).get(fname, "")
            if reg_text and len(reg_text) > len(ftext or ""):
                ftext = reg_text
            if file_registry is not None and fname:
                file_registry[fname] = ftext

            # ── PQC pre-extraction for binary formats ────────────────────────────
            # PDF, DOCX and images may have empty ftext at this point if the
            # branches above didn't fire (e.g. a .pdf uploaded in PQC mode that
            # bypassed the pypdf block, or a .jpg that the OCR block above set to
            # empty). Run pqc_extract_text() as a final safety net so PQCParser
            # always receives usable plain text for binary file types.
            if not ftext and fd.get("bytes") and fname_lower.endswith(
                (".pdf", ".docx", ".doc", ".png", ".jpg", ".jpeg",
                 ".webp", ".bmp", ".tiff", ".tif")
            ):
                try:
                    from src.core.parsers import pqc_extract_text
                    ftext = pqc_extract_text(fname, fd["bytes"]) or ""
                except Exception:
                    ftext = ""

            actionable, info = parse_tool_file(fname, ftext or "", framework=_dispatch_framework)


            # parse_tool_file's second return value differs by parser: a list of
            # informational (non-actionable) findings for Nessus/Burp, None for
            # Qualys/Trivy -- but nmap_parser.py returns an AssetInventory object
            # (open ports/target IP metadata, not findings) there instead. Blindly
            # doing `actionable + (info or [])` crashed with "can only concatenate
            # list (not 'AssetInventory') to list" on every Nmap upload, silently
            # producing zero findings for the whole file (caught by the outer
            # try/except and surfaced only as a generic "failed" status with no
            # findings extracted at all).
            info_findings = info if isinstance(info, list) else []
            combined_tool_findings = actionable + info_findings

            # ── Fallback for Image Screenshots in Fast Technical Mode ────────
            # When an image screenshot (PNG, JPG, WEBP, BMP, TIFF) is uploaded in fast
            # technical mode, parse_tool_file() skips XML/HTML tool parsing (returning []).
            # Extract structured findings directly from the image's OCR text so
            # screenshots of SQLi, XSS, Nmap, or port scans produce immediate findings!
            if not combined_tool_findings and fname_lower.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif")):
                raw_ocr = (ftext or "").strip()
                if not raw_ocr and fd.get("bytes"):
                    try:
                        import io
                        buf = io.BytesIO(fd.get("bytes"))
                        buf.name = fname
                        raw_ocr = extract_text(buf) or ""
                    except Exception:
                        raw_ocr = ""
                
                if raw_ocr and len(raw_ocr.strip()) > 10:
                    # Pass OCR text to Python tool parsers!
                    actionable_ocr, info_ocr = parse_tool_file("ocr_" + fname + ".txt", raw_ocr, framework=_dispatch_framework)
                    info_ocr_list = info_ocr if isinstance(info_ocr, list) else []
                    ocr_findings = actionable_ocr + info_ocr_list
                    if ocr_findings:
                        combined_tool_findings.extend(ocr_findings)
                    else:
                        import re
                        txt_low = raw_ocr.lower()
                        # Word-boundary matching, not bare substring: "script" is a literal
                        # substring of "de-SCRIPT-ion", and "port" of "re-PORT-ing"/"sup-PORT"/
                        # "im-PORT-ant" -- a plain `in` check misclassified any screenshot
                        # containing the ordinary word "Description" as XSS proof-of-concept,
                        # and would do the same to "report"/"support" for the Nmap branch.
                        def _kw_hit(*keywords):
                            return any(re.search(r'\b' + re.escape(kw) + r'\b', txt_low) for kw in keywords)

                        if _kw_hit("sql", "sqli", "union select", "database"):
                            f_ocr = ParsedFinding(
                                title=f"Visual PoC: SQL Injection Detected ({fname})",
                                severity="HIGH",
                                description=f"OCR extracted SQL injection proof-of-concept from evidence image '{fname}'.",
                                evidence=f"Target: Image Screenshot ({fname})\nScanner: Visual OCR\nPlugin Output:\n{raw_ocr[:1200]}",
                                source_tool="Visual OCR",
                                control_id="VAPT-4"
                            )
                            combined_tool_findings.append(f_ocr)
                        elif _kw_hit("xss", "script", "cross-site"):
                            f_ocr = ParsedFinding(
                                title=f"Visual PoC: Cross-Site Scripting (XSS) Detected ({fname})",
                                severity="MEDIUM",
                                description=f"OCR extracted XSS proof-of-concept from evidence image '{fname}'.",
                                evidence=f"Target: Image Screenshot ({fname})\nScanner: Visual OCR\nPlugin Output:\n{raw_ocr[:1200]}",
                                source_tool="Visual OCR",
                                control_id="VAPT-4"
                            )
                            combined_tool_findings.append(f_ocr)
                        elif _kw_hit("nmap", "port", "open", "tcp"):
                            f_ocr = ParsedFinding(
                                title=f"Visual PoC: Network Scan & Port Evidence ({fname})",
                                severity="INFO",
                                description=f"OCR extracted network scan and open port evidence from image '{fname}'.",
                                evidence=f"Target: Image Screenshot ({fname})\nScanner: Visual OCR\nPlugin Output:\n{raw_ocr[:1200]}",
                                source_tool="Visual OCR",
                                control_id="VAPT-3"
                            )
                            combined_tool_findings.append(f_ocr)
                        else:
                            f_ocr = ParsedFinding(
                                title=f"Visual Security Evidence ({fname})",
                                severity="MEDIUM",
                                description=f"OCR extracted security evidence from image '{fname}'.",
                                evidence=f"Target: Image Screenshot ({fname})\nScanner: Visual OCR\nPlugin Output:\n{raw_ocr[:1200]}",
                                source_tool="Visual OCR",
                                control_id="VAPT-3"
                            )
                            combined_tool_findings.append(f_ocr)

            for f in combined_tool_findings:
                # Skip exact-duplicate findings (same CVE, or same tool+plugin_id, or
                # same tool+normalized title — see Finding.dedup_key()) before they're
                # ever written to the report. Checks both this run's findings-so-far
                # AND whatever a previous run on this session already saved (pre-seeded
                # above), so re-scanning after uploading more evidence doesn't duplicate
                # findings from files that were already scanned before.
                _dedup_key_val = None
                if hasattr(f, "dedup_key"):
                    _dedup_key_val = f.dedup_key()
                    if _dedup_key_val in _seen_dedup_keys:
                        continue
                    _seen_dedup_keys.add(_dedup_key_val)

                # Preserve a control_id the parser itself already assigned (e.g. pqc_parser.py's
                # map_pqc_findings_list() sets PQC-1..PQC-12 via map_finding_to_pqc_control()) --
                # unconditionally calling the VAPT-specific map_finding_to_control() here used to
                # clobber it back to a VAPT-1..15 ID regardless of what framework the finding
                # actually belongs to. Only fall back to the VAPT mapper when nothing set it yet.
                c_id = getattr(f, "control_id", None) or map_finding_to_control(f)
                f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                f_dict["dedup_key"] = _dedup_key_val
                f_dict["control_id"] = c_id
                f_dict["control"] = f_dict.get("control") or c_id
                f_dict["status"] = "Non-Compliant" if f_dict.get("severity") != "INFO" else "Informational"
                f_dict["display_status"] = "Open"
                f_dict["source_files"] = fname   # Scan FILE name, not host IP
                # ── Build structured evidence snippet (Proof of Concept block) ──
                # This is what auditors see as "Evidence". It must show:
                #   Host/IP, Port, CVE, Plugin Output — not just the Nessus plugin description.
                _target = f_dict.get("target") or ""
                _cves = f_dict.get("cve_list") or []
                _cve_str = ", ".join(_cves) if _cves else "No CVE assigned"
                _plugin_id = f_dict.get("plugin_id") or ""
                _plugin_out = str(f_dict.get("evidence") or f_dict.get("evidence_snippet") or f_dict.get("evidence_quote") or "").strip()
                _desc_text = str(f_dict.get("description") or f_dict.get("title") or "").strip()
                _tool = f_dict.get("source_tool") or "Scanner"
                # Structured PoC block
                poc_lines = []
                if _target:
                    poc_lines.append(f"Target Host: {_target}")
                if _plugin_id:
                    poc_lines.append(f"Plugin ID:   {_plugin_id}")
                if _cves:
                    poc_lines.append(f"CVE(s):      {_cve_str}")
                poc_lines.append(f"Scanner:     {_tool}")
                if _plugin_out and "Not available in scan report" not in _plugin_out:
                    poc_lines.append(f"Plugin Output:\n{_plugin_out[:1200]}")
                elif _desc_text:
                    poc_lines.append(f"Plugin Output:\n{_desc_text[:1200]}")
                else:
                    poc_lines.append(f"Plugin Output:\nTarget endpoint verified: {_target}")
                poc_block = "\n".join(poc_lines)
                f_dict["evidence_snippet"] = poc_block
                all_findings.append(f_dict)
                resolved_ctrls.add(c_id)

        # Update database with VAPT findings
        try:
            with force_master():
                db_write = SessionLocal()
                report = db_write.query(AuditReport).filter(AuditReport.session_id == bg_key).first()
                if report:
                    for f in all_findings:
                        finding_kwargs = dict(
                            report_id=report.id,
                            control_id=f.get("control_id"),
                            control_name=f.get("title") or f.get("finding") or f.get("control") or f.get("control_id"),
                            severity=f.get("severity", "N/A"),
                            description=f.get("description") or f.get("finding") or "",
                            gap_detected=f.get("finding") or f.get("description") or "",
                            relevance_score=f.get("relevance_score", 0),
                            # The parser's real CVSS score, into the column that is
                            # actually named for it. It was previously written ONLY as a
                            # string into `evidence_found`, leaving `severity_score` at
                            # its 0.0 default -- so the scanner-derived score (e.g. 8.6
                            # for an SSRF) was computed, discarded, and then re-invented
                            # downstream from the severity band alone. Every VAPT report
                            # quoted a placeholder number rather than the assessed one.
                            severity_score=_safe_float(f.get("severity_score")),
                            evidence_found=str(f.get("severity_score", 0.0)),
                            evidence_snippet=f.get("evidence_snippet") or f.get("evidence") or "",
                            recommendation=f.get("remediation") or f.get("recommendation", ""),
                            reasoning=f.get("reasoning", ""),
                            status=f.get("status", "Non-Compliant"),
                            source_files=f.get("source_files", ""),  # Now = scan filename, NOT host IP
                            # VAPT enrichment fields -- previously computed by map_findings_list()
                            # then silently dropped here (no columns existed to persist them into),
                            # so every saved VAPT finding lost this data the moment the scan finished.
                            category=f.get("category") or "",
                            cia_impact=f.get("cia_impact") or "",
                            is_pii_exposed=bool(f.get("is_pii_exposed") or False),
                            remediation_actionable=f.get("remediation_actionable") or "",
                            dedup_key=f.get("dedup_key"),
                            # PQC (Post-Quantum Cryptography Readiness) enrichment fields --
                            # same pattern as the VAPT enrichment fields above: computed at
                            # parse time by pqc_parser.py, flow through Finding.to_dict(), but
                            # previously had no columns to persist into.
                            asset_name=f.get("asset_name") or "",
                            asset_category=f.get("asset_category") or "",
                            quantum_status=f.get("quantum_status") or "",
                            ca_algorithm=f.get("ca_algorithm") or "",
                            key_algorithm=f.get("key_algorithm") or "",
                            protocol_version=f.get("protocol_version") or "",
                            exposure_context=f.get("exposure_context") or "",
                            port=f.get("port") or "",
                            environment=f.get("environment") or "",
                            # PQC risk scoring / OEM readiness / migration-dependency fields --
                            # same pattern as the PQC context fields above. risk_score is an
                            # int-or-None numeric field (mirrors severity_score's convention
                            # elsewhere in this function) -- no string "or ''" fallback, since
                            # that could coerce a legitimate 0 into "".
                            risk_score=f.get("risk_score"),
                            risk_band=f.get("risk_band") or "",
                            business_priority=f.get("business_priority") or "",
                            oem_product=f.get("oem_product") or "",
                            oem_readiness_status=f.get("oem_readiness_status") or "",
                            dependency_chain=f.get("dependency_chain") or "",
                            migration_dependency_flag=bool(f.get("migration_dependency_flag") or False),
                            nist_80053_controls=f.get("nist_80053_controls") or "",
                        )
                        # Strip NUL bytes (0x00) from every text field -- PDFs, HTML, and OCR
                        # text occasionally extract with embedded NUL bytes, which SQLite/
                        # Postgres both reject outright ("string literal cannot contain NUL
                        # characters"), which previously failed the ENTIRE batch commit for
                        # every finding in the scan, not just the one offending record.
                        for _k, _v in finding_kwargs.items():
                            if isinstance(_v, str) and "\x00" in _v:
                                finding_kwargs[_k] = _v.replace("\x00", "")
                        db_write.add(Finding(**finding_kwargs))
                    
                    # Update Compliance Score
                    db_write.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).delete()
                    in_scope = [f for f in all_findings if f.get("status") in ("Compliant", "Partially Compliant", "Non-Compliant")]
                    compliant = [f for f in in_scope if f.get("status") == "Compliant"]
                    score_pct = int(len(compliant) / max(len(in_scope), 1) * 100) if in_scope else 0
                    db_write.add(ComplianceScore(
                        report_id=report.id,
                        framework=report.framework,
                        score_percent=score_pct
                    ))
                    
                    report.status = "Pending Review"
                    db_write.commit()
                db_write.close()
        except Exception as e:
            print(f"[PIPELINE-VAPT] Failed to write findings: {e}", flush=True)

        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": all_findings,
                "resolved_list": list(resolved_ctrls),
                "resolved_count": len(resolved_ctrls),
                "resolved_controls": resolved_ctrls,
                "error": None,
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
    except Exception as e:
        with _bg_lock:
            _bg_results[bg_key] = {
                "findings": [],
                "error": str(e),
                "completed": True
            }
        with _bg_lock:
            _bg_running.discard(bg_key)
