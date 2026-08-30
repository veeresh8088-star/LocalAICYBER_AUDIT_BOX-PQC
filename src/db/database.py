import os
import shutil
import random
import threading
import contextlib
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, text, Boolean, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session

Base = declarative_base()

# ── 6 NEW NORMALIZED TABLES + BACKWARD COMPATIBLE TABLES ─────────────────────

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role          = Column(String(50), nullable=False)
    totp_secret   = Column(String(100), nullable=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class AuditReport(Base):
    __tablename__ = "audit_reports"
    id                = Column(Integer, primary_key=True, autoincrement=True)
    session_id        = Column(String(100), unique=True, index=True) # maps to UI's UUID session_id
    session_title     = Column(String(300))
    auditee_id        = Column(Integer, nullable=True) # maps to User.id
    created_by        = Column(String(100), nullable=True, index=True) # maps to User.username who created the session
    framework         = Column(String(100)) # ISO 27001, SOC 2, NIST, GDPR
    controls_selected = Column(Text) # JSON serialized list of control integers
    status            = Column(String(50), default="Draft") # Draft, Pending Review, Reviewed, Approved, Rejected
    created_at             = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    reviewed_at            = Column(DateTime, nullable=True)
    requires_scoping_review = Column(Boolean, default=False)
    scoping_note           = Column(Text, nullable=True)
    assigned_auditor_id     = Column(Integer, nullable=True)
    assigned_auditor_username = Column(String(100), nullable=True, index=True)

class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    report_id   = Column(Integer, index=True) # links to audit_reports.id
    filename    = Column(String(200))
    file_path   = Column(Text)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status      = Column(String(50), default="Pending")
    is_auditor_uploaded = Column(Boolean, default=False, server_default="false")
    assigned_auditor_username = Column(String(100), nullable=True, index=True)
    is_deleted  = Column(Boolean, default=False, server_default="false")

class Finding(Base):
    __tablename__ = "findings"
    id                    = Column(Integer, primary_key=True, autoincrement=True)
    report_id             = Column(Integer, index=True) # links to audit_reports.id
    control_id            = Column(String(500)) # e.g. A.12.6.1 or custom checklist question
    control_name          = Column(String(500)) # e.g. Access Restriction
    severity              = Column(String(100)) # P1 Critical -> P4 Low
    description           = Column(Text) # finding description details
    gap_detected          = Column(Text) # detected gap text
    relevance_score       = Column(Integer, default=0)
    evidence_found        = Column(String(500))
    evidence_snippet      = Column(Text)
    recommendation        = Column(Text)
    reasoning             = Column(Text)
    status                = Column(String(100), default="Non-Compliant") # Compliant, Partially Compliant, Non-Compliant, Out Of Scope
    source_files          = Column(Text)
    created_at            = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    
    # Strict Forensic Auditor Fields
    standard              = Column(String(300), nullable=True)
    clause                = Column(String(300), nullable=True)
    evidence_quote        = Column(Text, nullable=True)
    evidence_location     = Column(Text, nullable=True)
    gap_description       = Column(Text, nullable=True)
    confidence            = Column(Integer, nullable=True)
    hallucination_check   = Column(String(50), nullable=True)
    document_type_match   = Column(Boolean, nullable=True)
    post_process_override = Column(String(10), nullable=True)
    requires_human_review = Column(Boolean, default=False)
    review_note           = Column(Text, nullable=True)
    human_verified        = Column(Boolean, default=False)
    verified_by           = Column(String(100), nullable=True)
    verified_date         = Column(DateTime, nullable=True)
    finding_is_final      = Column(Boolean, default=True)
    chunk_id              = Column(Integer, nullable=True)
    evidence_state        = Column(String(100), nullable=True)
    evidence_source_file  = Column(Text, nullable=True)
    evidence_source_type  = Column(String(100), nullable=True)
    evidence_page_number  = Column(Integer, nullable=True)
    evidence_row_number   = Column(Integer, nullable=True)
    evidence_slide_number = Column(Integer, nullable=True)
    evidence_image_id     = Column(String(200), nullable=True)
    
    # Policy / Evidence / Severity matrix fields
    policy_present        = Column(String(50), default="No", server_default="No")
    evidence_present      = Column(String(50), default="No", server_default="No")
    policy_result         = Column(String(100), nullable=True)
    evidence_result       = Column(String(100), nullable=True)
    severity_score        = Column(Float, default=0.0, server_default="0.0")
    is_saved_to_shakthi   = Column(Boolean, default=False, server_default="false")

    # Policy vs Evidence split (RAG accuracy overhaul, Phase 7) -- persists the
    # AuditFindingSchema fields from Phase 5/6. Dates kept as free-text strings
    # since documents state them in arbitrary formats, not parsed into real Date
    # columns. All nullable so existing rows aren't affected by the auto schema
    # reconciliation in init_db() picking these up as new columns.
    policy_status          = Column(String(50), nullable=True)
    policy_assessment      = Column(String(50), nullable=True)
    policy_name            = Column(String(300), nullable=True)
    policy_version         = Column(String(100), nullable=True)
    policy_clause          = Column(String(300), nullable=True)
    policy_effective_date  = Column(String(100), nullable=True)
    policy_review_date     = Column(String(100), nullable=True)
    policy_expiry_date     = Column(String(100), nullable=True)
    policy_validity        = Column(String(50), nullable=True)
    policy_finding         = Column(Text, nullable=True)
    policy_gap             = Column(Text, nullable=True)
    evidence_status        = Column(String(50), nullable=True)
    evidence_assessment    = Column(String(50), nullable=True)
    evidence_date          = Column(String(100), nullable=True)
    evidence_freshness     = Column(String(50), nullable=True)
    evidence_finding       = Column(Text, nullable=True)
    evidence_gap           = Column(Text, nullable=True)
    evidence_relevance     = Column(String(50), nullable=True)
    final_result           = Column(String(50), nullable=True)
    final_reason           = Column(Text, nullable=True)

    # Auditor-Grade Policy & Operational Evidence Coverage & NIST Risk fields
    policy_snippet               = Column(Text, nullable=True)
    operational_evidence_snippet = Column(Text, nullable=True)
    requirements_total           = Column(Integer, nullable=True)
    requirements_supported       = Column(Integer, nullable=True)
    requirements_partial         = Column(Integer, nullable=True)
    requirements_not_supported   = Column(Integer, nullable=True)
    requirements_coverage_json   = Column(Text, nullable=True)
    likelihood                   = Column(String(50), nullable=True)
    impact                       = Column(String(50), nullable=True)
    risk_level                   = Column(String(50), nullable=True)
    risk_rationale               = Column(Text, nullable=True)
    policy_items_json            = Column(Text, nullable=True)
    evidence_items_json          = Column(Text, nullable=True)
    requirement_question         = Column(Text, nullable=True)
    policy_required              = Column(Boolean, nullable=True)

    # VAPT enrichment fields (src/core/parsers/control_mapper.py::map_findings_list).
    # These were computed at parse time but never had a column to persist into --
    # bg_worker.py's VAPT save path silently dropped them, so every saved VAPT
    # finding lost this data the moment the scan finished. Nullable/no server_default
    # so the schema-reconciliation in init_db() can add these to existing tables
    # without touching already-saved rows.
    category               = Column(String(200), nullable=True)  # Risk category, e.g. "Injection"
    cia_impact             = Column(String(300), nullable=True)  # e.g. "C:HIGH | I:HIGH | A:NONE"
    is_pii_exposed         = Column(Boolean, nullable=True)
    remediation_actionable = Column(Text, nullable=True)         # Developer-actionable fix guidance

    # VAPT dedup identity (src/core/parsers/finding_schema.py::Finding.dedup_key()).
    # In-memory dedup during a single scan run worked, but nothing checked a new
    # finding against what a PREVIOUS run on this same session already saved -- since
    # the DB never stored the CVE/plugin_id/tool identity needed to recompute the key,
    # re-running a VAPT scan (e.g. after uploading more evidence) duplicated every
    # finding from files that were already scanned before. Persisting the key makes
    # cross-run comparison exact instead of guessing from title text.
    dedup_key               = Column(String(500), nullable=True, index=True)

    # PQC (Post-Quantum Cryptography Readiness) enrichment fields
    # (src/core/parsers/pqc_parser.py / finding_schema.py::Finding). Nullable/no
    # server_default so the schema-reconciliation in init_db() can add these to
    # existing tables without touching already-saved rows -- same pattern as the
    # VAPT enrichment fields above.
    asset_name       = Column(String(300), nullable=True)  # Best-effort asset/host context
    asset_category   = Column(String(100), nullable=True)  # Firewall | VPN | PKI/HSM | Database | Web/App | Cloud | Server | Load Balancer | Unknown
    quantum_status   = Column(String(20), nullable=True)    # "VULNERABLE" | "WEAK" | "SAFE"
    ca_algorithm     = Column(String(200), nullable=True)   # Certificate/CA-labeled algorithm
    key_algorithm    = Column(String(200), nullable=True)   # Key-exchange-labeled algorithm
    protocol_version = Column(String(200), nullable=True)   # Protocol-labeled algorithm/version
    exposure_context = Column(String(20), nullable=True)    # "EXTERNAL" | "INTERNAL" | ""
    port             = Column(String(10), nullable=True)    # Best-effort nearby port number
    environment      = Column(String(20), nullable=True)    # "PROD" | "NON_PROD" | ""

    # PQC risk scoring / OEM readiness / migration-dependency enrichment fields
    # (src\core\parsers\pqc_parser.py \ finding_schema.py::Finding). Same nullable,
    # no-server_default pattern as the PQC context fields above so schema
    # reconciliation in init_db() can add these without touching existing rows.
    risk_score                = Column(Integer, nullable=True)     # 0-100 PQC composite risk score
    risk_band                 = Column(String(20), nullable=True)  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    business_priority         = Column(String(20), nullable=True)  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | ""
    oem_product                = Column(String(200), nullable=True) # Matched vendor/product name
    oem_readiness_status       = Column(String(100), nullable=True) # e.g. "PQC Roadmap Available"
    dependency_chain           = Column(Text, nullable=True)        # Rendered dependency chain string
    migration_dependency_flag  = Column(Boolean, nullable=True)     # True if a downstream dependency is also vulnerable
    nist_80053_controls        = Column(String(200), nullable=True) # NIST SP 800-53 Rev 5 refs, e.g. "SC-12, SC-13"

    # Auditor-editable custom heading (overrides control_name display in UI and reports)
    # Nullable so existing rows are unaffected. Applied to both VAPT and ISO findings.
    custom_heading           = Column(String(500), nullable=True)

class AdminAuditLog(Base):
    """
    Audit log tracking administrative actions, force acceptances, and override events.
    """
    __tablename__ = "admin_audit_logs"
    id                  = Column(Integer, primary_key=True, autoincrement=True)
    timestamp           = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    auditor_user        = Column(String(100), default="Lead Auditor")
    session_id          = Column(String(100), index=True)
    action              = Column(String(100)) # e.g. "FORCE_ACCEPT_UNREVIEWED_CONTROLS"
    unreviewed_controls = Column(Text, nullable=True) # JSON list or comma-separated IDs
    details             = Column(Text, nullable=True)
    ip_address          = Column(String(50), nullable=True)

class SystemSetting(Base):
    """
    Admin-editable runtime settings (e.g. upload size limits) -- lets an admin
    change these from the UI without a code edit + server restart. Falls back
    to the existing hardcoded defaults (src/core/settings.py) for any key with
    no row here yet, so this table can start empty.
    """
    __tablename__ = "system_settings"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    key          = Column(String(100), unique=True, nullable=False, index=True)
    value        = Column(String(200), nullable=False)
    updated_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_by   = Column(String(100), nullable=True)

class AuditorLearningRule(Base):
    """
    Stores auditor modifications, false-positive feedback, and remediation edits.
    The LLM reads active learning rules to prevent repeat false positives and adhere
    to auditor domain knowledge across scans.
    """
    __tablename__ = "auditor_learning_rules"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    control_id  = Column(String(100), index=True)
    pattern_key = Column(String(250), index=True) # Normalized finding title or CVE pattern
    action      = Column(String(50)) # "FALSE_POSITIVE", "MODIFIED", "ACCEPTED", "REJECTED"
    original_text = Column(Text, nullable=True)
    auditor_feedback = Column(Text, nullable=True)
    adjusted_remediation = Column(Text, nullable=True)
    created_by  = Column(String(100), default="Auditor")
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class AuditRecord(Base):
    """Auditor review log containing review outcomes and comments."""
    __tablename__ = "audit_records"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    report_id   = Column(Integer, index=True) # links to audit_reports.id
    auditor_id  = Column(Integer, nullable=True) # links to User.id
    status      = Column(String(50)) # Approved, Rejected, Reviewed
    comments    = Column(Text)
    reviewed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class ComplianceScore(Base):
    __tablename__ = "compliance_scores"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    report_id     = Column(Integer, index=True) # links to audit_reports.id
    framework     = Column(String(100))
    score_percent = Column(Integer)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

# ── BACKWARD COMPATIBILITY & UTILITY TABLES ──────────────────────────────────
class AuditCheckpoint(Base):
    """Mid-audit progress checkpoints for crash-resilience."""
    __tablename__ = "audit_checkpoints"
    id                        = Column(Integer, primary_key=True, autoincrement=True)
    session_id                = Column(String(100), index=True)
    bg_key                    = Column(String(100))
    ai_model                  = Column(String(200))
    selected_sls_json         = Column(Text)
    file_names_json           = Column(Text)
    context_text              = Column(Text)
    total_controls            = Column(Integer, default=0)
    completed_batches         = Column(Integer, default=0)
    batch_size                = Column(Integer, default=10)
    # ── Per-control granular checkpoint (NEW) ────────────────────────────────
    completed_controls        = Column(Integer, default=0)          # count of controls saved so far
    completed_control_ids_json= Column(Text, default="[]")          # JSON list of control_id strings already evaluated
    # ────────────────────────────────────────────────────────────────────────
    partial_results_json      = Column(Text, default="[]")
    status                    = Column(String(50), default="in_progress")
    created_at                = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at                = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class ChatMessage(Base):
    """General chat history for the AI Assistant view."""
    __tablename__ = "chat_messages"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    session_id    = Column(String(100))
    session_title = Column(String(300))
    role          = Column(String(50))
    content       = Column(Text)
    username      = Column(String(150), nullable=True, index=True)  # owner of this chat
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class DocumentChunk(Base):
    """Stores text paragraph chunks of processed policies for RAG search."""
    __tablename__ = "document_chunks"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    filename      = Column(String(200), index=True)
    # Scopes every read/write to the AuditReport that owns this chunk. Without
    # this, filename was the ONLY key -- two different sessions uploading a
    # file with the same name would silently delete and overwrite each
    # other's chunks (save_document_chunks), and searches could cross-match
    # the wrong session's content. NULL for rows written before this column
    # existed; those become unreachable (never matched) rather than falsely
    # matching a real session, which is the safe failure direction.
    report_id     = Column(Integer, index=True, nullable=True)
    chunk_index   = Column(Integer)
    content       = Column(Text)
    metadata_json = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    # Production provenance columns (Phase 1 — multi-doc ingestion)
    source_file   = Column(Text, nullable=True)        # original upload filename
    source_type   = Column(String(50), nullable=True)  # pdf, docx, xlsx, csv, pptx, txt, png, jpg
    chunk_id      = Column(String(200), nullable=True) # unique chunk hash/id for dedup
    page_number   = Column(Integer, nullable=True)     # for PDF/PPTX
    row_number    = Column(Integer, nullable=True)     # for XLSX/CSV
    slide_number  = Column(Integer, nullable=True)     # for PPTX
    image_id      = Column(String(200), nullable=True) # for PNG/JPG
    section_heading = Column(String(500), nullable=True) # heading context

class AuditorFeedback(Base):
    """Stores auditor review decisions and overrides for in-context learning."""
    __tablename__ = "auditor_feedback"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    control_id       = Column(String(100), index=True)
    evidence_snippet = Column(Text, nullable=True)
    corrected_status = Column(String(50))
    finding          = Column(Text, nullable=True)
    recommendation   = Column(Text, nullable=True)
    auditor_comments = Column(Text, nullable=True)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class AuditTrail(Base):
    __tablename__ = "audit_trail"
    id                    = Column(Integer, primary_key=True, autoincrement=True)
    audit_id              = Column(String(100), index=True)
    document_name         = Column(String(255))
    standard              = Column(String(50))
    model_used            = Column(String(100))
    run_date              = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    total_controls        = Column(Integer)
    grounded_compliant    = Column(Integer)
    correct_non_compliant = Column(Integer)
    hallucinated          = Column(Integer)
    real_accuracy         = Column(Integer)
    full_report           = Column(Text) # JSON serialized string
    is_deleted            = Column(Boolean, default=False)
    deleted_at            = Column(DateTime, nullable=True)


class SystemEvent(Base):
    """Privacy-safe system event log. Never stores company names, document content, or finding text."""
    __tablename__ = "system_events"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(100), nullable=False)
    # FORCE_SAVE, AUDIT_COMPLETE, AUDIT_CRASH, REPLICATION_ERROR,
    # DB_CONNECT_ERROR, OLLAMA_ERROR, FAILOVER, SCHEMA_ERROR, STATUS_CHANGE
    actor      = Column(String(100), nullable=False)   # username or "SYSTEM"
    session_id = Column(String(100), nullable=True)
    framework  = Column(String(100), nullable=True)    # ISO 27001, SOC 2, etc.
    meta       = Column(Text, nullable=True)           # JSON: counts + short error msg only
    severity   = Column(String(20), default="INFO")    # INFO | WARNING | ERROR | CRITICAL
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class CustomControl(Base):
    """Auditor-managed controls that extend or supplement the hardcoded ISO 27001:2022 control set.
    Loaded at runtime by the Zero-LLM scoping engine to support dynamic scope pruning.
    """
    __tablename__ = "custom_controls"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    control_id     = Column(String(50),  nullable=False)   # e.g. "5.40"
    control_name   = Column(String(300), nullable=False)   # e.g. "5.40 AI System Security"
    framework      = Column(String(50),  default="ISO 27001")  # ISO 27001 | VAPT | DPDP | GDPR | SOC2 | BCMS | XBOM
    category       = Column(String(200), nullable=False)   # e.g. "Technology / IT Security Policy"
    description    = Column(Text, nullable=True)           # optional long description for semantic embedding
    keywords_json  = Column(Text, nullable=True)           # JSON list e.g. ["ai", "machine learning"]
    auto_generated = Column(Boolean, default=False)        # True = keywords were auto-generated
    is_active      = Column(Boolean, default=True)         # soft-delete flag
    is_global      = Column(Boolean, default=True)         # True = all auditors share it
    created_by     = Column(String(100), nullable=True)    # auditor username
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                            onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class LicenseWallet(Base):
    """
    Time-Bound & Token-Metered License Wallet engine for STPI Auditors and VAPT Teams.
    Supports Trial Mode (Time-Bound + Audit Count limits) and Paid Enterprise Licenses.
    """
    __tablename__ = "license_wallets"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    license_key      = Column(String(100), unique=True, nullable=False)
    license_type     = Column(String(50), default="TRIAL")  # TRIAL | ENTERPRISE | UNLIMITED
    auditor_group    = Column(String(100), default="STPI / VAPT Auditor")
    balance_rupees   = Column(Float, default=500.0)         # ₹500.00 default trial balance
    rate_per_m_tokens= Column(Float, default=10.0)          # ₹10 per 1,000,000 tokens
    allocated_tokens = Column(Integer, default=50000000)   # 50M tokens
    used_tokens      = Column(Integer, default=0)
    audits_allowed   = Column(Integer, default=5)          # 5 Full Audits allowed in Trial
    audits_completed = Column(Integer, default=0)
    expiry_days      = Column(Integer, default=14)         # 14-day Free Trial
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expiry_date      = Column(DateTime, nullable=True)
    is_active        = Column(Boolean, default=True)


class TokenUsageLog(Base):
    """Logs token usage and rupee cost per audit session."""
    __tablename__ = "token_usage_logs"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    session_id       = Column(String(100), index=True)
    control_id       = Column(String(100), nullable=True)
    prompt_tokens    = Column(Integer, default=0)
    completion_tokens= Column(Integer, default=0)
    total_tokens     = Column(Integer, default=0)
    cost_rupees      = Column(Float, default=0.0)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


def _log_db_event(event_type: str, meta: dict = None, severity: str = "ERROR"):
    """
    Write a SystemEvent directly using the master engine.
    Called from within database.py itself to avoid circular imports.
    Never stores company names, document content, or finding text.
    """
    import json as _json
    global engine_master, promoted_master_engine
    _engine = promoted_master_engine or engine_master
    if _engine is None:
        return  # DB not yet initialised — skip silently
    try:
        from sqlalchemy.orm import sessionmaker as _sm
        _Session = _sm(bind=_engine)
        _db = _Session()
        _db.add(SystemEvent(
            event_type=event_type,
            actor="SYSTEM",
            meta=_json.dumps(meta) if meta else None,
            severity=severity,
        ))
        _db.commit()
        _db.close()
    except Exception:
        pass  # Never crash on logging failure



# ── ROUTING CONTROLS ────────────────────────────────────────────────────────
_routing_state = threading.local()

@contextlib.contextmanager
def force_master():
    """Forces the active thread to route all database actions to the MASTER engine."""
    old = getattr(_routing_state, "force_master", False)
    _routing_state.force_master = True
    try:
        yield
    finally:
        _routing_state.force_master = old

# ── MASTER-SLAVE ENGINES & FAILOVER ──────────────────────────────────────────
engine_master = None
engine_slave1 = None
engine_slave2 = None
promoted_master_engine = None
db_label = "ShaktiDB"

# Slave health tracking for load balancing
slaves_health = {"Slave 1": True, "Slave 2": True}
slaves_health_lock = threading.Lock()

import queue
import time
import re

_replication_queue = queue.Queue()
_replication_pending_flag = False
_replication_flag_lock = threading.Lock()

# ── Dirty-table tracking for incremental replication ───────────────────────
# _execute_replicate_changes() used to wipe+reinsert EVERY table on EVERY cycle,
# regardless of what actually changed -- a full-database copy on every debounced
# commit. Instead, track which tables were actually touched (by ANY write, not
# just ORM object adds/deletes -- a bulk `db.query(Model).delete()` call, e.g.
# the admin "reset all data" endpoint, executes as a single DELETE statement and
# never appears in a Session's .new/.dirty/.deleted, so tracking is done at the
# actual SQL-statement level via an engine event instead of session state) and
# only sync those tables. "*" is a safe-fallback sentinel meaning "a write
# happened whose target table couldn't be confidently parsed -- sync everything
# rather than risk silently skipping a table that changed."
#
# The listener is attached to ALL THREE engines (master + both slaves), not
# just engine_master -- after a failover promotes Slave 1 to master
# (promoted_master_engine), application writes route through engine_slave1
# instead, and would go untracked forever if only engine_master were watched,
# permanently under-replicating from that point on.
#
# _replication_write_in_progress is a per-THREAD flag (sync_to_target below runs
# each target in its own thread) so the replication process's own DELETE/INSERT
# statements -- which write the exact same tables it just finished reading as
# "dirty" -- don't immediately re-mark those tables dirty and defeat the whole
# optimization every single cycle.
_dirty_tables_lock = threading.Lock()
_dirty_tables = {"*"}  # starts as "sync everything" until the first successful cycle
_replication_write_in_progress = threading.local()
_WRITE_STMT_TABLE_RE = re.compile(
    r'^\s*(?:INSERT INTO|UPDATE|DELETE FROM)\s+"?([A-Za-z_][A-Za-z0-9_]*)"?',
    re.IGNORECASE
)

def _track_write_statement(conn, cursor, statement, parameters, context, executemany):
    """SQLAlchemy 'before_cursor_execute' hook (attached to all 3 engines):
    records which table an INSERT/UPDATE/DELETE touched. Fires for every
    statement (reads included), so non-write statements are ignored quickly via
    the regex miss. Skipped entirely while this thread is inside
    _execute_replicate_changes()'s own sync writes."""
    if getattr(_replication_write_in_progress, "active", False):
        return
    m = _WRITE_STMT_TABLE_RE.match(statement)
    if m:
        with _dirty_tables_lock:
            _dirty_tables.add(m.group(1))
    elif statement.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
        # A write we couldn't confidently parse the table name from -- fail safe.
        with _dirty_tables_lock:
            _dirty_tables.add("*")

def _execute_replicate_changes():
    """Actual synchronous replication work to target engines. Only wipes+reinserts
    tables that were actually written to since the last successful cycle (see
    _dirty_tables above) instead of unconditionally doing all ~15 tables every
    time -- most single commits only touch 1-2 tables (e.g. findings or
    audit_checkpoints), not the whole schema."""
    global promoted_master_engine
    if engine_master is None or engine_slave1 is None or engine_slave2 is None:
        return

    # Determine source and target engines
    if promoted_master_engine is None:
        targets = [("Slave 1", engine_slave1), ("Slave 2", engine_slave2)]
        src_engine = engine_master
    else:
        # Slave 1 is promoted to master, replicate only to Slave 2
        targets = [("Slave 2", engine_slave2)]
        src_engine = engine_slave1

    import concurrent.futures

    # Snapshot what's dirty for THIS cycle. Anything that gets marked dirty
    # while this cycle is still running (by a concurrent write) is NOT in this
    # snapshot and will simply still be in _dirty_tables afterward -- caught by
    # the next cycle, never lost.
    with _dirty_tables_lock:
        dirty_snapshot = set(_dirty_tables)

    if "*" in dirty_snapshot:
        tables_to_sync = list(Base.metadata.sorted_tables)
    else:
        tables_to_sync = [t for t in Base.metadata.sorted_tables if t.name in dirty_snapshot]

    if not tables_to_sync:
        return  # Nothing changed since the last successful cycle -- nothing to do.

    replication_errors = {}

    def sync_to_target(target_name, target_engine):
        try:
            _replication_write_in_progress.active = True
            with target_engine.begin() as dest_conn:
                # Disable constraints and triggers on target
                dest_conn.execute(text("SET session_replication_role = 'replica';"))

                with src_engine.connect() as src_conn:
                    # Clean existing rows on target in reverse-dependency order
                    # using DELETE FROM instead of TRUNCATE TABLE CASCADE to avoid AccessExclusiveLocks.
                    # This prevents deadlock conflicts with active reader transactions.
                    # Restricted to tables_to_sync (the dirty subset) -- FK constraint
                    # checking is already disabled above (session_replication_role =
                    # 'replica'), so skipping untouched tables here is safe and
                    # doesn't risk a dependency-ordering issue.
                    for table in reversed(tables_to_sync):
                        dest_conn.execute(text(f'DELETE FROM "{table.name}";'))

                    for table in tables_to_sync:
                        table_name = table.name
                        # Read all rows from source
                        rows = src_conn.execute(text(f'SELECT * FROM "{table_name}"')).fetchall()

                        if rows:
                            # Construct INSERT
                            columns = rows[0]._fields if hasattr(rows[0], '_fields') else list(rows[0].keys())
                            col_names = ", ".join(f'"{col}"' for col in columns)
                            placeholders = ", ".join(f":{col}" for col in columns)
                            if "id" in columns:
                                update_cols = ", ".join(f'"{col}" = EXCLUDED."{col}"' for col in columns if col != "id")
                                if update_cols:
                                    insert_sql = text(f'INSERT INTO "{table_name}" ({col_names}) VALUES ({placeholders}) ON CONFLICT ("id") DO UPDATE SET {update_cols}')
                                else:
                                    insert_sql = text(f'INSERT INTO "{table_name}" ({col_names}) VALUES ({placeholders}) ON CONFLICT ("id") DO NOTHING')
                            else:
                                insert_sql = text(f'INSERT INTO "{table_name}" ({col_names}) VALUES ({placeholders})')

                            data = [dict(row._mapping) for row in rows]
                            dest_conn.execute(insert_sql, data)

                            # Reset sequence if id column is present
                            if "id" in columns:
                                try:
                                    seq_sql = text(f"SELECT setval(pg_get_serial_sequence('\"{table_name}\"', 'id'), coalesce(max(id), 1)) FROM \"{table_name}\";")
                                    dest_conn.execute(seq_sql)
                                except Exception:
                                    pass

                dest_conn.execute(text("SET session_replication_role = 'origin';"))
            print(f"[REPLICATION SUCCESS] Synced Master -> {target_name} ({len(tables_to_sync)} table(s): {', '.join(t.name for t in tables_to_sync)})")
            with slaves_health_lock:
                slaves_health[target_name] = True
        except Exception as e:
            print(f"[REPLICATION ERROR] Failed to sync to {target_name}: {e}")
            with slaves_health_lock:
                slaves_health[target_name] = False
            replication_errors[target_name] = str(e)
            _log_db_event(
                "REPLICATION_ERROR",
                meta={"target": target_name, "error": str(e)[:300]},
                severity="CRITICAL"
            )
        finally:
            _replication_write_in_progress.active = False

    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
            futures = [executor.submit(sync_to_target, name, eng) for name, eng in targets]
            concurrent.futures.wait(futures)

    if replication_errors:
        raise RuntimeError(f"Replication failed on targets: {replication_errors}")

    # Only clear the tables we just successfully synced to EVERY target this
    # cycle -- not the whole dirty set, in case something new was marked dirty
    # by a concurrent write while this cycle was still running.
    with _dirty_tables_lock:
        if "*" in dirty_snapshot:
            _dirty_tables.difference_update(dirty_snapshot)
        else:
            _dirty_tables.difference_update(t.name for t in tables_to_sync)


def _replication_worker_loop():
    global _replication_pending_flag
    while True:
        task = _replication_queue.get()
        if task is None:
            break
        
        # Debounce briefly to coalesce multiple rapid commits
        time.sleep(0.1)
        
        with _replication_flag_lock:
            _replication_pending_flag = False
            
        try:
            _execute_replicate_changes()
        except Exception as e:
            print(f"[ASYNC REPLICATION WARNING] Background replication task failed: {e}", flush=True)
            
        _replication_queue.task_done()

# Start background daemon thread
_replicate_worker = threading.Thread(target=_replication_worker_loop, daemon=True)
_replicate_worker.start()


def replicate_changes():
    """Asynchronously triggers database replication to slave engines."""
    global _replication_pending_flag, engine_master
    # No-op for SQLite
    if engine_master is not None and engine_master.dialect.name == "sqlite":
        return
    with _replication_flag_lock:
        if _replication_pending_flag:
            return
        _replication_pending_flag = True
    
    _replication_queue.put(True)

def reconcile_schemas(engine):
    """
    Checks if existing tables match the required SQLAlchemy models.
    If a table is missing expected columns, it drops the table so create_all can recreate it correctly.
    """
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables_to_check = [
        "users", "audit_reports", "findings", "evidence_files",
        "audit_records", "compliance_scores", "document_chunks",
        "auditor_feedback", "audit_trail", "system_events",
        "chat_messages", "custom_controls", "license_wallets",
        "token_usage_logs", "admin_audit_logs",
        "audit_checkpoints",   # ← per-control checkpoint columns
    ]
    
    # We want to check columns for each table
    for table_name in tables_to_check:
        if inspector.has_table(table_name):
            existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
            
            # Find the model class
            model_cls = None
            for mapper in Base.registry.mappers:
                if mapper.persist_selectable.name == table_name:
                    model_cls = mapper.class_
                    break
            
            if model_cls:
                # Get columns declared in model
                expected_cols = {col.name for col in model_cls.__table__.columns}
                migration_success = True  # default; only set False if ALTER TABLE fails
                
                # Check if all expected columns are in existing columns
                missing_cols = expected_cols - existing_cols
                if missing_cols:
                    print(f"[SCHEMA RECONCILIATION] Table '{table_name}' is missing columns {missing_cols}. Attempting safe migration (ALTER TABLE)...")
                    try:
                        with engine.begin() as conn:
                            for col_name in missing_cols:
                                col_obj = model_cls.__table__.columns[col_name]
                                type_str = str(col_obj.type)
                                if "VARCHAR" in type_str:
                                    type_str = "VARCHAR(300)" if "300" in type_str else ("VARCHAR(200)" if "200" in type_str else ("VARCHAR(100)" if "100" in type_str else "VARCHAR(50)"))
                                elif type_str == "INTEGER":
                                    type_str = "INTEGER"
                                elif type_str == "BOOLEAN":
                                    type_str = "BOOLEAN"
                                elif type_str == "TEXT":
                                    type_str = "TEXT"
                                elif "DATETIME" in type_str or "TIMESTAMP" in type_str:
                                    type_str = "TIMESTAMP"
                                elif "FLOAT" in type_str or "REAL" in type_str or "NUMERIC" in type_str:
                                    type_str = "FLOAT"
                                
                                default_clause = ""
                                if col_obj.default is not None:
                                    if hasattr(col_obj.default, 'arg'):
                                        if isinstance(col_obj.default.arg, bool):
                                            default_clause = f" DEFAULT {'TRUE' if col_obj.default.arg else 'FALSE'}"
                                        elif isinstance(col_obj.default.arg, (int, float, str)):
                                            default_clause = f" DEFAULT '{col_obj.default.arg}'"
                                
                                alter_sql = f'ALTER TABLE "{table_name}" ADD COLUMN "{col_name}" {type_str}{default_clause}'
                                print(f"[MIGRATION EXECUTE] {alter_sql}")
                                conn.execute(text(alter_sql))
                    except Exception as migrate_err:
                        print(f"[SCHEMA RECONCILIATION ERROR] ALTER TABLE migration failed for '{table_name}': {migrate_err}. Falling back to DROP/RECREATE...")
                        migration_success = False
                        
                # ── AUTO-WIDEN VARCHAR COLUMNS ──────────────────────────
                # Check if any existing VARCHAR columns need widening (PostgreSQL only)
                if engine.dialect.name != "sqlite":
                    try:
                        with engine.begin() as conn:
                            for col_name in existing_cols & expected_cols:
                                col_obj = model_cls.__table__.columns.get(col_name)
                                if col_obj is None:
                                    continue
                                model_type = col_obj.type
                                # Get current column info from inspector
                                db_col_info = None
                                for db_col in inspector.get_columns(table_name):
                                    if db_col["name"] == col_name:
                                        db_col_info = db_col
                                        break
                                if db_col_info is None:
                                    continue
                                db_type = db_col_info.get("type")
                                # Case 1: Model says Text but DB has VARCHAR → widen to TEXT
                                if isinstance(model_type, Text) and hasattr(db_type, 'length') and db_type.length is not None:
                                    alter_sql = f'ALTER TABLE "{table_name}" ALTER COLUMN "{col_name}" TYPE TEXT'
                                    print(f"[SCHEMA WIDEN] {alter_sql}")
                                    conn.execute(text(alter_sql))
                                # Case 2: Model says String(N) and DB has VARCHAR(M) where M < N → widen
                                elif isinstance(model_type, String) and model_type.length is not None:
                                    if hasattr(db_type, 'length') and db_type.length is not None:
                                        if db_type.length < model_type.length:
                                            alter_sql = f'ALTER TABLE "{table_name}" ALTER COLUMN "{col_name}" TYPE VARCHAR({model_type.length})'
                                            print(f"[SCHEMA WIDEN] {alter_sql}")
                                            conn.execute(text(alter_sql))
                    except Exception as widen_err:
                        print(f"[SCHEMA WIDEN WARNING] Failed to widen columns for '{table_name}': {widen_err}")

                if not migration_success:
                    # NEVER silently drop a table to "fix" a failed migration -- this used
                    # to run DROP TABLE ... CASCADE here, which deletes every row with no
                    # backup the instant an ALTER TABLE fails for ANY reason. Since
                    # reconcile_schemas() runs on every single app startup for every table
                    # (users, audit_reports, findings, evidence_files, ...), a single bad
                    # migration attempt permanently wiped the entire database on a routine
                    # restart -- confirmed in production: the users table was reduced to
                    # just a freshly-reseeded "admin" row, and audit_reports/findings/
                    # evidence_files were all emptied to 0 rows. Rename the table aside
                    # instead so create_all() can still build a correctly-shaped fresh
                    # table (self-healing preserved), but the old data is fully recoverable
                    # under the backup name rather than gone.
                    import time as _time
                    backup_name = f"{table_name}_backup_{int(_time.time())}"
                    try:
                        with engine.begin() as conn:
                            conn.execute(text(f'ALTER TABLE "{table_name}" RENAME TO "{backup_name}"'))
                        print(
                            f"[SCHEMA RECONCILIATION] Migration failed for '{table_name}' -- renamed the "
                            f"existing table to '{backup_name}' instead of dropping it. Its data is intact "
                            f"under that name; a fresh '{table_name}' will be created with the correct schema. "
                            f"Manual review/data-copy from '{backup_name}' is recommended.",
                            flush=True
                        )
                    except Exception as rename_err:
                        print(
                            f"[SCHEMA RECONCILIATION ERROR] Could not rename '{table_name}' aside either "
                            f"({rename_err}). Leaving the table exactly as-is rather than risk data loss -- "
                            f"the missing column(s) may need a manual migration.",
                            flush=True
                        )

def _resolve_bootstrap_admin_credentials():
    """
    Resolves the password hash and TOTP secret used to seed the default admin
    account the first time the users table is empty. This runs at module
    import time (before src.core.auth.seed_default_admin ever gets a chance
    to run), so it must not defer to that function -- doing so here would
    create a circular import against this module. The logic is intentionally
    duplicated in a minimal, self-contained form instead.

    Never falls back to a hardcoded password or TOTP secret -- both were once
    literal strings in source control ("admin123" and a fixed TOTP secret),
    which is a full authentication bypass for anyone who reads the repo.
    """
    import bcrypt
    import secrets
    import string
    import pyotp

    password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "").strip()
    if not password:
        upper, lower, digit = string.ascii_uppercase, string.ascii_lowercase, string.digits
        special = "!@#$%^&*()_+-="
        required = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digit), secrets.choice(special)]
        pool = upper + lower + digit + special
        chars = required + [secrets.choice(pool) for _ in range(16)]
        secrets.SystemRandom().shuffle(chars)
        password = "".join(chars)
        print(
            "=" * 70 + "\n"
            "[INIT DB] ADMIN_DEFAULT_PASSWORD not set -- generated a random admin "
            f"password:\n\n    {password}\n\n"
            "SAVE THIS NOW, it will not be shown again. Set ADMIN_DEFAULT_PASSWORD "
            "explicitly for future deployments.\n" + "=" * 70,
            flush=True
        )
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    totp_secret = os.environ.get("ADMIN_TOTP_SECRET", "").strip() or pyotp.random_base32()
    return pw_hash, totp_secret


def init_db():
    global engine_master, engine_slave1, engine_slave2, db_label
    
    try:
        # Initialize connection engines for the master and slave databases first (lazy connections)
        eng_m = create_engine(
            "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_master",
            connect_args={"connect_timeout": 3},
            pool_pre_ping=True
        )
        eng_s1 = create_engine(
            "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_slave1",
            connect_args={"connect_timeout": 3},
            pool_pre_ping=True
        )
        eng_s2 = create_engine(
            "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_slave2",
            connect_args={"connect_timeout": 3},
            pool_pre_ping=True
        )

        # Attach dirty-table tracking to all 3 engines -- not just eng_m -- so
        # writes still get tracked after a failover promotes Slave 1 to master
        # (application writes then route through eng_s1 instead of eng_m).
        from sqlalchemy import event as _sa_event
        for _eng in (eng_m, eng_s1, eng_s2):
            _sa_event.listen(_eng, "before_cursor_execute", _track_write_statement)

        # Quick check if database and tables already exist and are initialized.
        # Retried with backoff instead of failing on the first attempt: after an
        # unclean shutdown (e.g. the terminal window closed while a scan was
        # running, or Docker itself restarting), Postgres can need real time on
        # its next start to replay its WAL and finish crash recovery. A single
        # failed connection attempt during that window looks identical to "this
        # database doesn't exist" to the bare except below -- which used to fall
        # straight through to the bootstrap path further down and recreate
        # shakthidb_master from scratch, discarding every table's data, even
        # though the real database was still there and just not ready yet. This
        # is the most likely explanation for the DB being found completely
        # empty on 2026-08-15 with no prior warning.
        _last_connect_err = None
        for _attempt in range(8):
            try:
                with eng_m.connect() as conn:
                    conn.execute(text("SELECT 1 FROM users LIMIT 1"))
                if _attempt > 0:
                    print(f"[DATABASE] Connected to ShaktiDB after {_attempt} retr{'y' if _attempt == 1 else 'ies'} "
                          f"(likely still finishing startup/recovery) -- proceeding normally, NOT bootstrapping.", flush=True)
                # Database and tables exist, skip bootstrap but ALWAYS run reconcile_schemas to ensure columns exist
                engine_master = eng_m
                engine_slave1 = eng_s1
                engine_slave2 = eng_s2
                db_label = "ShaktiDB"

                reconcile_schemas(eng_m)
                reconcile_schemas(eng_s1)
                reconcile_schemas(eng_s2)

                Base.metadata.create_all(bind=eng_m)
                Base.metadata.create_all(bind=eng_s1)
                Base.metadata.create_all(bind=eng_s2)
                return eng_m, "ShaktiDB"
            except Exception as _connect_err:
                _last_connect_err = _connect_err
                if _attempt < 7:
                    time.sleep(1.5)
                continue
        print(f"[DATABASE WARNING] Could not connect to ShaktiDB after 8 retries (~12s): {_last_connect_err}. "
              f"Proceeding to check whether it needs bootstrapping.", flush=True)

        # Fallback: Bootstrapping and schema creation
        # Connect to the default 'shakthidb' database on port 15234 to bootstrap databases if they do not exist
        try:
            bootstrap_eng = create_engine(
                "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb",
                connect_args={"connect_timeout": 3},
                pool_pre_ping=True
            )
            with bootstrap_eng.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
                for db_name in ["shakthidb_master", "shakthidb_slave1", "shakthidb_slave2"]:
                    try:
                        c.execute(text(f"CREATE DATABASE {db_name}"))
                    except Exception:
                        pass
            bootstrap_eng.dispose()
        except Exception as bootstrap_err:
            print(f"[DATABASE BOOTSTRAP WARNING] Could not bootstrap databases: {bootstrap_err}")
        
        # Reconcile schemas and create tables on all engines
        reconcile_schemas(eng_m)
        reconcile_schemas(eng_s1)
        reconcile_schemas(eng_s2)
        
        Base.metadata.create_all(bind=eng_m)
        Base.metadata.create_all(bind=eng_s1)
        Base.metadata.create_all(bind=eng_s2)
        
        engine_master = eng_m
        engine_slave1 = eng_s1
        engine_slave2 = eng_s2
        db_label = "ShaktiDB"
        
        # Run user role migration
        try:
            migrated = False
            with eng_m.begin() as conn:
                # Rename 'reviewer' role to 'auditee'
                res = conn.execute(text("SELECT count(*) FROM users WHERE role = 'reviewer'")).scalar()
                if res and res > 0:
                    conn.execute(text("UPDATE users SET role = 'auditee' WHERE role = 'reviewer'"))
                    migrated = True
            if migrated:
                replicate_changes()
        except Exception as e:
            print(f"[INIT DB MIGRATION WARNING] Failed to migrate user roles: {e}")
            
        # Seed default admin if missing or if totp_secret is empty
        try:
            admin_seeded_or_updated = False
            with eng_m.begin() as conn:
                admin = conn.execute(text("SELECT id, totp_secret FROM users WHERE username = 'admin'")).first()
                if not admin:
                    admin_pw_hash, admin_totp_secret = _resolve_bootstrap_admin_credentials()
                    conn.execute(
                        text("INSERT INTO users (username, password_hash, role, totp_secret) VALUES ('admin', :pw_hash, 'admin', :totp_secret)"),
                        {"pw_hash": admin_pw_hash, "totp_secret": admin_totp_secret}
                    )
                    admin_seeded_or_updated = True
                    print("[INIT DB] Seeded default admin user with TOTP secret.")
                elif not admin[1]:  # admin.totp_secret is index 1
                    admin_totp_secret = os.environ.get("ADMIN_TOTP_SECRET", "").strip()
                    if not admin_totp_secret:
                        import pyotp as _pyotp
                        admin_totp_secret = _pyotp.random_base32()
                    conn.execute(
                        text("UPDATE users SET totp_secret = :totp_secret WHERE username = 'admin'"),
                        {"totp_secret": admin_totp_secret}
                    )
                    admin_seeded_or_updated = True
                    print("[INIT DB] Updated default admin user with TOTP secret.")
            if admin_seeded_or_updated:
                replicate_changes()
        except Exception as e:
            print(f"[INIT DB ADMIN SEEDING WARNING] Failed to seed default admin: {e}")
            
        return eng_m, "ShaktiDB"

    except Exception as pg_err:
        # REQUIRE_POSTGRES is set for every containerized deployment (see
        # docker-compose.yml / docker-compose.customer.yml) -- the customer bundle
        # must never silently land audit data in a throwaway container-local
        # SQLite file. Unset (native/dev runs), behavior below is unchanged.
        if os.environ.get("REQUIRE_POSTGRES"):
            raise
        print(f"[DATABASE WARNING] PostgreSQL/ShaktiDB is offline or unreachable: {pg_err}. Auto-switching to local SQLite fallback database...", flush=True)
        os.makedirs("data/sqlite", exist_ok=True)
        sqlite_path = "data/sqlite/shakthidb_sqlite.db"
        eng_sqlite = create_engine(
            f"sqlite:///{sqlite_path}",
            connect_args={
                "timeout": 30,          # FIX: wait up to 30s for DB lock (was 15s)
                "check_same_thread": False  # FIX: allow multi-thread access from FastAPI workers
            }
        )
        try:
            with eng_sqlite.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL;"))
                conn.execute(text("PRAGMA busy_timeout=30000;"))
                conn.execute(text("PRAGMA synchronous=NORMAL;"))
        except Exception:
            pass
        reconcile_schemas(eng_sqlite)
        Base.metadata.create_all(bind=eng_sqlite)
        engine_master = eng_sqlite
        engine_slave1 = eng_sqlite
        engine_slave2 = eng_sqlite
        db_label = "SQLite (Fallback)"
        
        try:
            with eng_sqlite.begin() as conn:
                admin = conn.execute(text("SELECT id FROM users WHERE username = 'admin'")).first()
                if not admin:
                    admin_pw_hash, admin_totp_secret = _resolve_bootstrap_admin_credentials()
                    conn.execute(
                        text("INSERT INTO users (username, password_hash, role, totp_secret) VALUES ('admin', :pw_hash, 'admin', :totp_secret)"),
                        {"pw_hash": admin_pw_hash, "totp_secret": admin_totp_secret}
                    )
                    print("[INIT DB SQLite] Seeded default admin user with TOTP secret in SQLite fallback.", flush=True)
        except Exception as seed_err:
            print(f"[INIT DB SQLite WARNING] Failed to seed SQLite admin: {seed_err}", flush=True)
            
        return eng_sqlite, "SQLite (Fallback)"

# Initialize single global connection layout
engine, db_label = init_db()

# ── ROUTING SESSION & SYNCHRONOUS REPLICATION ────────────────────────────────
class RoutingSession(Session):
    def get_bind(self, mapper=None, clause=None, **kw):
        global promoted_master_engine, engine_master
        if engine_master is not None and engine_master.dialect.name == "sqlite":
            return engine_master
            
        # Identify if current statement is a WRITE operation
        is_write = False
        if self._flushing:
            is_write = True
        elif clause is not None:
            from sqlalchemy.sql.expression import Insert, Update, Delete
            if isinstance(clause, (Insert, Update, Delete)):
                is_write = True
                
        # Force MASTER routing on WRITE or explicit context flag
        if is_write or getattr(_routing_state, "force_master", False):
            if promoted_master_engine is not None:
                return promoted_master_engine
            return engine_master
            
        # READ operations: Load-balance across healthy active replicas
        with slaves_health_lock:
            healthy_slaves = []
            if promoted_master_engine is None:
                if slaves_health.get("Slave 1"):
                    healthy_slaves.append(engine_slave1)
                if slaves_health.get("Slave 2"):
                    healthy_slaves.append(engine_slave2)
            else:
                if slaves_health.get("Slave 2"):
                    healthy_slaves.append(engine_slave2)
                    
        # Fallback to master/active replica if all are marked unhealthy
        if not healthy_slaves:
            if promoted_master_engine is not None:
                return promoted_master_engine
            return engine_master
            
        return random.choice(healthy_slaves)

    def commit(self):
        global promoted_master_engine
        try:
            super().commit()
            replicate_changes()
        except Exception as e:
            # Automated Failover: only promote Slave 1 to Master for genuine
            # connectivity/operational failures (can't reach the server, connection
            # lost, timeout) -- previously ANY exception except one containing the
            # literal substring "Replication failed" triggered promotion, including
            # ordinary data-level errors (a UNIQUE constraint violation from two
            # near-simultaneous writes, a deadlock, etc.) that are expected in
            # normal operation and have nothing to do with master health. That
            # turned a routine write conflict into a permanent, silent failover to
            # what was a read replica -- whose async/debounced replication could be
            # stale at that exact moment.
            from sqlalchemy.exc import OperationalError, InterfaceError
            if isinstance(e, (OperationalError, InterfaceError)):
                if promoted_master_engine is None and engine_master is not None and engine_master.dialect.name != "sqlite":
                    print(f"[FAILOVER PROMOTION] Master database write failed: {e}. Promoting Slave 1 to Master...")
                    promoted_master_engine = engine_slave1
                    # Log the failover event
                    _log_db_event(
                        "FAILOVER",
                        meta={"error": str(e)[:300], "action": "Slave 1 promoted to Master"},
                        severity="CRITICAL"
                    )
                    try:
                        self.rollback()
                    except Exception:
                        pass
            raise e

SessionLocal = sessionmaker(class_=RoutingSession)


def get_db_session():
    """Returns a new RoutingSession instance bound to the active engine.
    Caller is responsible for session.close().
    Usage::
        session = get_db_session()
        try:
            ...do work...
            session.commit()
        finally:
            session.close()
    """
    session = SessionLocal()
    session.bind = engine
    return session


def purge_old_logs(days=90):
    """
    Purges SystemEvent rows older than `days` days from the database.
    """
    from datetime import datetime, timedelta
    cutoff = datetime.now() - timedelta(days=days)
    db = SessionLocal()
    try:
        with force_master():
            deleted_count = db.query(SystemEvent).filter(SystemEvent.created_at < cutoff).delete()
            db.commit()
            return deleted_count
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


# ── CUSTOM CONTROLS CRUD ──────────────────────────────────────────────────────

def get_all_custom_controls(active_only: bool = True) -> list:
    """Returns all auditor-defined custom controls from the DB as dicts.

    Routed to the master engine (not a possibly-lagging replica) because the
    caller in controls.py reloads this list immediately after every
    create/update/delete -- a replica read here could momentarily miss a
    control the auditor just saved.
    """
    import json as _json
    with force_master():
        db = SessionLocal()
        try:
            q = db.query(CustomControl)
            if active_only:
                q = q.filter(CustomControl.is_active == True)
            rows = q.order_by(CustomControl.control_id).all()
            result = []
            for r in rows:
                result.append({
                    "id":             r.id,
                    "control_id":     r.control_id,
                    "control_name":   r.control_name,
                    "framework":      r.framework or "ISO 27001",
                    "category":       r.category,
                    "description":    r.description or "",
                    "keywords":       _json.loads(r.keywords_json) if r.keywords_json else [],
                    "auto_generated": r.auto_generated,
                    "is_active":      r.is_active,
                    "is_global":      r.is_global,
                    "created_by":     r.created_by or "unknown",
                    "created_at":     str(r.created_at),
                })
            return result
        finally:
            db.close()


def add_custom_control(control_id: str, control_name: str, category: str,
                       keywords: list, description: str = "",
                       auto_generated: bool = False, created_by: str = "auditor",
                       is_global: bool = True, framework: str = "ISO 27001") -> int:
    """Inserts a new CustomControl row. Returns the new row id."""
    import json as _json
    db = SessionLocal()
    try:
        with force_master():
            row = CustomControl(
                control_id=control_id.strip(),
                control_name=control_name.strip(),
                framework=(framework or "ISO 27001").strip(),
                category=category.strip(),
                description=description.strip(),
                keywords_json=_json.dumps([k.lower().strip() for k in keywords if k.strip()]),
                auto_generated=auto_generated,
                is_global=is_global,
                created_by=created_by,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            return row.id
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def update_custom_control(control_db_id: int, keywords: list = None,
                          description: str = None, is_active: bool = None,
                          framework: str = None, category: str = None) -> bool:
    """Updates keywords, description, framework/category, or active status of an existing custom control."""
    import json as _json
    db = SessionLocal()
    try:
        with force_master():
            row = db.query(CustomControl).filter(CustomControl.id == control_db_id).first()
            if not row:
                return False
            if keywords is not None:
                row.keywords_json = _json.dumps([k.lower().strip() for k in keywords if k.strip()])
                row.auto_generated = False  # manual update clears auto flag
            if description is not None:
                row.description = description
            if framework is not None:
                row.framework = framework
            if category is not None:
                row.category = category
            if is_active is not None:
                row.is_active = is_active
            db.commit()
            return True
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def delete_custom_control(control_db_id: int, soft: bool = True) -> bool:
    """Soft-deletes (deactivates) or hard-deletes a custom control."""
    db = SessionLocal()
    try:
        with force_master():
            row = db.query(CustomControl).filter(CustomControl.id == control_db_id).first()
            if not row:
                return False
            if soft:
                row.is_active = False
            else:
                db.delete(row)
            db.commit()
            return True
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

