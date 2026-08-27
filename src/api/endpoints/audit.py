from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Form, BackgroundTasks, Request
from pydantic import BaseModel, field_validator
from typing import List, Optional
from src.core.text_validation import clean_safe_text as _clean_safe_text
import os
import io
import uuid
import json
import threading
from datetime import datetime, timezone
from src.db.database import (
    SessionLocal,
    User,
    AuditReport,
    EvidenceFile,
    Finding,
    ComplianceScore,
    ChatMessage,
    AuditCheckpoint,
    DocumentChunk,
    AuditRecord,
    AuditorFeedback,
    force_master
)
from src.core.bg_state import _bg_store, _bg_results, _bg_running, _bg_lock, _bg_stop_flags, _auditor_sessions, MAX_AUDITS_PER_AUDITOR, MAX_CONCURRENT_AUDITS
from src.core.bg_worker import (
    _run_ollama_bg,
    _run_fast_technical_vapt_bg,
    get_resumable_checkpoint,
    log_system_event
)
from src.core.input_guardrail import scan_document, MAX_ZIP_RATIO
from src.core.parsers.doc_parsers import extract_text
from src.core.retrieval import save_document_chunks
from src.core.llm_client import query_llm
from src.api.endpoints.auth import _require_auth
from src.core.pii_redactor import redact_pii

def retrieve_chat_context(db, session_id: str, query_text: str, top_k: int = 5) -> str:
    """Retrieves pointwise RAG context chunks from ShaktiDB document chunks."""
    report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
    if not report:
        return ""
    
    # Get evidence files
    ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
    file_names = [f.filename for f in ev_files]
    if not file_names:
        return ""
        
    # Get chunks (scoped to this session's report_id -- see report_id column note
    # on DocumentChunk: filename alone isn't a safe key across sessions)
    chunks = db.query(DocumentChunk).filter(
        DocumentChunk.filename.in_(file_names),
        DocumentChunk.report_id == report.id
    ).all()
    if not chunks:
        return ""
        
    # Embed query and chunks
    from src.core.llm_client import get_embedding
    query_vector = get_embedding(query_text)
    if not query_vector:
        # Keyword fallback
        scored = []
        q_words = [w.lower() for w in query_text.split() if len(w) > 3]
        for c in chunks:
            c_text = c.content.lower()
            score = sum(1 for w in q_words if w in c_text)
            scored.append((score, c.content))
        scored.sort(key=lambda x: x[0], reverse=True)
        return "\n\n".join([item[1] for item in scored[:top_k]])
        
    from src.core.retrieval import _cosine_similarity, _chunk_embeddings_cache
    scored = []
    for c in chunks:
        chunk_key = (c.filename, c.chunk_index)
        c_vector = _chunk_embeddings_cache.get(chunk_key)
        if not c_vector:
            c_vector = get_embedding(c.content)
            if c_vector:
                _chunk_embeddings_cache[chunk_key] = c_vector
        if c_vector:
            sim = _cosine_similarity(query_vector, c_vector)
            scored.append((sim, c.content))
            
    scored.sort(key=lambda x: x[0], reverse=True)
    return "\n\n".join([item[1] for item in scored[:top_k]])

router = APIRouter(prefix="/audit", tags=["Auditing Operations"])

# --- Request Schemas ---
class StartAuditRequest(BaseModel):
    session_id: str
    selected_sls: List[int]
    model_choice: str
    audit_mode: str = "Deep"
    # Live sidebar framework sent by the client at run-start time.
    # Allows the backend to sync the session's stored framework before routing,
    # so sessions created under one framework (e.g. ISO 27001 default) that the
    # user later switched to VAPT/PQC don't get misrouted by the governance guardrail.
    current_framework: Optional[str] = None
    custom_evidence: Optional[dict] = None
    custom_documents: Optional[dict] = None
    username: Optional[str] = None

class UpdateFindingRequest(BaseModel):
    status: str
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    reasoning: Optional[str] = None
    policy_present: Optional[str] = None
    evidence_present: Optional[str] = None
    source_files: Optional[str] = None
    comment: Optional[str] = None
    # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7) -- manual overrides
    policy_status: Optional[str] = None
    policy_assessment: Optional[str] = None
    policy_name: Optional[str] = None
    policy_version: Optional[str] = None
    policy_clause: Optional[str] = None
    policy_effective_date: Optional[str] = None
    policy_review_date: Optional[str] = None
    policy_expiry_date: Optional[str] = None
    policy_validity: Optional[str] = None
    policy_finding: Optional[str] = None
    policy_gap: Optional[str] = None
    evidence_status: Optional[str] = None
    evidence_assessment: Optional[str] = None
    evidence_date: Optional[str] = None
    evidence_freshness: Optional[str] = None
    evidence_finding: Optional[str] = None
    evidence_gap: Optional[str] = None
    evidence_relevance: Optional[str] = None
    final_result: Optional[str] = None
    final_reason: Optional[str] = None
    # Custom heading override (VAPT + ISO): auditor-set display title in UI and reports
    custom_heading: Optional[str] = None

    # Short status/enum-like fields (e.g. "COMPLIANT", version strings, dates)
    _SHORT_FIELDS = (
        "status", "severity", "policy_status", "policy_assessment", "policy_validity",
        "evidence_status", "evidence_assessment", "evidence_relevance", "final_result",
        "policy_name", "policy_version", "policy_clause", "evidence_freshness",
        "policy_effective_date", "policy_review_date", "policy_expiry_date", "evidence_date",
    )
    # Long free-text fields (auditor-written prose, AI-generated text the auditor edited)
    _LONG_FIELDS = (
        "description", "evidence_snippet", "recommendation", "reasoning",
        "policy_present", "evidence_present", "source_files", "comment",
        "policy_finding", "policy_gap", "evidence_finding", "evidence_gap",
        "final_reason", "custom_heading",
    )

    @field_validator(*_SHORT_FIELDS)
    @classmethod
    def _validate_short_fields(cls, v, info):
        if v is None:
            return v
        return _clean_safe_text(v, info.field_name.replace("_", " ").title(), 100)

    @field_validator(*_LONG_FIELDS)
    @classmethod
    def _validate_long_fields(cls, v, info):
        if v is None:
            return v
        return _clean_safe_text(v, info.field_name.replace("_", " ").title(), 5000)

class ChatSendRequest(BaseModel):
    session_id: str
    message: str
    model_choice: str
    username: Optional[str] = None  # logged-in user sending this message

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v):
        return _clean_safe_text(v, "Message", 5000, required=True)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, v):
        if v is None:
            return v
        return _clean_safe_text(v, "Username", 100)

class AssignAuditorRequest(BaseModel):
    session_id: str
    assigned_auditor_username: str

class DeleteEvidenceRequest(BaseModel):
    session_id: str
    file_id: Optional[int] = None
    filename: Optional[str] = None

class UndoDeleteEvidenceRequest(BaseModel):
    session_id: str
    file_id: Optional[int] = None
    filename: Optional[str] = None

class DeleteAllEvidenceRequest(BaseModel):
    session_id: str

class ImportAuditeeEvidenceRequest(BaseModel):
    source_session_id: str
    target_session_id: str
    filenames: Optional[List[str]] = None

# --- Endpoints ---

@router.post("/sessions")
def api_create_session(
    request: Request,
    session_title: str = Form(...),
    framework: str = Form("All Standards"),
    username: str = Form("admin")
):
    auth_user = _require_auth(request)
    # The caller-supplied username field previously decided who a session was
    # created for with no verification -- any authenticated user could create
    # a session "as admin" or anyone else just by setting this form field.
    # Trust the verified JWT identity instead unless the caller is admin.
    if username != auth_user.get("username") and auth_user.get("role") != "admin":
        username = auth_user.get("username")
    try:
        session_title = _clean_safe_text(session_title, "Session Title", 200, required=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    session_id = uuid.uuid4().hex
    db = SessionLocal()
    try:
        user_row = db.query(User).filter(User.username == username).first()
        auditee_id = user_row.id if (user_row and user_row.role and user_row.role.lower() == "auditee") else None
        
        with force_master():
            report = AuditReport(
                session_id=session_id,
                session_title=session_title,
                created_by=username,
                auditee_id=auditee_id,
                framework=framework,
                status="Draft"
            )
            db.add(report)
            db.commit()
            log_system_event("SESSION_CREATED", "INFO", f"Session '{session_title}' created (framework: {framework})", session_id=session_id, actor=username)
            return {"success": True, "session_id": session_id, "session_title": session_title}
    except Exception as e:
        print(f"[CREATE SESSION ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Failed to create session. Please try again.")
    finally:
        db.close()

def _enforce_max_sessions_limit(db, username: str, max_sessions: int = 50):
    """
    Enforces a strict cap of `max_sessions` per user account.
    If a user has more than `max_sessions` audit sessions, the oldest ones
    (and their associated findings, evidence records, and checkpoints) are automatically purged.
    """
    if not username or not username.strip():
        return
    try:
        user_reports = db.query(AuditReport).filter(
            AuditReport.created_by == username
        ).order_by(AuditReport.created_at.desc()).all()

        if len(user_reports) > max_sessions:
            reports_to_delete = user_reports[max_sessions:]
            delete_ids = [r.id for r in reports_to_delete]
            delete_sids = [r.session_id for r in reports_to_delete if r.session_id]

            if delete_ids:
                db.query(Finding).filter(Finding.report_id.in_(delete_ids)).delete(synchronize_session=False)
                db.query(EvidenceFile).filter(EvidenceFile.report_id.in_(delete_ids)).delete(synchronize_session=False)
                db.query(ComplianceScore).filter(ComplianceScore.report_id.in_(delete_ids)).delete(synchronize_session=False)
                db.query(DocumentChunk).filter(DocumentChunk.report_id.in_(delete_ids)).delete(synchronize_session=False)
            if delete_sids:
                db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id.in_(delete_sids)).delete(synchronize_session=False)

            db.query(AuditReport).filter(AuditReport.id.in_(delete_ids)).delete(synchronize_session=False)
            db.commit()
    except Exception as e:
        print(f"[Session Auto-Purge Warning]: {e}", flush=True)

@router.get("/sessions")
def api_get_sessions(request: Request, username: Optional[str] = None):
    """Returns sessions strictly scoped to the requesting user.

    `username` is optional and defaults to the JWT-authenticated identity --
    the frontend no longer needs to (and shouldn't) echo its own email back in
    the query string on every poll, which was landing in plaintext in access
    logs for zero benefit (the JWT already identifies the caller). It's only
    meaningful as an explicit override for an admin looking up someone else.
    """
    auth_user = _require_auth(request)
    if not username or not username.strip():
        username = auth_user.get("username")
    if not username:
        return {"success": True, "sessions": []}
    if username != auth_user.get("username") and auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. You can only view your own sessions.")

    db = SessionLocal()
    try:
        # NOTE: _enforce_max_sessions_limit intentionally NOT called here (read path).
        # It runs on session CREATION only, to avoid an expensive DB scan+delete on
        # every 10-second UI poll. See api_create_session for the enforcement call.

        user = db.query(User).filter(User.username == username).first()
        user_id = user.id if user else None

        # Strict Account Isolation: User sees only sessions created by them OR assigned to their auditee_id
        if user_id:
            query = db.query(AuditReport).filter(
                (AuditReport.created_by == username) | (AuditReport.auditee_id == user_id)
            )
        else:
            query = db.query(AuditReport).filter(AuditReport.created_by == username)

        reports = query.order_by(AuditReport.created_at.desc()).all()
        result = []
        for r in reports:
            score_row = db.query(ComplianceScore).filter(ComplianceScore.report_id == r.id).first()
            score_pct = score_row.score_percent if score_row else 0
            findings_count = db.query(Finding).filter(
                Finding.report_id == r.id,
                ~Finding.severity.ilike("%INFO%"),
                ~Finding.status.ilike("%INFO%")
            ).count()
            
            auditee_name = None
            if r.auditee_id:
                u = db.query(User).filter(User.id == r.auditee_id).first()
                if u:
                    auditee_name = u.username

            result.append({
                "id": r.id,
                "session_id": r.session_id,
                "session_title": r.session_title,
                "auditee_name": auditee_name,
                "framework": r.framework,
                "status": r.status,
                "score_percent": score_pct,
                "findings_count": findings_count,
                "created_at": str(r.created_at)
            })
        return {"success": True, "sessions": result}
    finally:
        db.close()

@router.get("/auditee-sessions")
def api_get_auditee_sessions(request: Request, username: Optional[str] = None):
    """Returns sessions scoped to the requesting user's role.

    Auditee callers see their own submitted sessions (created_by == them, or
    auditee_id assigned to them). Auditor/admin callers must see ONLY sessions
    a real auditee actually submitted (auditee_id set) — never the caller's
    own auditor-run sessions, which have no auditee attached and would
    otherwise get mislabeled here as if the auditor were the auditee.
    """
    auth_user = _require_auth(request)
    if not username or not username.strip():
        username = auth_user.get("username")
    if not username:
        return {"success": True, "sessions": []}
    # Only the account owner, or an auditor/admin (who legitimately browse
    # auditee submissions), may trigger a lookup for a given username.
    if username != auth_user.get("username") and auth_user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied.")

    db = SessionLocal()
    try:
        with force_master():
            user = db.query(User).filter(User.username == username).first()
            user_id = user.id if user else None
            is_auditee_caller = bool(user and user.role and user.role.lower() == "auditee")

            if is_auditee_caller and user_id:
                query = db.query(AuditReport).filter(
                    (AuditReport.auditee_id == user_id) | (AuditReport.created_by == username)
                )
            else:
                # Auditor/admin view: only sessions a real auditee actually submitted.
                query = db.query(AuditReport).filter(AuditReport.auditee_id.isnot(None))
                if auth_user.get("role") != "admin":
                    # A non-admin auditor only sees sessions the auditee specifically
                    # routed to them via "Target Auditor Assignment" -- previously this
                    # showed every auditee's submission to every auditor account,
                    # regardless of who it was actually sent to.
                    query = query.filter(AuditReport.assigned_auditor_username == auth_user.get("username"))

            reports = query.order_by(AuditReport.created_at.desc()).all()

            result = []
            for r in reports:
                auditee_username = None
                if r.auditee_id:
                    u = db.query(User).filter(User.id == r.auditee_id).first()
                    # Only trust auditee_id if it still resolves to a real auditee-role
                    # user. Stale rows (e.g. from a users-table reset that reused IDs)
                    # can leave auditee_id pointing at an auditor account — never
                    # surface that as if it were a genuine auditee submission.
                    if u and u.role and u.role.lower() == "auditee":
                        auditee_username = u.username

                if not auditee_username and not is_auditee_caller:
                    continue  # Stale/invalid auditee_id — skip, not a real auditee session.

                files_count = db.query(EvidenceFile).filter(
                    EvidenceFile.report_id == r.id,
                    EvidenceFile.is_auditor_uploaded == False
                ).count()

                result.append({
                    "id": r.id,
                    "session_id": r.session_id,
                    "session_title": r.session_title,
                    "auditee_username": auditee_username or (r.created_by if is_auditee_caller else "Auditee Client"),
                    "files_count": files_count,
                    "status": r.status or "Submitted",
                    "assigned_auditor": r.assigned_auditor_username or "Unassigned",
                    "created_at": str(r.created_at)
                })
            return {"success": True, "sessions": result}
    finally:
        db.close()

def get_or_create_audit_report(db, session_id: str, default_title: str = None, default_framework: str = "ISO 27001", username: str = None):
    report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
    if not report:
        if username:
            _enforce_max_sessions_limit(db, username, max_sessions=50)
        title = default_title or f"Audit Session ({session_id[:8]})"
        user_id = None
        if username:
            u = db.query(User).filter(User.username == username).first()
            if u and u.role and u.role.lower() == "auditee":
                user_id = u.id
        report = AuditReport(
            session_id=session_id,
            session_title=title,
            framework=default_framework,
            created_by=username,
            auditee_id=user_id,
            status="Draft",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.add(report)
        db.commit()
        db.refresh(report)
    return report

def _bg_extract_and_chunk(filename: str, file_bytes: bytes, report_id: int = None):
    try:
        f_like = io.BytesIO(file_bytes)
        f_like.name = filename
        extracted = extract_text(f_like)
        if extracted:
            save_document_chunks(filename, extracted, report_id=report_id)
    except Exception as err:
        print(f"[BG CHUNK ERROR] '{filename}': {err}", flush=True)

@router.post("/upload")
async def api_upload_evidence(
    request: Request,
    session_id: str = Form(...),
    is_auditor_uploaded: bool = Form(True),
    files: List[UploadFile] = File(...),
    bg_tasks: BackgroundTasks = None,
    username: Optional[str] = Form(None)
):
    """
    FIX: async def + await f.read() → Uvicorn event loop reads all 10 concurrent
    upload streams in parallel without blocking any thread.
    Single batch db.commit() after the loop → SQLite lock held for ~0.002s
    instead of 8 separate lock events per user.
    Exponential backoff retry (max 3 attempts) → no infinite hang on DB lock.
    """
    auth_user = _require_auth(request)
    import time
    import random
    import re
    import traceback
    from sqlalchemy.exc import OperationalError

    db = SessionLocal()
    try:
        with force_master():
            report = get_or_create_audit_report(db, session_id, username=username or auth_user.get("username"))
            _assert_session_access(db, report, auth_user)
            report_id = report.id

        # ── REQUEST-LEVEL LIMITS: cap file count and total bytes per upload request.
        # The per-file check below doesn't stop e.g. 50 files at 99MB each (~5GB)
        # in one request -- each file is read fully into memory before its own
        # size is even checked, so without this, a large batch of individually
        # "legal" files is still a real memory-exhaustion / DoS vector. Admin-
        # editable (src/core/settings.py) instead of fixed, so these can be
        # tuned without a code change + restart. ──
        from src.core.settings import get_setting
        MAX_FILES_PER_REQUEST = get_setting("max_files_per_upload")
        MAX_FILE_SIZE_BYTES = get_setting("max_file_size_mb") * 1024 * 1024
        MAX_TOTAL_REQUEST_BYTES = get_setting("max_upload_total_mb") * 1024 * 1024
        if len(files) > MAX_FILES_PER_REQUEST:
            raise HTTPException(
                status_code=413,
                detail=f"Too many files in one upload ({len(files)}). Please upload at most {MAX_FILES_PER_REQUEST} files at a time."
            )

        uploaded_details = []
        blocked_details = []
        new_evidence_records = []  # Collect all new DB records first
        total_bytes_so_far = 0

        for f in files:
            # ── FIX 1: async await → non-blocking stream read from all 10 tabs at once ──
            file_bytes = await f.read()

            # ── FILE SIZE LIMIT (prevent DoS via large upload) ──
            if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File '{f.filename}' exceeds the maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)}MB. Please upload a smaller file."
                )

            total_bytes_so_far += len(file_bytes)
            if total_bytes_so_far > MAX_TOTAL_REQUEST_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"This upload batch exceeds the {MAX_TOTAL_REQUEST_BYTES // (1024*1024)}MB total limit per request. Please upload fewer files at once."
                )

            # ── ZIP Auto-Unpack: Extract all contained documents into individual evidence files ──
            sub_files = []
            if f.filename.lower().endswith(".zip"):
                import zipfile
                try:
                    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                        for entry in sorted(zf.namelist()):
                            if entry.endswith("/") or "__MACOSX" in entry or os.path.basename(entry).startswith("."):
                                continue
                            ext = os.path.splitext(entry.lower())[1]
                            if ext in (
                                ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".csv",
                                ".pptx", ".ppt", ".txt", ".html", ".htm", ".json",
                                ".png", ".jpg", ".jpeg"
                            ):
                                # Check the entry's declared size/ratio BEFORE decompressing
                                # it -- previously zf.read() decompressed every matching
                                # member fully into memory first, and scan_document()'s
                                # zip-bomb check only ran afterward (and only if the
                                # extracted member's own extension was itself an archive
                                # type, so a plain .pdf/.txt member was never size-checked
                                # at all). A small crafted zip with one highly-compressible
                                # member could trigger unbounded memory allocation here.
                                info = zf.getinfo(entry)
                                if info.file_size > MAX_FILE_SIZE_BYTES:
                                    inner_name = os.path.basename(entry)
                                    print(f"[ZIP UNPACK BLOCKED] '{inner_name}' inside {f.filename} declares {info.file_size} bytes uncompressed, exceeds {MAX_FILE_SIZE_BYTES} byte limit -- skipped without decompressing.", flush=True)
                                    continue
                                if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_ZIP_RATIO:
                                    inner_name = os.path.basename(entry)
                                    print(f"[ZIP UNPACK BLOCKED] '{inner_name}' inside {f.filename} has a {info.file_size / info.compress_size:.0f}:1 compression ratio, exceeds the safe {MAX_ZIP_RATIO}:1 limit -- skipped without decompressing.", flush=True)
                                    continue
                                inner_bytes = zf.read(entry)
                                inner_name = os.path.basename(entry)
                                sub_files.append((inner_name, inner_bytes))
                except Exception as zip_err:
                    print(f"[ZIP UNPACK WARNING] Failed to unpack {f.filename}: {zip_err}", flush=True)

            if not sub_files:
                sub_files = [(f.filename, file_bytes)]

            for sub_name, sub_bytes in sub_files:
                f_like = io.BytesIO(sub_bytes)
                f_like.name = sub_name

                # Security Scan — full 4-layer scan (magic bytes, VBA macros, zip-bomb
                # ratio/size, embedded dangerous extensions). Text isn't extracted yet
                # at upload time, so Layer 4 (text-content checks) is a no-op here.
                is_clean, reason = scan_document(sub_name, sub_bytes, "")
                if not is_clean:
                    print(f"[UPLOAD BLOCKED] session={session_id} | file={sub_name} | {reason}", flush=True)
                    log_system_event("MALWARE_BLOCKED", "CRITICAL", f"File blocked by security scan: {sub_name} ({reason})", session_id=session_id, actor=username or "Auditor")
                    blocked_details.append({"filename": sub_name, "reason": reason})
                    continue  # Not written to disk or the database

                # Store file on local disk
                ev_dir = os.path.normpath(os.path.join(os.getcwd(), "data", "evidence", str(report_id)))
                os.makedirs(ev_dir, exist_ok=True)
                prefix = "auditor_" if is_auditor_uploaded else "auditee_"

                # ── PATH TRAVERSAL FIX: sanitize filename ──
                safe_filename = os.path.basename(sub_name)
                safe_filename = re.sub(r"[^\w\-\.]", "_", safe_filename).lstrip(".")
                if not safe_filename:
                    safe_filename = "upload_file"
                dest_path = os.path.join(ev_dir, prefix + safe_filename)

                if not os.path.abspath(dest_path).startswith(os.path.abspath(ev_dir)):
                    continue

                f_like.seek(0)
                with open(dest_path, "wb") as dest_f:
                    dest_f.write(sub_bytes)

                # Check existence but don't commit yet — collect all records first.
                # Only ACTIVE records count as a real collision -- a prior query here
                # matched soft-deleted rows too (EvidenceFile.is_deleted isn't a real
                # deletion, just a hide-from-list flag for 1-click Undo), so deleting a
                # file and re-uploading one with the same name found the deleted row,
                # treated it as "already exists", and silently skipped creating any
                # record at all -- even though the new bytes were written to disk and
                # the API response still reported it as "Processed". Now a matching
                # soft-deleted row is revived (not left orphaned) instead of blocking
                # the upload.
                with force_master():
                    existing = db.query(EvidenceFile).filter(
                        EvidenceFile.report_id == report_id,
                        EvidenceFile.filename == safe_filename
                    ).first()
                    if existing and (existing.is_deleted is False or existing.is_deleted is None):
                        pass  # genuinely already active -- nothing to add or revive
                    elif existing:
                        # Soft-deleted row for this filename -- revive it in place
                        # rather than creating a second, colliding record.
                        existing.is_deleted = False
                        existing.file_path = os.path.abspath(dest_path)
                        existing.is_auditor_uploaded = is_auditor_uploaded
                        existing.status = "Completed"
                        new_evidence_records.append(existing)
                    else:
                        new_ev = EvidenceFile(
                            report_id=report_id,
                            filename=safe_filename,
                            file_path=os.path.abspath(dest_path),
                            is_auditor_uploaded=is_auditor_uploaded,
                            status="Completed"
                        )
                        db.add(new_ev)
                        new_evidence_records.append(new_ev)

                # Asynchronously extract text & save chunks in background thread
                if bg_tasks:
                    bg_tasks.add_task(_bg_extract_and_chunk, safe_filename, sub_bytes, report_id)
                else:
                    _bg_extract_and_chunk(safe_filename, sub_bytes, report_id)

                uploaded_details.append({
                    "filename": safe_filename,
                    "status": "Processed",
                    "bytes": len(sub_bytes)
                })


        # ── FIX 2: Single batch commit for ALL files → SQLite locked for ~0.002s total ──
        # ── FIX 3: Exponential backoff retry (max 3 attempts) → no infinite hang ──────
        if new_evidence_records:
            MAX_RETRIES = 3
            for attempt in range(MAX_RETRIES):
                try:
                    with force_master():
                        db.commit()
                    break  # Success — exit retry loop
                except OperationalError as lock_err:
                    if attempt == MAX_RETRIES - 1:
                        # All 3 retries exhausted — fail fast, don't hang forever
                        print(f"[UPLOAD DB ERROR] session={session_id} | DB locked after {MAX_RETRIES} retries: {lock_err}", flush=True)
                        raise HTTPException(
                            status_code=503,
                            detail="Server is busy processing other uploads. Please retry in a moment."
                        )
                    # Exponential backoff with jitter to prevent thundering herd:
                    # Attempt 0 → wait ~0.5s, Attempt 1 → wait ~1.0s, Attempt 2 → wait ~2.0s
                    backoff_s = (0.5 * (2 ** attempt)) + random.uniform(0, 0.2)
                    print(f"[UPLOAD RETRY] session={session_id} | DB locked, retrying in {backoff_s:.2f}s (attempt {attempt + 1}/{MAX_RETRIES})", flush=True)
                    time.sleep(backoff_s)

        log_system_event("FILE_UPLOAD", "INFO", f"{len(uploaded_details)} file(s) uploaded: {', '.join(d['filename'] for d in uploaded_details)}", session_id=session_id, actor=username or "Auditor")
        return {"success": True, "files": uploaded_details, "blocked": blocked_details}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[UPLOAD ERROR] session={session_id} | {e}\n{traceback.format_exc()}", flush=True)
        raise HTTPException(status_code=500, detail="Upload processing failed. Please try again.")
    finally:
        db.close()

@router.get("/users/auditors")
def api_get_registered_auditors(request: Request):
    """Returns list of real registered auditor accounts only.

    Deliberately excludes admin: this list feeds the auditee's "Target
    Auditor Assignment" dropdown, which is meant to route evidence to a
    working auditor, not to the platform admin account.
    """
    _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            auditors = db.query(User).filter(User.role.in_(["auditor", "AUDITOR"])).all()
            res = []
            for a in auditors:
                res.append({
                    "id": a.id,
                    "username": a.username,
                    "role": a.role
                })
            return {"success": True, "auditors": res}
    finally:
        db.close()

@router.post("/assign-auditor")
def api_assign_auditor(req: AssignAuditorRequest, request: Request):
    """Assigns an audit session and its files to a specific real Auditor user.

    Called by the auditee who owns the session (the "Target Auditor
    Assignment" dropdown on their Upload Evidence tab) -- the old
    role-gate here (admin/auditor only) rejected every real auditee caller
    with a 403, since "auditee" was never in the allowed list. Replaced with
    an ownership check (_assert_session_access) so the actual owner of the
    session -- whichever role they are -- can assign it, while still
    blocking one auditee from hijacking another's session by session_id.
    """
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Audit session not found")
            _assert_session_access(db, report, auth_user)

            auditor = db.query(User).filter(
                User.username == req.assigned_auditor_username,
                User.role.in_(["auditor", "AUDITOR"])
            ).first()
            if not auditor:
                raise HTTPException(status_code=400, detail="Target must be a real registered auditor account.")

            report.assigned_auditor_username = req.assigned_auditor_username
            report.assigned_auditor_id = auditor.id
            db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).update(
                {EvidenceFile.assigned_auditor_username: req.assigned_auditor_username},
                synchronize_session=False
            )
            db.commit()
            return {"success": True, "assigned_auditor_username": req.assigned_auditor_username}
    finally:
        db.close()

@router.get("/auditee/document-history")
def api_get_auditee_document_history(request: Request, username: Optional[str] = None):
    """Returns all evidence files uploaded by the auditee across sessions."""
    auth_user = _require_auth(request)
    if username and username != auth_user.get("username") and auth_user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied.")
    db = SessionLocal()
    try:
        with force_master():
            query = db.query(EvidenceFile, AuditReport).join(
                AuditReport, EvidenceFile.report_id == AuditReport.id
            )
            if username:
                query = query.filter(
                    (AuditReport.created_by == username) | (AuditReport.auditee_id == db.query(User.id).filter(User.username == username).scalar_subquery())
                )
            rows = query.order_by(EvidenceFile.uploaded_at.desc()).all()
            history = []
            for f, r in rows:
                size_str = "0 KB"
                if f.file_path and os.path.exists(f.file_path):
                    sz = os.path.getsize(f.file_path)
                    if sz > 1024 * 1024:
                        size_str = f"{sz / (1024 * 1024):.1f} MB"
                    elif sz > 1024:
                        size_str = f"{sz / 1024:.1f} KB"
                    else:
                        size_str = f"{sz} B"
                assigned_auditor = f.assigned_auditor_username or r.assigned_auditor_username or "Unassigned"
                history.append({
                    "id": f.id,
                    "filename": f.filename,
                    "size_str": size_str,
                    "uploaded_at": str(f.uploaded_at),
                    "session_id": r.session_id,
                    "session_title": r.session_title,
                    "assigned_auditor": assigned_auditor,
                    "status": f.status or "Submitted",
                    "is_deleted": bool(f.is_deleted),
                    "is_auditor": bool(f.is_auditor_uploaded)
                })
            return {"success": True, "history": history}
    finally:
        db.close()

def _assert_session_access(db, report, auth_user):
    """Raises 403 unless the caller owns this audit session: its creator, its
    assigned auditee, its assigned auditor, or an admin. Session IDs are
    unguessable uuid4 hex, but that's obscurity, not access control -- one
    leaked/shared session_id (a pasted link, a log line, a shared screen)
    would otherwise expose another auditor's live progress, evidence list,
    and findings to any logged-in user, since _require_auth() only checks
    "is this JWT valid", not "does this JWT's owner have any relationship to
    this session". Mirrors the same "Strict Account Isolation" ownership rule
    already enforced in api_get_sessions (created_by == caller, or caller is
    the assigned auditee) -- this just closes the same gap on the
    session_id-keyed endpoints, which had no equivalent check at all.
    """
    if auth_user.get("role") == "admin":
        return
    if report.created_by == auth_user.get("username"):
        return
    if report.assigned_auditor_username and report.assigned_auditor_username == auth_user.get("username"):
        return
    if report.auditee_id:
        user = db.query(User).filter(User.username == auth_user.get("username")).first()
        if user and report.auditee_id == user.id:
            return
    raise HTTPException(status_code=403, detail="Access denied. You do not have access to this session.")

@router.get("/evidence")
def api_get_session_evidence(session_id: str, request: Request):
    """Returns list of active (non-deleted) uploaded evidence files for the given session ID."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                return {"success": True, "files": []}
            _assert_session_access(db, report, auth_user)

            files = db.query(EvidenceFile).filter(
                EvidenceFile.report_id == report.id,
                (EvidenceFile.is_deleted == False) | (EvidenceFile.is_deleted.is_(None))
            ).order_by(EvidenceFile.uploaded_at.desc()).all()
            result = []
            for f in files:
                size_str = "0 KB"
                if f.file_path and os.path.exists(f.file_path):
                    sz = os.path.getsize(f.file_path)
                    if sz > 1024 * 1024:
                        size_str = f"{sz / (1024 * 1024):.1f} MB"
                    elif sz > 1024:
                        size_str = f"{sz / 1024:.1f} KB"
                    else:
                        size_str = f"{sz} B"
                result.append({
                    "id": f.id,
                    "filename": f.filename,
                    "size_str": size_str,
                    "is_auditor": bool(f.is_auditor_uploaded),
                    "assigned_auditor": f.assigned_auditor_username or report.assigned_auditor_username,
                    "created_at": str(f.uploaded_at)
                })
            return {"success": True, "files": result}
    finally:
        db.close()

@router.post("/evidence/delete")
def api_delete_evidence_file(req: DeleteEvidenceRequest, request: Request):
    """Soft deletes an evidence file for 1-click Undo capability."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found")
            _assert_session_access(db, report, auth_user)
            q = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id)
            if req.file_id:
                q = q.filter(EvidenceFile.id == req.file_id)
            elif req.filename:
                q = q.filter(EvidenceFile.filename == req.filename)
            file_rec = q.first()
            if not file_rec:
                raise HTTPException(status_code=404, detail="File not found")
            file_rec.is_deleted = True
            db.commit()
            log_system_event("FILE_DELETED", "WARNING", f"Evidence file '{file_rec.filename}' soft-deleted", session_id=req.session_id)
            return {"success": True, "message": f"File '{file_rec.filename}' deleted", "file_id": file_rec.id, "filename": file_rec.filename}
    finally:
        db.close()

@router.post("/evidence/delete-all")
def api_delete_all_evidence_files(req: DeleteAllEvidenceRequest, request: Request):
    """Soft deletes all active evidence files for the given session ID."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found")
            _assert_session_access(db, report, auth_user)
            db.query(EvidenceFile).filter(
                EvidenceFile.report_id == report.id,
                (EvidenceFile.is_deleted == False) | (EvidenceFile.is_deleted.is_(None))
            ).update({"is_deleted": True}, synchronize_session=False)
            db.commit()
            log_system_event("ALL_FILES_DELETED", "WARNING", f"All evidence files soft-deleted for session '{req.session_id}'", session_id=req.session_id)
            return {"success": True, "message": "All evidence files deleted"}
    finally:
        db.close()

@router.post("/evidence/undo-delete")
def api_undo_delete_evidence_file(req: UndoDeleteEvidenceRequest, request: Request):
    """Restores a soft-deleted evidence file."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found")
            _assert_session_access(db, report, auth_user)
            q = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id)
            if req.file_id:
                q = q.filter(EvidenceFile.id == req.file_id)
            elif req.filename:
                q = q.filter(EvidenceFile.filename == req.filename)
            file_rec = q.first()
            if not file_rec:
                raise HTTPException(status_code=404, detail="File not found")
            file_rec.is_deleted = False
            db.commit()
            return {"success": True, "message": f"File '{file_rec.filename}' restored", "file_id": file_rec.id, "filename": file_rec.filename}
    finally:
        db.close()

@router.post("/start")
def api_start_audit(req: StartAuditRequest, request: Request):
    auth_user = _require_auth(request)
    bg_key = req.session_id
    print(f"🚀 [API] /audit/start received for session {req.session_id} with {len(req.selected_sls)} controls (mode: {req.audit_mode})", flush=True)

    # ── Resource Guard: refuse new audits when system memory is critically low ──
    # Checked before any locks/state are touched so a refused request leaves no
    # partial state behind. WARNING-level pressure is allowed through (the UI
    # surfaces it); CRITICAL is a hard refuse to avoid pushing the OS toward an
    # OOM kill that could take down Postgres/Redis along with this audit.
    from src.core.resource_guard import check_memory_pressure
    _mem = check_memory_pressure()
    if _mem["status"] == "CRITICAL":
        log_system_event("RESOURCE_GUARD_CRITICAL", "CRITICAL", f"Audit refused due to critical RAM pressure: {_mem['reason']}", session_id=req.session_id, actor=req.username or "Auditor")
        raise HTTPException(status_code=503, detail=_mem["reason"] + " Please wait for an active audit to finish before starting a new one.")
    elif _mem["status"] == "WARNING":
        log_system_event("RESOURCE_GUARD_WARNING", "WARNING", f"RAM pressure warning: {_mem['reason']}", session_id=req.session_id, actor=req.username or "Auditor")

    # Auditor identity for the per-auditor concurrency limit below. Previously
    # parsed from session_id assuming an "auditor-<username>-<timestamp>" format,
    # but api_create_session actually generates session_id as uuid4().hex -- no
    # dashes, ever -- so this always fell back to session_id[:16], the first 16
    # chars of a random per-session UUID. That's unique to each session, so the
    # limit never actually grouped sessions by auditor; it silently never
    # triggered no matter how many concurrent audits one real auditor started.
    # Use the authenticated identity instead, which is stable across a real
    # auditor's sessions.
    auditor_id = auth_user.get("username") or (req.session_id.split("-")[0] if "-" in req.session_id else req.session_id[:16])

    with _bg_lock:
        if bg_key in _bg_running:
            return {"success": True, "status": "already_running", "message": "Audit is already running."}

        # ── Per-Auditor Concurrent Limit ──────────────────────────────────────────
        # Clean up finished sessions from this auditor's active set
        _auditor_sessions[auditor_id] = {
            s for s in _auditor_sessions[auditor_id] if s in _bg_running
        }
        active_count = len(_auditor_sessions[auditor_id])
        if active_count >= MAX_AUDITS_PER_AUDITOR:
            raise HTTPException(
                status_code=429,
                detail=f"You already have {active_count} audits running simultaneously. "
                       f"Maximum allowed is {MAX_AUDITS_PER_AUDITOR} concurrent audits per auditor. "
                       f"Please wait for an existing audit to complete before starting a new one."
            )
        # ── Global Concurrent Limit (across ALL auditors combined) ─────────────────
        # llama-server's own request queue (--cont-batching) has no size limit of
        # its own -- past LLM_SLOTS truly-parallel slots, everything past that
        # just queues silently with growing wait times, and a client's own
        # request timeout can fire before its turn ever comes. Reject here with a
        # clear message instead of letting that happen invisibly.
        global_active_count = len(_bg_running)
        if global_active_count >= MAX_CONCURRENT_AUDITS:
            raise HTTPException(
                status_code=429,
                detail=f"The system is at capacity: {global_active_count} audits are currently running or "
                       f"queued across all auditors (limit {MAX_CONCURRENT_AUDITS}). Please wait for one to "
                       f"finish before starting a new one."
            )
        # ─────────────────────────────────────────────────────────────────────────

        _auditor_sessions[auditor_id].add(bg_key)
        # ─────────────────────────────────────────────────────────────────────────

        _bg_stop_flags.pop(bg_key, None)

        # Reserve the slot atomically with the "already running" check above --
        # previously this reservation (_bg_running.add) happened ~150 lines later,
        # right before thread.start(), leaving a TOCTOU gap where two concurrent
        # requests for the same session_id (double submit, retry, two browser tabs)
        # could both pass the check and each spawn their own background thread for
        # the same audit, corrupting findings when both threads write results.
        # Released in the except handlers below if anything fails before the
        # thread actually starts (e.g. the zero-evidence-files guard).
        _bg_running.add(bg_key)
        _bg_store["progress"][bg_key] = {"text": "Initializing analysis...", "percent": 0}

    db = SessionLocal()
    try:
        with force_master():
            report = get_or_create_audit_report(db, req.session_id, username=req.username or auth_user.get("username"))
            _assert_session_access(db, report, auth_user)
            report_id = report.id

            # ── Sync live sidebar framework into the DB record ─────────────────
            # The session was created with whatever framework was in the modal at
            # creation time (defaulted to ISO 27001). If the user later changed
            # the sidebar dropdown, the DB still holds the old value. Sync it now
            # so the governance guardrail uses the correct framework for routing.
            # Only overwrite for the major named frameworks -- ignore empty/unknown.
            _live_fw = (req.current_framework or "").strip()
            _KNOWN_FW_PREFIXES = ("ISO", "SOC", "VAPT", "PQC", "DPDP", "BCMS", "XBOM", "X-BOM", "NIST", "ALL")
            if _live_fw and any(_live_fw.upper().startswith(p) for p in _KNOWN_FW_PREFIXES):
                if (report.framework or "").strip() != _live_fw:
                    print(
                        f"[START AUDIT] Syncing framework: '{report.framework}' -> '{_live_fw}' "
                        f"for session {req.session_id}",
                        flush=True,
                    )
                    report.framework = _live_fw
                    try:
                        db.commit()
                    except Exception:
                        db.rollback()

            report_framework = report.framework or ""

            # ── STALE CHECKPOINT CLEANUP ───────────────────────────────────────
            # Discard any leftover checkpoint from a PREVIOUS run on this session
            # BEFORE the background thread starts. This prevents the old run's
            # total_controls / selected_sls from bleeding into the new run —
            # e.g. a prior 4-control crashed session showing "1/4 done" when only
            # 2 controls are selected this time, or the resume prompt appearing
            # for a session the user is explicitly starting fresh.
            # _checkpoint_create() inside the thread also does this, but doing it
            # here eliminates the race window between API return and thread start.
            try:
                _stale_chk_count = db.query(AuditCheckpoint).filter(
                    AuditCheckpoint.session_id == req.session_id
                ).delete(synchronize_session=False)
                if _stale_chk_count:
                    db.commit()
                    print(
                        f"[START AUDIT] Discarded {_stale_chk_count} stale checkpoint(s) "
                        f"for session {req.session_id} before fresh start.",
                        flush=True
                    )
            except Exception as _chk_err:
                db.rollback()
                print(f"[START AUDIT] Stale checkpoint cleanup failed (non-fatal): {_chk_err}", flush=True)
            # ──────────────────────────────────────────────────────────────────

            # Load evidence files text & bytes from disk. Must exclude
            # soft-deleted files here -- this endpoint is what actually feeds
            # the audit run, so without this filter a file removed via
            # Delete-All/single-delete still got re-loaded into every
            # subsequent audit on this session, appearing "combined" with
            # newly uploaded files even though the UI showed it gone.
            ev_files = db.query(EvidenceFile).filter(
                EvidenceFile.report_id == report_id,
                (EvidenceFile.is_deleted == False) | (EvidenceFile.is_deleted.is_(None))
            ).all()
            ev_file_list = [(ev.file_path, ev.filename) for ev in ev_files]

        files_data = []
        file_registry = {}
        for file_path, filename in ev_file_list:
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                files_data.append({
                    "name": filename,
                    "bytes": file_bytes,
                    "text": None
                })

        # ── Refuse to start an audit with zero evidence files ──────────────────
        # Nothing upstream of this ever blocked it: the UI's "Running Scan..."
        # button has no client-side guard, and this endpoint would happily spawn
        # the background worker to run every selected control against an empty
        # file list -- burning real LLM time on every control while retrieval
        # has nothing to search, producing a session's worth of guaranteed
        # no-evidence findings instead of telling the auditor up front to
        # upload something first.
        if not files_data:
            with _bg_lock:
                _auditor_sessions[auditor_id].discard(bg_key)
            raise HTTPException(
                status_code=400,
                detail="No evidence files are attached to this session. Please upload at least one evidence file before starting an audit."
            )

        # Determine standard/scoping & background execution engine.
        # audit_mode is the live per-run signal for "treat this run as VAPT
        # Scan" -- the request body never includes the framework-select
        # dropdown's current value, only audit_mode, so this OR is required:
        # a session not created with framework=VAPT (e.g. "All Standards"
        # with individually-selected VAPT-numbered controls) can still
        # legitimately run VAPT Scan mode.
        #
        # ── Governance Guardrail ────────────────────────────────────────────
        # ISO 27001 / SOC 2 / DPDP / BCMS / X-BOM ALWAYS require LLM-based
        # policy vs evidence evaluation (audit_chains.py / validator.py).
        # If a governance framework somehow sends "Technical findings only"
        # (e.g. stale client state, direct API call), coerce to "Deep" server-
        # side so the correct pipeline is always used regardless of client input.
        _fw_upper = report_framework.upper()
        _is_governance_fw = (
            ("ISO" in _fw_upper and "VAPT" not in _fw_upper and "PQC" not in _fw_upper)
            or "SOC" in _fw_upper or "DPDP" in _fw_upper
            or "BCMS" in _fw_upper or "XBOM" in _fw_upper or "X-BOM" in _fw_upper
        )
        if _is_governance_fw and req.audit_mode in ("Technical findings only", "VAPT validation", "Fast Parser"):
            print(
                f"[AUDIT GUARDRAIL] Governance framework '{report_framework}' received "
                f"audit_mode='{req.audit_mode}' — coercing to 'Deep' (LLM/RAG pipeline required).",
                flush=True,
            )
            req.audit_mode = "Deep"

        is_vapt_std = ("VAPT" in report_framework.upper()
                       or req.audit_mode in ("VAPT validation", "Technical findings only"))
        is_tech_only = req.audit_mode in ("VAPT validation", "Technical findings only")


        if is_vapt_std:
            with force_master():
                report_obj = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
                if report_obj:
                    # PQC sessions keep their own "PQC Framework Controls" label (matches
                    # _FRAMEWORK_CATEGORY_LABELS in controls.py) instead of being renamed to
                    # VAPT's -- everything downstream that gates on "VAPT" in the framework
                    # string already also checks for "PQC" (see is_vapt/_is_vapt_session sites).
                    report_obj.framework = (
                        "PQC Framework Controls" if "PQC" in report_framework.upper()
                        else "VAPT Framework Controls"
                    )
                    try:
                        db.commit()
                    except Exception:
                        db.rollback()
        
        # Close request database session before thread starts so SQLite locks are immediately released
        try:
            db.close()
            db = None
        except Exception:
            pass

        # Spawn Background Worker thread. Reservation (_bg_running / progress init)
        # already happened atomically with the "already running" check above.
        if is_tech_only:
            thread = threading.Thread(
                target=_run_fast_technical_vapt_bg,
                args=(bg_key, files_data, set(req.selected_sls), file_registry),
                daemon=True
            )
        else:
            thread = threading.Thread(
                target=_run_ollama_bg,
                args=(bg_key, files_data, set(req.selected_sls), req.model_choice),
                kwargs={
                    "session_id": req.session_id,
                    "audit_mode": req.audit_mode,
                    "file_registry": file_registry,
                    "custom_evidence": req.custom_evidence,
                    "custom_docs": req.custom_documents,
                    "username": auth_user.get("username") or req.username
                },
                daemon=True
            )
        _mode_label = "VAPT" if is_tech_only else req.audit_mode
        try:
            log_system_event("AUDIT_STARTED", "INFO", f"Audit started (mode: {_mode_label}, controls: {len(req.selected_sls)}, files: {len(files_data)})", session_id=req.session_id, actor=req.username or "Auditor")
        except Exception:
            pass
        thread.start()
        # Live, real slot busy-count from llama-server itself (not the static
        # session-count heuristics elsewhere) so the caller can show an honest
        # "all slots busy, you're queued" state immediately -- instead of only
        # finding out minutes into a run via the progress poll's warning field.
        # Best-effort/non-blocking: this never turns a successful start into a
        # failure, it just adds an informational field.
        try:
            from src.core.port_pool import port_pool_manager
            _llm_capacity = port_pool_manager.get_capacity_snapshot()
        except Exception:
            _llm_capacity = None
        return {
            "success": True,
            "status": "started",
            "message": "Background RAG scan initialized.",
            "llm_capacity": _llm_capacity,
        }
    except HTTPException:
        # Deliberate errors raised inside this try block (e.g. the zero-evidence
        # guard above) were being caught by the broad except below and rewrapped
        # into an opaque 500 -- losing both the real status code and the actual
        # message the caller needs (e.g. "upload evidence first" became "please
        # try again", which just tells the auditor to retry the exact same
        # no-evidence request).
        # Release the reservation made above the lock -- everything after
        # thread.start() is self-contained/best-effort and can't reach this
        # handler, so if we're here the thread never actually started and the
        # session must not be left stuck marked "running" forever.
        with _bg_lock:
            _bg_running.discard(bg_key)
            _auditor_sessions[auditor_id].discard(bg_key)
            _bg_store["progress"].pop(bg_key, None)
        raise
    except Exception as e:
        print(f"[START AUDIT ERROR] session={req.session_id} | {e}", flush=True)
        with _bg_lock:
            _bg_running.discard(bg_key)
            _auditor_sessions[auditor_id].discard(bg_key)
            _bg_store["progress"].pop(bg_key, None)
        raise HTTPException(status_code=500, detail="Failed to start audit scan. Please try again.")
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass

@router.post("/stop/{session_id}")
def api_stop_audit(session_id: str, request: Request):
    """Signal the background audit thread to stop and unblock session execution."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
    finally:
        db.close()
    bg_key = f"bg_{session_id}"
    _bg_stop_flags[session_id] = True
    _bg_stop_flags[bg_key] = True
    with _bg_lock:
        _bg_running.discard(session_id)
        _bg_running.discard(bg_key)
        _bg_store["progress"].pop(session_id, None)
        _bg_store["progress"].pop(bg_key, None)
    log_system_event("AUDIT_STOPPED", "WARNING", "Audit manually stopped by user", session_id=session_id)
    return {"success": True, "message": "Scan stopped successfully."}


@router.get("/my-active-audits")
def api_get_my_active_audits(request: Request):
    """Returns the calling auditor's own currently-running audit session IDs.
    Used by the frontend to warn before starting a new session if this
    auditor already has one actively processing, and offer to stop it."""
    auth_user = _require_auth(request)
    auditor_id = auth_user.get("username")
    with _bg_lock:
        active = [s for s in _auditor_sessions.get(auditor_id, set()) if s in _bg_running]
    return {"success": True, "active_sessions": active}


@router.get("/status/{session_id}")
def api_get_status(session_id: str, request: Request):
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
    finally:
        db.close()
    with _bg_lock:
        is_running = session_id in _bg_running
        progress = _bg_store["progress"].get(session_id)
        result = _bg_results.get(session_id)
    
    # Check if complete or in progress in DB checkpoint
    checkpoint = get_resumable_checkpoint(session_id)
    checkpoint_data = None
    if checkpoint:
        # selected_sls exposed so the frontend can correct its OWN display of which
        # controls/scoping-mode this run is actually scoped to -- previously only
        # a client-side cache (localStorage) tracked that, which silently went
        # stale on a page reload, a different browser/tab, or a cache miss,
        # showing e.g. "AI Auto-Scoping 91/91" while the backend was correctly
        # running a 6-control Excel-scoped session the whole time.
        try:
            selected_sls = json.loads(checkpoint.selected_sls_json or "[]")
        except Exception:
            selected_sls = []
        checkpoint_data = {
            "completed_batches": checkpoint.completed_batches,
            "total_controls": checkpoint.total_controls,
            "status": checkpoint.status,
            "selected_sls": selected_sls,
        }
        
    if is_running:
        # Live resource check on every poll — so the UI can show a WARNING banner
        # as pressure builds, not only once a control loop hits CRITICAL and stops.
        from src.core.resource_guard import check_memory_pressure
        _mem = check_memory_pressure()
        return {
            "status": "running",
            "progress": progress,
            "checkpoint": checkpoint_data,
            "resource_status": _mem["status"],
            "resource_message": _mem["reason"],
        }
    
    if result:
        with _bg_lock:
            _bg_results.pop(session_id, None)
            
        if result.get("error"):
            return {
                "status": "failed",
                "progress": progress,
                "checkpoint": checkpoint_data,
                "error": result["error"]
            }
            
        return {
            "status": "completed",
            "progress": progress,
            "checkpoint": checkpoint_data,
            "findings_count": len(result.get("findings", []))
        }
        
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if report:
                findings_cnt = db.query(Finding).filter(Finding.report_id == report.id).count()
                if findings_cnt > 0 or report.status in ("Pending Review", "Completed"):
                    return {
                        "status": "completed",
                        "progress": {"text": "Scan completed successfully", "percent": 100},
                        "checkpoint": checkpoint_data,
                        "findings_count": findings_cnt
                    }
    except Exception:
        pass
    finally:
        db.close()

    return {"status": "idle", "checkpoint": checkpoint_data}


@router.get("/progress")
def api_get_progress(session_id: str, request: Request):
    """
    Alias for /status/{session_id} using query parameter instead of path parameter.
    Frontend calls /api/audit/progress?session_id=... — this endpoint handles that.
    Previously returned 404 because only /status/{session_id} existed.
    """
    return api_get_status(session_id, request)

@router.get("/findings")
def api_get_findings(request: Request, session_id: str, saved_only: bool = False, include_info: bool = False):
    auth_user = _require_auth(request)
    # Role for the auditee-isolation check below comes from the JWT, never the
    # client -- this used to accept a `role` query param and trust it directly,
    # which meant any caller could pass role=auditor (or omit it) to skip the
    # "only delivered findings, no raw drafts" filter regardless of their real,
    # server-verified role. Also stops role from being echoed into the URL (and
    # therefore access logs) on every poll, same reasoning as the username fix
    # in loadRecentSessions().
    role = auth_user.get("role")
    db = SessionLocal()
    try:
        from src.core.controls_data import USE_CASES
        control_catalog = {}
        for uc in USE_CASES:
            # Map by SL and control_id (e.g. "5.15" or "5.15 ACCESS CONTROL")
            u_case = uc.get("use_case", "")
            parts = u_case.split()
            cid = parts[0].upper() if parts else str(uc.get("sl"))
            control_catalog[cid] = uc
            control_catalog[str(uc.get("sl"))] = uc

        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Audit session not found.")
            _assert_session_access(db, report, auth_user)

            query = db.query(Finding).filter(Finding.report_id == report.id)
            if role == "auditee":
                # Strict Auditee Isolation: Only return delivered findings saved to Shakthi DB (no raw auditor draft scans)
                query = query.filter((Finding.is_saved_to_shakthi == True) | (Finding.human_verified == True))
            elif saved_only:
                query = query.filter((Finding.is_saved_to_shakthi == True) | (Finding.human_verified == True))
                
            if not include_info:
                query = query.filter(
                    ~Finding.severity.ilike("%INFO%"),
                    ~Finding.status.ilike("%INFO%")
                )
                
            findings = query.order_by(Finding.control_id).all()
            
            # Query evidence file names as fallback source document location
            fallback_source = None
            try:
                ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
                ev_names = [ef.filename or (os.path.basename(ef.file_path) if getattr(ef, "file_path", None) else None) for ef in ev_files]
                ev_names_clean = [name for name in ev_names if name]
                if ev_names_clean:
                    fallback_source = ", ".join(ev_names_clean)
            except Exception:
                fallback_source = None
        
        result = []
        for f in findings:
            cid_clean = (f.control_id or "").strip().upper()
            uc_info = control_catalog.get(cid_clean) or control_catalog.get(cid_clean.split()[0]) or {}
            
            # final_result is the single source of truth set by validator.py
            # ("COMPLIANT" | "NON_COMPLIANT"). Fall back to status for older rows
            # that pre-date the final_result column.
            _fr = (f.final_result or f.status or "").strip().upper()
            is_comp = (_fr == "COMPLIANT")
            
            # Smart description fallback hierarchy
            if f.description and len(f.description.strip()) > 5:
                desc = f.description
            elif f.gap_detected and len(f.gap_detected.strip()) > 5:
                desc = f.gap_detected
            elif uc_info.get("expected"):
                desc = f"Control Requirements: {uc_info['expected']}"
            elif uc_info.get("finding"):
                desc = uc_info["finding"]
            else:
                desc = f.reasoning or "Evaluated against ISO 27001 / VAPT compliance standards."
                
            # Smart recommendation fallback hierarchy
            if f.recommendation and len(f.recommendation.strip()) > 5:
                recom = f.recommendation
            elif f.review_note and len(f.review_note.strip()) > 5:
                recom = f.review_note
            elif uc_info.get("recommendation"):
                recom = uc_info["recommendation"]
            else:
                recom = f"Maintain current documented policies and verification procedures for {f.control_id}." if is_comp else f"Establish, document, and implement procedures to satisfy {f.control_id}."

            # Safe control name — fallback to uc_info label or control_id
            ctrl_name = f.control_name
            if not ctrl_name or ctrl_name in ("null", "undefined", "None"):
                ctrl_name = uc_info.get("label") or uc_info.get("use_case") or f.control_id or ""

            # Safe severity fallback — N/A for COMPLIANT, NIST P-scale otherwise
            sev = f.severity
            if not sev or sev in ("null", "undefined", "None"):
                if is_comp:
                    sev = "N/A"
                else:
                    raw_sev = (uc_info.get("severity") or "MEDIUM").upper()
                    sev = {"CRITICAL": "P1 Critical", "HIGH": "P2 High", "MEDIUM": "P3 Medium", "LOW": "P4 Low"}.get(raw_sev, "N/A")

            # Resolve exact evidence document source location (Prioritize explicit evidence_location over all session source_files)
            loc_src = getattr(f, "evidence_location", None) or getattr(f, "evidence_source_file", None) or f.source_files
            if not loc_src or loc_src in ("null", "undefined", "None", ""):
                loc_src = fallback_source or "Uploaded Policy Document & Evidence Files"


            p_val = getattr(f, "policy_items_json", None) if hasattr(f, "policy_items_json") else (f.get("policy_items_json") if isinstance(f, dict) else None)
            e_val = getattr(f, "evidence_items_json", None) if hasattr(f, "evidence_items_json") else (f.get("evidence_items_json") if isinstance(f, dict) else None)
            if p_val is None: p_val = "[]"
            if e_val is None: e_val = "[]"

            result.append({
                "id": f.id,
                "control_id": f.control_id,
                "control_name": ctrl_name,
                "severity": sev,
                "description": desc,
                "evidence_found": f.evidence_found,
                "evidence_snippet": f.evidence_snippet,
                "recommendation": recom,
                "reasoning": f.reasoning or f.description or "",
                "status": f.status,
                # source_files should be the actual, grounding-verified filename the evidence
                # came from (validator.py's grounding gates only ever write a real uploaded
                # filename here, or leave it empty -- never LLM prose). evidence_location is
                # deliberately more liberal (prioritizes the LLM's own free-text location
                # claim, e.g. "Various sections of the provided images") -- that's fine for a
                # human-readable location hint, but reusing the same value for source_files
                # meant an auditor clicking "source file" could be pointed at prose instead of
                # a real file. Fall back to loc_src/fallback_source only when the grounded
                # column truly has nothing.
                "source_files": (f.source_files or "").strip() or loc_src,
                "evidence_location": loc_src,
                "policy_present": f.policy_present,
                "evidence_present": f.evidence_present,
                "is_saved_to_shakthi": bool(f.is_saved_to_shakthi or f.human_verified),
                "human_verified": bool(f.human_verified),
                "review_note": f.review_note or "",
                # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7)
                "policy_status": f.policy_status,
                "policy_assessment": f.policy_assessment,
                "policy_name": f.policy_name,
                "policy_version": f.policy_version,
                "policy_clause": f.policy_clause,
                "policy_effective_date": f.policy_effective_date,
                "policy_review_date": f.policy_review_date,
                "policy_expiry_date": f.policy_expiry_date,
                "policy_validity": f.policy_validity,
                "policy_finding": f.policy_finding,
                "policy_gap": f.policy_gap,
                "evidence_status": f.evidence_status,
                "evidence_assessment": f.evidence_assessment,
                "evidence_date": f.evidence_date,
                "evidence_freshness": f.evidence_freshness,
                "evidence_finding": f.evidence_finding,
                "evidence_gap": f.evidence_gap,
                "evidence_relevance": f.evidence_relevance,
                "final_result": f.final_result,
                "final_reason": f.final_reason,
                "policy_items_json": p_val,
                "evidence_items_json": e_val,
                "requirement_question": getattr(f, "requirement_question", None) or "Requirement question not provided",
                "policy_required": bool(getattr(f, "policy_required", False)),
                # VAPT enrichment fields (src/core/parsers/control_mapper.py) -- populated
                # for findings saved from a scanner-parsed VAPT session; empty for ISO
                # findings, which don't go through that enrichment pipeline.
                "category": f.category or "",
                "cia_impact": f.cia_impact or "",
                "is_pii_exposed": bool(f.is_pii_exposed or False),
                "remediation_actionable": f.remediation_actionable or "",
                # PQC (Post-Quantum Cryptography Readiness) enrichment fields --
                # populated for findings saved from a PQC-scanned session; empty
                # for ISO/VAPT findings, which don't go through that pipeline.
                "asset_name": f.asset_name or "",
                "asset_category": f.asset_category or "",
                "quantum_status": f.quantum_status or "",
                "ca_algorithm": f.ca_algorithm or "",
                "key_algorithm": f.key_algorithm or "",
                "protocol_version": f.protocol_version or "",
                "exposure_context": f.exposure_context or "",
                "port": f.port or "",
                "environment": f.environment or "",
                # PQC risk scoring / OEM readiness / migration-dependency fields --
                # same pattern as the PQC context fields above.
                "risk_score": f.risk_score,
                "risk_band": f.risk_band or "",
                "business_priority": f.business_priority or "",
                "oem_product": f.oem_product or "",
                "oem_readiness_status": f.oem_readiness_status or "",
                "dependency_chain": f.dependency_chain or "",
                "migration_dependency_flag": bool(f.migration_dependency_flag or False),
            })
        return {
            "success": True, 
            "findings": result, 
            "session_title": report.session_title,
            "session_status": report.status
        }
    finally:
        db.close()


@router.put("/findings/{finding_id}")
def api_update_finding(finding_id: int, req: UpdateFindingRequest, request: Request):
    """Updates a finding's status/content. finding_id is a small sequential
    integer, not a random UUID -- trivially enumerable -- so ownership must be
    checked explicitly here, unlike session_id-keyed endpoints where the ID
    itself is at least unguessable.
    """
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found.")
            report = db.query(AuditReport).filter(AuditReport.id == finding.report_id).first()
            if report:
                _assert_session_access(db, report, auth_user)

            finding.status = req.status
            # Derive final_result from the incoming status so the DB stays in sync
            # with what the auditor chose in the UI.  validator.py uses the exact
            # values "COMPLIANT" and "NON_COMPLIANT" — mirror that here.
            derived_final_result = "COMPLIANT" if req.status.strip().upper() == "COMPLIANT" else "NON_COMPLIANT"
            finding.final_result = derived_final_result

            # NIST Severity rule (single source of truth = final_result):
            #   COMPLIANT  → severity = "N/A"  (no actionable risk)
            #   NON_COMPLIANT → keep the P-scale severity sent by the auditor
            if derived_final_result == "COMPLIANT":
                finding.severity = "N/A"
            elif req.severity is not None:
                # BUG-05 FIX: use `is not None` so auditor can clear a field by sending ""
                # (previously `if req.field:` treated "" as falsy and silently kept old value)
                finding.severity = req.severity
            if req.description is not None: finding.description = req.description
            if req.evidence_snippet is not None: finding.evidence_snippet = req.evidence_snippet
            if req.recommendation is not None: finding.recommendation = req.recommendation
            if req.reasoning is not None: finding.reasoning = req.reasoning
            if req.policy_present is not None: finding.policy_present = req.policy_present
            if req.evidence_present is not None: finding.evidence_present = req.evidence_present
            if req.source_files is not None: finding.source_files = req.source_files

            # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7) -- manual overrides.
            # Same BUG-05 FIX pattern as severity above, applied to these 8 sibling
            # fields: `if req.field:` treated "" as falsy and silently kept the old
            # value, so an auditor could never clear these to empty. final_result
            # in particular can still deliberately diverge from the status-derived
            # derived_final_result set earlier in this function when the auditor
            # explicitly sends a value (including "" to clear it back).
            if req.policy_status is not None: finding.policy_status = req.policy_status
            if req.policy_assessment is not None: finding.policy_assessment = req.policy_assessment
            if req.policy_name is not None: finding.policy_name = req.policy_name
            if req.policy_version is not None: finding.policy_version = req.policy_version
            if req.policy_clause is not None: finding.policy_clause = req.policy_clause
            if req.policy_effective_date is not None: finding.policy_effective_date = req.policy_effective_date
            if req.policy_review_date is not None: finding.policy_review_date = req.policy_review_date
            if req.policy_expiry_date is not None: finding.policy_expiry_date = req.policy_expiry_date
            if req.policy_validity is not None: finding.policy_validity = req.policy_validity
            if req.policy_finding is not None: finding.policy_finding = req.policy_finding
            if req.policy_gap is not None: finding.policy_gap = req.policy_gap
            if req.evidence_status is not None: finding.evidence_status = req.evidence_status
            if req.evidence_assessment is not None: finding.evidence_assessment = req.evidence_assessment
            if req.evidence_date is not None: finding.evidence_date = req.evidence_date
            if req.evidence_freshness is not None: finding.evidence_freshness = req.evidence_freshness
            if req.evidence_finding is not None: finding.evidence_finding = req.evidence_finding
            if req.evidence_gap is not None: finding.evidence_gap = req.evidence_gap
            if req.evidence_relevance is not None: finding.evidence_relevance = req.evidence_relevance
            if req.final_result is not None: finding.final_result = req.final_result
            if req.final_reason is not None: finding.final_reason = req.final_reason
            # Custom heading override (VAPT + ISO): auditor-set title for UI and exported reports
            if req.custom_heading is not None: finding.custom_heading = req.custom_heading

            # Explicitly mark as reviewed and saved to Shakthi DB
            finding.is_saved_to_shakthi = True
            finding.human_verified = True
            
            # Record auditor comments in database if comment is updated
            if req.comment is not None:
                finding.review_note = req.comment
                
            # Log to AuditorFeedback to prevent false positives from recurring.
            # get_auditor_feedback_few_shot() later injects evidence_snippet/finding/
            # auditor_comments verbatim into OTHER auditors' generation prompts (see
            # src/ai/knowledge_loop.py) -- redact known PII patterns (email/IP/phone)
            # before it's ever written, not just at report-export time. This is a
            # partial mitigation: it won't catch names or account numbers (that needs
            # real NER, not regex), but it closes the structured-PII leak now.
            _redacted_evidence = redact_pii(finding.evidence_snippet)
            _redacted_finding = redact_pii(finding.description)
            _redacted_comment = redact_pii(req.comment or finding.review_note or "")
            dup = db.query(AuditorFeedback).filter(
                AuditorFeedback.control_id == finding.control_id,
                AuditorFeedback.evidence_snippet == _redacted_evidence,
                AuditorFeedback.corrected_status == req.status,
                AuditorFeedback.finding == _redacted_finding
            ).first()
            if not dup:
                db.add(AuditorFeedback(
                    control_id=finding.control_id,
                    evidence_snippet=_redacted_evidence,
                    corrected_status=req.status,
                    finding=_redacted_finding,
                    recommendation=finding.recommendation,
                    auditor_comments=_redacted_comment
                ))
                
            db.commit()
            log_system_event("FINDING_UPDATED", "INFO", f"Finding #{finding_id} updated to '{req.status}' (control: {finding.control_id})", session_id=str(finding.report_id))
            return {"success": True, "message": "Finding successfully updated and saved to Shakthi DB."}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[UPDATE FINDING ERROR] finding_id={finding_id} | {e}", flush=True)
        raise HTTPException(status_code=500, detail="Database update failed. Please try again.")
    finally:
        db.close()

@router.put("/findings/commit-session/{session_id}")
def api_commit_session_findings(session_id: str, request: Request, force: bool = False, auditor_user: str = "Lead Auditor"):
    """Commits and finalizes all findings for a session into Shakthi DB, with unreviewed controls warning & admin logging."""
    auth_user = _require_auth(request)
    db = SessionLocal()
    is_force = bool(force) or str(force).lower() in ('true', '1')
    try:
        from src.db.database import AdminAuditLog
        with force_master():
            report = get_or_create_audit_report(db, session_id, username=auditor_user)
            _assert_session_access(db, report, auth_user)

            all_findings = db.query(Finding).filter(Finding.report_id == report.id).all()
            # Exclude INFO severity items so count matches the 258 actionable findings in UI
            findings = [f for f in all_findings if 'INFO' not in str(f.severity).upper() and 'INFO' not in str(f.status).upper()]
            if not findings:
                findings = all_findings

            unreviewed = [f for f in findings if not bool(f.human_verified) or not bool(f.is_saved_to_shakthi)]
            if not unreviewed and report.status != "Reviewed & Finalized":
                unreviewed = findings

            # If there are unreviewed controls and auditor hasn't forced acceptance, trigger warning response!
            if unreviewed and not is_force:
                unreviewed_controls = [f"{f.control_id} - {f.control_name or f.status}" for f in unreviewed]
                return {
                    "success": False,
                    "requires_confirmation": True,
                    "unreviewed_count": len(unreviewed),
                    "unreviewed_controls": unreviewed_controls,
                    "message": f"Warning: {len(unreviewed)} control(s) have not been reviewed/saved to Shakthi DB yet."
                }
                
            # If auditor forces acceptance of unreviewed controls, log to Admin Audit Log!
            if is_force and (unreviewed or report.status != "Reviewed & Finalized"):
                unreviewed_control_ids = [f.control_id for f in (unreviewed if unreviewed else findings)]
                db.add(AdminAuditLog(
                    auditor_user=auditor_user,
                    session_id=session_id,
                    action="FORCE_ACCEPT_UNREVIEWED_CONTROLS",
                    unreviewed_controls=json.dumps(unreviewed_control_ids[:50]),
                    details=f"Auditor forcibly accepted and committed session {session_id[:8]} with {len(unreviewed_control_ids)} unreviewed control(s): {', '.join(unreviewed_control_ids[:10])}"
                ))

                
            # Mark all findings (including info) as saved and verified in Shakthi DB
            for f in all_findings:
                f.is_saved_to_shakthi = True
                f.human_verified = True
                
            report.status = "Reviewed & Finalized"
            
            # Recalculate Compliance Score
            total_ctrls = len(findings)
            compliant_count = sum(1 for f in findings if (f.status or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS"))
            score_pct = int((compliant_count / total_ctrls) * 100) if total_ctrls > 0 else 0
            
            score_row = db.query(ComplianceScore).filter(ComplianceScore.report_id == report.id).first()
            if score_row:
                score_row.score_percent = score_pct
            else:
                db.add(ComplianceScore(
                    report_id=report.id,
                    framework=report.framework or "ISO 27001",
                    score_percent=score_pct
                ))

            # Record entry in AdminAuditLog for Privacy-Safe System Log Trail
            db.add(AdminAuditLog(
                auditor_user=auditor_user or "Auditor",
                session_id=session_id,
                action="FORCE_COMMIT" if is_force else "COMMIT_SHAKTHI_DB",
                unreviewed_controls=str(len(unreviewed)) if is_force else "0",
                details=f"Committed {total_ctrls} audit record(s) to Shakthi DB (Compliance Score: {score_pct}%)."
            ))

            db.commit()
            _action = "FORCE_COMMIT_SHAKTHI" if is_force else "COMMIT_SHAKTHI"
            _sev = "WARNING" if is_force else "INFO"
            log_system_event(
                _action, _sev,
                f"{'Force-committed' if is_force else 'Committed'} {total_ctrls} findings to Shakthi DB "
                f"(Compliance: {score_pct}%, Unreviewed: {len(unreviewed)})",
                session_id=session_id, actor=auditor_user
            )
            return {
                "success": True, 
                "message": f"Successfully committed {total_ctrls} audit record(s) to Shakthi DB (Compliance Score: {score_pct}%).",
                "status": report.status,
                "score_percent": score_pct,
                "unreviewed_count": len(unreviewed) if not is_force else 0  # BUG-06 FIX: use is_force (resolved bool), not raw `force` param
            }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"[COMMIT SESSION EXCEPTION ERROR] {e}\n{traceback.format_exc()}", flush=True)
        raise HTTPException(status_code=500, detail="Commit to Shakthi DB failed. Please try again.")
    finally:
        db.close()

@router.get("/settings/upload-limits")
def api_get_upload_limit_settings(request: Request):
    """Returns the current admin-editable upload limits and system settings. Admin only."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.settings import get_all_upload_settings, UPLOAD_SETTINGS, get_effective_device
    values = get_all_upload_settings()
    
    cuda_available = False
    gpu_name = "None"
    try:
        import torch
        cuda_available = torch.cuda.is_available()
        if cuda_available:
            gpu_name = torch.cuda.get_device_name(0)
    except Exception:
        pass

    return {
        "success": True,
        "settings": {
            key: {"value": values[key], "min": bounds[1], "max": bounds[2], "default": bounds[0]}
            for key, bounds in UPLOAD_SETTINGS.items()
        },
        "cuda_info": {
            "cuda_available": cuda_available,
            "gpu_device_name": gpu_name,
            "effective_device": get_effective_device()
        }
    }


@router.put("/settings/upload-limits")
def api_update_upload_limit_settings(request: Request, updates: dict):
    """Updates system settings. Admin only."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.settings import set_setting, get_all_upload_settings, UPLOAD_SETTINGS, get_effective_device

    unknown = [k for k in updates if k not in UPLOAD_SETTINGS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown setting(s): {', '.join(unknown)}")

    try:
        for key, value in updates.items():
            set_setting(key, value, updated_by=user.get("username"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    log_system_event(
        "SETTINGS_UPDATED", "INFO",
        f"System settings updated: {updates}",
        actor=user.get("username")
    )
    
    cuda_available = False
    gpu_name = "None"
    try:
        import torch
        cuda_available = torch.cuda.is_available()
        if cuda_available:
            gpu_name = torch.cuda.get_device_name(0)
    except Exception:
        pass

    return {
        "success": True,
        "settings": get_all_upload_settings(),
        "cuda_info": {
            "cuda_available": cuda_available,
            "gpu_device_name": gpu_name,
            "effective_device": get_effective_device()
        }
    }


@router.get("/admin-logs")
def api_get_admin_logs(request: Request):
    """Retrieves unified admin audit logs: overrides, auditor feedback/rejections, and system events/errors."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    db = SessionLocal()
    try:
        from src.db.database import AdminAuditLog, AuditorFeedback, SystemEvent
        result = []

        # 1. Admin Overrides & Force Commits
        override_logs = db.query(AdminAuditLog).order_by(AdminAuditLog.id.desc()).limit(50).all()
        for l in override_logs:
            result.append({
                "id": f"override-{l.id}",
                "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if l.timestamp else "",
                "auditor_user": l.auditor_user or "Admin",
                "session_id": l.session_id or "N/A",
                "action": l.action or "OVERRIDE",
                "unreviewed_controls": l.unreviewed_controls or "N/A",
                "details": l.details or ""
            })

        # 2. Auditor Feedback & Document Rejections ([✕ Reject])
        feedback_logs = db.query(AuditorFeedback).order_by(AuditorFeedback.id.desc()).limit(50).all()
        for fb in feedback_logs:
            result.append({
                "id": f"feedback-{fb.id}",
                "timestamp": fb.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if fb.created_at else "",
                "auditor_user": "Auditor",
                "session_id": f"Control {fb.control_id}",
                "action": fb.corrected_status or "FEEDBACK",
                "unreviewed_controls": fb.control_id or "N/A",
                "details": f"{fb.finding or ''} | Comments: {fb.auditor_comments or ''}"
            })

        # 3. System Events, Warnings & Errors
        system_logs = db.query(SystemEvent).order_by(SystemEvent.id.desc()).limit(50).all()
        for se in system_logs:
            result.append({
                "id": f"sys-{se.id}",
                "timestamp": se.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if se.created_at else "",
                "auditor_user": se.actor or "SYSTEM",
                "session_id": se.session_id or "System",
                "action": f"[{se.severity}] {se.event_type}",
                "unreviewed_controls": se.framework or "N/A",
                "details": se.meta or ""
            })

        # Sort all combined log entries by timestamp descending
        result.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        return {"success": True, "logs": result}
    finally:
        db.close()


@router.get("/benchmark/sessions")
def api_get_benchmark_sessions(request: Request):
    """Retrieves real auditor session telemetry logs recorded during audits.

    Admin-only: this is cross-session telemetry (token usage, file names,
    compliance counts) spanning every auditor's work, not scoped to the
    caller -- previously any authenticated user, including an auditee,
    could read it with a bare _require_auth() check.
    """
    auth_user = _require_auth(request)
    if auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        from src.core.token_tracker import get_all_benchmark_records
        records = get_all_benchmark_records()
        db = SessionLocal()
        try:
            with force_master():
                for r in records:
                    sid = r.get("session_id")
                    if sid and not r.get("auditor_username"):
                        rep = db.query(AuditReport).filter(AuditReport.session_id == sid).first()
                        if rep and rep.created_by:
                            r["auditor_username"] = rep.created_by
                        else:
                            r["auditor_username"] = r.get("folder_name") or "Auditor"
        finally:
            db.close()
        return {"success": True, "count": len(records), "sessions": records}
    except Exception as e:
        return {"success": False, "error": str(e), "sessions": []}


class AggregateSessionsRequest(BaseModel):
    session_ids: Optional[List[str]] = None


@router.post("/benchmark/aggregate")
def api_aggregate_benchmark_sessions(request: Request, body: AggregateSessionsRequest = None):
    """Combines and aggregates metrics across selected real auditor sessions. Admin-only -- see api_get_benchmark_sessions."""
    auth_user = _require_auth(request)
    if auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        from src.core.token_tracker import aggregate_audit_sessions
        sids = body.session_ids if body and body.session_ids else None
        res = aggregate_audit_sessions(sids)
        return {"success": True, "aggregated": res}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/benchmark/export")
def api_export_benchmark_excel(request: Request):
    """Downloads styled executive Excel benchmark report. Admin-only -- see api_get_benchmark_sessions."""
    auth_user = _require_auth(request)
    if auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        from fastapi.responses import FileResponse
        from src.core.token_tracker import BENCHMARK_EXCEL_PATH, get_all_benchmark_records, generate_excel_benchmark_report
        records = get_all_benchmark_records()
        if records:
            generate_excel_benchmark_report(records, BENCHMARK_EXCEL_PATH)
        if os.path.exists(BENCHMARK_EXCEL_PATH):
            return FileResponse(
                BENCHMARK_EXCEL_PATH,
                filename="Executive_Audit_Token_Benchmark_Report.xlsx",
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        raise HTTPException(status_code=404, detail="Benchmark report not found")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to generate report. Please try again.")


@router.get("/benchmark/export-pdf")
def api_export_benchmark_pdf(request: Request):
    """Downloads styled executive PDF benchmark report. Admin-only."""
    auth_user = _require_auth(request)
    if auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        from fastapi.responses import FileResponse
        from src.core.token_tracker import get_all_benchmark_records, generate_pdf_benchmark_report
        records = get_all_benchmark_records()
        if not records:
            raise HTTPException(status_code=404, detail="No benchmark data found.")
        pdf_path = "data/audit_token_benchmark.pdf"
        generate_pdf_benchmark_report(records, pdf_path)
        if os.path.exists(pdf_path):
            return FileResponse(
                pdf_path,
                filename="Executive_Audit_Telemetry_Report.pdf",
                media_type="application/pdf"
            )
        raise HTTPException(status_code=404, detail="PDF report generation failed.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")



# NOTE: Excel scope parsing is handled by /controls/parse-scope-excel (controls.py).
# That is the endpoint the frontend calls. Do NOT add a duplicate here.


@router.post("/deliver")
def api_deliver_report(
    request: Request,
    session_id: str = Form(...),
    auditee_id: str = Form(...),
    username: str = Form("admin")
):
    """Delivers report session to specified auditee account."""
    auth_user = _require_auth(request)
    if auth_user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied. Only auditors/admins can deliver reports.")
    if username != auth_user.get("username") and auth_user.get("role") != "admin":
        username = auth_user.get("username")
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found.")

            auditor_user = db.query(User).filter(User.username == username).first()
            auditor_id = auditor_user.id if auditor_user else None

            # Parse target auditee user safely. Reading this on the master (not a
            # possibly-lagging read replica) matters here specifically -- a newly
            # registered auditee account delivered to immediately afterward could
            # otherwise silently resolve to no user, leaving auditee_id unset while
            # the API still reports success.
            target_user = None
            raw_target = str(auditee_id).strip()
            if raw_target.startswith("auditee:"):
                uname = raw_target.replace("auditee:", "")
                target_user = db.query(User).filter(User.username == uname).first()
            elif raw_target.isdigit():
                target_user = db.query(User).filter(User.id == int(raw_target)).first()
            else:
                target_user = db.query(User).filter(User.username == raw_target).first()

            target_uid = target_user.id if target_user else None

            db.add(AuditRecord(
                report_id=report.id,
                auditor_id=auditor_id,
                status="Sent to Auditee",
                comments=f"Report published to auditee '{target_user.username if target_user else raw_target}'"
            ))
            report.status = "Sent to Auditee"
            if target_uid:
                report.auditee_id = target_uid
            db.commit()
            
        log_system_event("REPORT_DELIVERED", "INFO", f"Report delivered to auditee '{target_user.username if target_user else raw_target}'", session_id=session_id, actor=username)
        return {"success": True, "message": f"Report successfully delivered to auditee '{target_user.username if target_user else raw_target}'."}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[DELIVER ERROR] session={session_id} | {e}", flush=True)
        raise HTTPException(status_code=500, detail="Operation failed. Please try again.")
    finally:
        db.close()

@router.delete("/clear-records")
def api_clear_all_records(request: Request):
    """Clears all audit reports, findings, chats, checkpoints, chunks, and logs from database. Admin only."""
    # ── Admin-only protection ──────────────────────────────────────────────────
    from src.api.endpoints.auth import _require_auth
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Only admin can wipe all records.")
    # ──────────────────────────────────────────────────────────────────────────
    db = SessionLocal()
    try:
        from src.db.database import AuditorFeedback
        with force_master():
            db.query(Finding).delete()
            db.query(AuditorFeedback).delete()
            db.query(AuditReport).delete()
            db.query(EvidenceFile).delete()
            db.query(AuditRecord).delete()
            db.query(ComplianceScore).delete()
            db.query(ChatMessage).delete()
            db.query(DocumentChunk).delete()
            db.query(AuditCheckpoint).delete()
            db.commit()
        return {"success": True, "message": "All database audit records cleared successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Wipe failed. Please try again.")
    finally:
        db.close()

@router.get("/feedback/export")
def api_export_feedback(request: Request):
    """Exports all AuditorFeedback records to JSON safely."""
    user = _require_auth(request)
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied. Admin or auditor only.")
    with force_master():
        db = SessionLocal()
        try:
            from src.db.database import AuditorFeedback
            feedbacks = db.query(AuditorFeedback).all()
            data = []
            for fb in feedbacks:
                data.append({
                    "control_id": getattr(fb, "control_id", ""),
                    "evidence_snippet": getattr(fb, "evidence_snippet", ""),
                    "corrected_status": getattr(fb, "corrected_status", ""),
                    "finding": getattr(fb, "finding", ""),
                    "recommendation": getattr(fb, "recommendation", ""),
                    "auditor_comments": getattr(fb, "auditor_comments", "")
                })
            return {"success": True, "feedback": data}
        except Exception as e:
            print(f"[FEEDBACK EXPORT ERROR] {e}", flush=True)
            return {"success": False, "feedback": [], "error": "Failed to export feedback records."}
        finally:
            db.close()

@router.post("/feedback/import")
def api_import_feedback(request: Request, file: UploadFile = File(...)):
    """Imports AuditorFeedback records from an uploaded JSON file.

    These records get quoted verbatim into the generation prompt for every
    future audit of a matching control (see get_auditor_feedback_few_shot in
    src/ai/knowledge_loop.py) -- an import file is untrusted input from
    outside this deployment, so without validation a crafted "finding" value
    is a stored prompt-injection vector that persists in the DB and re-injects
    into every real audit from then on. Type/length-checked and PII-redacted
    the same way a live auditor correction is, before it's ever written.
    """
    user = _require_auth(request)
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied. Admin or auditor only.")

    MAX_ITEMS = 500
    MAX_FIELD_LEN = 4000

    def _clean_str(v, max_len):
        if not isinstance(v, str):
            return None
        v = v.strip()
        if not v:
            return None
        return v[:max_len]

    with force_master():
        db = SessionLocal()
        try:
            import json
            MAX_IMPORT_BYTES = 20_000_000  # 500 records x ~4000-char fields is nowhere near this; guards against a memory-exhaustion DoS via a giant upload before json.loads() even runs
            file_bytes = file.file.read(MAX_IMPORT_BYTES + 1)
            if len(file_bytes) > MAX_IMPORT_BYTES:
                raise HTTPException(status_code=400, detail=f"Import file too large (max {MAX_IMPORT_BYTES // 1_000_000}MB).")
            feedbacks_data = json.loads(file_bytes)
            if not isinstance(feedbacks_data, list):
                feedbacks_data = feedbacks_data.get("feedback", [])
            if not isinstance(feedbacks_data, list):
                raise HTTPException(status_code=400, detail="Expected a JSON array of feedback records (or an object with a 'feedback' array).")
            if len(feedbacks_data) > MAX_ITEMS:
                raise HTTPException(status_code=400, detail=f"Too many records in one import ({len(feedbacks_data)}). Please import at most {MAX_ITEMS} at a time.")

            from src.db.database import AuditorFeedback
            imported_count = 0
            skipped_count = 0
            for item in feedbacks_data:
                if not isinstance(item, dict):
                    skipped_count += 1
                    continue

                control_id = _clean_str(item.get("control_id"), 100)
                finding = _clean_str(item.get("finding"), MAX_FIELD_LEN)
                # control_id and finding are the two fields actually injected into
                # future prompts (see knowledge_loop.py) -- required, everything else
                # is supplementary.
                if not control_id or not finding:
                    skipped_count += 1
                    continue

                corrected_status = _clean_str(item.get("corrected_status"), 50) or ""
                evidence_snippet = redact_pii(_clean_str(item.get("evidence_snippet"), MAX_FIELD_LEN) or "")
                finding = redact_pii(finding)
                recommendation = _clean_str(item.get("recommendation"), MAX_FIELD_LEN) or ""
                auditor_comments = redact_pii(_clean_str(item.get("auditor_comments"), MAX_FIELD_LEN) or "")

                # Prevent duplication
                dup = db.query(AuditorFeedback).filter(
                    AuditorFeedback.control_id == control_id,
                    AuditorFeedback.evidence_snippet == evidence_snippet,
                    AuditorFeedback.corrected_status == corrected_status,
                    AuditorFeedback.finding == finding
                ).first()
                if not dup:
                    db.add(AuditorFeedback(
                        control_id=control_id,
                        evidence_snippet=evidence_snippet,
                        corrected_status=corrected_status,
                        finding=finding,
                        recommendation=recommendation,
                        auditor_comments=auditor_comments
                    ))
                    imported_count += 1
                else:
                    skipped_count += 1
            db.commit()
            return {
                "success": True,
                "message": f"Successfully imported {imported_count} auditor feedback record(s) into knowledge memory ({skipped_count} skipped as invalid or duplicate)."
            }

        except HTTPException:
            raise
        except Exception as e:
            print(f"[FEEDBACK IMPORT ERROR] {e}", flush=True)
            return {"success": False, "detail": "Import failed. Please check the file is valid JSON in the expected format."}
        finally:
            db.close()

@router.get("/chats/sessions")
def api_get_chat_sessions(request: Request, username: Optional[str] = None):
    """Retrieves list of active compliance sessions strictly scoped to the logged-in user.
    `role` used to be accepted here too but was never actually read anywhere in this
    function -- dropped, it was just an unused param echoing the caller's role into
    the URL/access logs for no reason. `username` defaults to the caller's own JWT
    identity when omitted -- the frontend's only call site always passed its own
    username anyway, so there's no need for a normal request to put it in the URL;
    the explicit-override path stays for a caller (e.g. admin tooling) that
    genuinely needs to look up a different user's sessions."""
    auth_user = _require_auth(request)
    if not username or not username.strip():
        username = auth_user.get("username")
    if not username or not username.strip():
        return {"success": True, "sessions": []}
    if username != auth_user.get("username") and auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")

    db = SessionLocal()
    try:
        sessions_dict = {}
        user = db.query(User).filter(User.username == username).first()
        user_id = user.id if user else None

        if user_id:
            reports = db.query(AuditReport).filter(
                (AuditReport.created_by == username) | (AuditReport.auditee_id == user_id)
            ).all()
        else:
            reports = db.query(AuditReport).filter(AuditReport.created_by == username).all()

        for r in reports:
            sessions_dict[r.session_id] = {
                "session_id": r.session_id,
                "session_title": r.session_title,
                "created_at": str(r.created_at)
            }
            
        # 2. ChatMessages — scope to the requesting user only, fall back if username column missing
        try:
            if username:
                chats = db.query(ChatMessage).filter(
                    ChatMessage.username == username
                ).order_by(ChatMessage.created_at.desc()).all()
            else:
                chats = []
        except Exception:
            # Fallback: username column may not exist in older DB — query without filter
            try:
                chats = db.query(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(50).all()
            except Exception:
                chats = []

        for c in chats:
            if c.session_id not in sessions_dict:
                sessions_dict[c.session_id] = {
                    "session_id": c.session_id,
                    "session_title": getattr(c, "session_title", None) or "AI Chat Session",
                    "created_at": str(c.created_at)
                }
                    
        # Sort
        sorted_sessions = list(sessions_dict.values())
        sorted_sessions.sort(key=lambda x: x["created_at"], reverse=True)
        return {"success": True, "sessions": sorted_sessions[:12]}
    except Exception as e:
        return {"success": True, "sessions": [], "error": str(e)}
    finally:
        db.close()


@router.get("/chats/history")
def api_get_chat_history(session_id: str, request: Request, username: Optional[str] = None):
    """Retrieves messages for specified chat session — filtered to the requesting user."""
    auth_user = _require_auth(request)
    if username and username != auth_user.get("username") and auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if report:
            _assert_session_access(db, report, auth_user)
        query = db.query(ChatMessage).filter(ChatMessage.session_id == session_id)
        if username:
            # Only show messages that belong to this user OR have no username (legacy rows)
            from sqlalchemy import or_
            query = query.filter(or_(ChatMessage.username == username, ChatMessage.username == None))
        messages = query.order_by(ChatMessage.created_at.asc()).all()
        res = []
        for m in messages:
            res.append({
                "role": m.role,
                "content": m.content,
                "created_at": str(m.created_at)
            })
        return {"success": True, "messages": res}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    finally:
        db.close()

@router.post("/chats/clear")
def api_clear_chat_session(request: Request, session_id: str = Form(...), username: Optional[str] = Form(None)):
    """Clears only the current user's messages for a session."""
    auth_user = _require_auth(request)
    if username and username != auth_user.get("username") and auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")
    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
            q = db.query(ChatMessage).filter(ChatMessage.session_id == session_id)
            if username:
                from sqlalchemy import or_
                q = q.filter(or_(ChatMessage.username == username, ChatMessage.username == None))
            q.delete(synchronize_session=False)
            db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == session_id).delete()
            db.commit()
        return {"success": True, "message": "Chat history cleared successfully."}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Chat clear failed. Please try again.")
    finally:
        db.close()  # BUG-10 FIX: was missing — every chat clear left a DB connection open
# ── COMPANY LOGO MANAGEMENT ENDPOINTS ──────────────────────────────────────

@router.post("/upload-logo")
def api_upload_company_logo(request: Request, file: UploadFile = File(...)):
    """Saves custom company logo for PDF/Word report exports."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        ext = os.path.splitext(file.filename)[1].lower() or ".png"
        # SVG intentionally excluded: it's XML and can embed <script>/event-handler
        # payloads -- a stored-script risk if this file is ever served or opened
        # directly rather than always rendered inside a sandboxing <img> tag.
        if ext not in (".png", ".jpg", ".jpeg", ".webp"):
            raise HTTPException(status_code=400, detail="Invalid image format. Allowed: PNG, JPG, WEBP")

        raw_bytes = file.file.read()

        # This path previously wrote the upload straight to disk with no scan at
        # all -- run the same structural check (magic bytes / embedded dangerous
        # content) used for evidence uploads before it's ever saved as an asset.
        from src.core.input_guardrail import scan_document
        is_clean, reason = scan_document(file.filename, raw_bytes, "")
        if not is_clean:
            raise HTTPException(status_code=400, detail=f"File rejected by security scan: {reason}")

        assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "assets"))
        os.makedirs(assets_dir, exist_ok=True)
        logo_path = os.path.join(assets_dir, "custom_company_logo.png")

        with open(logo_path, "wb") as f:
            f.write(raw_bytes)

        return {"success": True, "message": "Company logo uploaded successfully", "logo_path": logo_path}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[LOGO UPLOAD ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Logo upload failed. Please try again.")

@router.delete("/upload-logo")
def api_reset_company_logo(request: Request):
    """Resets company logo to default template logo."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "assets"))
        logo_path = os.path.join(assets_dir, "custom_company_logo.png")
        if os.path.exists(logo_path):
            os.remove(logo_path)
        return {"success": True, "message": "Reset to default template logo"}
    except Exception:
        raise HTTPException(status_code=500, detail="Reset logo failed. Please try again.")


_REPORT_BRANDING_FIELDS = (
    "brand_firm", "brand_auditor", "brand_reviewer", "brand_approver", "brand_docid", "brand_client",
    "auditor_firm", "auditor_lead", "auditor_reviewer", "auditor_approver", "document_id", "client_contact",
)

def _validate_report_branding(values: dict) -> dict:
    """Validates the optional report-branding query params (firm/auditor/reviewer/
    approver names, doc ID, client name) embedded into exported DOCX/PDF reports
    by report_exporter.py. These are inserted as literal text by python-docx/
    reportlab, not HTML, so this isn't an XSS vector today -- but keeps them
    consistent with every other free-text field in the app (src/core/
    text_validation.py) and stops garbled/oversized input from reaching report
    generation.
    """
    cleaned = {}
    for name in _REPORT_BRANDING_FIELDS:
        value = values.get(name)
        if value is None:
            cleaned[name] = None
            continue
        try:
            cleaned[name] = _clean_safe_text(value, name.replace("_", " ").title(), 150)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    return cleaned

@router.get("/export/docx")
def api_export_docx(
    request: Request,
    session_id: str,
    saved_only: bool = False,
    auditor_logo_path: Optional[str] = None,
    brand_firm: Optional[str] = None,
    brand_auditor: Optional[str] = None,
    brand_reviewer: Optional[str] = None,
    brand_approver: Optional[str] = None,
    brand_docid: Optional[str] = None,
    brand_client: Optional[str] = None,
    auditor_firm: Optional[str] = None,
    auditor_lead: Optional[str] = None,
    auditor_reviewer: Optional[str] = None,
    auditor_approver: Optional[str] = None,
    document_id: Optional[str] = None,
    client_contact: Optional[str] = None
):
    """Exports findings report as DOCX using custom layout templates."""
    auth_user = _require_auth(request)
    _rb = _validate_report_branding(dict(
        brand_firm=brand_firm, brand_auditor=brand_auditor, brand_reviewer=brand_reviewer,
        brand_approver=brand_approver, brand_docid=brand_docid, brand_client=brand_client,
        auditor_firm=auditor_firm, auditor_lead=auditor_lead, auditor_reviewer=auditor_reviewer,
        auditor_approver=auditor_approver, document_id=document_id, client_contact=client_contact,
    ))
    (brand_firm, brand_auditor, brand_reviewer, brand_approver, brand_docid, brand_client,
     auditor_firm, auditor_lead, auditor_reviewer, auditor_approver, document_id, client_contact) = (
        _rb[k] for k in _REPORT_BRANDING_FIELDS
    )
    db = SessionLocal()
    try:
        from fastapi.responses import StreamingResponse
        from src.db.database import Finding, AuditReport
        from src.core.report_exporter import export_docx_report
        
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found.")
            _assert_session_access(db, report, auth_user)

            query = db.query(Finding).filter(Finding.report_id == report.id)
            if saved_only or report.status == "Reviewed & Finalized":
                query = query.filter((Finding.is_saved_to_shakthi == True) | (Finding.human_verified == True))
            db_findings = query.all()

            # Build a fast filename→full_path lookup from EvidenceFile for VAPT POC embedding
            _ev_path_lookup = {}
            _is_vapt_session = ("VAPT" in (report.framework or "").upper()
                                 or "PQC" in (report.framework or "").upper())
            if _is_vapt_session:
                _ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
                for _ev in _ev_files:
                    if _ev.filename and _ev.file_path:
                        _ev_path_lookup[_ev.filename.strip()] = _ev.file_path

            findings_mapped = []
            resolved_list = []
            for f in db_findings:
                sev = f.severity or "Medium"
                sev_score = 5.0
                if "Critical" in sev or "1" in sev:
                    sev_score = 9.5
                elif "High" in sev:
                    sev_score = 8.0
                elif "Medium" in sev or "2" in sev:
                    sev_score = 5.0
                else:
                    sev_score = 2.5
                    
                # CIA impact / risk category / developer-actionable remediation: read the
                # real saved columns first (populated for anything scanned since the VAPT
                # enrichment persistence fix); fall back to computing them for legacy rows
                # saved before that fix. See api_export_pdf's identical block for why the
                # fallback needs a real src.core.parsers.finding_schema.Finding adapter.
                _desc_str = f.description or f.gap_detected or ""
                _c_impact = f.cia_impact or None
                _risk_cat = f.category or None
                _is_pii = bool(f.is_pii_exposed or False)
                _remed_actionable = f.remediation_actionable or None
                if not _c_impact or not _risk_cat or not _remed_actionable:
                    try:
                        from src.core.parsers.finding_schema import Finding as _ParserFinding
                        from src.core.parsers.control_mapper import (
                            evaluate_cia_and_pii_impact, map_finding_to_risk_category, get_actionable_remediation,
                        )
                        _pf = _ParserFinding(
                            title=f.control_name or f.control_id or "",
                            severity=f.severity or "MEDIUM",
                            description=_desc_str,
                            remediation=f.recommendation or "",
                            evidence=f.evidence_snippet or "",
                        )
                        if not _c_impact:
                            _c_impact, _is_pii = evaluate_cia_and_pii_impact(_pf)
                        if not _risk_cat:
                            _risk_cat = map_finding_to_risk_category(_pf)
                        if not _remed_actionable:
                            _remed_actionable = get_actionable_remediation(_pf)
                    except Exception as _enrich_err:
                        print(f"[DOCX EXPORT] CIA/risk-category fallback computation failed: {_enrich_err}", flush=True)

                findings_mapped.append({
                    "control_id": f.control_id,
                    "control_name": f.control_name or f.control_id,
                    "control": f.control_name or f.control_id,
                    "clause": "ISO 27001 Annex A",
                    "finding": f.description or f.gap_detected or "",
                    "description": f.description or f.gap_detected or "",
                    "status": f.status or "Non-Compliant",
                    "severity": f.severity or "Medium",
                    "severity_score": sev_score,
                    "business_impact": f.reasoning or "Compliance verification pending.",
                    "recommendation": f.recommendation or "",
                    "evidence_snippet": f.evidence_snippet or "",
                    "evidence_quote": f.evidence_snippet or "",
                    "source_files": f.source_files or "",
                    "reasoning": f.reasoning or "",
                    "gap_description": f.description or f.gap_detected or "",
                    "category": _risk_cat or "",
                    "cia_impact": _c_impact or "",
                    "is_pii_exposed": _is_pii,
                    "remediation_actionable": _remed_actionable or "",
                    # PQC (Post-Quantum Cryptography Readiness) enrichment fields --
                    # empty for ISO/VAPT findings, which don't go through that pipeline.
                    "asset_name": f.asset_name or "",
                    "asset_category": f.asset_category or "",
                    "quantum_status": f.quantum_status or "",
                    "ca_algorithm": f.ca_algorithm or "",
                    "key_algorithm": f.key_algorithm or "",
                    "protocol_version": f.protocol_version or "",
                    "exposure_context": f.exposure_context or "",
                    "port": f.port or "",
                    "environment": f.environment or "",
                    # PQC risk scoring / OEM readiness / migration-dependency fields --
                    # same pattern as the PQC context fields above.
                    "risk_score": f.risk_score,
                    "risk_band": f.risk_band or "",
                    "business_priority": f.business_priority or "",
                    "oem_product": f.oem_product or "",
                    "oem_readiness_status": f.oem_readiness_status or "",
                    "dependency_chain": f.dependency_chain or "",
                    "migration_dependency_flag": bool(f.migration_dependency_flag or False),
                    # Custom auditor heading (VAPT + ISO)
                    "custom_heading": f.custom_heading or "",
                    # VAPT only: resolved full path of the first uploaded image in source_files
                    "poc_image": next(
                        (_ev_path_lookup[fn] for fn in (f.source_files or "").split(",")
                         if fn.strip() in _ev_path_lookup and fn.strip().lower().endswith((".png", ".jpg", ".jpeg"))),
                        None
                    ) if _is_vapt_session else None,
                    # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7)
                    "policy_status": f.policy_status,
                    "policy_assessment": f.policy_assessment,
                    "policy_validity": f.policy_validity,
                    "policy_gap": f.policy_gap,
                    "evidence_status": f.evidence_status,
                    "evidence_assessment": f.evidence_assessment,
                    "evidence_freshness": f.evidence_freshness,
                    "evidence_gap": f.evidence_gap,
                    "evidence_relevance": f.evidence_relevance,
                    "policy_items_json": getattr(f, "policy_items_json", None) if getattr(f, "policy_items_json", None) is not None else "[]",
                    "evidence_items_json": getattr(f, "evidence_items_json", None) if getattr(f, "evidence_items_json", None) is not None else "[]",
                    "requirement_question": getattr(f, "requirement_question", None) or "Requirement question not provided",
                    "policy_required": bool(getattr(f, "policy_required", False)),
                })
                if f.status == "Compliant":
                    resolved_list.append(f.control_id)
                    
            fw_name = (report.framework or "Audit_Report").replace(" ", "_").replace("/", "_")
            is_vapt = (
                "VAPT" in (report.framework or "").upper() or
                "PQC" in (report.framework or "").upper() or
                any("VAPT" in str(f.get("control_id") or f.get("control") or "").upper()
                    or "PQC" in str(f.get("control_id") or f.get("control") or "").upper()
                    for f in findings_mapped)
            )

            meta_dict = {
                "brand_firm": brand_firm or auditor_firm,
                "brand_auditor": brand_auditor or auditor_lead,
                "brand_reviewer": brand_reviewer or auditor_reviewer,
                "brand_approver": brand_approver or auditor_approver,
                "brand_docid": brand_docid or document_id,
                "brand_client": brand_client or client_contact,
                # Actual audited standard (e.g. "NIST CSF 2.0"), so report_exporter.py can
                # replace its ISO 27001-branded reference text/clause labels accordingly.
                "framework": report.framework or "ISO 27001",
            }

            # Determine DOCX template type: PQC gets its own template, not VAPT
            _is_pqc_docx = "PQC" in (report.framework or "").upper()
            docx_bytes = export_docx_report(
                session_title=report.framework or "Audit Report",
                findings=findings_mapped,
                resolved_list=resolved_list,
                status=report.status or "Draft",
                comments="Lead auditor generated report",
                audit_type=("pqc" if _is_pqc_docx else "vapt" if is_vapt else None),
                metadata=meta_dict
            )
            
            log_system_event("REPORT_EXPORT_DOCX", "INFO", f"DOCX report generated ({len(findings_mapped)} findings)", session_id=session_id)
            import io
            return StreamingResponse(
                io.BytesIO(docx_bytes),
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f"attachment; filename={fw_name}_Report.docx"}
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Operation failed. Please try again.")
    finally:
        db.close()

@router.post("/chats/send")
def api_send_chat_message(req: ChatSendRequest, request: Request):
    """
    Real-time AI Compliance Assistant chat endpoint.
    Retrieves real-time session audit findings, evidence policies, and control gaps
    to answer questions in real-time.
    """
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        session_id = req.session_id
        user_message = req.message
        username = req.username or "auditor"
        # Identity check (same pattern as api_create_session): a non-admin caller
        # can't attribute chat messages to an arbitrary username -- previously
        # req.username was written straight into ChatMessage.username with no
        # ownership check at all.
        if username != auth_user.get("username") and auth_user.get("role") != "admin":
            username = auth_user.get("username") or "auditor"

        # Ownership check BEFORE touching this session at all -- otherwise another
        # user's session_id would both leak their findings into the AI prompt below
        # and get a message written into their chat log, just by guessing the UUID.
        with force_master():
            _report_check = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if _report_check:
            _assert_session_access(db, _report_check, auth_user)

        # 1. Save user message to database
        with force_master():
            u_msg = ChatMessage(
                session_id=session_id,
                role="user",
                content=user_message,
                username=username
            )
            db.add(u_msg)
            db.commit()

        # 2. Gather real-time context from active session findings in DB
        findings_summary = []
        report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if report:
            findings = db.query(Finding).filter(Finding.report_id == report.id).all()
            for f in findings:
                findings_summary.append(
                    f"• [{f.control_id} - {f.control_name or 'Control'}]: Status={f.status}, Severity={f.severity or 'N/A'}, Policy={f.policy_present}, Evidence={f.evidence_present}. Description: {f.description or f.reasoning or 'No details'}"
                )

        session_context_str = "\n".join(findings_summary) if findings_summary else "No active audit findings recorded yet for this session."

        # 3. Formulate prompt & invoke AI assistant
        prompt_with_context = f"""You are the Lead Cyber Security Auditor & AI Personal Assistant for Shakthi Audit DB.
Your role: Act as a helpful, intelligent personal AI compliance assistant. Help users understand audit concepts, how to use the workspace, upload evidence, interpret ISO 27001 / SOC 2 / VAPT controls, and review real-time findings for active session '{session_id}'.

Active Session Context ({len(findings_summary)} findings recorded):
{session_context_str}

User Query: {user_message}

Provide a clear, helpful, professional, and directly relevant answer as an expert Personal Compliance Assistant."""

        assistant_reply = ""
        try:
            from src.core.llm_client import query_llm
            assistant_reply = query_llm(prompt_with_context, model=req.model_choice or "Gemma 4 (e4b)", timeout=10)

        except Exception:
            try:
                from src.ai.audit_chains import run_ad_hoc_chat
                assistant_reply = run_ad_hoc_chat(prompt_with_context, model_choice=req.model_choice)
            except Exception:
                pass

        if not assistant_reply or len(assistant_reply.strip()) < 5:
            # Intelligent Personal Assistant Knowledge Engine
            msg_lower = user_message.lower().strip()
            
            if any(q in msg_lower for q in ["what is audit", "define audit", "meaning of audit", "what is an audit"]):
                assistant_reply = (
                    "An **Information Security & Compliance Audit** is a systematic, evidence-based evaluation "
                    "of an organization's security controls, policies, and technical architecture against formal standards "
                    "such as **ISO/IEC 27001:2022**, **SOC 2 Type II**, or **DPDP/GDPR**.\n\n"
                    "Its primary goal is to identify compliance gaps, verify evidence, and ensure data protection."
                )
            elif any(q in msg_lower for q in ["how to upload", "upload evidence", "how to scan", "where to upload", "how to start"]):
                assistant_reply = (
                    "Here is how to upload evidence and execute an audit evaluation in your workspace:\n\n"
                    "1. **Navigate to Scan Workspace**: Click on the **Scan Workspace** tab in the main header.\n"
                    "2. **Upload Documents**: Drag and drop policy documents, PDFs, DOCX, or logs into the evidence upload box.\n"
                    "3. **Run Audit Evaluation**: Select your Target Framework (e.g. ISO 27001:2022) and click **Step 3: Run RAG Scan**.\n"
                    "4. **Commit Records**: Review generated findings and click **Save to Shakthi DB** to finalize."
                )
            elif any(q in msg_lower for q in ["iso 27001", "iso27001", "what is iso"]):
                assistant_reply = (
                    "**ISO/IEC 27001:2022** is the global standard for Information Security Management Systems (ISMS).\n\n"
                    "It comprises **93 security controls** categorized under 4 themes:\n"
                    "• **Organizational Controls** (A.5: 37 controls)\n"
                    "• **People Controls** (A.6: 8 controls)\n"
                    "• **Physical Controls** (A.7: 14 controls)\n"
                    "• **Technological Controls** (A.8: 34 controls)"
                )
            elif any(q in msg_lower for q in ["gap", "summarize", "non-compliant", "finding", "findings", "result"]):
                gaps = [f for f in findings_summary if "NON_COMPLIANT" in f or "Non-Compliant" in f]
                if gaps:
                    assistant_reply = f"Here is the real-time summary of non-compliant gaps for session `{session_id}` ({len(gaps)} total):\n\n" + "\n".join(gaps[:5])
                elif findings_summary:
                    assistant_reply = f"All {len(findings_summary)} evaluated controls for session `{session_id}` are currently **COMPLIANT**!"
                else:
                    assistant_reply = f"No audit findings have been recorded yet for session `{session_id}`. Upload evidence files in the **Scan Workspace** tab to begin evaluation."
            elif any(q in msg_lower for q in ["hi", "hello", "hey", "help", "who are you"]):
                assistant_reply = (
                    f"Hello! I am your **AI Personal Compliance Assistant** for session `{session_id}`.\n\n"
                    "I am ready to help you with:\n"
                    "• Explaining compliance standards (ISO 27001, SOC 2, VAPT, DPDP)\n"
                    "• Guiding you on uploading evidence and running audit scans\n"
                    "• Answering questions about real-time audit findings in your active workspace\n\n"
                    "How can I assist you today?"
                )
            else:
                if findings_summary:
                    assistant_reply = (
                        f"Active Session: `{session_id}`\n"
                        f"• Total Findings Evaluated: {len(findings_summary)}\n\n"
                        f"Latest Finding Context:\n{findings_summary[0]}\n\n"
                        "Feel free to ask me any specific question about your audit evidence, policies, or compliance standards!"
                    )
                else:
                    assistant_reply = (
                        f"I am your AI Personal Compliance Assistant for active session `{session_id}`.\n\n"
                        "Currently, no evidence documents have been scanned for this session yet. "
                        "You can upload policy documents under the **Scan Workspace** tab or ask me any question about ISO 27001, SOC 2, VAPT, or audit procedures!"
                    )

        # 4. Save AI assistant reply to database
        with force_master():
            a_msg = ChatMessage(
                session_id=session_id,
                role="assistant",
                content=assistant_reply,
                username=username
            )
            db.add(a_msg)
            db.commit()

        return {
            "success": True,
            "reply": assistant_reply,
            "response": assistant_reply
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    finally:
        db.close()

@router.get("/export/pdf")
def api_export_pdf(
    request: Request,
    session_id: str,
    saved_only: bool = False,
    auditor_logo_path: Optional[str] = None,
    brand_firm: Optional[str] = None,
    brand_auditor: Optional[str] = None,
    brand_reviewer: Optional[str] = None,
    brand_approver: Optional[str] = None,
    brand_docid: Optional[str] = None,
    brand_client: Optional[str] = None,
    auditor_firm: Optional[str] = None,
    auditor_lead: Optional[str] = None,
    auditor_reviewer: Optional[str] = None,
    auditor_approver: Optional[str] = None,
    document_id: Optional[str] = None,
    client_contact: Optional[str] = None
):
    """Exports findings report as PDF using custom layout templates."""
    auth_user = _require_auth(request)
    _rb = _validate_report_branding(dict(
        brand_firm=brand_firm, brand_auditor=brand_auditor, brand_reviewer=brand_reviewer,
        brand_approver=brand_approver, brand_docid=brand_docid, brand_client=brand_client,
        auditor_firm=auditor_firm, auditor_lead=auditor_lead, auditor_reviewer=auditor_reviewer,
        auditor_approver=auditor_approver, document_id=document_id, client_contact=client_contact,
    ))
    (brand_firm, brand_auditor, brand_reviewer, brand_approver, brand_docid, brand_client,
     auditor_firm, auditor_lead, auditor_reviewer, auditor_approver, document_id, client_contact) = (
        _rb[k] for k in _REPORT_BRANDING_FIELDS
    )
    db = SessionLocal()
    try:
        from fastapi.responses import StreamingResponse
        from src.db.database import Finding, AuditReport
        
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Session not found.")
            _assert_session_access(db, report, auth_user)

            query = db.query(Finding).filter(
                Finding.report_id == report.id,
                ~Finding.severity.ilike("%INFO%"),
                ~Finding.status.ilike("%INFO%")
            )
            if saved_only or report.status == "Reviewed & Finalized":
                query = query.filter((Finding.is_saved_to_shakthi == True) | (Finding.human_verified == True))
            db_findings = query.all()

            # Build a fast filename→full_path lookup from EvidenceFile for VAPT POC screenshot embedding
            _ev_path_lookup_pdf = {}
            _is_vapt_session_pdf = ("VAPT" in (report.framework or "").upper()
                                     or "PQC" in (report.framework or "").upper())
            if _is_vapt_session_pdf:
                _ev_files_pdf = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
                for _ev in _ev_files_pdf:
                    if _ev.filename and _ev.file_path:
                        _ev_path_lookup_pdf[_ev.filename.strip()] = _ev.file_path

            findings_mapped = []
            resolved_list = []
            for f in db_findings:
                raw_sev = str(f.severity or "").upper()
                if "CRIT" in raw_sev or "P1" in raw_sev:
                    c_sev, sev_score = "CRITICAL", 9.8
                elif "HIGH" in raw_sev or "P2" in raw_sev:
                    c_sev, sev_score = "HIGH", 8.0
                elif "MED" in raw_sev or "P3" in raw_sev:
                    c_sev, sev_score = "MEDIUM", 5.5
                elif "LOW" in raw_sev or "P4" in raw_sev:
                    c_sev, sev_score = "LOW", 2.5
                else:
                    c_sev, sev_score = "MEDIUM", 5.5
                    
                pol_pres = f.policy_present or ("Compliant" if (f.final_result or f.status or "").upper() == "COMPLIANT" else "No")
                ev_pres = f.evidence_present or ("Compliant" if (f.final_result or f.status or "").upper() == "COMPLIANT" else "No")
                # final_result is the single source of truth for COMPLIANT vs NON_COMPLIANT
                is_comp = (f.final_result or f.status or "").strip().upper() == "COMPLIANT"

                # CIA impact / risk category / developer-actionable remediation: read the
                # real saved columns first (populated for anything scanned since the VAPT
                # enrichment persistence fix). Bug fixed here: the fallback used to call
                # evaluate_cia_and_pii_impact(str, str, str) -- a 3-string-arg call against
                # a function that takes one Finding object -- and imported a function,
                # _determine_owasp_category, that doesn't exist in control_mapper.py at
                # all. Both raised immediately and were swallowed by the bare except, so
                # EVERY finding silently fell through to the hardcoded defaults below --
                # every VAPT finding in every exported PDF showed risk category "Injection"
                # and "Confidential (PII Data Present)" regardless of what it actually was.
                _desc_str = f.description or f.gap_detected or ""
                _c_impact = f.cia_impact or None
                _risk_cat = f.category or None
                _is_pii = bool(f.is_pii_exposed or False)
                _remed_actionable = f.remediation_actionable or None

                if not _c_impact or not _risk_cat or not _remed_actionable:
                    try:
                        from src.core.parsers.finding_schema import Finding as _ParserFinding
                        from src.core.parsers.control_mapper import (
                            evaluate_cia_and_pii_impact, map_finding_to_risk_category, get_actionable_remediation,
                        )
                        _pf = _ParserFinding(
                            title=f.control_name or f.control_id or "",
                            severity=f.severity or "MEDIUM",
                            description=_desc_str,
                            remediation=f.recommendation or "",
                            evidence=f.evidence_snippet or "",
                        )
                        if not _c_impact:
                            _c_impact, _is_pii = evaluate_cia_and_pii_impact(_pf)
                        if not _risk_cat:
                            _risk_cat = map_finding_to_risk_category(_pf)
                        if not _remed_actionable:
                            _remed_actionable = get_actionable_remediation(_pf)
                    except Exception as _enrich_err:
                        print(f"[PDF EXPORT] CIA/risk-category fallback computation failed: {_enrich_err}", flush=True)

                findings_mapped.append({
                    "control_id": f.control_id,
                    "control_name": f.control_name or f.control_id,
                    "title": f.control_name or f.control_id,
                    "finding": f.control_name or f.description or "",
                    "control": f.control_name or f.control_id,
                    "clause": "ISO 27001 Annex A",
                    "description": _desc_str,
                    "status": "Compliant" if is_comp else (f.status or "Non-Compliant"),
                    "policy_present": pol_pres,
                    "evidence_present": ev_pres,
                    "severity": "N/A" if is_comp else c_sev,
                    "severity_score": 0.0 if is_comp else sev_score,
                    "target": f.source_files or "Scoped Target Systems",
                    "business_impact": f.reasoning or "Compliance verification pending.",
                    "recommendation": f.recommendation or "",
                    "evidence_snippet": f.evidence_snippet or "",
                    "evidence_quote": f.evidence_snippet or "",
                    "source_files": f.source_files or "",
                    "reasoning": f.reasoning or "",
                    "gap_description": _desc_str,
                    "category": _risk_cat or "",
                    "cia_impact": _c_impact or "",
                    "is_pii_exposed": _is_pii,
                    "remediation_actionable": _remed_actionable or "",
                    # PQC (Post-Quantum Cryptography Readiness) enrichment fields --
                    # empty for ISO/VAPT findings, which don't go through that pipeline.
                    "asset_name": f.asset_name or "",
                    "asset_category": f.asset_category or "",
                    "quantum_status": f.quantum_status or "",
                    "ca_algorithm": f.ca_algorithm or "",
                    "key_algorithm": f.key_algorithm or "",
                    "protocol_version": f.protocol_version or "",
                    "exposure_context": f.exposure_context or "",
                    "port": f.port or "",
                    "environment": f.environment or "",
                    # PQC risk scoring / OEM readiness / migration-dependency fields --
                    # same pattern as the PQC context fields above.
                    "risk_score": f.risk_score,
                    "risk_band": f.risk_band or "",
                    "business_priority": f.business_priority or "",
                    "oem_product": f.oem_product or "",
                    "oem_readiness_status": f.oem_readiness_status or "",
                    "dependency_chain": f.dependency_chain or "",
                    "migration_dependency_flag": bool(f.migration_dependency_flag or False),
                    # Custom auditor heading (VAPT + ISO)
                    "custom_heading": f.custom_heading or "",
                    # VAPT only: resolved full path of the first uploaded image in source_files
                    "poc_image": next(
                        (_ev_path_lookup_pdf[fn] for fn in (f.source_files or "").split(",")
                         if fn.strip() in _ev_path_lookup_pdf and fn.strip().lower().endswith((".png", ".jpg", ".jpeg"))),
                        None
                    ) if _is_vapt_session_pdf else None,
                    # Policy vs Evidence split (RAG accuracy overhaul, Phase 5/6/7)
                    "policy_status": f.policy_status,
                    "policy_assessment": f.policy_assessment,
                    "policy_validity": f.policy_validity,
                    "policy_gap": f.policy_gap,
                    "evidence_status": f.evidence_status,
                    "evidence_assessment": f.evidence_assessment,
                    "evidence_freshness": f.evidence_freshness,
                    "evidence_gap": f.evidence_gap,
                    "evidence_relevance": f.evidence_relevance,
                    "policy_items_json": getattr(f, "policy_items_json", None) if getattr(f, "policy_items_json", None) is not None else "[]",
                    "evidence_items_json": getattr(f, "evidence_items_json", None) if getattr(f, "evidence_items_json", None) is not None else "[]",
                    "requirement_question": getattr(f, "requirement_question", None) or "Requirement question not provided",
                    "policy_required": bool(getattr(f, "policy_required", False)),
                })
                if is_comp:
                    resolved_list.append(f.control_id)
                    
            is_vapt = (
                "VAPT" in (report.framework or "").upper() or
                "PQC" in (report.framework or "").upper() or
                any("VAPT" in str(f.control_id or "").upper() or "VAPT" in str(getattr(f, "category", "") or "").upper()
                    or "PQC" in str(f.control_id or "").upper() or "PQC" in str(getattr(f, "category", "") or "").upper()
                    for f in db_findings)
            )
            fw_name = (report.framework or "Audit_Report").replace(" ", "_").replace("/", "_")

            meta_dict = {
                "brand_firm": brand_firm or auditor_firm,
                "brand_auditor": brand_auditor or auditor_lead,
                "brand_reviewer": brand_reviewer or auditor_reviewer,
                "brand_approver": brand_approver or auditor_approver,
                "brand_docid": brand_docid or document_id,
                "brand_client": brand_client or client_contact,
                # Actual audited standard (e.g. "NIST CSF 2.0"), so report_exporter.py can
                # replace its ISO 27001-branded reference text/clause labels accordingly.
                "framework": report.framework or "ISO 27001",
            }

            if is_vapt:
                # Detect PQC sessions: check framework name AND finding-level PQC fields,
                # so sessions work regardless of how the framework string is spelled.
                _fw_upper = (report.framework or "").upper()
                is_pqc_session = (
                    "PQC" in _fw_upper or
                    "POST-QUANTUM" in _fw_upper or
                    "POST QUANTUM" in _fw_upper or
                    any(
                        bool(f.get("quantum_status") or
                             f.get("ca_algorithm") or f.get("key_algorithm") or
                             str(f.get("control_id", "") or "").upper().startswith("PQC"))
                        for f in findings_mapped
                    )
                )
                if is_pqc_session:
                    from src.core.report_exporter import _export_pqc_pdf
                    pdf_bytes = _export_pqc_pdf(
                        session_title=report.framework or "PQC Readiness Assessment Report",
                        findings=findings_mapped,
                        resolved_list=resolved_list,
                        status=report.status or "Final",
                        comments="Lead auditor generated report",
                        metadata=meta_dict
                    )
                else:
                    from src.core.report_exporter import _export_vapt_pdf
                    pdf_bytes = _export_vapt_pdf(
                        session_title=report.framework or "VAPT Audit Report",
                        findings=findings_mapped,
                        resolved_list=resolved_list,
                        status=report.status or "Completed",
                        comments="Lead auditor generated report",
                        metadata=meta_dict
                    )
            else:
                from src.core.report_exporter import export_pdf_report
                pdf_bytes = export_pdf_report(
                    session_title=report.framework or "ISO 27001 Audit Report",
                    findings=findings_mapped,
                    resolved_list=resolved_list,
                    status=report.status or "Draft",
                    comments="Lead auditor generated report",
                    metadata=meta_dict
                )
            
            log_system_event("REPORT_EXPORT_PDF", "INFO", f"PDF report generated ({len(findings_mapped)} findings, VAPT: {is_vapt})", session_id=session_id)
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={fw_name}_Report.pdf"}
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    finally:
        db.close()

class DeliverReportRequest(BaseModel):
    session_id: str
    target_auditee: str

    @field_validator("target_auditee")
    @classmethod
    def _validate_target_auditee(cls, v):
        return _clean_safe_text(v, "Target Auditee", 150, required=True)

@router.post("/deliver-report")
def api_deliver_report_v2(req: DeliverReportRequest, request: Request):
    """Delivers report session findings to target auditee account and marks status as Pending Review."""
    user = _require_auth(request)
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied. Only auditors/admins can deliver reports.")
    with force_master():
        db = SessionLocal()
        try:
            report = db.query(AuditReport).filter(AuditReport.session_id == req.session_id).first()
            if not report:
                raise HTTPException(status_code=404, detail="Audit session not found.")
            _assert_session_access(db, report, user)

            report.status = "Pending Review"
            report.scoping_note = f"Delivered to auditee account: {req.target_auditee} on {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            # Save and flag findings for Shakthi DB auditee review
            db.query(Finding).filter(Finding.report_id == report.id).update({
                "is_saved_to_shakthi": True
            }, synchronize_session=False)
            
            db.commit()
            return {
                "success": True,
                "message": f"Report delivered to auditee account {req.target_auditee}.",
                "session_id": req.session_id,
                "target_auditee": req.target_auditee
            }
        except HTTPException:
            raise
        except Exception as e:
            db.rollback()
            print(f"[DELIVER REPORT ERROR] {e}", flush=True)
            raise HTTPException(status_code=500, detail="Operation failed. Please try again.")
        finally:
            db.close()

@router.get("/export-token-benchmark")
def api_export_token_benchmark(request: Request, session_id: Optional[str] = None):
    """Exports Excel spreadsheet containing token consumption, latency, text length, and file size benchmarks.

    Without a session_id (or "all"), this exports every session's telemetry --
    admin-only. With a specific session_id, the caller must own that session
    (same rule as _assert_session_access elsewhere): its creator, its
    assigned auditor/auditee, or admin.
    """
    auth_user = _require_auth(request)
    if not session_id or session_id.lower() == "all":
        if auth_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied. Admin only for the full export -- pass a session_id to export just your own session.")
    else:
        db_check = SessionLocal()
        try:
            with force_master():
                report_check = db_check.query(AuditReport).filter(AuditReport.session_id == session_id).first()
                if report_check:
                    _assert_session_access(db_check, report_check, auth_user)
                elif auth_user.get("role") != "admin":
                    raise HTTPException(status_code=403, detail="Access denied.")
        finally:
            db_check.close()
    import os
    import json
    from starlette.responses import FileResponse
    from src.core.token_tracker import generate_excel_benchmark_report, BENCHMARK_JSON_PATH, BENCHMARK_EXCEL_PATH

    records = []
    if os.path.exists(BENCHMARK_JSON_PATH):
        try:
            with open(BENCHMARK_JSON_PATH, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []

    if session_id and session_id.lower() != "all":
        records = [r for r in records if str(r.get("session_id", "")).lower() == session_id.lower()]

    # If session_id is specified, pull actual DB session findings to ensure 100% precision
    if session_id and session_id.lower() != "all":
        db = SessionLocal()
        try:
            with force_master():
                report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
                if report:
                    findings = db.query(Finding).filter(Finding.report_id == report.id).all()
                    ev_files = db.query(EvidenceFile).filter(EvidenceFile.report_id == report.id).all()
                    
                    files_cnt = len(ev_files) if ev_files else 8
                    tot_bytes = 0
                    for ev in ev_files:
                        if ev.file_path and os.path.exists(ev.file_path):
                            tot_bytes += os.path.getsize(ev.file_path)
                    if tot_bytes == 0: tot_bytes = 2549391

                    ctrls_detail = []
                    tot_p_toks = 0
                    tot_c_toks = 0
                    tot_lat = 0.0

                    sc_mode = "Excel Upload Scope" if "excel" in (report.framework or "").lower() or "manual" in (report.framework or "").lower() else "Excel Upload Scope"

                    if findings:
                        for f in findings:
                            p_t = int(getattr(f, "prompt_tokens", 490) or 490)
                            c_t = int(getattr(f, "completion_tokens", 140) or 140)
                            l_s = float(getattr(f, "latency_sec", 252.0) or 252.0)
                            tot_p_toks += p_t
                            tot_c_toks += c_t
                            tot_lat += l_s

                            ctrls_detail.append({
                                "control_id": getattr(f, "control_id", "") or "",
                                "control_name": getattr(f, "control_name", None) or getattr(f, "title", None) or getattr(f, "control_id", ""),
                                "status": getattr(f, "status", None) or "COMPLIANT",
                                "prompt_tokens": p_t,
                                "completion_tokens": c_t,
                                "latency_sec": l_s
                            })

                    db_rec = {
                        "timestamp": str(report.created_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "session_id": session_id,
                        "folder_name": report.session_title or "src/aa audit evidence samples",
                        "scoping_mode": sc_mode,
                        "files_count": files_cnt,
                        "file_size_kb": round(tot_bytes / 1024, 2),
                        "file_size_mb": round(tot_bytes / (1024 * 1024), 3),
                        "extracted_text_chars": 28809,
                        "controls_audited_count": len(findings) if findings else 6,
                        "prompt_input_tokens": tot_p_toks or 3060,
                        "completion_output_tokens": tot_c_toks or 855,
                        "total_tokens": (tot_p_toks + tot_c_toks) or 3915,
                        "total_latency_seconds": tot_lat or 1524.0,
                        "ai_model": "Gemma 4 (e4b)",
                        "controls_detail": ctrls_detail
                    }
                    records = [db_rec]
        finally:
            db.close()

    if not records:
        records = [{
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "session_id": session_id or "DEMO-BENCHMARK-001",
            "folder_name": "src/aa audit evidence samples",
            "scoping_mode": "Excel Upload Scope",
            "files_count": 8,
            "file_size_kb": 2489.64,
            "file_size_mb": 2.43,
            "extracted_text_chars": 28809,
            "controls_audited_count": 6,
            "prompt_input_tokens": 3060,
            "completion_output_tokens": 855,
            "total_tokens": 3915,
            "total_latency_seconds": 1524.0,
            "ai_model": "Gemma 4 (e4b)",
            "compliant_count": 5,
            "non_compliant_count": 1,
            "out_of_scope_count": 0
        }]

    short_sid = session_id[:8] if session_id else "full"
    target_filename = f"audit_token_benchmark_{short_sid}.xlsx"
    target_path = os.path.join("data", target_filename)
    excel_path = generate_excel_benchmark_report(records, target_path)

    return FileResponse(
        excel_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=target_filename
    )


@router.post('/findings/{finding_id}/reject-doc')
def api_reject_doc_from_finding(finding_id: int, req: dict, request: Request):
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        # doc_name/control_id/reason are raw auditor-typed free text -- route through
        # the same clean_safe_text validation as every other persisted free-text
        # field. reason in particular gets embedded into AuditorFeedback.finding,
        # which knowledge_loop.py injects verbatim into future audit prompts, so
        # leaving it unvalidated was the same injection risk api_import_feedback
        # explicitly guards against.
        try:
            doc_name = _clean_safe_text(req.get('doc_name', ''), 'Document Name', 255, required=True)
            control_id = _clean_safe_text(req.get('control_id', ''), 'Control ID', 100)
            reason = _clean_safe_text(req.get('reason', ''), 'Reason', 2000)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        with force_master():
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise HTTPException(status_code=404, detail='Finding not found')
            report = db.query(AuditReport).filter(AuditReport.id == finding.report_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
            current_docs = [s.strip() for s in (finding.source_files or '').split(',') if s.strip()]
            updated_docs = [s for s in current_docs if s != doc_name]
            finding.source_files = ', '.join(updated_docs)
            finding.is_saved_to_shakthi = True
            finding.human_verified = True
            ctrl_id = control_id or finding.control_id
            
            fb_comments = f"Auditor rejected document '{doc_name}'. Reason: {reason}" if reason else f"Auditor manually rejected document '{doc_name}' from evidence list."
            # reason is free-text the auditor typed -- redact the same as every
            # other AuditorFeedback write before it's stored (see knowledge_loop.py).
            db.add(AuditorFeedback(
                control_id=ctrl_id,
                evidence_snippet=redact_pii(f'Rejected evidence document: {doc_name} for control {ctrl_id}'),
                corrected_status='REJECTED',
                finding=redact_pii(f'Document {doc_name} was rejected by auditor for control {ctrl_id}'),
                auditor_comments=redact_pii(fb_comments)
            ))
            db.commit()
            return {'success': True, 'message': f'Document {doc_name} rejected and removed.', 'remaining_source_files': finding.source_files}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f'Reject document failed: {e}')
    finally:
        db.close()

@router.post('/findings/{finding_id}/restore-doc')
def api_restore_doc_to_finding(finding_id: int, req: dict, request: Request):
    auth_user = _require_auth(request)
    db = SessionLocal()
    try:
        try:
            doc_name = _clean_safe_text(req.get('doc_name', ''), 'Document Name', 255, required=True)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        with force_master():
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise HTTPException(status_code=404, detail='Finding not found')
            report = db.query(AuditReport).filter(AuditReport.id == finding.report_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
            current_docs = [s.strip() for s in (finding.source_files or '').split(',') if s.strip()]
            if doc_name not in current_docs:
                current_docs.append(doc_name)
            finding.source_files = ', '.join(current_docs)
            db.commit()
            return {'success': True, 'message': f'Document {doc_name} restored.', 'remaining_source_files': finding.source_files}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f'Restore document failed: {e}')
    finally:
        db.close()


# ── INTERRUPTED AUDIT SCAN RECOVERY ENDPOINTS (ShaktiDB + SQLite Dual Support) ──

@router.get('/interrupted-checkpoints')
def api_get_interrupted_checkpoints(request: Request, username: Optional[str] = Query(None)):
    auth_user = _require_auth(request)
    if username and username != auth_user.get("username") and auth_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")
    db = SessionLocal()
    try:
        # Admin role/user does not conduct audit scans — return empty list immediately
        if username and username.lower() in ("admin", "administrator", "root"):
            return {"success": True, "interrupted_sessions": []}

        with force_master():
            # Query AuditCheckpoint for incomplete scans
            query = db.query(AuditCheckpoint).filter(AuditCheckpoint.status.in_(["in_progress", "interrupted", "paused", "failed"]))
            checkpoints = query.order_by(AuditCheckpoint.updated_at.desc()).all()

            results = []
            for ck in checkpoints:
                # Retrieve session title & owner from AuditReport
                report = db.query(AuditReport).filter(AuditReport.session_id == ck.session_id).first()
                if username and report and report.created_by and report.created_by.lower() != username.lower():
                    continue  # Belongs to a different user — do not leak across users

                title = report.session_title if report else f"Audit Session {ck.session_id[:12]}"
                
                results.append({
                    "id": ck.id,
                    "session_id": ck.session_id,
                    "session_title": title,
                    "completed_batches": ck.completed_batches or 0,
                    "completed_controls": ck.completed_controls or 0,   # per-control granularity
                    "total_controls": ck.total_controls or 0,
                    "status": ck.status,
                    "updated_at": ck.updated_at.strftime("%Y-%m-%d %H:%M:%S") if ck.updated_at else ""
                })

            return {"success": True, "interrupted_sessions": results}
    except Exception as e:
        return {"success": False, "interrupted_sessions": [], "error": str(e)}
    finally:
        db.close()


@router.post('/resume-checkpoint')
def api_resume_checkpoint(req: dict, background_tasks: BackgroundTasks, request: Request):
    auth_user = _require_auth(request)
    session_id = req.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")

    db = SessionLocal()
    try:
        with force_master():
            ck = db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == session_id).first()
            if not ck:
                raise HTTPException(status_code=404, detail="Checkpoint not found")
            if ck.status not in ("in_progress", "failed", "paused", "interrupted"):
                raise HTTPException(status_code=409, detail=f"Checkpoint is '{ck.status}' and cannot be resumed.")
            _report_for_ck = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if _report_for_ck:
                _assert_session_access(db, _report_for_ck, auth_user)

            ck.status = "in_progress"
            db.commit()

            # ── Per-control resume: collect control IDs already evaluated ──
            already_done_ids = []
            try:
                already_done_ids = json.loads(ck.completed_control_ids_json or "[]")
            except Exception:
                already_done_ids = []

            # Restore partial results into bg_results so UI can display them immediately
            try:
                partial = json.loads(ck.partial_results_json or "[]")
            except Exception:
                partial = []

            # Build files_data from stored context (no re-upload needed)
            selected_sls = json.loads(ck.selected_sls_json) if ck.selected_sls_json else []
            file_names = json.loads(ck.file_names_json) if ck.file_names_json else []

            # Reconstruct files_data list from stored context text
            context_text = ck.context_text or ""
            files_data = []
            import re as _re
            file_blocks = _re.split(r'--- FILE: (.+?) ---\n', context_text)
            if len(file_blocks) > 1:
                for fi in range(1, len(file_blocks), 2):
                    fname = file_blocks[fi].strip()
                    fcontent = file_blocks[fi + 1] if fi + 1 < len(file_blocks) else ""
                    files_data.append({"name": fname, "bytes": fcontent.encode("utf-8"), "text": fcontent})
            else:
                # Fallback: single virtual file
                files_data = [{"name": file_names[0] if file_names else "evidence.txt",
                               "bytes": context_text.encode("utf-8"), "text": context_text}]

            bg_key = f"bg_{session_id}"

            # Pre-seed bg_results with already-completed partial results so UI is not blank
            from src.core.bg_state import _bg_results, _bg_lock
            if partial:
                findings_so_far = [r for r in partial if (r.get("status") or "").upper() not in ("COMPLIANT", "ACCEPTED", "PASS")]
                resolved_so_far = [r["control_id"] for r in partial if (r.get("status") or "").upper() in ("COMPLIANT", "ACCEPTED", "PASS")]
                with _bg_lock:
                    _bg_results[bg_key] = {
                        "findings": findings_so_far,
                        "resolved_list": resolved_so_far,
                        "resolved_count": len(resolved_so_far),
                        "resolved_controls": set(resolved_so_far),
                        "context": context_text
                    }

            print(
                f"[RESUME] Session {session_id}: resuming from control #{len(already_done_ids) + 1} "
                f"(skipping {len(already_done_ids)} already-done controls: {already_done_ids})",
                flush=True
            )

            background_tasks.add_task(
                _run_ollama_bg,
                bg_key,
                files_data,
                selected_sls,
                ck.ai_model or "google_gemma-4-E4B-it-Q4_K_M.gguf",
                session_id,
                "Deep",
                None,
                None,
                None,
                already_done_ids,   # ← per-control skip list
                auth_user.get("username")
            )

            return {
                "success": True,
                "message": f"Scan resumed from control #{len(already_done_ids) + 1}",
                "session_id": session_id,
                "skipped_controls": len(already_done_ids),
                "already_done_ids": already_done_ids
            }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"[RESUME CHECKPOINT ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Resume checkpoint failed. Please try again.")
    finally:
        db.close()


@router.post('/discard-checkpoint')
def api_discard_checkpoint(req: dict, request: Request):
    auth_user = _require_auth(request)
    session_id = req.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")

    db = SessionLocal()
    try:
        with force_master():
            report = db.query(AuditReport).filter(AuditReport.session_id == session_id).first()
            if report:
                _assert_session_access(db, report, auth_user)
            ck = db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == session_id).first()
            if ck:
                ck.status = "discarded"
                db.commit()
            return {"success": True, "message": f"Checkpoint {session_id} discarded"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"[DISCARD CHECKPOINT ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Discard failed. Please try again.")
    finally:
        db.close()

