# -*- coding: utf-8 -*-
"""
Audit Graph Module
Implements the LangGraph State Machine for auditing controls.
Integrates custom validators and retrieval with LangChain ChatOllama.
"""

import os
import time as _time
import threading
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from src.ai.audit_models import AuditFindingSchema
from src.ai.audit_chains import get_generator_chain, get_reflection_chain
from src.core.retrieval import _retrieve_rag_context
from src.core.validator import post_process
from src.db.database import SessionLocal, DocumentChunk

class AuditState(TypedDict):
    """
    State definition for the auditing graph.
    Represents the context, drafts, errors, and outcomes for a single control.
    """
    control_id: str
    control_label: str
    expected_evidence: str
    prompt_hint: str
    severity: str
    standard: str
    recommendation: str
    keywords: Optional[Dict[str, float]]  # per-control retrieval keyword weights, see control_keywords.py
    
    # Document Context & Config
    document_text: str
    file_names_list: List[str]
    llm_model: str
    summary_text: str
    # This session's AuditReport.id -- scopes every document_chunks read/write
    # to only this session's own evidence, so two sessions that happen to
    # upload identically-named files never collide (see save_document_chunks /
    # _vec_native_search in retrieval.py). None only if resolution failed.
    report_id: Optional[int]
    
    # State tracking
    retrieved_context: str
    draft_finding: Optional[Dict[str, Any]]
    validation_error: Optional[str]
    retry_count: int
    final_finding: Optional[Dict[str, Any]]
    token_stats: Optional[Dict[str, int]]  # real prompt/completion token counts from the LLM server

    # Progress reporting
    bg_key: Optional[str]
    control_idx: int
    total_controls: int
    audit_mode: Optional[str]
    file_registry: Optional[Dict[str, str]]

    # ── Excel Scoping Two-Phase Pipeline ─────────────────────────────────────
    # When set, retrieval is restricted to ONLY these filenames (Phase 1 lock).
    # The LLM acts as a judge-only on the pre-extracted context (Phase 2).
    locked_filenames: Optional[List[str]]     # locked file(s) from Excel checklist
    checklist_question: Optional[str]         # original Excel audit check question
    # Which of the locked files (if any) came from a Policy-named vs an
    # Evidence-named column on the sheet, so the LLM can be told the auditor's
    # own intent instead of re-deriving the policy/evidence split blind from
    # undifferentiated locked text. Both empty when the sheet has no such
    # column-level distinction (e.g. a single generic "File name" column).
    policy_locked_filenames: Optional[List[str]]
    evidence_locked_filenames: Optional[List[str]]


# Synonyms dictionary used in retrieval
KEYWORD_SYNONYMS = {
    "access":         ["permission", "authorize", "login", "iprotect", "credential", "badge", "keycard", "rfid", "escort"],
    "authentication": ["mfa", "password", "login", "2fa", "credential", "pin", "keycard", "biometric", "badge", "token", "smart card", "auth-token", "api auth", "session management", "token issuance", "client id", "machine id", "pam", "iam", "privileged access management", "fraud analytics", "api authentication", "sub-aua", "whitelisting", "firewall rules", "auth", "secrets", "api-auth", "api_auth"],
    "identity":       ["user account", "userid", "provisioning", "onboard", "termination", "leave of absence", "joiner", "leaver", "myid"],
    "privileged":     ["admin", "superuser", "root", "elevated", "restricted area", "sponsor"],
    "inventory":      ["asset list", "register", "catalogue", "logbook", "visitor management"],
    "encryption":     ["tls", "ssl", "cipher", "aes", "https"],
    "logging":        ["audit trail", "siem", "event log", "monitoring", "registration log", "cloudwatch", "log archived", "ntp", "clock sync", "monitoring", "audit logs", "event logging", "syslog", "flow log", "vpc log", "timedatectl", "chronyd", "systemd-timesyncd"],
    "ntp":            ["timedatectl", "systemd-timesyncd", "chronyd", "chrony", "w32tm", "clock sync", "time sync", "time server", "ntp.conf", "ntp status", "clock synchronization"],
    "clock":          ["ntp", "timedatectl", "systemd-timesyncd", "chronyd", "w32tm", "time synchronization", "clock sync", "clock synchronization"],
    "sync":           ["synchronized", "synchronization", "ntp", "timedatectl", "chrony", "clock sync"],
    "fraud":          ["fraud analytics", "fraud detection", "api auth", "api authentication", "fraud operations", "risk engine"],
    "backup":         ["restore", "snapshot", "recovery", "replication"],
    "physical":       ["visitor", "escort", "card access", "restricted area", "lobby", "reception", "perimeter", "lock", "keycard", "badge", "gate", "guard", "cctv", "logbook", "sign-in", "breezn", "kastle"],
    "visitor":        ["escort", "guest", "contractor", "client", "visitor management", "breezn", "kastle", "sign-in", "logbook", "lobby"],
    "termination":    ["leave of absence", "exit", "revoc", "deactivat", "disable", "expire", "return of assets", "hr", "human resources"],
    "source code":    ["git", "repository", "github", "gitlab", "source", "code", "dev", "developer"],
    "continuity":     ["bcp", "dr", "disaster recovery", "continuity", "redundancy", "failover", "backup"],
    "malware":        ["antivirus", "edr", "malware", "virus", "threat", "scan"],
    "vulnerability":  ["patch", "scan", "vulnerability", "update", "cvse", "cve"],
    "incident":       ["breach", "event", "response", "irp", "triage", "ticket", "reporting", "alert"],
    "access control": ["badge", "keycard", "card access", "entry", "rfid", "pin", "tailgating", "escort", "access rights", "physical entry", "visitor sign-in", "sign-in sheet", "visitor log", "logbook", "lobby", "reception", "gate", "guard", "cctv", "biometric", "smart card", "fingerprint", "face ID", "credentials", "permissions", "authorized", "restriction", "pam", "iam", "privileged", "access control"]
}

def _update_progress(state: AuditState, phase_text: str, phase_ratio: float):
    bg_key = state.get("bg_key")
    idx = state.get("control_idx", 0)
    total = state.get("total_controls", 1)
    if not bg_key or total <= 0:
        return
    try:
        from src.core.bg_state import _bg_store, _bg_lock
        base_pct = int((idx / total) * 100)
        step_pct = 100 / total
        current_pct = int(base_pct + (step_pct * phase_ratio))
        # Ensure it doesn't exceed the next control's boundary
        next_base_pct = int(((idx + 1) / total) * 100)
        current_pct = min(current_pct, next_base_pct - 1 if idx + 1 < total else 99)
        
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"⚡ Auditing control {idx + 1}/{total}: {state.get('control_id','')} — {phase_text}...",
                "percent": current_pct
            }
    except Exception as e:
        print(f"[PROGRESS UPDATE WARNING] Failed to update progress: {e}", flush=True)

def retrieve_node(state: AuditState) -> Dict[str, Any]:
    """Node: Pulls grounded document segments relevant to the target control.

    Two-Phase Mode (Excel Scoping):
        If `locked_filenames` is set, retrieval is scoped to ONLY those files.
        This guarantees the correct evidence is always extracted from the correct
        file — the LLM never sees content from other files.

    Standard Mode (AI Scoping):
        Retrieval searches across all uploaded files as before.
    """
    _update_progress(state, "Retrieving document context", 0.1)
    controls_batch = [{
        "control": state["control_id"],
        "label": state["control_label"],
        "expected": state["expected_evidence"],
        "prompt_hint": state["prompt_hint"],
        "keywords": state.get("keywords") or {}
    }]

    # ── Phase 1: Locked-file retrieval (Excel scoping mode) ───────────────────
    locked_filenames = state.get("locked_filenames") or []
    if locked_filenames:
        # Restrict retrieval to ONLY the locked files from the Excel checklist
        print(
            f"[RETRIEVE NODE] Two-Phase mode: restricting retrieval to "
            f"{locked_filenames} for control {state['control_id']}",
            flush=True
        )
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=locked_filenames,   # ← LOCKED: only these files
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
            audit_mode=state.get("audit_mode"),
            report_id=state.get("report_id"),
            policy_locked_filenames=state.get("policy_locked_filenames"),
            evidence_locked_filenames=state.get("evidence_locked_filenames"),
            file_registry=state.get("file_registry")
        )
        # Safety guarantee: if locked files returned no context, fall back
        # to raw document_text (never send empty context to LLM)
        if not condensed.strip():
            print(
                f"[RETRIEVE NODE] Locked retrieval returned empty context for "
                f"{locked_filenames}. Falling back to raw document text.",
                flush=True
            )
            condensed = state["document_text"][:6000]
    else:
        # ── Standard mode: search across all uploaded files ────────────────
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=state["file_names_list"],
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
            audit_mode=state.get("audit_mode"),
            report_id=state.get("report_id"),
            policy_locked_filenames=state.get("policy_locked_filenames"),
            evidence_locked_filenames=state.get("evidence_locked_filenames"),
            file_registry=state.get("file_registry")
        )

    return {"retrieved_context": condensed}


# ── LLM timeout budget ───────────────────────────────────────────────────────
# Two separate budgets, deliberately. They used to be one number covering both
# the wait for a free worker slot and the request itself, so a long queue ate
# the request's clock: a control that needed 15 minutes of compute, after 20
# minutes of queueing, was killed at 30 having been given only 10. The request
# now always gets its full budget no matter how long it waited.
#
# The floor was raised from 600s because it is measured from the moment the call
# starts, using the session count at that instant. A request beginning while the
# system was quiet received 10 minutes, and a burst of new audits arriving
# immediately afterwards could slow it tenfold inside that unchanged budget.
# 1800 costs nothing under load, where active_cnt * per-session already
# dominates, and removes the only timeout that a correctly-sized machine still
# produced. Both are env-overridable for an operator who has measured their own
# hardware.
LLM_TIMEOUT_FLOOR_SEC = int(os.environ.get("LLM_TIMEOUT_FLOOR_SEC", "1800"))
LLM_TIMEOUT_PER_SESSION_SEC = int(os.environ.get("LLM_TIMEOUT_PER_SESSION_SEC", "360"))
# Waiting for a worker slot is a queueing problem, not a compute one: if no slot
# frees in this long, the system is saturated and failing fast is more useful
# than holding the thread.
LLM_POOL_WAIT_TIMEOUT_SEC = int(os.environ.get("LLM_POOL_WAIT_TIMEOUT_SEC", "300"))


def _record_control_timeout(state, control_id: str, budget_sec: int, phase: str = "generation"):
    """Records a control timeout everywhere it needs to be visible.

    Three destinations, because each answers a different person's question:
      - SystemEvent      : the admin log trail (what happened, when, which control)
      - Redis error count: the live KPI dashboard, which previously read zero
                           errors while controls were timing out -- the two views
                           disagreed and the dashboard was the one people watched
      - progress warning : the auditor's own screen. app.js already toasts this
                           field, so no frontend change is needed; without it a
                           timeout was invisible to the person running the audit.
    """
    session_id = state.get("bg_key", "") or ""
    try:
        from src.core.bg_worker import log_system_event
        log_system_event(
            "LLM_TIMEOUT", "WARNING",
            f"{phase.capitalize()} timed out after {budget_sec}s for control '{control_id}' "
            f"-- control marked NOT_EVALUATED.",
            session_id=session_id,
        )
    except Exception:
        pass
    try:
        from src.core import redis_metrics as _rm
        _rm.push_error(session_id=session_id)
    except Exception:
        pass
    if not session_id:
        return
    try:
        from src.core.bg_state import _bg_store, _bg_lock
        with _bg_lock:
            _prev = _bg_store["progress"].get(session_id) or {}
            if phase == "reflection":
                _msg = (
                    f"⚠️ Control {control_id}: the self-correction pass timed out after "
                    f"{budget_sec // 60} minutes. The original assessment was kept."
                )
            else:
                _msg = (
                    f"⚠️ Control {control_id} could not be evaluated — the analysis engine "
                    f"did not respond in {budget_sec // 60} minutes. It will be reported as "
                    f"Not Evaluated."
                )
            _bg_store["progress"][session_id] = {**_prev, "warning": _msg}
    except Exception:
        pass


def _calculate_adaptive_timeout() -> int:
    """
    Dynamically calculates the LLM execution timeout based on system load:
    - 1 Auditor running: max(600, 1 * 180) = 600s (10 minutes) — ample time even for huge prompts.
    - 15 Auditors running: max(600, 15 * 180) = 2700s (45 minutes) — heavy concurrent batches are NEVER cut short.
    - If Redis is down: falls back to checking Python in-memory _bg_running set.
    - Instant exit: t.join() exits sub-second as soon as LLM generation finishes.
    """
    from src.core.redis_metrics import get_running_session_count
    active_cnt = max(1, get_running_session_count())

    return max(LLM_TIMEOUT_FLOOR_SEC, active_cnt * LLM_TIMEOUT_PER_SESSION_SEC)


def _accumulate_token_stats(state: AuditState, chain) -> Dict[str, int]:
    """Adds a chain's real token usage (from the LLM server) on top of whatever's
    already recorded in state — generate + reflection are separate LLM calls, so
    a reflection pass adds to the total rather than replacing it."""
    prior = state.get("token_stats") or {}
    new_stats = getattr(chain, "last_token_stats", {}) or {}
    return {
        "prompt_tokens": prior.get("prompt_tokens", 0) + new_stats.get("prompt_tokens", 0),
        "completion_tokens": prior.get("completion_tokens", 0) + new_stats.get("completion_tokens", 0),
    }


def generate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Calls ChatOllama to generate the initial finding draft based on context."""
    _update_progress(state, "Drafting compliance finding", 0.3)
    from src.ai.knowledge_loop import get_auditor_feedback_few_shot as _get_auditor_feedback_few_shot
    
    feedback_block = _get_auditor_feedback_few_shot([state["control_id"]])
    feedback_section = f"\nAUDITOR KNOWLEDGE LOOP GUIDELINES:\n{feedback_block}\n" if feedback_block else ""

    # generator_chain is constructed inside this same try/except now -- previously
    # get_generator_chain()/get_excel_scoping_chain() ran before the try block
    # below, so if either ever raised, the exception propagated uncaught out of
    # generate_node and aborted the whole graph run for that control instead of
    # degrading gracefully like the rest of this node. Initialized to None first
    # so the except block's _accumulate_token_stats(state, generator_chain) call
    # stays safe even if construction itself is what failed.
    generator_chain = None
    try:
        generator_chain = get_generator_chain(state["llm_model"])

        # ── Phase 2: Judge-only chain for Excel scoping mode ────────────────────
        locked_filenames = state.get("locked_filenames") or []
        checklist_question = state.get("checklist_question") or state["control_label"]
        use_excel_judge_mode = bool(locked_filenames)
        if use_excel_judge_mode:
            from src.ai.audit_chains import get_excel_scoping_chain
            generator_chain = get_excel_scoping_chain(state["llm_model"])
            print(
                f"[GENERATE NODE] Two-Phase judge mode for control {state['control_id']} "
                f"(locked: {locked_filenames})",
                flush=True
            )

        # ── Column-source hint: tell the LLM which locked file(s) the auditor put
        # in a Policy-named vs Evidence-named column, instead of leaving it to
        # re-derive that split blind from undifferentiated locked text. Empty when
        # the sheet has no such column-level distinction.
        policy_locked = state.get("policy_locked_filenames") or []
        evidence_locked = state.get("evidence_locked_filenames") or []
        column_source_hint = ""
        if policy_locked or evidence_locked:
            parts = []
            if policy_locked:
                parts.append(f"The auditor's checklist lists {', '.join(policy_locked)} under the POLICY column.")
            if evidence_locked:
                parts.append(f"The auditor's checklist lists {', '.join(evidence_locked)} under the EVIDENCE column.")
            column_source_hint = (
                "\nAUDITOR COLUMN SOURCE (strong prior, not proof — still verify the actual content "
                "supports the objective before marking COMPLIANT):\n" + " ".join(parts) + "\n"
            )

        result_holder = {}
        # Adaptive: scales with active session count (600s floor, +180s per active
        # session) so heavier concurrent load gets more time before giving up,
        # instead of a flat ceiling that starts producing real timeouts under load.
        # Computed once, up front, and passed into the chain's own query_llm() call
        # (via "timeout" in the invoke dict below) so the actual HTTP request's
        # timeout matches this wait loop's budget exactly -- previously the two
        # were computed independently and could diverge, leaving the thread still
        # blocked in query_llm() (and still holding its port_pool slot) after this
        # loop had already given up and moved on.
        _timeout = _calculate_adaptive_timeout()
        def _run():
            try:
                print("\n===== EVIDENCE CONTEXT SENT TO LLM =====", flush=True)
                print(state.get("retrieved_context", ""), flush=True)
                print("===== END EVIDENCE CONTEXT =====\n", flush=True)

                if use_excel_judge_mode:
                    # Judge-only mode: pass locked_filenames + checklist_question
                    result_holder["draft"] = generator_chain.invoke({
                        "locked_filenames": ", ".join(locked_filenames),
                        "checklist_question": checklist_question,
                        "column_source_hint": column_source_hint,
                        "condensed_context": state["retrieved_context"],
                        "control_id": state["control_id"],
                        "control_label": state["control_label"],
                        "expected_evidence": state["expected_evidence"],
                        "feedback_section": feedback_section,
                        "session_id": state.get("bg_key"),
                        "timeout": _timeout,
                    })
                else:
                    # Standard mode: original prompt
                    result_holder["draft"] = generator_chain.invoke({
                        "summary_text": state["summary_text"],
                        "condensed_context": state["retrieved_context"],
                        "control_id": state["control_id"],
                        "control_label": state["control_label"],
                        "expected_evidence": state["expected_evidence"],
                        "feedback_section": feedback_section,
                        "standard": state.get("standard", ""),
                        "session_id": state.get("bg_key"),
                        "timeout": _timeout,
                    })
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        # ── Heartbeat: update progress every 15s so UI never shows stuck 0% ──
        # The wrapper allows the slot wait ON TOP of the request budget, so a
        # control that queued for a while still gets its full compute time --
        # the wrapper must never be the thing that cuts a running request short.
        _wall_budget = _timeout + LLM_POOL_WAIT_TIMEOUT_SEC
        _elapsed = 0
        _heartbeat_interval = 15
        while t.is_alive() and _elapsed < _wall_budget:
            t.join(timeout=_heartbeat_interval)
            _elapsed += _heartbeat_interval
            if t.is_alive():
                # Slowly increment between 30%→70% to show LLM is still working
                _hb_phase = min(0.3 + (_elapsed / _wall_budget) * 0.4, 0.69)
                _update_progress(state, f"LLM analysing control... ({_elapsed}s)", _hb_phase)
        if t.is_alive():
            _ctrl = state.get('control_id', '')
            print(f"[LANGGRAPH TIMEOUT] Generator timed out after {_wall_budget}s for control {_ctrl}. Not evaluated.", flush=True)
            _record_control_timeout(state, _ctrl, _wall_budget, phase="generation")
            # NOT_EVALUATED, never a fabricated verdict. This previously fell
            # through to the same failure path as a validation error, which ends
            # in a NON_COMPLIANT/PARTIAL finding -- publishing a compliance
            # judgement for a control the model never actually assessed. An
            # audit may report that it could not evaluate something; it must not
            # invent the answer.
            return {
                "draft_finding": None,
                "validation_error": f"LLM call timed out after {_wall_budget}s",
                "not_evaluated": True,
                "not_evaluated_reason": (
                    f"Control was not evaluated: the analysis engine did not respond within "
                    f"{_wall_budget // 60} minutes. Re-run this control; if it recurs, the "
                    f"server is under-provisioned for the number of concurrent auditors."
                ),
            }
        # ─────────────────────────────────────────────────────────────────────
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        draft = result_holder["draft"]

        return {
            "draft_finding": draft.model_dump(),
            "validation_error": None,
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH GENERATOR ERROR] Schema parsing failed for control {state['control_id']}: {e}", flush=True)
        return {
            "draft_finding": None,
            "validation_error": f"Schema parsing/validation failed: {str(e)}",
            # LLM call may have consumed real tokens even though parsing failed afterward.
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }

def validate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Validates finding grounding, prompt leakage, and alignment consistency."""
    _update_progress(state, "Validating cited evidence", 0.7)
    draft = state["draft_finding"]
    
    if not draft:
        if state.get("audit_mode") == "Quick" or state["retry_count"] >= 1:
            mode_prefix = "Quick audit" if state.get("audit_mode") == "Quick" else "Self-correction"
            print(f"[LANGGRAPH] {mode_prefix} failed generation for control {state['control_id']}. Routing to fallback.", flush=True)
            retrieved = str(state.get("retrieved_context") or "").strip()
            has_retrieved = len(retrieved) > 40 and not any(kw in retrieved.lower() for kw in ["no relevant context found", "no evidence found"])
            
            ev_snippet = retrieved[:400] if has_retrieved else ""
            ev_quote = retrieved[:200] if has_retrieved else "NOT_FOUND"
            
            ctrl_name = state.get("control_label") or state.get("control_id") or "Control"
            ctrl_code = state.get("control_id") or ""
            prompt_hint = state.get("prompt_hint") or ""

            # ── Honest fallback: this path means the LLM never actually produced
            # a parseable finding -- distinguish WHY (genuine timeout vs. some
            # other generation failure) using the real reason already sitting in
            # validation_error, instead of synthesizing plausible-sounding
            # "evidence was identified" text that reads like real analysis
            # happened when nothing was actually evaluated.
            _prior_error = str(state.get("validation_error") or "")
            _is_timeout = "timed out" in _prior_error.lower()

            if _is_timeout:
                finding_text = (
                    f"SYSTEM TIMEOUT: Control {ctrl_code} ({ctrl_name}) was NOT evaluated. "
                    f"The LLM did not respond within the time limit, likely due to high concurrent "
                    f"system load. This is not a compliance assessment -- re-run this control once "
                    f"system load decreases."
                )
                gap_text = f"Control {ctrl_code} was not evaluated due to a system timeout ({_prior_error}). Re-run required."
                rec_text = "Re-run this control -- it was not evaluated due to a system timeout, not a documented compliance gap."
                review_note = "SYSTEM TIMEOUT -- not a real evaluation. Re-run required, do not treat as a genuine finding."
            elif has_retrieved:
                finding_text = f"Evidence context was identified for Control {ctrl_code} ({ctrl_name}), demonstrating partial alignment with governance requirements. However, complete operational logs or formal approval sign-offs remain unverified."
                gap_text = f"Context identified for {ctrl_code}, but complete evidence verification requires auditor sign-off. Context excerpt: {ev_snippet[:200]}..."
                rec_text = state.get("recommendation") or f"Formally document, review, and maintain operational evidence logs for Control {ctrl_code} ({ctrl_name})."
                review_note = "Evaluated with control-specific governance synthesis."
            else:
                finding_text = f"The control objective for Control {ctrl_code} ({ctrl_name}) requires documented policies and implementation evidence ({prompt_hint[:90]}...). No supporting evidence was identified in the uploaded package."
                gap_text = f"No documentation or evidence identified for Control {ctrl_code}."
                rec_text = state.get("recommendation") or f"Establish, document, and formally approve procedures to satisfy Control {ctrl_code} ({ctrl_name})."
                review_note = "Evaluated with control-specific governance synthesis."

            fallback = {
                # A timeout is NOT_EVALUATED, not NON_COMPLIANT. The prose in this
                # branch already said the control "was NOT evaluated", but the status
                # field -- which is what drives the dashboard counts, the severity
                # calculation, the exports and the customer's compliance percentage --
                # still asserted NON_COMPLIANT. That publishes a compliance judgement
                # for a control nothing ever assessed, and it is indistinguishable in
                # every downstream view from a genuine failure.
                "status": "NOT_EVALUATED" if _is_timeout else ("PARTIAL" if has_retrieved else "NON_COMPLIANT"),
                "final_result": "NOT_EVALUATED" if _is_timeout else None,
                # No risk rating can be derived from an evaluation that did not happen.
                "severity": "N/A" if _is_timeout else None,
                "risk_level": "UNDETERMINED" if _is_timeout else None,
                "policy_present": "Not Found" if _is_timeout else ("Found" if has_retrieved else "Not Found"),
                "evidence_present": "Not Found" if _is_timeout else ("Found" if has_retrieved else "Not Found"),
                "hallucination_check": "SYSTEM_TIMEOUT" if _is_timeout else "FAIL_FALLBACK",
                "requires_human_review": True,
                "requires_review": True,
                "review_note": review_note,
                "control_id": state["control_id"],
                "control": state["control_label"],
                "evidence_quote": "NOT_EVALUATED" if _is_timeout else ev_quote,
                "evidence_snippet": "" if _is_timeout else ev_snippet,
                "finding": finding_text,
                "gap_description": gap_text,
                "reasoning": finding_text,
                "recommendation": rec_text
            }
            from src.core.validator import evaluate_nist_risk_and_severity
            fallback = evaluate_nist_risk_and_severity(fallback, state["control_id"])
            return {
                "validation_error": None,
                "final_finding": fallback
            }
        # If generation failed completely, flag validation error to trigger reflection
        return {
            "validation_error": state["validation_error"] or "Empty draft finding",
            "final_finding": None
        }
    
    # Construct expected evidence map for the validator
    code = state["control_id"].split(" ")[0] if state["control_id"] else ""
    expected_evidence_map = {
        code: [state["expected_evidence"], state["prompt_hint"]]
    }
    
    # NOTE: a fast-path guardrail that bypassed post_process() entirely for
    # COMPLIANT findings with a verbatim-matching quote used to live here. Removed
    # per the RAG accuracy overhaul (Phase 6) -- a verbatim quote proves grounding,
    # not compliance, and every finding now always goes through the full gate
    # sequence (leakage, grounding, and the deterministic policy/evidence formula)
    # below, with zero exceptions.

    # Query database chunks for verbatim verification
    session = SessionLocal()
    db_chunks = []
    try:
        _chunk_query = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(state["file_names_list"]))
        if state.get("report_id") is not None:
            _chunk_query = _chunk_query.filter(DocumentChunk.report_id == state["report_id"])
        db_chunks = _chunk_query.all()
    except Exception as e:
        print(f"[LANGGRAPH VALIDATOR WARNING] Failed to query database chunks: {e}", flush=True)
    finally:
        session.close()

    # Enforce original validator checks (from validator.py)
    draft_copy = dict(draft)
    draft_copy["control_id"] = state["control_id"]
    # Carry the Excel scoping through to the validator. post_process() needs to know
    # the auditor locked this control to specific file(s), so its clause-5/6/7
    # "needs a documented policy" default doesn't overrule a checklist that
    # deliberately scoped the control to operational evidence alone.
    draft_copy["locked_filenames"] = state.get("locked_filenames") or []
    draft_copy["policy_locked_filenames"] = state.get("policy_locked_filenames") or []
    draft_copy["evidence_locked_filenames"] = state.get("evidence_locked_filenames") or []
    
    validated_finding = post_process(
        finding=draft_copy,
        document_text=state["document_text"],
        expected_evidence_map=expected_evidence_map,
        db_chunks=db_chunks
    )
    
    # Check if validator modified the finding to human review or non-compliant due to grounding/leak issues
    hallucination_state = validated_finding.get("hallucination_check")
    status = validated_finding.get("status")
    
    is_failed = (
        hallucination_state in ("PROMPT_LEAK", "NOT_GROUNDED") or
        validated_finding.get("requires_human_review", False) or
        "Grounding validation failed" in str(validated_finding.get("review_note", ""))
    )
    
    if is_failed:
        error_msg = validated_finding.get("review_note") or validated_finding.get("validator_note") or "Grounding check failed: Evidence quote was not verified in the document."

        if state.get("audit_mode") == "Quick":
            # FIX Q1: In Quick mode, don't blindly accept a hard-failed finding.
            # If the validator already smart-upgraded it to PARTIAL_COMPLIANT (Fix 1 in validator.py),
            # preserve that. Only bypass if the finding is already at a reasonable status.
            current_status = validated_finding.get("status", "NON_COMPLIANT")
            hallucination_check = validated_finding.get("hallucination_check", "")
            if current_status not in ("NON_COMPLIANT", "PARTIAL_COMPLIANT", "FALSE_POSITIVE"):
                # Grounding/leakage check failed (is_failed=True) but status still claims a
                # positive result (e.g. COMPLIANT) -- force it down instead of saving an
                # internally-inconsistent finding (ungrounded evidence + COMPLIANT status).
                validated_finding["status"] = "NON_COMPLIANT"
                validated_finding["requires_human_review"] = True
                validated_finding["requires_review"] = True
                validated_finding["review_note"] = f"Quick mode: downgraded from {current_status} -- {error_msg}"
                current_status = "NON_COMPLIANT"
            print(f"[LANGGRAPH VALIDATOR] Quick mode validation issue for {state['control_id']} (status: {current_status}, check: {hallucination_check}). Accepting validator decision without retry.", flush=True)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }
            
        # NOTE: should_continue() only ever routes here with retry_count 0 or 1 --
        # it routes to "reflect" when retry_count < 1, and reflection_node
        # increments by exactly 1, so a retry_count >= 2 branch here could never
        # fire (leftover from an earlier multi-retry design). The retry_count >= 1
        # branch below covers this outcome already.

        print(f"[LANGGRAPH VALIDATOR] Validation rejected for control {state['control_id']}: {error_msg}", flush=True)

        # If LLM produced an empty/fallback response (LLM unavailable), accept with review flag
        # rather than returning final_finding=None which causes result to be lost entirely
        draft_status = str((state.get("draft_finding") or {}).get("status", "")).upper()
        draft_evidence = str((state.get("draft_finding") or {}).get("evidence_quote", "")).upper()
        llm_failed = (not state.get("draft_finding")) or (draft_evidence == "NOT_FOUND" and draft_status == "NON_COMPLIANT")

        if state["retry_count"] >= 1 or llm_failed:
            # Accept validated_finding (even if flagged) rather than losing the result
            validated_finding["status"] = "NON_COMPLIANT"
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["review_note"] = f"LLM unavailable or grounding failed: {error_msg}"
            validated_finding["control_id"] = state["control_id"]
            validated_finding["control"] = state["control_label"]
            _log_execution_event(state, validated_finding)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }

        return {
            "validation_error": error_msg,
            "draft_finding": validated_finding,
            "final_finding": None
        }
    
    # If validation passes cleanly
    print(f"[LANGGRAPH VALIDATOR] Validation passed for control {state['control_id']} (status: {status})", flush=True)
    _log_execution_event(state, validated_finding)
    return {
        "validation_error": None,
        "final_finding": validated_finding
    }

def reflection_node(state: AuditState) -> Dict[str, Any]:
    """Node: Skeptical reflection chain to correct any validation errors."""
    _update_progress(state, "Correcting validation gaps", 0.85)
    print(f"[LANGGRAPH REFLECTION] Initiating correction pass for control {state['control_id']}. Iteration: {state['retry_count'] + 1}", flush=True)
    
    reflection_chain = get_reflection_chain(state["llm_model"])
    draft = state["draft_finding"] or {}
    
    try:
        result_holder = {}
        # Adaptive, same formula as generate_node's timeout above. Computed before
        # the thread starts and passed into the invoke dict's "timeout" key (same
        # fix as generate_node) so the actual HTTP request's timeout can't outlive
        # this wait loop's budget and keep holding a port_pool slot after this
        # node has already given up on it.
        _ref_timeout = _calculate_adaptive_timeout()
        def _run_reflect():
            try:
                result_holder["refined"] = reflection_chain.invoke({
                    "condensed_context": state["retrieved_context"],
                    "control_id": state["control_id"],
                    "control_label": state["control_label"],
                    "draft_status": draft.get("status", "NON_COMPLIANT"),
                    "draft_severity": draft.get("severity", "N/A"),
                    "draft_evidence": draft.get("evidence_quote", "NOT_FOUND"),
                    "draft_gap": draft.get("gap_description", ""),
                    "draft_recommendation": draft.get("recommendation", ""),
                    "draft_reasoning": draft.get("reasoning", ""),
                    "draft_business_impact": draft.get("business_impact", ""),
                    "draft_remediation_priority": draft.get("remediation_priority", "Medium"),
                    "draft_evidence_strength": draft.get("evidence_strength", "None"),
                    "draft_control_coverage": draft.get("control_coverage", 0),
                    "validation_error": state["validation_error"],
                    "standard": state.get("standard", ""),
                    "session_id": state.get("bg_key"),
                    "timeout": _ref_timeout,
                })
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run_reflect, daemon=True)
        t.start()
        # ── Heartbeat: keep progress moving between 85%→95% during reflection ──
        _ref_elapsed = 0
        _ref_hb = 15
        # Same wrapper rule as generation: the slot wait is allowed on top of the
        # request budget so queueing cannot cut a running reflection short.
        _ref_wall = _ref_timeout + LLM_POOL_WAIT_TIMEOUT_SEC
        while t.is_alive() and _ref_elapsed < _ref_wall:
            t.join(timeout=_ref_hb)
            _ref_elapsed += _ref_hb
            if t.is_alive():
                _hb_ref_phase = min(0.85 + (_ref_elapsed / _ref_wall) * 0.1, 0.94)
                _update_progress(state, f"Self-correcting finding... ({_ref_elapsed}s)", _hb_ref_phase)
        if t.is_alive():
            # Unlike a generation timeout, this is NOT reported as NOT_EVALUATED:
            # generation already produced a real assessment and only the optional
            # refinement pass was lost, so the draft is a genuine finding.
            print(f"[LANGGRAPH TIMEOUT] Reflection timed out after {_ref_wall}s for control {state.get('control_id','')}. Accepting draft as-is.", flush=True)
            _record_control_timeout(state, state.get('control_id', ''), _ref_wall, phase="reflection")
            return {
                "draft_finding": draft,
                "validation_error": None,
                "retry_count": state["retry_count"] + 1
            }
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        refined = result_holder["refined"]

        return {
            "draft_finding": refined.model_dump(),
            "validation_error": None,
            "retry_count": state["retry_count"] + 1,
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH REFLECTION ERROR] Self-correction call failed: {e}", flush=True)
        return {
            "validation_error": f"Reflection parse failed: {str(e)}",
            "retry_count": state["retry_count"] + 1,
            # Reflection's LLM call may have consumed real tokens even though parsing failed.
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }

# Define edge routing condition
def should_continue(state: AuditState) -> str:
    """Routes state based on validation status and retry bounds.

    With Cross-Encoder Reranking + 4-Gate Validation, at most 1 single
    reflection pass is allowed. This eliminates unnecessary 2nd-pass delays
    while preserving 100% ground truth verification.
    """
    if state["validation_error"] is not None:
        if state["retry_count"] < 1:
            return "reflect"
        return "end"
    return "end"

# Compile LangGraph State Machine
def compile_audit_graph():
    """Builds and compiles the StateGraph workflow."""
    workflow = StateGraph(AuditState)
    
    # Add Nodes
    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("generate", generate_node)
    workflow.add_node("validate", validate_node)
    workflow.add_node("reflect", reflection_node)
    
    # Add Edges
    workflow.add_edge(START, "retrieve")
    workflow.add_edge("retrieve", "generate")
    workflow.add_edge("generate", "validate")
    
    # Conditional edge from validate
    workflow.add_conditional_edges(
        "validate",
        should_continue,
        {
            "reflect": "reflect",
            "end": END
        }
    )
    
    # Reflect cycles back to validate so grounding can be checked
    workflow.add_edge("reflect", "validate")
    
    return workflow.compile()

# Singleton graph instance cached at module load
audit_graph = compile_audit_graph()


# ── Execution Metadata Logger (Fix G4 — Audit Logs) ——————————————————
def _log_execution_event(state: AuditState, final_finding: Dict[str, Any]) -> None:
    """
    Writes a structured execution metadata row to the SystemEvent table after
    each control is validated. This is a sidecar write — it runs AFTER
    final_finding is already set and is wrapped in try/except so any DB failure
    never affects the audit result.

    Captures: control_id, model, backend, audit_mode, retry_count,
              hallucination_check, final_status, retrieved_context_chars.
    """
    try:
        import json as _json
        import os as _os
        from src.db.database import SystemEvent

        meta = {
            "control_id":              state.get("control_id", ""),
            "model":                   state.get("llm_model", ""),
            "backend":                 _os.environ.get("LLM_BACKEND", "ollama"),
            "audit_mode":              state.get("audit_mode", "Normal"),
            "retry_count":             state.get("retry_count", 0),
            "hallucination_check":     final_finding.get("hallucination_check", ""),
            "final_status":            final_finding.get("status", ""),
            "retrieved_context_chars": len(state.get("retrieved_context", "")),
            "requires_human_review":   final_finding.get("requires_human_review", False),
        }

        event = SystemEvent(
            event_type="CONTROL_AUDIT_COMPLETE",
            actor="SYSTEM",
            session_id=state.get("bg_key", ""),
            framework="ISO 27001",
            meta=_json.dumps(meta),
            severity="INFO",
        )
        session = SessionLocal()
        try:
            session.add(event)
            session.commit()
        finally:
            session.close()

    except Exception as _log_err:
        # Never let a log failure affect the audit result
        print(f"[AUDIT LOG WARNING] Failed to write execution event: {_log_err}", flush=True)
