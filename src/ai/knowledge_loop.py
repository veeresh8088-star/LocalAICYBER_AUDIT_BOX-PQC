# -*- coding: utf-8 -*-
"""
Knowledge Loop Module
Filters historical auditor feedback and formats it as hints for in-context learning.
"""
from src.core.pii_redactor import redact_pii

def filter_feedback_record(feedback):
    """
    Applies the Loop Knowledge filtering rules.
    Blocks:
      - Findings/Feedback with PROMPT_LEAK flag
      - Findings/Feedback with confidence below 8
      - Findings that are not human verified (if from Findings table)
    """
    # Block prompt leaks
    if getattr(feedback, "hallucination_check", None) == "PROMPT_LEAK":
        return False
        
    # Block confidence below 8
    confidence = getattr(feedback, "confidence", None)
    if confidence is not None:
        try:
            if int(confidence) < 8:
                return False
        except (ValueError, TypeError):
            pass
            
    # Check if human verified
    # If the object is a Finding model, it must have human_verified=True
    if hasattr(feedback, "human_verified"):
        if not getattr(feedback, "human_verified", False):
            return False
            
    return True


def format_loop_hints(feedbacks):
    """
    Formats the allowed loop knowledge as prompts hints.
    """
    section_hints = []
    document_scope = []
    known_non_compliant = []
    
    for fb in feedbacks:
        if not filter_feedback_record(fb):
            continue
            
        control_id = getattr(fb, "control_id", "")
        # Redacted again here (not just at write time in audit.py) so records
        # written before that redaction existed are still protected before
        # this text gets injected verbatim into another auditor's prompt.
        comments = redact_pii(getattr(fb, "auditor_comments", "") or "")
        status = getattr(fb, "corrected_status", "") or getattr(fb, "status", "") or ""

        # Standardize status to check compliance
        status_upper = str(status).upper()

        # If rejected or dismissed, add to negative constraint guidelines so LLM doesn't repeat the mistake
        if "REJECTED" in status_upper or "DISMISSED" in status_upper:
            finding = redact_pii(getattr(fb, "finding", "") or getattr(fb, "description", "") or "")
            if finding:
                known_non_compliant.append(f"- For Control {control_id}: Note that a previous finding was REJECTED by the auditor: \"{finding}\". Do NOT repeat or generate this false finding.")
            continue

        # A STATUS CORRECTION is knowledge on its own, with or without a comment.
        #
        # This used to `continue` whenever auditor_comments was empty, which
        # discarded the single most valuable signal the loop can receive: an
        # auditor changing NON_COMPLIANT to COMPLIANT (or the reverse) on a
        # control the model got wrong. The correction is written to
        # AuditorFeedback.corrected_status by the finding-edit endpoint, but
        # auditor_comments is only populated when someone also types free text --
        # and most auditors just change the dropdown. Verified against the live
        # table: two of the three most recent real feedback rows had empty
        # comments and were both dropped here, so the model was told nothing.
        #
        # Emitted as a prior, not as evidence: the prompt tells the model an
        # auditor previously reached a different conclusion on this control and
        # to weigh the evidence carefully -- it must not copy the verdict, which
        # would be a different bug (a finding asserted from no evidence at all).
        cleaned_comment = str(comments).strip()
        if not cleaned_comment:
            corrected = status_upper.replace("-", "_")
            if corrected in ("COMPLIANT", "NON_COMPLIANT", "PARTIAL_COMPLIANT", "FALSE_POSITIVE"):
                known_non_compliant.append(
                    f"- For Control {control_id}: an auditor previously reviewed this control and "
                    f"recorded it as {corrected}. Treat that as a prior from a human reviewer, not "
                    f"as evidence -- assess the uploaded documents on their own merits and only "
                    f"agree if the evidence supports it."
                )
            continue


        # Parse into hints category
        if "section" in cleaned_comment.lower() or "heading" in cleaned_comment.lower() or "page" in cleaned_comment.lower():
            section_hints.append(f"- For Control {control_id}: look near sections matching {cleaned_comment}")
        elif "scope" in cleaned_comment.lower() or "covers" in cleaned_comment.lower():
            document_scope.append(f"- For Control {control_id}: check document scope boundaries {cleaned_comment}")
        elif "NON_COMPLIANT" in status_upper or "NON-COMPLIANT" in status_upper:
            known_non_compliant.append(f"- For Control {control_id}: note that requirements are typically absent.")
        else:
            # Map general hints
            section_hints.append(f"- For Control {control_id}: structure hint: {cleaned_comment}")
            
    if not section_hints and not document_scope and not known_non_compliant:
        return ""
        
    hints_blocks = []
    hints_blocks.append("DOCUMENT NAVIGATION HINTS:")
    hints_blocks.append(" Use these to know WHERE to look.")
    hints_blocks.append(" Do NOT use as compliance evidence.")
    
    if section_hints:
        hints_blocks.append(" " + "\n ".join(section_hints))
    if document_scope:
        hints_blocks.append(" " + "\n ".join(document_scope))
    if known_non_compliant:
        hints_blocks.append(" " + "\n ".join(known_non_compliant))
        
    return "\n".join(hints_blocks)


def get_auditor_feedback_few_shot(control_ids):
    """Retrieve up to 20 most recent auditor feedbacks matching the given control IDs,
    and format them as general compliance rules (knowledge) for the prompt.
    """
    if not control_ids:
        return ""
    
    from src.db.database import SessionLocal, AuditorFeedback, force_master
    with force_master():
        session = SessionLocal()
        try:
            feedbacks = (
                session.query(AuditorFeedback)
                .filter(AuditorFeedback.control_id.in_(control_ids))
                .order_by(AuditorFeedback.created_at.desc())
                .limit(20)
                .all()
            )
            if not feedbacks:
                return ""
            return format_loop_hints(feedbacks)
        except Exception as e:
            print(f"[FEEDBACK] Error retrieving auditor feedback: {e}")
            return ""
        finally:
            session.close()
