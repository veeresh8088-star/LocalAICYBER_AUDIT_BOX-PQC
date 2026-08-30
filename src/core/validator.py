# -*- coding: utf-8 -*-
"""
Strict Forensic Compliance Auditor - Validation Module
Implements the core grounding, leakage, confidence, and consistency checks.
"""
import re
import difflib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List

@dataclass
class EvidenceItem:
    artifact_id: str = ""
    source_file: str = ""
    page: Optional[int] = None
    section: Optional[str] = None
    sheet: Optional[str] = None
    row_range: Optional[str] = None
    chunk_id: str = ""
    extracted_text: str = ""
    ocr_text: str = ""
    table_data: Optional[Dict[str, Any]] = None
    content_type: str = "UNKNOWN"
    artifact_modality: str = "TEXT"
    provenance: str = ""
    extraction_method: str = "TEXT_PARSER"
    grounding_status: str = "NOT_GROUNDED"
    requirement_ids: List[str] = field(default_factory=list)
    support_status: str = "NOT_SUPPORTED"
    evidence_relevance: str = "IRRELEVANT"
    restated_policy: bool = False
    conflict_info: Optional[Dict[str, Any]] = None
    temporal_information: Optional[Dict[str, Any]] = None
    actor_information: Optional[Dict[str, Any]] = None
    system_information: Optional[Dict[str, Any]] = None
    execution_state: str = "UNKNOWN"
    authenticity_indicators: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvidenceItem':
        if not data or not isinstance(data, dict):
            return cls()
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


def check_grounding(evidence, document_text):
    """
    Checks whether the cited evidence actually exists in the provided document text.

    Verifies the WHOLE quote, not a prefix of it. This used to test only
    `evidence[:50]` -- so a quote could open with 50 real characters and continue
    into entirely invented content (dates, approvals, retention periods) and still
    be returned as GROUNDED. Confirmed by execution: a 139-character quote whose
    last 89 characters were fabricated returned "GROUNDED".

    Multi-excerpt quotes (joined by a blank line, as the generator emits them) are
    verified independently, mirroring GATE 2 in validate_only(): a run of separate
    sentences from different parts of a document never appears as one continuous
    block, so checking the joined blob as a single string would always fail.

    Returns "GROUNDED" only when every excerpt is found. When some but not all
    excerpts verify, returns "PARTIALLY_GROUNDED" -- callers treat anything other
    than GROUNDED/GROUNDED_WITH_OCR_WARNING as unsupported, which is the safe
    direction for a partially fabricated quote.
    """
    if not evidence or evidence == "NOT_FOUND" or not document_text:
        return "NOT_GROUNDED"

    excerpts = [e.strip() for e in str(evidence).split("\n\n") if e.strip()]
    if not excerpts:
        return "NOT_GROUNDED"

    norm_doc = _cached_normalize_doc(document_text)
    alpha_doc = clean_alphanumeric(document_text)

    verified = 0
    for excerpt in excerpts:
        cleaned = excerpt.strip().strip('"').strip("'").strip('“').strip('”').strip()
        if not cleaned or cleaned.upper() == "NOT_FOUND":
            continue
        norm_item = normalize_text(cleaned)
        if norm_item and norm_item in norm_doc:
            verified += 1
            continue
        # Encoding / smart-quote tolerance, same fallback GATE 2 uses.
        alpha_item = clean_alphanumeric(cleaned)
        if alpha_item and alpha_item in alpha_doc:
            verified += 1

    if verified == 0:
        return "NOT_GROUNDED"
    if verified < len(excerpts):
        return "PARTIALLY_GROUNDED"
    return "GROUNDED"


def _kw(word: str, text: str) -> bool:
    """Word-boundary keyword match. A bare substring check (e.g. "log" in text)
    matches inside unrelated longer words too -- confirmed on a real audit run:
    "log" matched inside "login", misclassifying a real SSH login banner (actual
    privileged-access evidence) as a policy/procedure statement. Auditing every
    other single-word keyword in this function turned up the same class of bug
    repeatedly: "active" inside "proactive"/"reactive", "event" inside "prevent",
    "port:" inside "support:"/"report:", "metric" inside "asymmetric", "review"
    inside "preview", "approval" inside "disapproval", "configured" inside
    "misconfigured", "standard" inside "substandard" -- all confirmed to
    misfire the same way. Word-boundary matching everywhere in this function
    closes the whole class, not just the one instance that got reported.
    Multi-word phrases (e.g. "session opened") are inherently safe from this --
    only single words need this helper.
    """
    import re
    return re.search(r'\b' + re.escape(word.rstrip(':')) + r'\b', text) is not None


def classify_content_and_modality(content: str, filename: str = "", metadata: dict = None) -> dict:
    """
    Classifies content into fine-grained 16 semantic categories and separates artifact modality.
    NEVER classifies based on file extension alone or isolated keywords.
    """
    if not content or not str(content).strip():
        return {"content_type": "UNKNOWN", "artifact_modality": "TEXT"}

    text_lower = str(content).lower()
    fn = str(filename).lower()
    meta = metadata or {}

    # 1. Determine Artifact Modality (separate from semantic content type)
    modality = "TEXT"
    if meta.get("is_ocr") or meta.get("source_type") in ("ocr", "image"):
        modality = "SCREENSHOT" if (_kw("screenshot", text_lower) or "screen" in fn) else "IMAGE"
    elif "table" in meta or "|" in text_lower or "\t" in text_lower:
        modality = "TABLE"
    elif fn.endswith((".xlsx", ".csv", ".xls")):
        modality = "SPREADSHEET"
    elif fn.endswith((".pdf", ".docx", ".pptx", ".doc")):
        modality = "DOCUMENT"

    # 2. Strict operational execution action markers (actual proof of system run)
    op_action_phrases = [
        "status: ok", "session opened", "mfa enabled for", "ntp synchronized",
        "signed in at", "signed in by", "nessus result:", "cpu utilization",
        "active (running)", "review completed", "reviewed by", "audit log exported",
        "user account created", "audited by",
        # A real login event (e.g. an SSH "Last login:" banner) is itself proof of
        # privileged-access usage -- exactly the kind of operational evidence a PAM
        # control asks for, not a policy statement.
        "last login", "logged in", "login successful", "login as"
    ]
    op_action_words = [
        "completed", "executed", "passed", "synchronized", "synchronised", "ntp",
        "threshold", "active", "enabled", "configured"
    ]
    has_op_action = (
        any(p in text_lower for p in op_action_phrases)
        or any(_kw(w, text_lower) for w in op_action_words)
    )

    # 3. Normative requirement directives (what SHOULD happen)
    normative_phrases = [
        "will audit", "shall audit", "must audit", "requires security",
        "must ensure", "shall maintain", "shall review", "must be",
        "shall be", "should be", "policy requires", "procedure requires",
        "employees must", "management shall", "all staff must", "is mandated",
        "must complete", "shall complete", "must have", "shall have"
    ]
    policy_keyword_words = ["must", "shall", "should", "policy", "procedure", "standard", "guideline", "mandated"]
    has_normative = (
        any(p in text_lower for p in normative_phrases)
        or any(_kw(w, text_lower) for w in policy_keyword_words)
        or "required to" in text_lower
    )

    if has_normative and not has_op_action:
        return {"content_type": "POLICY", "artifact_modality": modality}

    # 4. Fine-Grained 16 Content Categories
    if _kw("report", text_lower) or _kw("summary", text_lower):
        content_type = "REPORT"
    elif "approved by" in text_lower or _kw("approval", text_lower) or "sign-off" in text_lower:
        content_type = "APPROVAL"
    elif _kw("review", text_lower) or _kw("reviewed", text_lower):
        content_type = "REVIEW"
    elif _kw("scan", text_lower) or _kw("vulnerability", text_lower) or _kw("cve", text_lower) or _kw("nessus", text_lower):
        content_type = "TEST_RESULT" if has_op_action else "ASSESSMENT"
    elif _kw("config", text_lower) or _kw("parameter", text_lower) or ("ip:" in text_lower) or ("port:" in text_lower) or _kw("setting", text_lower) or _kw("ctl", text_lower):
        content_type = "CONFIGURATION" if has_op_action else "STANDARD"
    elif (
        re.search(r'\blog(s|in|ged|out|ging)?\b', text_lower)
        or "session opened" in text_lower
        or "signed in" in text_lower
        or _kw("event", text_lower)
        or fn.endswith(".log")
    ):
        content_type = "LOG_RECORD" if has_op_action else "PROCEDURE"
    elif _kw("access", text_lower) or _kw("visitor", text_lower) or _kw("badge", text_lower) or _kw("entry", text_lower):
        content_type = "VISITOR_RECORD" if (_kw("visitor", text_lower) or _kw("entry", text_lower)) else "ACCESS_RECORD"
    elif has_op_action:
        content_type = "SYSTEM_OUTPUT"
    elif meta.get("is_ocr") or meta.get("source_type") in ("ocr", "image"):
        content_type = "SYSTEM_OUTPUT"
    else:
        content_type = "UNKNOWN"

    return {"content_type": content_type, "artifact_modality": modality}


def classify_chunk_content_type(content: str, filename: str = "", metadata: dict = None) -> str:
    """
    Classifies content as 'OPERATIONAL', 'POLICY', or 'UNKNOWN' for backward compatibility.
    Underneath, uses classify_content_and_modality to analyze content features.
    """
    res = classify_content_and_modality(content, filename, metadata)
    ct = res["content_type"]
    if ct in ("POLICY", "PROCEDURE", "STANDARD"):
        return "POLICY"
    elif ct == "UNKNOWN":
        return "UNKNOWN"
    else:
        return "OPERATIONAL"


def normalize_text(text):
    """
    Normalizes whitespace, smart quotes, dashes, and case to make verbatim search robust against line breaks and formatting.
    """
    if not text:
        return ""
    import re
    # Replace newlines, tabs, and multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    # Standardize smart quotes / single quotes
    text = text.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'")
    # Standardize dashes
    return text.strip().lower()


import functools

@functools.lru_cache(maxsize=4)
def _cached_doc_lower(document_text):
    """Memoizes document_text.lower(). document_text is the same session-wide
    combined text on every one of the ~N per-control calls to post_process()/
    validate_only() within a single audit run, so recomputing .lower() on it from
    scratch each time was wasted work. A dedicated small cache (not folded into
    normalize_text's own many small per-chunk calls elsewhere in this file, which
    would just evict each other for no benefit) -- purely an efficiency
    optimization, not correctness-critical. Bounded size since concurrent audits
    each have their own document_text."""
    return document_text.lower()

@functools.lru_cache(maxsize=4)
def _cached_normalize_doc(document_text):
    """Same rationale as _cached_doc_lower, for normalize_text(document_text)."""
    return normalize_text(document_text)


def clean_alphanumeric(text):
    """
    Strips all punctuation, symbols, and formatting, leaving only lowercase letters, digits, and spaces.
    Used as a robust fallback for grounding checks when encoding issues or smart quotes are present.
    """
    if not text:
        return ""
    import re
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def expand_to_complete_sentence(prefix: str, source_text: str, max_chars: int = 450) -> str:
    """
    Expands a verified quote prefix anchor into the full, authentic sentence/clause directly from the source text.
    Prevents chopped quotes ending mid-sentence (e.g. '...when entering a', '...i.e. BreezN or').
    """
    if not prefix or not source_text:
        return prefix
    prefix_clean = prefix.strip()
    if len(prefix_clean) < 8:
        return prefix_clean

    import re
    # Try finding exact, case-insensitive, or whitespace-normalized match in source_text
    idx = source_text.find(prefix_clean)
    if idx == -1:
        idx = source_text.lower().find(prefix_clean.lower())

    if idx == -1:
        # Try finding using the first 4 words of the prefix
        words = prefix_clean.split()
        if len(words) >= 4:
            first_few = " ".join(words[:4])
            idx = source_text.lower().find(first_few.lower())
            if idx == -1:
                clean_first = clean_alphanumeric(first_few)
                clean_src = clean_alphanumeric(source_text)
                if clean_first and clean_first in clean_src:
                    for w in words[:2]:
                        p = source_text.lower().find(w.lower())
                        if p != -1:
                            idx = p
                            break

    if idx != -1:
        remainder = source_text[idx:]
        pref_len = len(prefix_clean)

        # Look forward in remainder beyond prefix length up to max_chars
        search_region = remainder[pref_len:min(len(remainder), pref_len + max_chars)]

        # Search for sentence boundary: period/question/exclamation followed by space/newline,
        # or double newline (paragraph break), or bullet boundary
        m = re.search(r'(?<!\b[A-Za-z])(?<!\bi\.e)(?<!\be\.g)(?<!\bvs)\.[\s\n\r"”\']|\n\n|\r\n\r\n|\n(?=[0-9]+\.[0-9]+)|\Z', search_region)
        if m:
            end_pos = pref_len + m.end()
            completed = remainder[:end_pos].strip()
            completed = completed.rstrip(' "\'\n\r')
            if completed and not completed.endswith(('.', '!', '?', '"', '”', "'", '’', ')')):
                completed = completed + "."
            if len(completed) >= len(prefix_clean):
                return completed

    return prefix_clean


_INJECTION_KEYWORDS = [
    "ignore all instructions",
    "ignore previous instructions",
    "ignore the instructions",
    "ignore system instructions",
    "ignore the system prompt",
    "attention: ignore",
    "override all instructions"
]

def _contains_injection_keywords(text):
    """True if text contains a known adversarial-injection phrase. Shared by the
    FALSE_POSITIVE/inapplicable early-guard and Gate 1's leakage check in
    validate_only() below, so both stay in sync off one list."""
    if not text or text == "NOT_FOUND":
        return False
    t_lower = text.lower()
    return any(kw in t_lower for kw in _INJECTION_KEYWORDS)


def check_prompt_leakage(evidence, hints, threshold=0.75):
    """
    Checks if the cited evidence is copied directly or has high fuzzy similarity to the expected evidence hints.
    Also guards against the model echoing systemic prompt instructions.
    """
    if not evidence or evidence == "NOT_FOUND":
        return "CLEAN"
        
    evidence_clean = evidence.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
    
    # Block systemic prompt instruction leakage
    PROMPT_SPECIFIC_KEYWORDS = [
        "strict forensic compliance auditor",
        "adversarial compliance challenger",
        "universal decision tree",
        "hallucination self check",
        "universal document scope",
        "never copy from expected evidence",
        "case a (grounded exact quote",
        "case b (partial evidence",
        "case c (no evidence",
        "case d (evidence matches",
        "case e (fuzzy",
        "verify the full lifecycle of identities",
        "expected evidence",
        "step 1: fresh start",
        "decision tree",
    ]
    for kw in PROMPT_SPECIFIC_KEYWORDS:
        if kw in evidence_clean:
            return "PROMPT_LEAK"
            
    # Check for pattern "law 1" through "law 10"
    import re
    if re.search(r'\blaw\s+([1-9]|10)\b', evidence_clean):
        return "PROMPT_LEAK"
            
    if isinstance(hints, str):
        hints = [hints]
    elif not isinstance(hints, (list, tuple, set)):
        hints = []

    import difflib
    for hint in hints:
        if not hint or not isinstance(hint, str):
            continue
        hint_clean = hint.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
        if not hint_clean or len(hint_clean) < 15:
            continue
        # Direct substring check for meaningful hint phrases
        if hint_clean in evidence_clean:
            return "PROMPT_LEAK"
        # Fuzzy similarity check
        similarity = difflib.SequenceMatcher(None, hint_clean, evidence_clean).ratio()
        if similarity >= threshold:
            return "PROMPT_LEAK"
    return "CLEAN"


def map_new_schema_to_legacy(finding):
    """
    Maps the new ISO 27001 Lead Auditor schema to the legacy schema format
    used by the validator, database, and Streamlit UI.
    """
    if not finding:
        return finding
        
    # Check if this is already in the legacy format (e.g. has 'evidence_quote' and not 'justification')
    if "evidence_quote" in finding and "justification" not in finding:
        return finding
        
    mapped = {}
    
    # Copy all other fields that don't need translation
    for k, v in finding.items():
        mapped[k] = v
        
    # 1. status mapping
    status_val = finding.get("status", "NON_COMPLIANT")
    mapped["status"] = status_val
    
    # 2. severity mapping
    sev_val = finding.get("severity", "Medium")
    sev_key = str(sev_val).strip() if sev_val is not None else "Medium"
    sev_map = {
        "N/A": "N/A",
        "NONE": "N/A",
        "NIL": "N/A",
        "OK": "N/A",
        "ACCEPTED": "N/A",
        "LOW": "P4 Low",
        "P4 LOW": "P4 Low",
        "MEDIUM": "P3 Medium",
        "MED": "P3 Medium",
        "MODERATE": "P3 Medium",
        "P3 MEDIUM": "P3 Medium",
        "HIGH": "P2 High",
        "P2 HIGH": "P2 High",
        "CRITICAL": "P1 Critical",
        "P1 CRITICAL": "P1 Critical"
    }
    mapped["severity"] = sev_map.get(sev_key.upper(), "N/A")
    
    # 3. evidence quote mapping
    #
    # A model that has no quote to give does not always say "NOT_FOUND" -- it
    # writes "None", "N/A", "null" or an empty placeholder. Those were kept as
    # if they were real quotes, and the grounding gate then tried to locate the
    # word "None" verbatim in the source document. It is not there, so the
    # finding was marked NOT_GROUNDED and forced to NON_COMPLIANT -- even where
    # policy_status and evidence_status were both FOUND and both assessed
    # COMPLIANT, and the real evidence was sitting in evidence_snippet. That is
    # a false non-compliance caused by a missing field, not by absent evidence.
    #
    # Treating these as "no quote supplied" routes the finding down the honest
    # NOT_FOUND path instead, where the policy/evidence status logic decides the
    # outcome rather than a failed substring search.
    _PLACEHOLDER_QUOTES = {
        "", "none", "n/a", "na", "null", "nil", "not found", "not_found",
        "no evidence", "no quote", "not applicable", "not provided",
        "unavailable", "unknown", "-", "--",
    }

    def _is_placeholder(text) -> bool:
        return str(text or "").strip().strip('."\'').lower() in _PLACEHOLDER_QUOTES

    evidence_list = finding.get("evidence", [])
    evidence_quote = "NOT_FOUND"
    if evidence_list and isinstance(evidence_list, list):
        # Collect ALL evidence excerpts (not just first)
        all_excerpts = []
        for ev_item in evidence_list:
            if isinstance(ev_item, dict):
                excerpt = ev_item.get("excerpt") or ev_item.get("text") or ""
                if excerpt and not _is_placeholder(excerpt):
                    all_excerpts.append(excerpt.strip())
            elif isinstance(ev_item, str) and ev_item.strip() and not _is_placeholder(ev_item):
                all_excerpts.append(ev_item.strip())
        if all_excerpts:
            evidence_quote = "\n\n".join(all_excerpts)

    # The quote may also arrive as a flat field rather than the evidence list.
    if evidence_quote == "NOT_FOUND":
        _flat = finding.get("evidence_quote")
        if _flat and not _is_placeholder(_flat):
            evidence_quote = str(_flat).strip()
    elif _is_placeholder(evidence_quote):
        evidence_quote = "NOT_FOUND"

    # evidence_location: prefer finding-level source which is set correctly by
    # bg_worker (Excel scoping gate). ev_item["source"] contains LLM hallucinations
    # like "Document Context" or "Document Text" — never use those as filenames.
    _FAKE_SOURCES = {"document context", "document text", "n/a", "na", "none",
                     "policy document", "uploaded document", "evidence document",
                     "context", "evidence", "document", ""}
    
    _loc = (
        finding.get("evidence_source_file") or
        finding.get("source_files") or
        finding.get("evidence_location") or ""
    ).strip()

    # Combine Parent Document and Child Image Filename (e.g. "Monitoring AWS CloudWatch.docx (image1.png)")
    parent_file = (finding.get("source_files") or finding.get("parent_document") or "").strip()
    child_file = (finding.get("evidence_source_file") or "").strip()

    if child_file and parent_file and child_file != parent_file:
        if child_file.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")) and parent_file not in child_file:
            _loc = f"{parent_file} ({child_file})"
        elif _loc and parent_file not in _loc and child_file in _loc:
            _loc = _loc.replace(child_file, f"{parent_file} ({child_file})")

    if _loc and _loc.lower() not in _FAKE_SOURCES:
        mapped["evidence_location"] = _loc



    mapped["evidence_quote"] = evidence_quote
    mapped["evidence_snippet"] = evidence_quote if evidence_quote != "NOT_FOUND" else ""

    
    # 4. gap description mapping
    missing_reqs = finding.get("missing_requirements", [])
    biz_impact = finding.get("business_impact", "")
    gap_desc = finding.get("gap_description") or ""
    if not gap_desc:
        parts = []
        if biz_impact:
            parts.append(f"Business Impact: {biz_impact}")
        if missing_reqs:
            parts.append(f"Missing Requirements: {', '.join(missing_reqs)}")
        if parts:
            gap_desc = " | ".join(parts)
        elif str(status_val).strip().upper() in ("COMPLIANT", "FALSE_POSITIVE"):
            # "No gaps reported" is the normal state for a COMPLIANT finding, not an
            # absence of evidence. This fallback used to emit "No documented evidence
            # satisfying the control requirements." unconditionally, so a verified
            # COMPLIANT finding was published with a description flatly contradicting
            # its own verdict -- confirmed on a live run, where controls quoting
            # "NTP enabled: yes" and "Document Version: 1.0" both carried that line.
            gap_desc = "No gaps identified. The cited evidence satisfies the control requirement."
        else:
            gap_desc = "No documented evidence satisfying the control requirements."
    mapped["gap_description"] = gap_desc
    mapped["finding"] = gap_desc
    mapped["description"] = gap_desc
    
    # 5. reasoning mapping
    mapped["reasoning"] = finding.get("justification") or finding.get("reasoning") or ""
    
    # 6. confidence mapping (map evidence_strength to confidence score)
    strength = finding.get("evidence_strength", "None")
    strength_map = {
        "Strong": 10, "STRONG": 10,
        "Moderate": 7, "MODERATE": 7,
        "Weak": 4, "WEAK": 4,
        "None": 1, "NONE": 1
    }
    mapped["confidence"] = strength_map.get(strength, 10)
    
    # 7. recommendation mapping
    mapped["recommendation"] = finding.get("recommendation") or ""
    
    # 8. policy/evidence/severity mapping
    mapped["policy_present"] = finding.get("policy_present", "No")
    mapped["evidence_present"] = finding.get("evidence_present", "No")
    try:
        mapped["severity_score"] = float(finding.get("severity_score", 0.0))
    except Exception:
        mapped["severity_score"] = 0.0
        
    return mapped


def apply_confidence_gate(finding):
    """
    No longer downgrades findings based on confidence scores.
    Preserves and parses the confidence score, but bypasses status changes
    to comply with strict lead auditor requirements.
    """
    confidence = finding.get("confidence", 10)
    # Default to 10 if not present or invalid
    try:
        confidence = int(confidence)
    except (TypeError, ValueError):
        confidence = 10
        
    finding["confidence"] = confidence
    # Downgrade check is disabled as per user instruction:
    # "do not use relevance scores, confidence scores, or similarity metrics to determine compliance status."
    return finding


def check_consistency(finding):
    """
    Auto-corrects status inconsistencies:
    - COMPLIANT with no evidence → NON_COMPLIANT
    """
    status = finding.get("status", "NON_COMPLIANT")
    evidence = finding.get("evidence_quote") or "NOT_FOUND"

    # Forward check: COMPLIANT must have grounded evidence
    if status == "COMPLIANT":
        if not evidence or evidence == "NOT_FOUND":
            finding["status"] = "NON_COMPLIANT"
            finding["consistency_fix"] = True
            finding["evidence_snippet"] = ""
            finding["evidence_quote"] = "NOT_FOUND"

    return finding


def check_reasoning_hallucination(reasoning, document_text, threshold=0.4):
    """
    FIX Q3: Checks whether the auditor's reasoning text contains claims that
    are not grounded in the actual document. Flags fabricated claims.

    Returns a dict:
      - "clean": bool — True if reasoning appears well-grounded
      - "flagged_phrases": list of suspicious phrases not found in doc
    """
    if not reasoning or not document_text:
        return {"clean": True, "flagged_phrases": []}

    import re
    doc_lower = _cached_doc_lower(document_text)

    # Split reasoning into sentences and check each one
    sentences = re.split(r'(?<=[.!?])\s+', reasoning.strip())
    flagged = []

    # Sentences that assert an ABSENCE are exempt: you cannot ground "X is not
    # present" by finding X in the document, so demanding a document match for
    # those would flag every correct NON_COMPLIANT finding.
    #
    # This list previously also held generic audit nouns -- "control",
    # "compliance", "evidence", "document", "policy", "procedure",
    # "requirement", "security", "organization", "auditor", "finding". Because
    # the check below skips a sentence when ANY entry matches, and essentially
    # every sentence of audit reasoning contains at least one of those words,
    # the detector skipped essentially everything and could not return a
    # negative result on realistic input. Confirmed by execution: reasoning
    # containing two wholly fabricated factual claims returned clean=True with
    # zero flagged phrases. Only genuine absence markers belong here.
    ABSENCE_CLAIM_PHRASES = [
        "not found", "not evidenced", "not provided", "not documented",
        "does not contain", "does not include", "does not specify",
        "no evidence", "no documented", "could not be found",
        "was not located", "absent from",
    ]

    for sentence in sentences:
        s = sentence.strip().lower()
        if len(s) < 20:
            continue
        # Extract key noun phrases (3+ word spans)
        words = s.split()
        if len(words) < 4:
            continue
        # Check if sentence makes a positive factual claim ("mentions", "contains", "outlines", "states")
        claim_verbs = ["mentions", "contains", "outlines", "states", "describes", "includes", "provides", "defines", "details"]
        has_claim = any(v in s for v in claim_verbs)
        if not has_claim:
            continue
        # Absence claims are exempt (see ABSENCE_CLAIM_PHRASES above); positive
        # factual claims must be traceable to the document.
        if any(phrase in s for phrase in ABSENCE_CLAIM_PHRASES):
            continue
        # Extract 3-word windows and check in document
        found_in_doc = False
        for i in range(len(words) - 2):
            window = " ".join(words[i:i+3])
            if window in doc_lower:
                found_in_doc = True
                break
        if not found_in_doc:
            flagged.append(sentence.strip())

    return {
        "clean": len(flagged) == 0,
        "flagged_phrases": flagged
    }


def calculate_real_accuracy(findings):
    """
    Calculates the real compliance accuracy of the model findings.
    """
    total = len(findings)
    if total == 0:
        return {
            "total": 0,
            "grounded_compliant": 0,
            "correct_non_compliant": 0,
            "hallucinated": 0,
            "real_accuracy": 0.0,
            "claimed_accuracy": "DISABLED - was misleading"
        }
        
    grounded_compliant = sum(
        1 for f in findings
        if f.get("status") == "COMPLIANT"
        and f.get("hallucination_check") == "GROUNDED"
    )
    correct_non_compliant = sum(
        1 for f in findings
        if f.get("status") == "NON_COMPLIANT"
    )
    hallucinated = sum(
        1 for f in findings
        if f.get("hallucination_check") in ["NOT_GROUNDED", "PROMPT_LEAK"]
    )
    
    real_accuracy = round(
        (grounded_compliant + correct_non_compliant) / total * 100, 1
    )
    
    return {
        "total": total,
        "grounded_compliant": grounded_compliant,
        "correct_non_compliant": correct_non_compliant,
        "hallucinated": hallucinated,
        "real_accuracy": real_accuracy,
        "claimed_accuracy": "DISABLED - was misleading"
    }


def potential_evidence_exists(control_id, document_text):
    """
    Fuzzy checks if any keyword from the control description or keywords is present in the document.
    """
    if not control_id or not document_text:
        return False
        
    # Split control_id to get words (excluding clause prefix like 5.15)
    parts = control_id.split(" ")
    keywords = []
    for p in parts[1:]:
        cleaned = "".join(c for c in p if c.isalnum()).lower()
        if len(cleaned) > 3:
            keywords.append(cleaned)
            
    # Dynamically extract keywords for ALL 93 ISO 27001 controls from USE_CASES
    try:
        from src.core.controls_data import USE_CASES
        for uc in USE_CASES:
            uc_id = str(uc.get("use_case", ""))
            uc_lbl = str(uc.get("label", ""))
            sl_str = str(uc.get("sl", ""))
            if control_id in (uc_id, uc_lbl, sl_str) or uc_id.startswith(control_id) or uc_lbl.startswith(control_id):
                combined_desc = f"{uc_id} {uc_lbl} {uc.get('description', '')} {' '.join(uc.get('keywords', []))}"
                for w in combined_desc.split():
                    cleaned = "".join(c for c in w if c.isalnum()).lower()
                    if len(cleaned) > 3 and cleaned not in keywords:
                        keywords.append(cleaned)
                break
    except Exception as e:
        print(f"[VALIDATOR] Dynamic keywords error: {e}", flush=True)

    doc_lower = _cached_doc_lower(document_text)
    for kw in keywords:
        if kw in doc_lower:
            return True
    return False


def evaluate_nist_risk_and_severity(finding, control_id=None):
    """
    Evaluates risk using NIST SP 800-30 Rev. 1 criteria:
    Likelihood + Impact -> NIST risk-matrix lookup -> Risk Level -> application-defined P1–P4 severity:
      - LOW Risk      -> P4 Low
      - MEDIUM Risk   -> P3 Medium
      - HIGH Risk     -> P2 High
      - CRITICAL Risk -> P1 Critical

    This is a matrix lookup, NOT mathematical multiplication.
    P1-P4 is the project's application-defined severity scale, NOT a NIST-defined scale.

    Does NOT hardcode P3 Medium anywhere.
    Does NOT alter compliance status (COMPLIANT / NON_COMPLIANT / FALSE_POSITIVE).
    If risk cannot be reliably determined: sets likelihood=N/A, impact=N/A, risk_level=UNDETERMINED, severity=N/A.
    """
    status_upper = str(finding.get("status") or "").upper()
    # NOT_EVALUATED means the control never reached an assessment (engine timeout).
    # Scoring risk from a non-evaluation would manufacture a severity for a finding
    # that has no result, so it exits here alongside COMPLIANT -- but with its own
    # rationale, because "no risk action required" would be a false reassurance.
    if status_upper == "NOT_EVALUATED" or finding.get("final_result") == "NOT_EVALUATED":
        finding["severity"] = "N/A"
        finding["risk_level"] = "UNDETERMINED"
        finding["likelihood"] = "N/A"
        finding["impact"] = "N/A"
        finding["risk_rationale"] = (
            "NOT EVALUATED: The analysis engine did not return a result for this control, "
            "so no risk determination can be made. Re-run this control."
        )
        return finding
    if status_upper in ("COMPLIANT", "FALSE_POSITIVE") or finding.get("final_result") == "COMPLIANT":
        finding["severity"] = "N/A"
        finding["risk_level"] = "N/A"
        finding["likelihood"] = "N/A"
        finding["impact"] = "N/A"
        finding["risk_rationale"] = (
            "COMPLIANT: No risk action required. Control is adequately evidenced "
            "and policy is documented."
        )
        return finding

    cid = control_id or finding.get("control_id") or finding.get("control") or ""

    # 1. Extract LLM / Grounded Likelihood & Impact candidates
    VALID_LH_IMP = ("LOW", "MODERATE", "HIGH")
    llm_lh = str(finding.get("likelihood") or "").strip().upper()
    llm_imp = str(finding.get("impact") or "").strip().upper()
    lh_valid = llm_lh in VALID_LH_IMP
    imp_valid = llm_imp in VALID_LH_IMP

    # 2. Determine lh/imp from valid grounded LLM/context values, or from the
    # policy/evidence combination, or mark UNDETERMINED.
    #
    # The "LLM provided likelihood/impact" branch below is effectively unreachable
    # in practice -- neither GENERATOR_PROMPT_TEMPLATE nor VAPT_GENERATOR_PROMPT_TEMPLATE
    # in audit_chains.py ever asks the model for a <likelihood>/<impact> tag (those
    # words only appear in prose severity *descriptions*, never as fields to emit),
    # so llm_lh/llm_imp are empty on every real finding. Before this fix, the only
    # other path to a real severity was ONE specific combination (policy FOUND +
    # evidence NOT_FOUND) -- every other NON_COMPLIANT policy/evidence combination
    # (evidence found without a formal policy; both missing; evidence found but
    # assessed insufficient) always fell through to severity=N/A. Observed directly:
    # 2 NON_COMPLIANT findings in one audit, only one got a real severity. All four
    # policy x evidence combinations now map to a defensible likelihood/impact
    # instead of just the one the code happened to handle.
    policy_status_u = str(finding.get("policy_status") or "").upper()
    evidence_status_u = str(finding.get("evidence_status") or "").upper()
    evidence_assessment_u = str(finding.get("evidence_assessment") or "").upper()

    if lh_valid and imp_valid:
        lh = llm_lh
        imp = llm_imp
        rationale_basis = "Assessed likelihood and impact validated against NIST SP 800-30 Rev. 1 3x3 matrix"
    elif policy_status_u == "FOUND" and evidence_status_u == "NOT_FOUND":
        # Policy documented but implementation evidence absent.
        lh = llm_lh if lh_valid else "LOW"
        imp = llm_imp if imp_valid else "MODERATE"
        rationale_basis = "Policy documented but evidence absent; assessed likelihood and impact mapped to matrix"
    elif policy_status_u == "NOT_FOUND" and evidence_status_u == "NOT_FOUND":
        # Neither a policy nor any implementation evidence exists -- the most
        # complete gap possible for this control.
        lh = llm_lh if lh_valid else "MODERATE"
        imp = llm_imp if imp_valid else "HIGH"
        rationale_basis = "Neither policy nor evidence found; assessed likelihood and impact mapped to matrix"
    elif policy_status_u == "NOT_FOUND" and evidence_status_u == "FOUND":
        # Operationally implemented (evidence exists) but not formally documented --
        # a real gap, but a smaller one than having neither in place.
        lh = llm_lh if lh_valid else "LOW"
        imp = llm_imp if imp_valid else "LOW"
        rationale_basis = "Evidence found without a formal policy; assessed likelihood and impact mapped to matrix"
    elif policy_status_u == "FOUND" and evidence_status_u == "FOUND" and evidence_assessment_u == "NON_COMPLIANT":
        # Both present, but the evidence itself was assessed as not satisfying the
        # control (insufficient, contradictory, or incomplete evidence).
        lh = llm_lh if lh_valid else "MODERATE"
        imp = llm_imp if imp_valid else "MODERATE"
        rationale_basis = "Policy and evidence both found, but evidence assessed as insufficient; assessed likelihood and impact mapped to matrix"
    else:
        # Cannot ground risk — output UNDETERMINED with Severity = N/A (zero fallbacks to P3/P4)
        finding["likelihood"] = "N/A"
        finding["impact"] = "N/A"
        finding["risk_level"] = "UNDETERMINED"
        finding["severity"] = "N/A"
        finding["risk_rationale"] = (
            "NIST SP 800-30 Rev. 1 risk assessment: Risk could not be reliably determined from the "
            "available grounded information. Severity set to N/A to avoid fabricating a risk rating."
        )
        return finding

    # 4. NIST SP 800-30 Rev. 1 3x3 Risk Matrix Lookup (Likelihood + Impact -> Risk Level)
    matrix = {
        ("LOW",      "LOW"):       "LOW",
        ("LOW",      "MODERATE"):  "LOW",
        ("LOW",      "HIGH"):      "MEDIUM",
        ("MODERATE", "LOW"):       "LOW",
        ("MODERATE", "MODERATE"):  "MEDIUM",
        ("MODERATE", "HIGH"):      "HIGH",
        ("HIGH",     "LOW"):       "MEDIUM",
        ("HIGH",     "MODERATE"):  "HIGH",
        ("HIGH",     "HIGH"):      "CRITICAL",
    }
    risk_level = matrix.get((lh, imp), "MEDIUM")

    # 5. Application-Defined Severity Mapping (LOW -> P4 Low, MEDIUM -> P3 Medium, HIGH -> P2 High, CRITICAL -> P1 Critical)
    sev_map = {
        "LOW":      "P4 Low",
        "MEDIUM":   "P3 Medium",
        "HIGH":     "P2 High",
        "CRITICAL": "P1 Critical",
    }
    app_severity = sev_map.get(risk_level, "P3 Medium")

    finding["likelihood"] = lh
    finding["impact"] = imp
    finding["risk_level"] = risk_level
    finding["severity"] = app_severity
    finding["risk_rationale"] = (
        f"NIST SP 800-30 Rev. 1 risk-matrix lookup: Likelihood={lh} + Impact={imp} -> "
        f"Risk Level={risk_level} mapped to project severity scale: {app_severity}. ({rationale_basis})"
    )
    return finding


def validate_only(finding, document_text, expected_evidence_map, db_chunks=None):
    """
    Runs core validation rules on a single finding without triggering requires_human_review.
    Enforces the explicit gate order:
      1. Leakage check (fails immediately on prompt leak)
      2. Verbatim Grounding check
      3. Fuzzy OCR Grounding check (if verbatim fails)
      4. Confidence & Consistency checks
    """
    finding = map_new_schema_to_legacy(finding)
    control_id = finding.get("control_id") or finding.get("control") or ""
    code = control_id.split(" ")[0] if control_id else ""
    
    # ── DEBUG: Log raw LLM output before any validation ──
    raw_status = finding.get("status", "UNKNOWN")
    raw_evidence = finding.get("evidence_quote") or finding.get("evidence_snippet") or "NOT_FOUND"
    raw_confidence = finding.get("confidence", "N/A")
    raw_gap = finding.get("gap_description") or finding.get("finding") or ""
    print(f"\n{'='*60}", flush=True)
    print(f"[VALIDATOR DEBUG] Control: {control_id}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Status: {raw_status}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Evidence: {raw_evidence}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Confidence: {raw_confidence}", flush=True)
    print(f"[VALIDATOR DEBUG] RAW LLM Gap: {raw_gap}", flush=True)
    print(f"{'='*60}", flush=True)
    
    raw_status_upper = str(raw_status).upper().strip()
    is_false_positive_or_inapplicable = any(fp_kw in raw_status_upper for fp_kw in ["FALSE_POSITIVE", "FALSE POSITIVE", "OUT_OF_SCOPE", "OUT OF SCOPE", "INAPPLICABLE"])

    # Adversarial prompt-injection guard: FALSE_POSITIVE/inapplicable must never be
    # allowed to short-circuit past Gate 1 (the leakage check below) when the
    # model's own cited evidence contains an injection attempt. Without this, a
    # malicious document whose injected text doesn't read like real
    # control-relevant content could get the model to decide "not applicable" --
    # which used to return immediately, before Gate 1 ever ran -- letting the
    # attack dodge the one check specifically built to catch it, even though it
    # never succeeded in forcing a false COMPLIANT.
    if is_false_positive_or_inapplicable and _contains_injection_keywords(raw_evidence):
        print(f"[VALIDATOR DEBUG] [INJECTION GUARD] {control_id}: FALSE_POSITIVE claim overridden -- cited evidence contains an injection phrase, routing through Gate 1 instead of short-circuiting.", flush=True)
        is_false_positive_or_inapplicable = False

    if is_false_positive_or_inapplicable:
        finding["status"] = "FALSE_POSITIVE"
        finding["hallucination_check"] = "OUT_OF_SCOPE"
        finding["validator_note"] = "Control evaluated as FALSE_POSITIVE / INAPPLICABLE"
        finding["severity"] = "N/A"
        finding["recommendation"] = "No recommendation required. This control has been identified as not applicable to the agreed audit scope."
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates as FALSE_POSITIVE / INAPPLICABLE!", flush=True)
        return check_consistency(apply_confidence_gate(finding))

    evidence = finding.get("evidence_quote") or "NOT_FOUND"
    evidence_clean = evidence.strip().strip('"').strip("'").strip('“').strip('”').strip()
    if not evidence_clean or evidence_clean == "NOT_FOUND":
        evidence_clean = "NOT_FOUND"
    evidence_clean_lower = evidence_clean.lower()
        
    finding["evidence_quote"] = evidence_clean
    finding["evidence_snippet"] = evidence_clean if evidence_clean != "NOT_FOUND" else ""
    finding["chunk_id"] = None
    # validate_only() runs once after generation and again after reflection (LangGraph:
    # retrieve -> generate -> validate -> reflect -> validate) -- evidence_quote/snippet/
    # chunk_id above are correctly reset each pass so they reflect only the CURRENT
    # evidence, but source_files was left out of that reset. The grounding gates below
    # append a matched chunk's file to source_files (existing_sf.append(...)) rather than
    # replace it, so a file grounded only in an earlier, superseded draft's evidence
    # stayed attached to the final finding -- e.g. a control whose real evidence came
    # from one screenshot ended up listing every file in the session as its source.
    finding["source_files"] = ""

    if evidence_clean == "NOT_FOUND":
        # NOT_FOUND must never be silently auto-approved. This used to check for a loose
        # keyword match anywhere in the full combined document text (all uploaded files,
        # unscoped) and, if found, stamp the finding COMPLIANT with hardcoded boilerplate
        # text written for one specific control (8.6 Capacity Management) -- which then
        # appeared verbatim on unrelated controls (e.g. 5.1 Policies for Information
        # Security) any time the LLM itself found no real evidence to quote. A generic
        # keyword match is not evidence the control is satisfied. Fail safe instead:
        # always NON_COMPLIANT, flagged for human review; the keyword hit only changes
        # the review note/severity, it never upgrades the status.
        has_keyword_hit = potential_evidence_exists(control_id, document_text)
        # Describe WHAT is missing, not just that review is needed -- pull the control's
        # own expected-evidence description (set upstream in audit_graph.py) so the finding
        # names the actual requirement instead of a generic "requires manual review" note.
        expected_hints = expected_evidence_map.get(code) if expected_evidence_map else None
        expected_text = str(expected_hints[0]).strip().rstrip(".") if expected_hints and expected_hints[0] else ""
        print(
            f"[VALIDATOR DEBUG] [NON_COMPLIANT] {control_id}: LLM returned NOT_FOUND evidence "
            f"(keyword-level match in documents: {has_keyword_hit}). Setting NON_COMPLIANT for human review.",
            flush=True
        )
        finding["status"] = "NON_COMPLIANT"
        finding["hallucination_check"] = "NOT_FOUND"
        finding["requires_human_review"] = True
        finding["requires_review"] = True
        finding["confidence"] = 1

        pol_stat = str(finding.get("policy_status") or "").upper()
        pol_assess = str(finding.get("policy_assessment") or "").upper()
        if pol_stat == "FOUND" and pol_assess == "COMPLIANT":
            gap_text = "Policy requirements are adequately documented, but no operational evidence was provided to demonstrate implementation."
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["finding"] = gap_text
            finding = evaluate_nist_risk_and_severity(finding, control_id)
            finding["recommendation"] = (
                f"A policy for {control_id} was found and is adequately documented, but no evidence "
                f"of implementation was provided. Provide appropriate evidence such as access logs, "
                f"visitor records, access approval records, or completed review records demonstrating implementation."
            )
        elif has_keyword_hit:
            gap_text = (
                f"The uploaded documents reference related terms, but do not contain {expected_text}."
                if expected_text else
                "The uploaded documents reference related terms, but no passage documenting this control's requirement could be found."
            )
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["finding"] = gap_text
            finding = evaluate_nist_risk_and_severity(finding, control_id)
            finding["recommendation"] = (
                f"Upload or point to the specific document containing {expected_text}, "
                f"or add the missing passage to an existing document, for auditor review."
                if expected_text else
                f"Provide the specific document demonstrating compliance with {control_id} for auditor review."
            )
        else:
            gap_text = (
                f"The uploaded documents contain no evidence of {expected_text}."
                if expected_text else
                f"The uploaded documents contain no evidence addressing {control_id}."
            )
            finding["validator_note"] = gap_text
            finding["review_note"] = gap_text
            finding["recommendation"] = (
                f"Establish, document, and implement {expected_text} to satisfy this control."
                if expected_text else
                f"Establish, document, and implement procedures to satisfy {control_id}."
            )
            finding["finding"] = gap_text
            finding["severity"] = "N/A"

    # ── PHYSICAL VS LOGICAL IDENTITY GATING ──
    if code == "5.16" or "identity management" in control_id.lower():
        evidence = finding.get("evidence_quote") or "NOT_FOUND"
        evidence_lower = evidence.lower()
        if evidence != "NOT_FOUND":
            physical_terms = ["badge", "keycard", "facility access", "physical entry", "visitor sign-in", "visitor log", "escort", "reception", "breezn", "kastle"]
            logical_terms = ["account", "active directory", "database", "system", "logical", "provision", "revoke", "termination", "joiner", "leaver", "myid"]
            
            has_physical = any(term in evidence_lower for term in physical_terms)
            has_logical = any(term in evidence_lower for term in logical_terms)
            
            # If evidence is purely physical and lacks logical IT terms, reject it
            if has_physical and not has_logical:
                print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Physical Badge domain check!", flush=True)
                finding["status"] = "NON_COMPLIANT"
                finding["hallucination_check"] = "NOT_GROUNDED"
                finding["validator_note"] = "Cited evidence refers to physical badging, which does not satisfy logical identity management."
                finding["evidence_snippet"] = ""
                finding["evidence_quote"] = "NOT_FOUND"
                finding["finding"] = "Control requirements not addressed; cited evidence is restricted to physical facility badging."
                finding = evaluate_nist_risk_and_severity(finding, control_id)
                finding["finding_is_final"] = True
                finding = apply_confidence_gate(finding)
                finding = check_consistency(finding)
                return finding

    # ════════════════════════════════════════
    # GATE 1: Leakage check (always first)
    # ════════════════════════════════════════
    hints = expected_evidence_map.get(code, []) if expected_evidence_map else []
    leakage = check_prompt_leakage(evidence_clean, hints)
    
    # Pre-emptively detect adversarial prompt injections in THIS finding's own cited
    # evidence. Previously scanned the whole session's combined document_text, so one
    # unrelated document anywhere in the session (e.g. a phishing-training sample
    # quoting an injection phrase) flagged every control in the audit, not just the
    # ones that actually cited that document. Uses the same keyword list as the
    # FALSE_POSITIVE injection guard above, so the two can't drift out of sync.
    if _contains_injection_keywords(evidence_clean):
        leakage = "PROMPT_LEAK"
                
    print(f"[VALIDATOR DEBUG] GATE 1 (Leakage): {control_id} -> {leakage}", flush=True)
    if leakage == "PROMPT_LEAK":
        print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Leakage Gate! Evidence matched prompt hints or prompt injection detected.", flush=True)
        print(f"[VALIDATOR DEBUG]   Hints: {hints[:2]}", flush=True)
        finding["status"] = "NON_COMPLIANT"
        finding["hallucination_check"] = "PROMPT_LEAK"
        finding["validator_note"] = "Evidence matches Expected Evidence hint — rejected"
        finding["evidence_snippet"] = ""
        finding["evidence_quote"] = "NOT_FOUND"
        finding["finding"] = "Control requirements not addressed in policy document; prompt template echoed by model."
        finding = evaluate_nist_risk_and_severity(finding, control_id)
        finding["finding_is_final"] = True
        finding = apply_confidence_gate(finding)
        finding = check_consistency(finding)
        return finding

    # ════════════════════════════════════════
    # GATE 2: Verbatim Grounding & Chunk Mapping (Normalized)
    # evidence_clean may contain multiple distinct excerpts joined by "\n\n" (multi-
    # evidence findings). Each one is verified INDEPENDENTLY here — checking the whole
    # joined blob as a single quote would (and did) always fail, since 6 sentences from
    # different parts of a document never appear as one continuous block anywhere in the
    # source, which silently collapsed correct multi-item findings down to whichever
    # single prefix happened to match first.
    # ════════════════════════════════════════
    grounded_state = "NOT_GROUNDED"
    matched_chunk_id = None

    candidate_items = (
        [c.strip() for c in evidence_clean.split("\n\n") if c.strip()]
        if evidence_clean != "NOT_FOUND" else []
    )
    grounded_items = []
    # Counts excerpts that only verified via the longest-prefix fallback -- i.e. the
    # tail of the quote was NOT found in the source. Surfaced for human review below,
    # because the model's verdict was formed on text that includes that unverified tail.
    prefix_only_items = 0

    for item_text in candidate_items:
        norm_item = normalize_text(item_text)
        if not norm_item or norm_item == "not_found":
            continue

        item_grounded = False
        item_final_text = item_text

        if db_chunks:
            for chunk in db_chunks:
                norm_chunk = normalize_text(chunk.content)
                if norm_item in norm_chunk:
                    item_grounded = True
                    matched_chunk_id = matched_chunk_id or chunk.id
                    item_final_text = expand_to_complete_sentence(item_text, chunk.content)
                    # Deterministically correct the evidence source to the file this
                    # chunk ACTUALLY came from -- previously this only fired when
                    # metadata_json carried an explicit "source_file" sub-key, which
                    # is only populated for genuinely embedded/nested content (an
                    # image inside a ZIP or a Word doc). For the common case --
                    # several separate top-level files uploaded together -- that key
                    # is absent, so nothing here ever corrected the LLM's own
                    # self-reported filename, which can (and does) misattribute
                    # evidence to the wrong uploaded file once multiple files share
                    # the same RAG context. chunk.filename is set unconditionally by
                    # retrieval.py on every chunk regardless of embedding, so use it
                    # as the reliable base correction; metadata_json's "source_file"
                    # (child image name), when present, is layered in as the more
                    # specific piece -- map_new_schema_to_legacy combines the two
                    # into "Parent.docx (image1.png)".
                    true_source = getattr(chunk, "filename", None)
                    if true_source:
                        existing_sf = [x.strip() for x in str(finding.get("source_files") or "").split(",") if x.strip()]
                        if true_source not in existing_sf:
                            existing_sf.append(true_source)
                        finding["source_files"] = ", ".join(existing_sf)
                        finding["evidence_source_file"] = true_source
                    if chunk.metadata_json:
                        try:
                            import json as _json
                            meta = _json.loads(chunk.metadata_json)
                            if "source_file" in meta:
                                # More specific than chunk.filename for embedded child
                                # content -- overrides the parent-file default above.
                                finding["evidence_source_file"] = meta["source_file"]
                            if "source_type" in meta:
                                finding["evidence_source_type"] = meta["source_type"]
                        except Exception:
                            pass
                    break

        # Fallback to checking the full document text (essential when retrieval bypassed chunking for small files)
        if not item_grounded and document_text:
            norm_doc = _cached_normalize_doc(document_text)
            if norm_item in norm_doc:
                item_grounded = True
                item_final_text = expand_to_complete_sentence(item_text, document_text)
            else:
                # Fallback: check via alphanumeric-only match to handle smart quote / encoding differences
                alpha_item = clean_alphanumeric(item_text)
                alpha_doc = clean_alphanumeric(document_text)
                if alpha_item and alpha_item in alpha_doc:
                    item_grounded = True
                    item_final_text = expand_to_complete_sentence(item_text, document_text)
                    print(f"[VALIDATOR] Grounding matched via alphanumeric fallback for control {control_id}", flush=True)
                else:
                    # Look for the longest prefix of THIS item (word by word) that exists
                    # in the document.
                    #
                    # The floor used to be 6 words (`range(len(words), 5, -1)`), which is
                    # no evidential bar at all: "The organization shall implement access
                    # control" is six generic words present in almost any policy document,
                    # and matching them marked a quote of ANY length GROUNDED -- the
                    # remaining words could be entirely fabricated. Require a substantial
                    # share of the quote instead, and never fewer than 12 words.
                    words = item_text.split()
                    min_prefix_words = max(12, (len(words) + 1) // 2)
                    for i in range(len(words), min_prefix_words - 1, -1):
                        prefix = " ".join(words[:i])
                        norm_prefix = normalize_text(prefix)
                        if norm_prefix in norm_doc:
                            item_final_text = expand_to_complete_sentence(prefix, document_text)
                            item_grounded = True
                            prefix_only_items += 1
                            print(f"[VALIDATOR] Longest matching quote prefix expanded to complete sentence: '{item_final_text}'", flush=True)
                            break
                        alpha_prefix = clean_alphanumeric(prefix)
                        if alpha_prefix and alpha_prefix in alpha_doc:
                            item_final_text = expand_to_complete_sentence(prefix, document_text)
                            item_grounded = True
                            prefix_only_items += 1
                            print(f"[VALIDATOR] Longest matching quote prefix expanded (alphanumeric): '{item_final_text}'", flush=True)
                            break

        if item_grounded:
            grounded_items.append(item_final_text)

    if grounded_items:
        grounded_state = "GROUNDED"
        evidence_clean = "\n\n".join(grounded_items)
        finding["evidence_quote"] = evidence_clean
        finding["evidence_snippet"] = evidence_clean

    # Same deterministic source correction as the evidence loop above, but for the
    # POLICY-side text (policy_clause/policy_finding). Previously only the EVIDENCE
    # quote was checked against db_chunks, so whenever the matched real content was
    # classified as a POLICY statement instead of evidence, its source file was
    # never corrected and stayed at whatever the LLM guessed -- often a generic
    # placeholder. Confirmed on a real audit run: an SSH terminal login banner,
    # OCR'd from a screenshot, got classified as a "policy statement" and shown
    # with source "Embedded Image OCR" instead of the real uploaded filename.
    _policy_text_check = str(finding.get("policy_clause") or finding.get("policy_finding") or "").strip()
    if _policy_text_check and _policy_text_check.upper() != "NOT_FOUND" and db_chunks:
        norm_policy = normalize_text(_policy_text_check)
        if norm_policy:
            for chunk in db_chunks:
                if norm_policy in normalize_text(chunk.content):
                    true_source = getattr(chunk, "filename", None)
                    if true_source:
                        existing_sf = [x.strip() for x in str(finding.get("source_files") or "").split(",") if x.strip()]
                        if true_source not in existing_sf:
                            existing_sf.append(true_source)
                        finding["source_files"] = ", ".join(existing_sf)
                        if not finding.get("evidence_source_file"):
                            finding["evidence_source_file"] = true_source
                    if chunk.metadata_json and not finding.get("evidence_source_file"):
                        try:
                            import json as _json
                            meta = _json.loads(chunk.metadata_json)
                            if "source_file" in meta:
                                finding["evidence_source_file"] = meta["source_file"]
                        except Exception:
                            pass
                    break

    norm_evidence = normalize_text(evidence_clean) if evidence_clean != "NOT_FOUND" else ""


    # ════════════════════════════════════════
    # GATE 3: Fuzzy OCR Grounding Fallback
    # ════════════════════════════════════════
    if grounded_state == "NOT_GROUNDED":
        import difflib
        if db_chunks:
            for chunk in db_chunks:
                words_evidence = evidence_clean_lower.split()
                words_chunk = chunk.content.lower().split()
                n_words = len(words_evidence)
                if n_words == 0 or len(words_chunk) < n_words:
                    continue
                best_ratio = 0.0
                for start in range(len(words_chunk) - n_words + 1):
                    window_text = " ".join(words_chunk[start : start + n_words])
                    ratio = difflib.SequenceMatcher(None, evidence_clean_lower, window_text).ratio()
                    if ratio > best_ratio:
                        best_ratio = ratio
                if best_ratio >= 0.85:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    matched_chunk_id = chunk.id
                    # Extract source details from metadata_json if present (to map to specific files inside a ZIP)
                    if chunk.metadata_json:
                        try:
                            import json as _json
                            meta = _json.loads(chunk.metadata_json)
                            if "source_file" in meta:
                                sfile = meta["source_file"]
                                finding["evidence_source_file"] = sfile
                                existing_sf = [x.strip() for x in str(finding.get("source_files") or "").split(",") if x.strip()]
                                if sfile not in existing_sf:
                                    existing_sf.append(sfile)
                                finding["source_files"] = ", ".join(existing_sf)
                            if "source_type" in meta:
                                finding["evidence_source_type"] = meta["source_type"]
                        except Exception:
                            pass
                    break
        else:
            paragraphs = [p.strip().lower() for p in document_text.split('\n') if len(p.strip()) > 40]
            for p in paragraphs:
                words_evidence = evidence_clean_lower.split()
                words_p = p.split()
                n_words = len(words_evidence)
                if n_words == 0 or len(words_p) < n_words:
                    continue
                best_ratio = 0.0
                for start in range(len(words_p) - n_words + 1):
                    window_text = " ".join(words_p[start : start + n_words])
                    ratio = difflib.SequenceMatcher(None, evidence_clean_lower, window_text).ratio()
                    if ratio > best_ratio:
                        best_ratio = ratio
                if best_ratio >= 0.85:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    break

    # ════════════════════════════════════════
    # GATE 3.5: Image Key-Term Overlap Grounding
    # ════════════════════════════════════════
    # Problem: OCR text from images is noisy (e.g. "enablad" instead of "enabled").
    # The LLM reads it and generates a cleaned paraphrase quote. Gates 2 and 3 both
    # fail because the quote doesn't match verbatim or via 85% sliding-window.
    # Fix: For image-sourced chunks only, check if ≥60% of meaningful domain words
    # from the LLM's quote appear ANYWHERE in the OCR chunk text.
    # e.g. LLM says "NTP enabled synchronized to time.google.com"
    #      OCR text: "NTP enablad synchronizd timegoogl.com"
    # Key terms: [ntp, enabled, synchronized, time, google, com] → 5/6 = 83% → GROUNDED
    if grounded_state == "NOT_GROUNDED" and db_chunks:
        import re as _re_g35
        _STOPWORDS_G35 = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "is", "are", "was", "were", "be", "been", "being",
            "has", "have", "had", "do", "does", "did", "will", "would", "could",
            "should", "may", "might", "shall", "can", "not", "no", "yes", "it",
            "its", "this", "that", "these", "those", "from", "as", "by", "into",
            "which", "who", "what", "when", "where", "how", "all", "any", "both"
        }
        # Extract meaningful words (≥3 chars, not stopwords) from the LLM's evidence quote
        quote_key_terms = [
            w for w in _re_g35.findall(r'\b[a-z0-9]{3,}\b', evidence_clean_lower)
            if w not in _STOPWORDS_G35
        ]
        if len(quote_key_terms) >= 3:
            for chunk in db_chunks:
                # Only apply to image / OCR source chunks
                chunk_source_type = ""
                if chunk.metadata_json:
                    try:
                        import json as _json_g35
                        _meta_g35 = _json_g35.loads(chunk.metadata_json)
                        chunk_source_type = _meta_g35.get("source_type", "")
                    except Exception:
                        pass
                chunk_fname = (chunk.filename or "").lower()
                is_image_chunk = (
                    chunk_source_type == "image"
                    or chunk_fname.endswith((".png", ".jpg", ".jpeg", ".gif", ".tiff", ".bmp"))
                    or "[embedded image ocr" in chunk.content.lower()
                )
                if not is_image_chunk:
                    continue  # Gate 3.5 applies only to image/OCR chunks

                # Terms must co-occur inside a bounded WINDOW of the chunk, matched
                # on word boundaries -- not scattered anywhere in it as substrings.
                #
                # This previously did `sum(1 for t in quote_key_terms if t in
                # chunk_text_lower)`: order-free, distance-free, and a bare substring
                # test, so "com" matched inside "commit" and "ntp" inside "ntpd", and
                # terms drawn from opposite ends of a long OCR dump counted as a
                # match. Confirmed by execution: the quote "NTP enabled synchronized
                # configuration status" -- which appears nowhere in the source as a
                # phrase -- scored 80% and was rated GROUNDED, and a quote whose
                # conclusion inverted the source scored 100%. Since most controls here
                # are screenshot-scoped, this is the gate most evidence passes through.
                #
                # The window keeps genuine OCR tolerance (terms may be reordered or
                # interrupted by OCR noise within a local region) while rejecting
                # document-wide scavenging.
                chunk_words = _re_g35.findall(r'\b[a-z0-9]+\b', chunk.content.lower())
                if not chunk_words:
                    continue
                window_size = max(len(quote_key_terms) * 3, 25)
                unique_terms = set(quote_key_terms)
                best_matched = 0
                for w_start in range(0, max(1, len(chunk_words) - window_size + 1)):
                    window_set = set(chunk_words[w_start : w_start + window_size])
                    hits = len(unique_terms & window_set)
                    if hits > best_matched:
                        best_matched = hits
                        if best_matched == len(unique_terms):
                            break
                matched_terms = best_matched
                overlap = matched_terms / len(unique_terms)
                if overlap >= 0.60:
                    grounded_state = "GROUNDED_WITH_OCR_WARNING"
                    matched_chunk_id = chunk.id
                    print(
                        f"[VALIDATOR] Gate 3.5 (Image Key-Term) PASS for {control_id}: "
                        f"{matched_terms}/{len(unique_terms)} terms ({overlap:.0%}) "
                        f"co-occurring within a {window_size}-word window of '{chunk.filename}'",
                        flush=True
                    )
                    if chunk.metadata_json:
                        try:
                            import json as _json_g35b
                            _meta_g35b = _json_g35b.loads(chunk.metadata_json)
                            if "source_file" in _meta_g35b:
                                sfile = _meta_g35b["source_file"]
                                finding["evidence_source_file"] = sfile
                                existing_sf = [x.strip() for x in str(finding.get("source_files") or "").split(",") if x.strip()]
                                if sfile not in existing_sf:
                                    existing_sf.append(sfile)
                                finding["source_files"] = ", ".join(existing_sf)
                            if "source_type" in _meta_g35b:
                                finding["evidence_source_type"] = _meta_g35b["source_type"]
                        except Exception:
                            pass
                    break

    finding["chunk_id"] = matched_chunk_id
    finding["hallucination_check"] = grounded_state

    print(f"[VALIDATOR DEBUG] GATE 2+3 (Grounding): {control_id} -> {grounded_state}", flush=True)
    raw_status_upper = str(raw_status).upper().strip()
    is_false_positive_or_inapplicable = any(fp_kw in raw_status_upper for fp_kw in ["FALSE_POSITIVE", "FALSE POSITIVE", "OUT_OF_SCOPE", "OUT OF SCOPE", "INAPPLICABLE"])

    if is_false_positive_or_inapplicable:
        finding["status"] = "FALSE_POSITIVE"
        finding["hallucination_check"] = "OUT_OF_SCOPE"
        finding["validator_note"] = "Control evaluated as FALSE_POSITIVE / INAPPLICABLE"
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates as FALSE_POSITIVE / INAPPLICABLE!", flush=True)
    elif grounded_state == "NOT_GROUNDED":
        print(f"[VALIDATOR DEBUG] [FAIL] {control_id}: REJECTED by Grounding Gate! Evidence not found in document.", flush=True)
        print(f"[VALIDATOR DEBUG]   Evidence (first 100 chars): {evidence_clean[:100]}", flush=True)
        # Check for COMPLIANT or PARTIAL, but NOT NON_COMPLIANT (which contains "COMPLIANT" as substring)
        is_compliant_claim = (raw_status_upper == "COMPLIANT" or raw_status_upper == "PARTIAL"
                              or raw_status_upper == "PARTIALLY_COMPLIANT")
        if is_compliant_claim:
            finding["status"] = "NON_COMPLIANT"
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            finding["validator_note"] = "Grounding failed but model claimed compliant/partial — downgraded to NON_COMPLIANT"
            finding["review_note"] = "Grounding validation failed: cited evidence quote was not found in policy document text. Downgraded to NON_COMPLIANT pending manual verification."
        else:
            finding["status"] = "NON_COMPLIANT"
            finding["validator_note"] = "Evidence quote not found in document text — rejected"
            finding["evidence_snippet"] = ""
            finding["evidence_quote"] = "NOT_FOUND"
            finding["finding"] = f"Control requirements for {control_id} are completely missing from the policy document."
            finding = evaluate_nist_risk_and_severity(finding, control_id)
    elif grounded_state == "GROUNDED_WITH_OCR_WARNING":
        finding["requires_human_review"] = True
        finding["requires_review"] = True
        finding["validator_note"] = "Verbiage matched with fuzzy correlation (potential OCR distortion)"
        existing_note = finding.get("review_note") or ""
        ocr_note = "Potential OCR distortion: Cited evidence was grounded via fuzzy correlation. Verify exact spelling in PDF."
        if existing_note:
            if ocr_note not in existing_note:
                finding["review_note"] = f"{existing_note} {ocr_note}"
        else:
            finding["review_note"] = ocr_note
    else:
        print(f"[VALIDATOR DEBUG] [OK] {control_id}: PASSED all gates! Status: {finding.get('status')}", flush=True)
        finding["validator_note"] = None

    # FIX Q3: Reasoning hallucination check — runs for all findings that passed grounding.
    # Scans reasoning text for positive factual claims not grounded in the document.
    reasoning_text = finding.get("reasoning") or finding.get("justification") or ""
    if reasoning_text and grounded_state in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING"):
        hallucination_result = check_reasoning_hallucination(reasoning_text, document_text)
        if not hallucination_result["clean"]:
            flagged = hallucination_result["flagged_phrases"]
            print(f"[VALIDATOR DEBUG] [WARN] {control_id}: Reasoning contains {len(flagged)} potentially hallucinated claim(s).", flush=True)
            finding["reasoning_hallucination_warning"] = True
            finding["reasoning_flagged_phrases"] = flagged
            existing_note = finding.get("review_note") or ""
            hal_note = f"Reasoning hallucination warning: {len(flagged)} claim(s) in the auditor reasoning could not be verified in the document text. Review: {'; '.join(flagged[:2])}"
            if existing_note:
                if "hallucination warning" not in existing_note:
                    finding["review_note"] = f"{existing_note} | {hal_note}"
            else:
                finding["review_note"] = hal_note

    # Get & Normalize status — strictly binary COMPLIANT/NON_COMPLIANT, with FALSE_POSITIVE
    # preserved as its own third state (a control that doesn't apply is not the same as a
    # failed one). Pre-existing bug fixed here: FALSE_POSITIVE doesn't contain the substring
    # "COMPLIANT", so this used to always fall through to the `else` and get silently
    # relabeled NON_COMPLIANT, destroying the FALSE_POSITIVE/Out-of-Scope classification
    # set earlier in this function (the "PASSED all gates as FALSE_POSITIVE" branch above).
    status = finding.get("status", "NON_COMPLIANT").upper()
    if status == "FALSE_POSITIVE":
        finding["status"] = "FALSE_POSITIVE"
    elif "COMPLIANT" in status and "NON" not in status and "PARTIAL" not in status:
        finding["status"] = "COMPLIANT"
    else:
        finding["status"] = "NON_COMPLIANT"
    # Confidence check
    if "confidence" not in finding or finding["confidence"] is None:
        finding["confidence"] = 10 if finding["status"] == "COMPLIANT" else 2
        
    pre_gate_status = finding.get("status")
    # ── NIST SP 800-30 Rev. 1 Risk Assessment & P1-P4 Severity Mapping ──────
    finding = evaluate_nist_risk_and_severity(finding, control_id)
    finding = apply_confidence_gate(finding)
    finding = check_consistency(finding)
    post_gate_status = finding.get("status")
    if pre_gate_status != post_gate_status:
        print(f"[VALIDATOR DEBUG] [WARN] {control_id}: Status changed by Confidence/Consistency gate: {pre_gate_status} -> {post_gate_status}", flush=True)
    print(f"[VALIDATOR DEBUG] FINAL: {control_id} -> Status={finding.get('status')}, Evidence={'YES' if finding.get('evidence_quote') not in ('', 'NOT_FOUND', None) else 'NO'}", flush=True)
    
    # Ensure severity is N/A for COMPLIANT and FALSE_POSITIVE, otherwise resolve based on severity_score
    current_status = finding.get("status", "NON_COMPLIANT")
    if current_status in ("COMPLIANT", "FALSE_POSITIVE"):
        finding["severity"] = "N/A"
    else:
        # Fallback to default control severity if not already set by evaluate_nist_risk_and_severity
        if "severity" not in finding or finding["severity"] in (None, ""):
            from src.core.controls_data import USE_CASES
            uc_severity = "MEDIUM"
            for uc in USE_CASES:
                if uc["use_case"] == control_id or uc["label"] == control_id or uc["use_case"].startswith(control_id):
                    uc_severity = uc.get("severity", "MEDIUM")
                    break
            severity_map = {
                "CRITICAL": "P1 Critical",
                "HIGH": "P2 High",
                "MEDIUM": "P3 Medium",
                "LOW": "P4 Low"
            }
            finding["severity"] = severity_map.get(uc_severity.upper()) or "N/A"

    # FIX 2: Ensure recommendation is populated and appropriate for the compliance status.
    if current_status in ("COMPLIANT", "FALSE_POSITIVE"):
        if current_status == "COMPLIANT":
            finding["recommendation"] = "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
        else:
            finding["recommendation"] = "No recommendation required. This control has been identified as not applicable to the audited document scope."
    else:
        _rec_lower = finding.get("recommendation", "").lower()
        if not finding.get("recommendation") or _rec_lower.startswith("establish") or _is_stale_no_action_recommendation(_rec_lower):
            from src.core.controls_data import USE_CASES

            # ── Base recommendation from USE_CASES (control-specific fallback) ──
            rec = ""
            for uc in USE_CASES:
                if uc["use_case"] == control_id or uc["label"] == control_id:
                    rec = uc.get("recommendation", "")
                    break
            if not rec and code:
                for uc in USE_CASES:
                    if uc["use_case"].startswith(code) or uc["label"].startswith(code):
                        rec = uc.get("recommendation", "")
                        break
            if not rec:
                rec = f"Establish, document, and implement procedures to satisfy {control_id}."

            # ── Smart recommendation: diagnose WHY it failed, give targeted advice ──
            # Priority order: OCR/image quality → wrong document → missing policy →
            # missing evidence → insufficient evidence → fallback to USE_CASES rec.
            _ev_gap   = str(finding.get("evidence_gap")   or "").lower()
            _pol_gap  = str(finding.get("policy_gap")     or "").lower()
            _ev_rel   = str(finding.get("evidence_relevance") or "").upper()
            _ev_stat  = str(finding.get("evidence_status")    or "").upper()
            _pol_stat = str(finding.get("policy_status")      or "").upper()
            _ev_snip  = str(finding.get("evidence_snippet") or finding.get("evidence_quote") or "").lower()

            # 1. OCR / image quality issue — blurry, unreadable, garbled text
            _ocr_signals = ("cannot read", "unreadable", "unclear", "blurry", "illegible",
                            "ocr", "poor quality", "low resolution", "garbled", "distorted",
                            "text not extracted", "no text", "image quality", "scan quality")
            if any(s in _ev_gap for s in _ocr_signals) or any(s in _ev_snip for s in _ocr_signals):
                rec = (
                    f"The uploaded image/scan could not be read clearly by OCR. "
                    f"Re-upload a higher-resolution scan or a text-based PDF for {control_id}. "
                    f"Ensure the document is at least 150 DPI and not password-protected."
                )

            # 2. Wrong document type — evidence is IRRELEVANT to this control
            elif _ev_rel == "IRRELEVANT":
                rec = (
                    f"The uploaded document does not contain evidence relevant to {control_id}. "
                    f"Upload the correct document type. Expected: "
                    f"{next((uc.get('expected','') for uc in USE_CASES if uc['use_case']==control_id or uc['label']==control_id), 'appropriate evidence for this control')}."
                )

            # 3. Policy missing, evidence present → need a policy statement
            elif _pol_stat == "NOT_FOUND" and _ev_stat == "FOUND":
                rec = (
                    f"Evidence of implementation was found but no formal policy statement was identified for {control_id}. "
                    f"Document a written policy or procedure that mandates this control requirement."
                )

            # 4. Policy present, evidence missing → need operational proof
            elif _pol_stat == "FOUND" and _ev_stat == "NOT_FOUND":
                rec = (
                    f"A policy for {control_id} was found but no operational evidence of implementation was provided. "
                    f"Upload records, logs, screenshots, or reports that demonstrate the policy is actively followed."
                )

            # 5. Both missing — nothing found at all
            elif _pol_stat == "NOT_FOUND" and _ev_stat == "NOT_FOUND":
                rec = (
                    f"No policy or evidence was found for {control_id}. "
                    f"Upload both: (1) a documented policy or procedure, and (2) operational evidence "
                    f"such as logs, reports, or screenshots that prove implementation."
                )

            # 6. Both found but insufficient — use gap text if available
            elif _ev_gap and _ev_gap not in ("no evidence gap identified.", "none", "n/a", ""):
                # Use the LLM's own gap description trimmed to 200 chars
                _gap_summary = _ev_gap[:200].rstrip("., ")
                rec = (
                    f"For {control_id}: {_gap_summary.capitalize()}. "
                    f"Address this specific gap and re-upload supporting evidence."
                )

            finding["recommendation"] = rec

    return finding


_STALE_NO_ACTION_PHRASES = [
    "no action required", "no action needed", "no further action",
    "no corrective action", "no remediation required", "no remediation needed",
    "evidence satisfies", "adequately addressed", "not required",
    "continue to maintain current procedures",
]


def _is_stale_no_action_recommendation(rec_lower: str) -> bool:
    """True if a recommendation reads like a COMPLIANT closure note (any phrasing),
    which must never survive on a finding whose final status is NON_COMPLIANT."""
    return any(phrase in rec_lower for phrase in _STALE_NO_ACTION_PHRASES)


# ── Date grounding & deterministic freshness/validity ──────────────────────────
# The LLM's own evidence_date / policy_*_date and evidence_freshness /
# policy_validity fields were previously trusted unverified -- unlike the main
# evidence quote, which is grounding-checked against the source text, a claimed
# date could be entirely fabricated (never appeared anywhere in the document)
# and still get labeled CURRENT, or a genuinely old-but-real date could get
# labeled CURRENT because LLMs are unreliable at date arithmetic. Both were
# observed on a real audit run: a claimed 2026 date with no date anywhere in
# the source text, and real 2024 backup dates labeled CURRENT during a 2026
# audit.

_STALENESS_KEYWORDS = [
    "expired", "deprecated", "decommissioned", "no longer valid", "no longer used",
    "no longer in use", "superseded", "obsolete", "discontinued", "retired",
    "end of life", "end-of-life", "sunset", "not in use",
]


def _has_staleness_language(text):
    """Explicit staleness signal in the text itself, independent of any date --
    catches documents that say they're outdated even when no parseable date
    exists to compare, or overrides a stale document that happens to carry a
    misleadingly recent-looking date."""
    if not text:
        return False
    t = text.lower()
    return any(kw in t for kw in _STALENESS_KEYWORDS)


def _extract_date_tokens(date_str):
    import re
    return re.findall(r"\d+", date_str or "")


def check_date_grounding(date_str, *texts):
    """
    Verifies a claimed date has real support in the source text(s), the same
    principle as check_grounding() for evidence quotes -- don't trust a date
    the LLM output unless the document actually contains it. Loosely matches
    on numeric tokens (a 4-digit year plus at least one day/month-sized token)
    rather than requiring an exact string match, since dates get reformatted
    between the LLM's output and whatever format the source document used.
    """
    if not date_str:
        return False
    tokens = _extract_date_tokens(date_str)
    if not tokens:
        return False
    year_tokens = [t for t in tokens if len(t) == 4]
    other_tokens = [t for t in tokens if len(t) in (1, 2)]
    haystack = " ".join(t for t in texts if t).lower()
    if not haystack:
        return False
    year_ok = any(t in haystack for t in year_tokens) if year_tokens else True
    other_ok = any(t in haystack for t in other_tokens) if other_tokens else True
    return year_ok and other_ok


def _parse_loose_date(date_str):
    """Best-effort parse of a date string in whatever format the LLM/document used."""
    if not date_str:
        return None
    from datetime import datetime
    formats = [
        "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%d %B %Y",
        "%b %d, %Y", "%d %b %Y", "%Y/%m/%d", "%d-%b-%Y", "%d.%m.%Y",
    ]
    s = date_str.strip()
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def resolve_evidence_freshness(finding, document_text, db_chunks=None):
    """
    Replaces the LLM's raw, unverified evidence_freshness self-rating with a
    grounded, conservative determination:
      - evidence_date must actually appear in the source text, or it's wiped
        and freshness forced to UNKNOWN (never trust an ungrounded date).
      - Evidence has no documented required-recency in this system (unlike
        policy, which can carry its own stated review/expiry dates) -- so a
        grounded-but-old date does NOT get auto-flipped to STALE; that would
        be inventing a cadence requirement that was never actually stated
        anywhere. Freshness stays UNKNOWN, but the real grounded date is kept
        and shown, so a human auditor can judge the age themselves instead of
        being told (wrongly) that it's current.
      - Explicit staleness language in the evidence text itself (e.g.
        "decommissioned", "no longer in use") overrides to STALE regardless
        of any date, since that's a real, checkable textual signal.
    """
    chunks_text = " ".join(c.content for c in db_chunks if getattr(c, "content", None)) if db_chunks else ""
    evidence_date = str(finding.get("evidence_date") or "").strip()
    evidence_quote = str(finding.get("evidence_quote") or finding.get("evidence_snippet") or "")

    if evidence_date and not check_date_grounding(evidence_date, document_text or "", chunks_text, evidence_quote):
        finding["evidence_date"] = ""
        evidence_date = ""

    # Only the specific cited evidence_quote is checked for staleness language --
    # not the full document_text, which is the *entire* combined text of every
    # locked file for the whole audit session, shared across every control
    # evaluated in that run. Scanning all of it meant one unrelated staleness
    # word anywhere in a large multi-document set (confirmed on a real audit:
    # an unrelated note that a different internal tool "will be decommissioned"
    # buried in the policy doc) silently marked EVERY finding in the session
    # STALE, regardless of whether that sentence had anything to do with the
    # specific control being evaluated.
    if _has_staleness_language(evidence_quote):
        finding["evidence_freshness"] = "STALE"
    elif not evidence_date:
        finding["evidence_freshness"] = "UNKNOWN"
    else:
        # Grounded date exists but no stated recency requirement to compare
        # against -- keep it visible, don't assert a verdict it can't support.
        finding["evidence_freshness"] = "UNKNOWN"

    return finding


def resolve_policy_validity(finding, document_text, db_chunks=None):
    """
    Same grounding principle as resolve_evidence_freshness(), but policy DOES
    have an explicit requirement to compare against when the document states
    one: its own effective/review/expiry dates. When those are grounded and
    parseable, validity is computed deterministically against today's real
    date instead of trusting the LLM's own arithmetic.
    """
    chunks_text = " ".join(c.content for c in db_chunks if getattr(c, "content", None)) if db_chunks else ""
    policy_text = str(finding.get("policy_finding") or "") + " " + str(finding.get("policy_clause") or "")

    for field in ("policy_effective_date", "policy_review_date", "policy_expiry_date"):
        val = str(finding.get(field) or "").strip()
        if val and not check_date_grounding(val, document_text or "", chunks_text, policy_text):
            finding[field] = ""

    # Only the specific cited policy_text is checked -- see the matching note in
    # resolve_evidence_freshness() above; scanning the full combined document_text
    # let one unrelated staleness word anywhere in a large multi-document set mark
    # EVERY finding in the session EXPIRED regardless of relevance to that control.
    if _has_staleness_language(policy_text):
        finding["policy_validity"] = "EXPIRED"
        return finding

    from datetime import datetime
    today = datetime.now()

    expiry = _parse_loose_date(finding.get("policy_expiry_date"))
    if expiry:
        finding["policy_validity"] = "EXPIRED" if expiry < today else "CURRENT"
        return finding

    review = _parse_loose_date(finding.get("policy_review_date"))
    if review:
        finding["policy_validity"] = "REVIEW_OVERDUE" if review < today else "CURRENT"
        return finding

    finding["policy_validity"] = "UNKNOWN"
    return finding


def derive_policy_required(req_text: str, control_id: str = "", control_name: str = "") -> bool:
    """
    Derive policy_required from the semantic meaning of the authoritative atomic requirement
    and control metadata. The implementation may use normative-language features as signals,
    but must not decide policy applicability from isolated keywords alone. The result must represent
    what the requirement actually demands: documented policy/procedure/standard, implementation/configuration,
    monitoring, review, approval, records, testing, or other obligations.

    CRITICAL RULE:
    Do not infer policy_required from the absence/presence of a policy file.
    First determine the obligation from the authoritative requirement; then evaluate whether the required artifact exists.
    """
    txt = (str(req_text or "") + " " + str(control_name or "")).lower()
    
    # Check if the requirement demands a documented policy/procedure/standard/framework
    policy_phrases = (
        "policy", "policies", "procedure", "procedures", "documented procedure", "written standard",
        "governance framework", "documented strategy", "shall document", "shall define",
        "approved policy", "documented rules", "formal procedure"
    )
    has_policy_phrase = any(phrase in txt for phrase in policy_phrases)
    
    # Check if requirement is explicitly an operational/technical implementation, configuration, or log obligation
    implementation_phrases = (
        "shall configure", "shall implement", "shall synchronize", "shall monitor",
        "system log", "access log", "metric", "status output", "configuration setting",
        "time server", "audit trail"
    )
    has_impl_phrase = any(phrase in txt for phrase in implementation_phrases)
    
    if has_policy_phrase:
        return True
    if has_impl_phrase:
        return False

    # ISO 27001:2022 Annex A clause fallback -- only reached when the requirement
    # text itself gave no explicit signal either way (the keyword checks above
    # always win when they match). Organizational (5.x), People (6.x), and
    # Physical (7.x) controls are, by the standard's own framing, documented
    # rules an organization follows (access authorization rules, screening
    # procedures, entry controls) -- not just a technical setting to switch on.
    # Previously this function accepted control_id but never used it, so a
    # control like "7.2 Physical Entry" (whose expected/prompt_hint text
    # doesn't happen to contain the literal word "policy") silently defaulted
    # to policy_required=False even though a documented physical access policy
    # is exactly what a real ISO audit of that control expects.
    # Clause 8 (Technological) is deliberately excluded: it's a genuine mix of
    # procedural controls (8.9 configuration management, 8.32 change
    # management) and pure technical checks (8.17 clock sync, 8.15 logging)
    # where the keyword signal above -- not a blanket clause default -- is the
    # right call, and the existing "8.17/8.2 don't need policy" behavior must
    # not change.
    clause_match = re.match(r'^\s*(\d+)\.', str(control_id or ""))
    if clause_match and clause_match.group(1) in ("5", "6", "7"):
        return True

    # Default to False for general operational checks unless documented policy is semantically demanded
    return False


def policy_required_reason(req_text: str, control_id: str = "", control_name: str = "") -> str:
    """Why derive_policy_required() answered as it did: 'keyword', 'clause_fallback', or 'none'.

    The two True paths carry very different weight. A requirement that literally asks
    for a policy or procedure is explicit evidence of intent. The clause 5/6/7 branch
    is a blanket default applied to every Organizational, People and Physical control
    whose text happens not to mention one -- a reasonable prior, but only a prior.

    Callers that hold stronger evidence of the auditor's intent (an Excel checklist
    that scoped the control to specific files) need to tell the two apart, so they can
    override the prior without also overriding an explicit demand.
    """
    txt = (str(req_text or "") + " " + str(control_name or "")).lower()
    policy_phrases = (
        "policy", "policies", "procedure", "procedures", "documented procedure", "written standard",
        "governance framework", "documented strategy", "shall document", "shall define",
        "approved policy", "documented rules", "formal procedure"
    )
    if any(phrase in txt for phrase in policy_phrases):
        return "keyword"

    implementation_phrases = (
        "shall configure", "shall implement", "shall synchronize", "shall monitor",
        "system log", "access log", "metric", "status output", "configuration setting",
        "time server", "audit trail"
    )
    if any(phrase in txt for phrase in implementation_phrases):
        return "none"

    clause_match = re.match(r'^\s*(\d+)\.', str(control_id or ""))
    if clause_match and clause_match.group(1) in ("5", "6", "7"):
        return "clause_fallback"

    return "none"


def post_process(finding, document_text, expected_evidence_map=None, db_chunks=None):
    """
    Applies post-processing policies to a single finding.
    """
    if expected_evidence_map is None:
        expected_evidence_map = {}
        
    # Respect BLOCK override (if overridden by human or system rules)
    if finding.get("post_process_override") == "BLOCK":
        return validate_only(finding, document_text, expected_evidence_map, db_chunks)
        
    # Run normal validation check
    finding = validate_only(finding, document_text, expected_evidence_map, db_chunks)
    
    # Skip potential evidence check if prompt leak
    if finding.get("hallucination_check") == "PROMPT_LEAK":
        return finding
        
    # Trigger review flag for potential evidence (only if not already matched fuzzy/verbatim).
    if finding.get("status") == "NON_COMPLIANT" and finding.get("hallucination_check") not in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING"):
        control_id = finding.get("control_id") or finding.get("control") or ""
        if potential_evidence_exists(control_id, document_text):
            finding["requires_human_review"] = True
            finding["requires_review"] = True
            existing_note = finding.get("review_note") or ""
            pot_note = "Potential evidence found. Human verification needed."
            if existing_note:
                if pot_note not in existing_note:
                    finding["review_note"] = f"{existing_note} {pot_note}"
            else:
                finding["review_note"] = pot_note

    # ── DETERMINISTIC POLICY/EVIDENCE FINAL RESULT (RAG accuracy overhaul, Phase 6) ──
    # Replaces both the removed "Rule 8" heuristic upgrade (which silently upgraded
    # NON_COMPLIANT to COMPLIANT based on keyword matches in the LLM's own reasoning
    # text) and the old policy_present/evidence_present combination matrix. This is
    # plain Python conditional logic operating on the Phase 5 policy/evidence fields,
    # not LLM judgment -- per the user's explicit "deterministic, not free LLM
    # judgment" requirement. The LLM still gets exactly one chance to judge
    # equivalent-terminology evidence as satisfying the control, in its own
    # evidence_assessment/evidence_relevance fields -- there is no second guess here.
    #
    # FALSE_POSITIVE (control doesn't apply) is a different concept entirely and is
    # left untouched rather than being forced into this formula.
    if finding.get("status") != "FALSE_POSITIVE":
        control_id = finding.get("control_id") or finding.get("control") or ""
        # Replace the LLM's raw, unverified date/freshness self-ratings with a
        # grounded, deterministic determination before the formula below reads
        # them -- see resolve_evidence_freshness/resolve_policy_validity for why.
        finding = resolve_evidence_freshness(finding, document_text, db_chunks)
        finding = resolve_policy_validity(finding, document_text, db_chunks)

        policy_status = str(finding.get("policy_status") or "NOT_FOUND").strip().upper()
        policy_assessment = str(finding.get("policy_assessment") or "NON_COMPLIANT").strip().upper()
        policy_validity = str(finding.get("policy_validity") or "UNKNOWN").strip().upper()
        evidence_status = str(finding.get("evidence_status") or "NOT_FOUND").strip().upper()
        evidence_assessment = str(finding.get("evidence_assessment") or "NON_COMPLIANT").strip().upper()
        evidence_freshness = str(finding.get("evidence_freshness") or "UNKNOWN").strip().upper()

        # ── AUDITOR-GRADE POLICY VS EVIDENCE SEPARATION ──────────
        evidence_quote_text = str(finding.get("evidence_quote") or finding.get("evidence_snippet") or "").strip()

        _ev_rel = str(finding.get("evidence_relevance") or "").upper()
        if _ev_rel == "IRRELEVANT":
            evidence_status = "NOT_FOUND"
            finding["evidence_status"] = "NOT_FOUND"
            finding["evidence_assessment"] = "NON_COMPLIANT"

        policy_items: List[EvidenceItem] = []
        evidence_items: List[EvidenceItem] = []

        if finding.get("evidence_items_json") or finding.get("policy_items_json"):
            try:
                ev_raw = finding.get("evidence_items_json")
                pol_raw = finding.get("policy_items_json")
                raw_items = []
                if ev_raw:
                    raw_items.extend(json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw)
                if pol_raw:
                    raw_items.extend(json.loads(pol_raw) if isinstance(pol_raw, str) else pol_raw)
                for ri in raw_items:
                    it_obj = EvidenceItem.from_dict(ri)
                    if it_obj.content_type in ("POLICY", "PROCEDURE", "STANDARD") or it_obj.restated_policy:
                        if not any(x.artifact_id == it_obj.artifact_id for x in policy_items):
                            policy_items.append(it_obj)
                    else:
                        if not any(x.artifact_id == it_obj.artifact_id for x in evidence_items):
                            evidence_items.append(it_obj)
            except Exception:
                pass

        if _ev_rel == "IRRELEVANT":
            evidence_items = []

        raw_policy_snip = str(finding.get("policy_snippet") or "")

        if not policy_items and not evidence_items and evidence_quote_text and evidence_quote_text.upper() != "NOT_FOUND":
            c_meta = classify_content_and_modality(evidence_quote_text, str(finding.get("source_files") or ""))
            gr_stat = finding.get("hallucination_check") if finding.get("hallucination_check") in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING") else check_grounding(evidence_quote_text, document_text)
            e_item = EvidenceItem(
                artifact_id="item_1",
                source_file=str(finding.get("source_files") or "Document"),
                chunk_id="chunk_1",
                extracted_text=evidence_quote_text,
                content_type=c_meta["content_type"],
                artifact_modality=c_meta["artifact_modality"],
                grounding_status=gr_stat or "GROUNDED",
                evidence_relevance=_ev_rel or "DIRECT"
            )
            if c_meta["content_type"] in ("POLICY", "PROCEDURE", "STANDARD"):
                e_item.restated_policy = True
                # support_status here means "adequately satisfies the policy requirement" --
                # derive it from the LLM's own raw policy_assessment rather than hardcoding
                # NOT_SUPPORTED, which used to force policy_assessment=NON_COMPLIANT at the
                # policy-adequacy gate below even when the LLM rated the policy COMPLIANT.
                e_item.support_status = "NOT_SUPPORTED" if str(finding.get("policy_assessment") or "").strip().upper() == "NON_COMPLIANT" else "SUPPORTED"
                policy_items.append(e_item)
            else:
                e_item.support_status = "SUPPORTED" if (evidence_status == "FOUND" and evidence_assessment == "COMPLIANT") else "NOT_SUPPORTED"
                evidence_items.append(e_item)

        if not policy_items and (finding.get("policy_finding") or finding.get("policy_snippet")) and str(finding.get("policy_status") or "").upper() == "FOUND":
            pol_text = str(finding.get("policy_finding") or finding.get("policy_snippet")).strip()
            if pol_text and len(pol_text) > 5 and pol_text.upper() != "NOT_FOUND":
                p_item = EvidenceItem(
                    artifact_id="item_pol_fallback",
                    source_file=str(finding.get("source_files") or "Policy Document").split(",")[0].strip(),
                    chunk_id="chunk_pol_1",
                    extracted_text=pol_text,
                    content_type="POLICY",
                    artifact_modality="TEXT",
                    grounding_status="GROUNDED",
                    evidence_relevance="DIRECT",
                    restated_policy=True,
                    support_status="NOT_SUPPORTED" if str(finding.get("policy_assessment") or "").strip().upper() == "NON_COMPLIANT" else "SUPPORTED"
                )
                policy_items.append(p_item)

        if _ev_rel == "IRRELEVANT":
            evidence_items = []
            evidence_status = "NOT_FOUND"
            evidence_assessment = "NON_COMPLIANT"
            finding["evidence_status"] = "NOT_FOUND"
            finding["evidence_assessment"] = "NON_COMPLIANT"

        # ── GOVERNANCE/DOCUMENTATION CARVE-OUT (AGENTS.md "Evidence status / assessment") ──
        # For governance/documentation controls (5.1, 5.37, 6.6-style, or a checklist question
        # asking what the approved policy document itself states -- version, date, content),
        # the approved policy document IS the documentary evidence. The generator prompt
        # already tells the LLM this and it self-reports EVIDENCE_STATUS=FOUND /
        # EVIDENCE_ASSESSMENT=COMPLIANT accordingly -- but that signal was previously discarded
        # here: content classified POLICY/PROCEDURE/STANDARD only ever landed in policy_items,
        # and evidence_status was then forced NOT_FOUND whenever evidence_items came up empty.
        # That produced findings whose own reasoning said the policy "satisfies the
        # requirement" but whose final status was NON_COMPLIANT, because no *separate*
        # operational artifact existed -- a contradiction for exactly the control types where
        # none is expected to exist. Trust the LLM's raw self-report (not a keyword
        # re-derivation) since the prompt already implements the governance/operational
        # distinction; give the mirrored item a distinct artifact_id so the overlap-invariant
        # check below doesn't strip it back out.
        if (
            not evidence_items
            and policy_items
            and _ev_rel != "IRRELEVANT"
            and str(finding.get("evidence_status") or "").strip().upper() == "FOUND"
            and str(finding.get("evidence_assessment") or "").strip().upper() == "COMPLIANT"
        ):
            for p_item in policy_items:
                gov_item = EvidenceItem.from_dict(p_item.to_dict())
                gov_item.artifact_id = f"{p_item.artifact_id}_gov_evidence"
                gov_item.restated_policy = False
                gov_item.support_status = "SUPPORTED"
                evidence_items.append(gov_item)

        # Overlap Check Runtime Invariant: policy_items ∩ evidence_items == ∅
        pol_ids = {it.artifact_id for it in policy_items if it.artifact_id}
        ev_ids = {it.artifact_id for it in evidence_items if it.artifact_id}
        overlap_ids = list(pol_ids.intersection(ev_ids))
        if overlap_ids:
            evidence_items = [it for it in evidence_items if it.artifact_id not in pol_ids]
            overlap_ids = []

        # Populate policy_snippet ONLY from policy_items or valid requirement snippet
        if policy_items:
            finding["policy_snippet"] = "\n\n".join([it.extracted_text for it in policy_items if it.extracted_text])
        elif raw_policy_snip:
            finding["policy_snippet"] = raw_policy_snip
        else:
            finding["policy_snippet"] = ""

        # Populate operational_evidence_snippet ONLY from evidence_items
        if evidence_items:
            finding["operational_evidence_snippet"] = "\n\n".join([it.extracted_text for it in evidence_items if it.extracted_text])
        else:
            finding["operational_evidence_snippet"] = ""

        conflict_detected = False
        conflict_notes = []
        if len(evidence_items) > 1:
            item_texts = [it.extracted_text.lower() for it in evidence_items if it.extracted_text]
            has_pos = any("enabled" in t or "success" in t or "passed" in t or "ok" in t for t in item_texts)
            has_neg = any("disabled" in t or "failed" in t or "missing" in t or "error" in t for t in item_texts)
            if has_pos and has_neg:
                conflict_detected = True
                conflict_notes.append("Conflicting evidence detected across retrieved artifacts.")

        if raw_policy_snip and "\n\n" in raw_policy_snip:
            auth_req_text = raw_policy_snip
        else:
            auth_req_text = (
                finding.get("question") or
                finding.get("requirement") or
                finding.get("control_description") or
                finding.get("control_name") or
                raw_policy_snip or
                finding.get("control_id") or
                "General Control Requirement"
            )
        parts = [p.strip() for p in str(auth_req_text).split("\n\n") if p.strip()]
        raw_reqs = parts if parts else [str(auth_req_text)]

        req_total = len(raw_reqs)
        coverage_list = []
        req_supported_cnt = 0
        req_partial_cnt = 0
        req_not_supported_cnt = 0

        raw_ev_assess = str(finding.get("evidence_assessment") or "").strip().upper()
        if evidence_items:
            evidence_status = "FOUND"
            if raw_ev_assess == "NON_COMPLIANT":
                evidence_assessment = "NON_COMPLIANT"
            else:
                evidence_assessment = "COMPLIANT"

        NEGATIVE_PROOF_INDICATORS = (
            "disabled", "inactive", "failed", "failure", "missing", "denied",
            "expired", "not configured", "unsupported", "error", "not synchronized",
            "synchronized: no", "enabled: no", "active: no", "mfa: disabled",
            "mfa disabled", "sshd: disabled", "telnet: enabled", "http: enabled"
        )

        # The subset of the list above whose meaning DEPENDS on what the control asks
        # for. "disabled" disproves a control that expects something enabled, and
        # confirms one that expects it disabled. The remaining entries (failed,
        # denied, expired, error...) indicate a problem either way and are never
        # suppressed.
        _STATE_OFF_NEG = (
            "disabled", "inactive", "not configured", "not synchronized",
            "synchronized: no", "enabled: no", "active: no",
            "mfa: disabled", "mfa disabled", "sshd: disabled",
        )

        # Unambiguous "this control is OFF" statements. Narrower than the list above
        # on purpose: this set is applied to the SOURCE document, where common words
        # like "error" or "missing" appear innocuously all the time, and a false hit
        # would wrongly sink a genuinely compliant finding.
        SOURCE_CONTRADICTION_INDICATORS = (
            "enabled: no", "synchronized: no", "active: no", "status: disabled",
            "inactive (dead)", "not synchronized", "not configured",
            "mfa: disabled", "mfa disabled", "sshd: disabled",
            "disabled", "inactive",
        )

        def _negation_hits(text, indicators):
            """Negation matching with word boundaries for single words.

            A bare `neg in text` test matches inside unrelated longer words --
            the same class of bug `_kw()` documents elsewhere in this file
            ("error" inside "errors"/"terror", "inactive" inside "inactivex").
            Multi-word and punctuated phrases are inherently safe, so those keep
            plain substring matching.
            """
            if not text:
                return []
            low = text.lower()
            hits = []
            for neg in indicators:
                if " " in neg or ":" in neg:
                    if neg in low:
                        hits.append(neg)
                elif _kw(neg, low):
                    hits.append(neg)
            return hits

        # ── SOURCE-SIDE CONTRADICTION CHECK ────────────────────────────────
        # The negative-proof scan below reads each evidence item's extracted_text --
        # which is the MODEL'S OWN QUOTE, not the document it came from. A model
        # that quotes selectively simply omits the disqualifying words and the
        # scan sees a clean string. Confirmed by execution: source reading
        # "NTP enabled: no / synchronized: no / chronyd.service: inactive (dead)"
        # produced a full-pipeline verdict of COMPLIANT, because the model quoted
        # "NTP enabled synchronized chronyd service time zone" and dropped every
        # negation. The guard was inspecting the suspect's statement instead of
        # the source record.
        #
        # Scan the actual grounded source text as well. Restricted to the chunk(s)
        # this finding was grounded against -- never the whole session document --
        # so an unrelated file mentioning "disabled" cannot poison other controls.
        source_scan_text = ""
        try:
            if db_chunks:
                _fid = finding.get("chunk_id")
                _srcs = {
                    s.strip().lower()
                    for s in str(finding.get("source_files") or "").split(",")
                    if s.strip()
                }
                _matched = [c for c in db_chunks if _fid is not None and getattr(c, "id", None) == _fid]
                if not _matched and _srcs:
                    _matched = [
                        c for c in db_chunks
                        if str(getattr(c, "filename", "") or "").strip().lower() in _srcs
                    ]
                source_scan_text = " ".join(
                    str(getattr(c, "content", "") or "") for c in _matched
                )
        except Exception as e:
            print(f"[VALIDATOR] Source contradiction scan skipped: {e}", flush=True)
            source_scan_text = ""

        # Control key terms, used to require that a negation actually refers to THIS
        # control. Without this a chunk reading "NTP enabled: yes ... IPv6: disabled"
        # would sink a correct COMPLIANT finding about NTP on the strength of an
        # unrelated line -- trading the false pass for a false failure, which is just
        # as wrong for an audit.
        _CTRL_STOP = {
            "the", "and", "for", "with", "whether", "that", "this", "are", "was",
            "has", "have", "been", "any", "all", "its", "from", "into", "not",
            "is", "of", "in", "on", "to", "a", "an", "or", "by", "as", "at",
        }
        _ctrl_term_src = " ".join(str(x or "") for x in (
            finding.get("question"), finding.get("control_name"), finding.get("control_id")
        )).lower()
        control_key_terms = {
            w for w in re.findall(r'\b[a-z0-9]{3,}\b', _ctrl_term_src) if w not in _CTRL_STOP
        }

        # A control that legitimately expects something to be OFF (e.g. "whether Telnet
        # is disabled") is CONFIRMED, not contradicted, by the word "disabled" in its
        # source. Detecting that keeps the check from inverting such controls.
        _OFF_EXPECTED = (
            "disabled", "disable", "removed", "blocked", "prohibited", "restricted",
            "not permitted", "turned off", "deactivated", "denied", "revoked",
        )
        control_expects_off = any(p in _ctrl_term_src for p in _OFF_EXPECTED)

        def _proximate_negations(text, indicators, window=8):
            """Negations sitting near a term that belongs to THIS control.

            Proximity is required on BOTH the quote and the source, because each
            routinely carries unrelated neighbouring lines.
            expand_to_complete_sentence() widens a verified quote by up to ~450
            characters, and terminal screenshots carry no sentence punctuation, so a
            correct "NTP enabled: yes" citation reliably drags in an adjacent
            "IPv6 forwarding: disabled". Scanning that flat -- as this check did --
            marked the requirement NOT_SUPPORTED and sank a genuinely compliant
            finding: a false failure, which is no better for an audit than a false pass.
            """
            if not text or not indicators or not control_key_terms:
                return []
            low = text.lower()
            hits = []
            for neg in indicators:
                start = low.find(neg)
                while start != -1:
                    before = re.findall(r'\b[a-z0-9]+\b', low[:start])[-window:]
                    after = re.findall(
                        r'\b[a-z0-9]+\b', low[start + len(neg): start + len(neg) + 60]
                    )
                    if (set(before) | set(after)) & control_key_terms:
                        hits.append(neg)
                        break
                    start = low.find(neg, start + 1)
            return hits

        # Polarity filter applied at the call site so both sides share one rule: a
        # control that expects something OFF is confirmed, not contradicted, by the
        # off-state words.
        _src_indicators = tuple(
            n for n in SOURCE_CONTRADICTION_INDICATORS
            if not (control_expects_off and n in _STATE_OFF_NEG)
        )
        source_contradictions = _proximate_negations(source_scan_text, _src_indicators)

        # True when the auditor's Excel checklist locked this control to specific
        # file(s). Set by audit_graph.validate_node from the graph state; absent for
        # standard (non-scoped) runs, which keep the clause default untouched.
        excel_scoped = bool(
            finding.get("locked_filenames")
            or finding.get("evidence_locked_filenames")
            or finding.get("policy_locked_filenames")
        )

        for idx, req_text in enumerate(raw_reqs):
            req_id = f"R{idx+1}"
            policy_req = derive_policy_required(req_text, control_id, finding.get("control_name") or "")

            # Excel scoping is a stronger statement of intent than the clause default.
            #
            # derive_policy_required() defaults every 5.x/6.x/7.x control to
            # "needs a documented policy" when its text doesn't say otherwise. When the
            # auditor's own checklist has locked this control to specific file(s), they
            # have already declared what is in scope for it -- and if they scoped only an
            # operational artifact, failing the control for a missing policy artifact they
            # never put in scope is the tool overruling the auditor.
            #
            # Confirmed on a live run: 5.33 "Whether log archival is done?" was locked to
            # a single screenshot. Clause-5 fallback demanded a policy, none existed in a
            # JPG, and the requirement was marked NOT_SUPPORTED before the model's
            # assessment counted for anything -- unpassable regardless of the evidence.
            #
            # Only the blanket clause default is overridden. A requirement that explicitly
            # asks for a policy or procedure still requires one, scoped or not.
            if policy_req and excel_scoped and not policy_items:
                if policy_required_reason(req_text, control_id, finding.get("control_name") or "") == "clause_fallback":
                    policy_req = False
                    finding["policy_requirement_waived"] = True
                    print(
                        f"[VALIDATOR] Policy requirement waived for {control_id} ({req_id}): "
                        f"clause-{str(control_id).split('.')[0]} default overridden because the Excel "
                        f"checklist scoped this control to evidence only.",
                        flush=True
                    )
            matching_items = [it for it in evidence_items if not it.restated_policy and it.grounding_status in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING", "VERIFIED", "")]
            
            # Polarity matters on the quote side too. "disabled"/"inactive" prove
            # non-compliance only when the control expects the thing to be ON. For a
            # control that expects it OFF ("whether Telnet is disabled"), the correct
            # evidence necessarily contains the word "disabled" -- and the flat list
            # below marked exactly that evidence NOT_SUPPORTED, so such a control could
            # never pass no matter what was uploaded. Words that are bad regardless of
            # polarity (failed, denied, expired) still apply either way.
            quote_indicators = tuple(
                neg for neg in NEGATIVE_PROOF_INDICATORS
                if not (control_expects_off and neg in _STATE_OFF_NEG)
            )

            has_negative_proof = False
            negative_from_source = False
            for it in matching_items:
                if _proximate_negations(it.extracted_text, quote_indicators):
                    has_negative_proof = True
                    break

            # The source itself says the control is off, even if the model's quote
            # carefully avoided saying so. This is the check that closes the
            # false-COMPLIANT path; it fires regardless of what the quote contains.
            if source_contradictions and matching_items:
                has_negative_proof = True
                negative_from_source = True

            if conflict_detected:
                r_status = "NOT_SUPPORTED"
                r_reason = "Conflicting evidence sources detected for this requirement."
                r_op_source = evidence_items[0].source_file if evidence_items else None
            elif policy_req and not policy_items:
                r_status = "NOT_SUPPORTED"
                r_reason = "Requirement mandates documented policy/procedure/standard, but no acceptable policy artifact was found."
                r_op_source = None
            elif has_negative_proof:
                r_status = "NOT_SUPPORTED"
                if negative_from_source:
                    r_reason = (
                        "Source document contradicts the cited evidence: the grounded source text "
                        f"states {', '.join(repr(h) for h in source_contradictions[:3])}, "
                        "indicating the control is not in effect."
                    )
                    finding["contradiction_suspected"] = True
                    finding["contradiction_terms"] = source_contradictions[:5]
                    # requires_human_review also routes this back through the reflection
                    # pass in audit_graph.py (should_continue -> "reflect"), which
                    # previously never saw a confidently-wrong-but-grounded finding
                    # because nothing marked one as failed.
                    finding["requires_human_review"] = True
                    finding["requires_review"] = True
                    _cd_note = (
                        "Contradiction: the source document states "
                        f"{', '.join(repr(h) for h in source_contradictions[:3])}, which is "
                        "inconsistent with the assessment drawn from it. Verify against the original artifact."
                    )
                    _existing_cd = finding.get("review_note") or ""
                    if "Contradiction:" not in _existing_cd:
                        finding["review_note"] = f"{_existing_cd} | {_cd_note}".strip(" |")
                    print(
                        f"[VALIDATOR] SOURCE CONTRADICTION for {finding.get('control_id')}: "
                        f"{source_contradictions[:3]} present in grounded source -- forcing NOT_SUPPORTED.",
                        flush=True
                    )
                else:
                    r_reason = "Retrieved grounded evidence indicates non-compliance or a disabled/failed security control state."
                r_op_source = matching_items[0].source_file if matching_items else None
                evidence_assessment = "NON_COMPLIANT"
            elif matching_items and raw_ev_assess != "NON_COMPLIANT":
                r_status = "SUPPORTED"
                best_item = matching_items[0]
                best_item.support_status = "SUPPORTED"
                r_reason = f"Verified by {best_item.content_type} ({best_item.artifact_modality}) from {best_item.source_file}."
                r_op_source = best_item.source_file
                if best_item.page:
                    r_op_source += f" (Page {best_item.page})"
            elif matching_items:
                r_status = "PARTIAL"
                r_reason = f"Operational requirement evaluated against evidence from {finding.get('source_files') or 'Evidence Document'}."
                r_op_source = finding.get("source_files") or "Evidence Document"
            else:
                r_status = "NOT_SUPPORTED"
                r_reason = "No operational implementation evidence was provided for this requirement."
                r_op_source = None

            if r_status == "SUPPORTED":
                req_supported_cnt += 1
            elif r_status == "PARTIAL":
                req_partial_cnt += 1
            else:
                req_not_supported_cnt += 1

            coverage_list.append({
                "requirement_id": req_id,
                "requirement": req_text[:120],
                "mandatory": True,
                "policy_required": policy_req,
                "policy_source": finding.get("source_files") or "Policy Document",
                "operational_source": r_op_source,
                "status": r_status,
                "reason": r_reason
            })

        finding["requirements_total"] = req_total
        finding["requirements_supported"] = req_supported_cnt
        finding["requirements_partial"] = req_partial_cnt
        finding["requirements_not_supported"] = req_not_supported_cnt
        finding["requirements_coverage_json"] = json.dumps(coverage_list)
        finding["policy_items_json"] = json.dumps([it.to_dict() for it in policy_items])
        finding["evidence_items_json"] = json.dumps([it.to_dict() for it in evidence_items])
        if conflict_detected:
            finding["conflicting_evidence"] = True
            finding["conflict_notes"] = " ".join(conflict_notes)

        # Mandatory-Atomic policy_required calculation from authoritative normalized semantics
        policy_required = any(
            cov.get("mandatory", True) and cov.get("policy_required", False)
            for cov in coverage_list
        ) if coverage_list else False

        # Canonical Policy State Machine (Descriptive Metadata Track Only — NEVER mutates final_status)
        raw_pol_assess = str(finding.get("policy_assessment") or "").strip().upper()
        if policy_items:
            policy_status = "FOUND"
            # Policy Adequacy: FOUND does not automatically mean COMPLIANT. Evaluate policy requirement adequacy.
            if raw_pol_assess == "NON_COMPLIANT" or any(getattr(it, "support_status", "") == "NOT_SUPPORTED" for it in policy_items):
                policy_assessment = "NON_COMPLIANT"
                pol_present = "Found"
            else:
                policy_assessment = "COMPLIANT"
                pol_present = "Compliant"
        elif policy_required:
            policy_status = "NOT_FOUND"
            policy_assessment = "NON_COMPLIANT"
            pol_present = "Not Found"
        else:
            policy_status = "NOT_REQUIRED"
            policy_assessment = "NOT_APPLICABLE"
            pol_present = "Not Required"

        # Only overwrite policy_gap with the "not required" message in the genuine
        # NOT_REQUIRED case (no policy needed AND none was found) -- this used to
        # fire on `not policy_required` alone, which also matched the FOUND branch
        # above whenever derive_policy_required() defaulted to False for a control
        # whose requirement text doesn't literally say "policy" (e.g. "7.2 Physical
        # Entry"). That produced a self-contradicting finding: policy_status=FOUND
        # (a real policy document was located and used) next to a policy_gap saying
        # "policy is not required for this requirement" -- confusing regardless of
        # which of the two a reader trusts.
        if policy_status == "NOT_REQUIRED":
            finding["policy_gap"] = "Not applicable — policy is not required for this requirement."

        if not evidence_items:
            evidence_status = "NOT_FOUND"
            evidence_assessment = "NON_COMPLIANT"
            ev_present = "Not Found"
        elif any(it.support_status == "SUPPORTED" for it in evidence_items) and req_not_supported_cnt == 0:
            evidence_status = "FOUND"
            evidence_assessment = "COMPLIANT"
            ev_present = "Compliant"
        else:
            evidence_status = "FOUND"
            evidence_assessment = "NON_COMPLIANT"
            ev_present = "Found"

        # UNKNOWN validity/freshness is acceptable (confirmed with the user) -- most
        # real documents never state effective/review/expiry dates or evidence
        # timestamps, and "never invent/assume" means an absent date is not itself
        # evidence of a problem. Only an explicitly *confirmed* issue (EXPIRED,
        # REVIEW_OVERDUE, STALE) blocks COMPLIANT.
        policy_valid_ok = policy_validity in ("CURRENT", "UNKNOWN")
        evidence_fresh_ok = evidence_freshness in ("CURRENT", "UNKNOWN")

        # Mandatory Atomic Requirement Authority: Overall COMPLIANT only when
        # every mandatory atomic requirement is SUPPORTED, no requirement is PARTIAL or NOT_SUPPORTED,
        # and no unresolved conflict exists.
        is_compliant = (
            req_supported_cnt == req_total
            and req_partial_cnt == 0
            and req_not_supported_cnt == 0
            and not conflict_detected
            and policy_valid_ok
            and evidence_fresh_ok
        )

        # Structured Runtime Debug Output
        print("\n============================================================", flush=True)
        print(f"POLICY ITEMS:\n  {[it.artifact_id for it in policy_items]}", flush=True)
        print(f"EVIDENCE ITEMS:\n  {[it.artifact_id for it in evidence_items]}", flush=True)
        print(f"OVERLAP:\n  {overlap_ids}", flush=True)
        for cov in coverage_list:
            print(f"POLICY APPLICABILITY:\n  requirement_id={cov['requirement_id']}\n  requirement_text={cov['requirement']}\n  policy_required={cov['policy_required']}", flush=True)
            print(f"REQUIREMENT RESULT:\n  requirement_id={cov['requirement_id']}\n  status={cov['status']}\n  operational_source={cov['operational_source']}", flush=True)
        print(f"[POLICY CONSISTENCY DEBUG]\n  control={finding.get('control_id')}\n  policy_required={policy_required}\n  policy_status={policy_status}\n  policy_assessment={policy_assessment}\n  evidence_status={evidence_status}\n  evidence_assessment={evidence_assessment}\n  final_status={'COMPLIANT' if is_compliant else 'NON_COMPLIANT'}", flush=True)
        print(f"FINAL AUTHORITY:\n  mandatory_supported={req_supported_cnt}\n  mandatory_partial={req_partial_cnt}\n  mandatory_not_supported={req_not_supported_cnt}\n  unresolved_conflict={conflict_detected}\n  final_status={'COMPLIANT' if is_compliant else 'NON_COMPLIANT'}", flush=True)
        print("============================================================\n", flush=True)

        finding["requirement_question"] = finding.get("requirement_question") or finding.get("question") or finding.get("requirement") or auth_req_text
        finding["policy_required"] = policy_required
        finding["policy_status"] = policy_status
        finding["policy_assessment"] = policy_assessment
        finding["evidence_status"] = evidence_status
        finding["evidence_assessment"] = evidence_assessment
        finding["final_result"] = "COMPLIANT" if is_compliant else "NON_COMPLIANT"
        finding["status"] = finding["final_result"]
        finding["policy_present"] = pol_present
        finding["evidence_present"] = ev_present

        if is_compliant:
            finding["severity"] = "N/A"
            if finding.get("reasoning"):
                finding["description"] = finding["reasoning"]
            finding["recommendation"] = finding.get("recommendation") or "No action required. Continue to maintain current procedures and ensure periodic review of compliance evidence."
        else:
            cid = finding.get("control_id") or ""
            cname = finding.get("control_name") or "Control"
            print(f"[DETERMINISTIC FINAL RESULT] Control {cid}: policy_status={policy_status}, "
                  f"policy_assessment={policy_assessment}, policy_validity={policy_validity}, "
                  f"evidence_status={evidence_status}, evidence_assessment={evidence_assessment}, "
                  f"evidence_freshness={evidence_freshness} -> NON_COMPLIANT", flush=True)

            # ── FOUND vs NOT FOUND & POLICY vs EVIDENCE MAPPING ──────
            doc_text_present = bool(str(finding.get("condensed_context") or
                                       finding.get("evidence_snippet") or
                                       finding.get("justification") or "").strip())
            pol_found = policy_status == "FOUND"
            ev_found = evidence_status == "FOUND"

            # Separate presence mapping for policy and evidence
            if pol_found:
                finding["policy_present"] = "Compliant" if policy_assessment == "COMPLIANT" else "Found"
            elif policy_required:
                finding["policy_present"] = "Not Found"
            else:
                finding["policy_present"] = "Not Required"

            if ev_found:
                finding["evidence_present"] = "Compliant" if evidence_assessment == "COMPLIANT" else "Found"
            else:
                finding["evidence_present"] = "Not Found"

            # Targeted smart recommendation for NON_COMPLIANT findings
            rec_str = str(finding.get("recommendation") or "").lower()
            if pol_found and policy_assessment == "COMPLIANT" and not ev_found:
                if not rec_str or "operational evidence" not in rec_str or _is_stale_no_action_recommendation(rec_str):
                    finding["recommendation"] = (
                        f"A policy for {cname} (ISO 27001 Control {cid}) was found and is adequately documented, "
                        f"but no operational evidence of implementation was provided. Provide appropriate "
                        f"operational evidence such as access logs, visitor records, access approval records, "
                        f"or completed access-review records demonstrating implementation."
                    )
            elif not rec_str or _is_stale_no_action_recommendation(rec_str):
                if not pol_found and ev_found:
                    finding["recommendation"] = (
                        f"Operational evidence was found for {cname} (ISO 27001 Control {cid}), but no formal "
                        f"policy statement was identified. Document and approve a written policy or standard "
                        f"that mandates this control requirement."
                    )
                elif pol_found or ev_found or doc_text_present:
                    finding["recommendation"] = (
                        f"The uploaded document was read but does not fully satisfy {cname} "
                        f"(ISO 27001 Control {cid}). Review and update the existing policy to address "
                        f"the identified gaps, strengthen evidence logging, and ensure all required "
                        f"control objectives are explicitly covered."
                    )
                else:
                    # Clear misleading snippet if evidence absent
                    snip_lower = str(finding.get("evidence_snippet") or "").lower()
                    if any(neg in snip_lower for neg in ["no evidence", "not found", "focuses entirely on", "exclusively details"]):
                        finding["evidence_snippet"] = ""
                    finding["recommendation"] = (
                        f"No policy or evidence document was uploaded for {cname} "
                        f"(ISO 27001 Control {cid}). Create a formally approved policy document, "
                        f"implement technical controls, establish evidence logging procedures, "
                        f"and upload the documentation before the next audit cycle."
                    )

            # Safeguard: if marked NON_COMPLIANT, ensure severity is calculated from NIST risk
            if not finding.get("severity") or finding.get("severity") == "N/A":
                finding = evaluate_nist_risk_and_severity(finding, cid)

    # ── Self-consistency guard: the model itself claimed no gap exists (evidence_gap
    # / policy_gap says "no gap identified") yet the finding still landed NON_COMPLIANT.
    # Observed on a real audit run: a genuinely compliant, versioned policy document
    # got marked NON_COMPLIANT while evidence_gap/reasoning/final_reason all affirmed
    # it satisfied the control -- the boilerplate "Establish a policy..." recommendation
    # then confidently told the auditor to redo work the evidence showed was already done.
    # Do NOT punt to "have a human review this" -- auditors need an actionable
    # recommendation, not a shrug. Build one from the control's own expected-evidence
    # text and the model's own specific reasoning instead of the generic canned template.
    if str(finding.get("status") or finding.get("final_result") or "").upper() == "NON_COMPLIANT":
        _no_gap_phrases = ("no evidence gap identified", "no gap identified", "none", "n/a")
        _ev_gap_c = str(finding.get("evidence_gap") or "").strip().lower().rstrip(".")
        _pol_gap_c = str(finding.get("policy_gap") or "").strip().lower().rstrip(".")
        if _ev_gap_c in _no_gap_phrases or _pol_gap_c in _no_gap_phrases:
            cid = finding.get("control_id") or finding.get("control") or ""
            code = str(cid).split(" ")[0] if cid else ""
            _expected = ""
            _entry = (expected_evidence_map or {}).get(code)
            if isinstance(_entry, (list, tuple)) and _entry:
                _expected = str(_entry[0] or "").strip()
            elif _entry:
                _expected = str(_entry).strip()

            _basis = str(finding.get("final_reason") or finding.get("reasoning") or "").strip()
            _summary = (_basis[:300].rstrip(". ") + ".") if _basis else ""
            finding["description"] = (
                f"Evidence was located and assessed against {cid}, but the automated check could "
                f"not conclusively confirm every requirement is met. {_summary}"
            ).strip()
            finding["gap_description"] = finding["description"]
            finding["finding"] = finding["description"]
            finding["recommendation"] = (
                (f"Confirm the existing evidence explicitly and formally covers: {_expected}. "
                 if _expected else
                 "Confirm the existing evidence explicitly and formally covers every requirement "
                 "of this control. ")
                + "If it does, reclassify this finding as Compliant; if a specific element is "
                "missing, document and close that exact gap."
            )

    return finding


def validate_findings(findings, document_text, expected_evidence_map):
    """
    Bulk validates a list of findings using the validate_only logic.
    """
    validated = []
    for f in findings:
        validated.append(validate_only(f, document_text, expected_evidence_map))
    return validated


def validate_cross_control_duplicates(findings):
    """
    Checks all findings in a batch. If the exact same non-trivial evidence quote is cited
    across 2 or more different controls, flags those findings for human review.
    """
    # Group findings by normalized evidence quote
    quote_map = {}
    for f in findings:
        status = f.get("status", "NON_COMPLIANT")
        if status in ["Out of Scope", "NON_COMPLIANT", "Non-Compliant"]:
            continue
        ev = f.get("evidence_quote") or f.get("evidence_snippet") or "NOT_FOUND"
        ev_norm = ev.strip().strip('"').strip("'").strip('“').strip('”').strip().lower()
        if not ev_norm or ev_norm == "not_found" or len(ev_norm) < 15:
            # Skip short or generic quotes
            continue
            
        if ev_norm not in quote_map:
            quote_map[ev_norm] = []
        quote_map[ev_norm].append(f)
        
    for ev_norm, f_list in quote_map.items():
        if len(f_list) >= 2:
            # Flag duplicate citations across multiple controls
            for f in f_list:
                f["requires_human_review"] = True
                f["requires_review"] = True
                existing_note = f.get("review_note") or ""
                dup_note = "Duplicate evidence citation: This quote was also cited in other controls (potential citation reuse)."
                if existing_note:
                    if dup_note not in existing_note:
                        f["review_note"] = f"{existing_note} {dup_note}"
                else:
                    f["review_note"] = dup_note
                    
    return findings


# ── Excel Scoping Two-Phase Safety Gate ───────────────────────────────────────
def apply_excel_scoping_safety_gate(
    finding: dict,
    locked_filenames: list,
    retrieved_context: str,
    checklist_question: str = ""
) -> dict:
    """
    Final post-processing safety gate for Excel Scoping (Two-Phase) mode.

    Corrects two categories of LLM errors that can still occur even in judge mode:
    1. N/A or empty evidence_snippet → override with first sentence from retrieved_context
    2. Wrong source_file (not in locked_filenames) → override with correct locked filename

    This makes evidence discrepancies structurally impossible in Excel scoping mode.
    Called by audit.py after each finding is generated in Excel scoping mode.
    """
    import re

    if not locked_filenames:
        return finding  # Not in Excel scoping mode — do nothing

    primary_locked = locked_filenames[0]

    # ── Guard 1: Fix N/A or empty evidence_snippet ─────────────────────────────
    snippet = (
        finding.get("evidence_snippet") or
        finding.get("evidence_quote") or
        finding.get("excerpt") or ""
    ).strip().strip('"').strip("'")

    is_empty_snippet = (
        not snippet or
        snippet.lower() in ("n/a", "na", "none", "not found", "not_found", "") or
        len(snippet) < 10
    )

    if is_empty_snippet and retrieved_context and retrieved_context.strip():
        # Extract first meaningful sentence from retrieved_context
        sentences = re.split(r'(?<=[.!?])\s+', retrieved_context.strip())
        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) > 20:
                finding["evidence_snippet"] = s_clean[:500]
                finding["evidence_quote"] = s_clean[:500]
                print(
                    f"[SAFETY GATE] Overrode empty evidence_snippet with retrieved context "
                    f"for locked file '{primary_locked}'.",
                    flush=True
                )
                break

    # ── Guard 2: Fix wrong source_file (not among the locked filenames) ───────
    # Provenance Preservation: only correct when the cited file is genuinely OUTSIDE
    # the locked scope (hallucinated/wrong filename). If it's one of several
    # legitimately locked files, leave it untouched -- don't collapse real
    # per-file provenance (page/chunk_id) onto a single primary filename.
    source_file = (finding.get("source_file") or "").strip()
    if source_file and source_file not in locked_filenames:
        print(
            f"[SAFETY GATE] Overrode wrong source_file '{source_file}' "
            f"(not in locked scope {locked_filenames}) with '{primary_locked}'.",
            flush=True
        )
        finding["source_file"] = primary_locked

    return finding
