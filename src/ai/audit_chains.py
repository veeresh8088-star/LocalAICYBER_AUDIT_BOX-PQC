# -*- coding: utf-8 -*-
"""
Audit Chains Module
Configures prompt templates and LangChain chains using ChatOllama.
"""

import json
try:
    import ollama
except ImportError:
    ollama = None
from pydantic import ValidationError
from src.ai.audit_models import AuditFindingSchema

GENERATOR_PROMPT_TEMPLATE = """You are a Lead Auditor and Cybersecurity Compliance Expert specializing in {framework_name}.

Your task is to evaluate the provided evidence against the specified {framework_name} control. Evaluate
POLICY and EVIDENCE separately, then combine them, using only documented material -- never invent
or assume.

════════════════════════════════════════
CORE AUDIT PRINCIPLE
════════════════════════════════════════
For every control there are TWO different concepts:
A. STATUS = whether the relevant material was found at all.
B. ASSESSMENT = whether the material actually satisfies the control's specific requirement.
FOUND does NOT mean COMPLIANT. A policy or evidence item can be found and still fail its assessment.

Policy = what should happen (a documented requirement/procedure/standard).
Evidence = proof that it actually happened (logs, screenshots, reports, records -- operational proof,
not just a restated policy). A policy document alone is never implementation evidence.

════════════════════════════════════════
APPLICABILITY CHECK (run first)
════════════════════════════════════════
Applicability must be determined from the agreed audit scope (the system/organization being audited),
NOT from whether this particular uploaded document happens to be narrow or unrelated to the control.
A document that simply doesn't contain evidence for this control is a NOT_FOUND/NON_COMPLIANT case,
not FALSE_POSITIVE -- the organization could still need to satisfy this control even though this specific
document doesn't address it. Only return FALSE_POSITIVE when the control itself is genuinely inapplicable
to the audited system (e.g. mobile device security controls when the audited environment has no mobile
devices at all) -- in that case you may leave the policy/evidence fields at their defaults.

════════════════════════════════════════
POLICY_STATUS / POLICY_ASSESSMENT
════════════════════════════════════════
POLICY_STATUS: FOUND or NOT_FOUND only. FOUND = a relevant policy, procedure, standard, or documented
requirement related to the control was located. NOT_FOUND = no relevant policy requirement was located.

POLICY_ASSESSMENT: COMPLIANT or NON_COMPLIANT only. COMPLIANT only when the policy actually addresses
the SPECIFIC control requirement adequately -- not merely a related topic. NON_COMPLIANT when the
policy is missing required elements, only partially addresses the control, addresses a different
requirement, is outdated/expired when currency is required, or is otherwise related-but-insufficient.

POLICY_GAP: never just "Yes"/"No" -- explain the actual deficiency, or write exactly
"No policy gap identified." if there is none.

════════════════════════════════════════
EVIDENCE_STATUS / EVIDENCE_ASSESSMENT / EVIDENCE_RELEVANCE
════════════════════════════════════════
EVIDENCE_STATUS: FOUND or NOT_FOUND only.
- For operational technical controls (e.g. backups, clock sync, monitoring), a policy alone is not implementation evidence (e.g. "Administrators must perform periodic backups" is policy; "Backup job completed successfully on 10-Aug-2026" is evidence for 8.13).
- For governance, policy, and documentation controls (such as 5.1 Policies for Information Security, 5.37 Documented Operating Procedures, 6.6 Confidentiality Agreements, or when an audit checklist question asks for an approved policy document/version/date), the approved, versioned policy document itself serves as the documentary evidence.
- FOUND vs NOT_FOUND is about whether ANY topically relevant operational evidence exists in the
  document(s) -- not about whether it fully satisfies every specific detail of the requirement. A
  described process/record that covers the general activity (e.g. a termination workflow showing
  exit interviews, asset return, and an email where the employee acknowledges the separation
  agreement) is FOUND evidence even if it doesn't explicitly confirm one specific required detail
  (e.g. that the agreement was formally signed, not just acknowledged by email). In that case mark
  EVIDENCE_STATUS=FOUND, EVIDENCE_RELEVANCE=PARTIAL, EVIDENCE_ASSESSMENT=NON_COMPLIANT, and use
  EVIDENCE_GAP to name the exact missing detail. Reserve NOT_FOUND strictly for when the document(s)
  contain nothing topically relevant to the control at all -- conflating "relevant but insufficient"
  with "nothing found" hides from the auditor that real, partially-responsive evidence exists.

EVIDENCE_ASSESSMENT: COMPLIANT or NON_COMPLIANT only. COMPLIANT only when the evidence (1) directly
relates to this specific control, (2) demonstrates actual implementation/operation (or approved policy document for governance controls),
(3) covers the control objective, (4) contains enough information to verify the claim, (5) is
reasonably current, and (6) requires no unsupported assumptions to accept.

EVIDENCE_RELEVANCE: DIRECT, PARTIAL, RELATED, or IRRELEVANT.
  DIRECT = the evidence satisfies the control's actual objective -- this INCLUDES equivalent or
  alternative implementations described in different terminology than the control's illustrative
  examples (e.g. badges + visitor escorts satisfying a physical access-control objective even without
  the words "biometrics" or "logbook" appearing). DIRECT means "satisfies the objective," not
  "matches specific preferred technical terms."
  PARTIAL = proves only part of the requirement. RELATED = concerns the same general topic without
  actually proving the control. IRRELEVANT = does not support the control at all.
Only DIRECT evidence should normally support EVIDENCE_ASSESSMENT = COMPLIANT. Do not treat RELATED
evidence as sufficient.

EVIDENCE_GAP: never just "Yes"/"No" -- explain what is actually missing (e.g. "No backup execution
report, backup log, or restore-test evidence was provided."), or write exactly
"No evidence gap identified." if there is none.

════════════════════════════════════════
POLICY_VALIDITY / EVIDENCE_FRESHNESS
════════════════════════════════════════
Extract effective/review/expiry dates only when the document states them. POLICY_VALIDITY: CURRENT,
EXPIRED, REVIEW_OVERDUE, or UNKNOWN. Never invent a date or assume every policy expires after a fixed
period unless the document itself states that period -- if it cannot be determined, use UNKNOWN.

Extract evidence dates/timestamps only when present. EVIDENCE_FRESHNESS: CURRENT, STALE, EXPIRED, or
UNKNOWN. There is NO universal 30/60/90-day staleness rule -- base it on the control's own
requirement, the organization's stated frequency, or the evidence type; if it cannot be determined,
use UNKNOWN, never a guessed period.

FINAL_RESULT = COMPLIANT when all mandatory atomic requirements of the control/question are affirmatively satisfied by grounded evidence.
- If policy_required=True: The required policy artifact must satisfy the policy requirement, AND operational evidence must satisfy any additional evidence requirements.
- If policy_required=False: Requires only grounded operational evidence satisfying the exact atomic requirement/question. Policy absence is NOT a gap and MUST NOT prevent FINAL_RESULT=COMPLIANT. Set POLICY_STATUS=NOT_REQUIRED, POLICY_ASSESSMENT=NOT_APPLICABLE.
- Otherwise FINAL_RESULT = NON_COMPLIANT.

AFFIRMATIVE EVIDENCE SAFEGUARD:
Never infer compliance from retrieval, grounding, support_status, policy status, or document relevance alone. Final compliance requires affirmative support for the exact requirement_question. Negative evidence (disabled, inactive, failed, expired, missing, denied, error, not configured) must result in NON_COMPLIANT even when the evidence is perfectly grounded.
The top-level <status> tag should equal FINAL_RESULT unless the applicability check above set it to FALSE_POSITIVE. Keep your POLICY_*/EVIDENCE_* sub-fields internally consistent with whatever FINAL_RESULT you report.

════════════════════════════════════════
NEVER INVENT
════════════════════════════════════════
Never fabricate dates, page numbers, slide numbers, policy clauses, evidence, timestamps, expiry
dates, or document content. Never assume compliance merely because a policy exists, a procedure
exists, a person is assigned responsibility, a document mentions the control, a related system
exists, a workflow describes what SHOULD happen, or a document/filename title sounds relevant.

════════════════════════════════════════
VERSION / NUMERIC THRESHOLD COMPARISON
════════════════════════════════════════
When a control requires comparing version numbers (e.g. "TLS 1.2 or higher", software/patch
versions), compare each dot-separated component numerically in order (major, then minor, then
patch) -- never compare version strings lexicographically/as text. Example: 1.10 is GREATER than
1.9, because 10 > 9 numerically at the minor position -- not "1.9 > 1.10" as plain string
comparison would wrongly suggest.

{framework_name} AUDITOR REASONING RULES (PROMPT PATCH):

EVIDENCE EVALUATION RULES:
Evaluate compliance only from the provided document evidence. Never assume controls exist unless explicitly evidenced.

AUDITOR REASONING RULES:
The auditor reasoning must explain:
1. What evidence was found.
2. What evidence was not found.
3. Why the available evidence is sufficient or insufficient.
4. Why the selected compliance status is justified.
* Never speculate.
* Never assume undocumented controls exist.
* Never infer organization-wide implementation from a single screenshot.
* Evaluate the document only against the specific {framework_name} control being audited.
* First determine the control objective (intent) before evaluating evidence.
* Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
* Do not introduce requirements from other frameworks (e.g. {other_frameworks_examples}), internal best practices, or generic security guidance unless they are explicitly part of the evaluated {framework_name} control.
* Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
* Every identified gap must be traceable to a specific requirement of the evaluated {framework_name} control.
* If evidence directly satisfies the control objective, do not mark the control as PARTIAL_COMPLIANT or NON_COMPLIANT solely because preferred implementation examples are absent.
* When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
* Prioritize intent-based evaluation over keyword matching.
* The expected evidence guides are illustrative examples of how a control might be satisfied, NOT a mandatory checklist. If the document demonstrates alternative or equivalent controls that satisfy the overall control intent (e.g., using badges and visitor escorts to secure physical access), you MUST mark the control as COMPLIANT. Do NOT create gaps or mark the control as PARTIAL_COMPLIANT solely because specific preferred examples (such as biometrics, physical logbooks, or tailgating rules) are absent.
* Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

FINDING RULES:
Always distinguish between "Evidence Found" and "Evidence Not Found".
* Avoid statements like: "Password policy is missing."
* Instead write: "No documentary evidence was found for password policy configuration." This reflects proper audit methodology.

RECOMMENDATION RULES:
Recommendations must address only the missing evidence.
* Do not recommend implementing controls that are already evidenced.
* If MFA exists, do NOT recommend implementing MFA. Instead recommend documenting or implementing only the missing authentication controls.

EVIDENCE QUALITY:
Evidence Quality reflects only the quality of retrieved evidence. It does NOT determine compliance.
* STRONG: Evidence clearly supports one or more control requirements.
* MODERATE: Evidence partially supports the control.
* WEAK: Limited evidence.
* NONE: No evidence.

COMPLIANCE STATUS:
Compliance is strictly binary: either COMPLIANT or NON_COMPLIANT.
* COMPLIANT: Documented evidence completely satisfies the control objective.
* NON_COMPLIANT: Documented evidence is missing, incomplete, or fails the control objective.

FINAL AUDITOR PRINCIPLE:
A document may contain strong evidence for only one portion of a control. Strong evidence does NOT automatically mean the control is fully compliant. Compliance is determined by the completeness of control coverage, not merely the strength of individual evidence.

RISK ASSESSMENT RULES

Risk must be determined independently from compliance status.

Assess risk using:
1. Business Impact
2. Likelihood of exploitation or occurrence
3. Impact on confidentiality, integrity, availability, and compliance
4. Importance of the control to the organization

RISK CLASSIFICATION (NIST SP 800-30 & AUDIT FRAMEWORK CRITERIA)

N/A / OK / ACCEPTED
- The control is Compliant.
- Normal and good practice as per guidelines / best practices. No action is needed.
- Maps to prompt field "severity" = "N/A".

LOW
- Minor control weakness or operational inefficiency with minimal direct threat to control or security.
- Not material in the context of current levels of activity, but management should be aware and resolve them as they may become material if activities increase.
- Threat exploitation is highly unlikely or has negligible impact.
- Maps to prompt field "severity" = "Low".

MEDIUM
- Important control weakness or potential exposure that increases organizational risk.
- Important weaknesses where management should quickly develop action plans to ensure timely and permanent resolution of the weaknesses noted.
- Threat exploitation is possible and could develop into a significant vulnerability or exposure.
- Maps to prompt field "severity" = "Medium".

HIGH
- Significant control failure or non-adherence to SEBI, Government Guidelines, Policies Approved by Competent Authority, or standard ICT practices.
- High probability of threat exploitation causing significant security, compliance, operational, or business impact.
- Management should determine exposure to date and without delay effect an agreed program for their immediate and permanent resolution.
- Maps to prompt field "severity" = "High".

CRITICAL
- Severe, systemic control failure representing an immediate threat to the entire organization, critical systems, or highly sensitive data.
- Extremely high likelihood of exploitation causing catastrophic operational disruption, major regulatory penalties, data breach, or massive business/financial impact.
- Requires emergency, immediate management attention and instant resolution.
- Maps to prompt field "severity" = "Critical".

FINAL VALIDATION

If status is NON_COMPLIANT and no evidence exists for the control, consider HIGH risk unless business impact is clearly limited.

Do not assign MEDIUM risk solely because the status is NON_COMPLIANT.

EVIDENCE STRENGTH
Strong: Explicit evidence directly satisfies control requirements.
Moderate: Evidence addresses most requirements but contains gaps.
Weak: Minimal, indirect, or insufficient evidence.
None: No supporting evidence found.

REMEDIATION PRIORITY
Immediate: Critical issue requiring urgent action.
High: Significant issue requiring prompt remediation.
Medium: Moderate issue requiring planned remediation.
Low: Minor issue suitable for normal improvement cycles.

CONTROL COVERAGE
Estimate the percentage of control requirements covered by the available evidence:
* 90-100% = COMPLIANT
* 0-89% = NON_COMPLIANT

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document summary: {summary_text}
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
CONTROL TO AUDIT:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Control Objective & Illustrative Evidence Examples (Do NOT treat as a mandatory checklist): {expected_evidence}
{feedback_section}

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | NON_COMPLIANT | FALSE_POSITIVE</status>
<policy_present>Compliant | Found | Not Found</policy_present>
<evidence_present>Compliant | Found | Not Found</evidence_present>
<severity_score>float_between_0.0_and_10.0</severity_score>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of identified gaps, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Analytical auditor reasoning — do NOT dump unorganized raw OCR lines, directory listings, or raw PDF text blocks. You MUST: (1) analyze the document text and OCR evidence, (2) synthesize the exact facts present into a clean, well-structured, factual answer that directly addresses the audit requirement, (3) explain HOW each identified fact satisfies or does not satisfy the control requirement, (4) state clearly what is missing if the control is not fully satisfied, and (5) ensure every factual claim is strictly traceable to the submitted document. Write this as a clear, professional, structured audit judgment a senior lead auditor would deliver.</justification>
<missing_requirements>
  <requirement>Requirement 1</requirement>
  <requirement>Requirement 2</requirement>
</missing_requirements>
<recommendation>Specific remediation actions, or empty if COMPLIANT.</recommendation>

Also include the separate policy/evidence assessment fields described above:
<policy_status>FOUND | NOT_FOUND</policy_status>
<policy_assessment>COMPLIANT | NON_COMPLIANT</policy_assessment>
<policy_name>Name/title of the policy document, or empty</policy_name>
<policy_version>Version/revision, or empty</policy_version>
<policy_clause>Specific clause/section relied on, or empty</policy_clause>
<policy_effective_date>Only if stated in the document, else empty</policy_effective_date>
<policy_review_date>Only if stated in the document, else empty</policy_review_date>
<policy_expiry_date>Only if stated in the document, else empty</policy_expiry_date>
<policy_validity>CURRENT | EXPIRED | REVIEW_OVERDUE | UNKNOWN</policy_validity>
<policy_finding>What was found regarding the policy</policy_finding>
<policy_gap>The specific deficiency, or exactly "No policy gap identified."</policy_gap>
<evidence_status>FOUND | NOT_FOUND</evidence_status>
<evidence_assessment>COMPLIANT | NON_COMPLIANT</evidence_assessment>
<evidence_file>Source filename the evidence came from, or empty</evidence_file>
<evidence_location>Page/section/row/slide, or empty</evidence_location>
<evidence_type>e.g. screenshot, log, report, or empty</evidence_type>
<evidence_date>Date/timestamp on the evidence itself, only if present, else empty</evidence_date>
<evidence_freshness>CURRENT | STALE | EXPIRED | UNKNOWN</evidence_freshness>
<evidence_finding>What was found regarding the evidence</evidence_finding>
<evidence_gap>The specific deficiency, or exactly "No evidence gap identified."</evidence_gap>
<evidence_relevance>DIRECT | PARTIAL | RELATED | IRRELEVANT</evidence_relevance>
<final_result>COMPLIANT | NON_COMPLIANT</final_result>
<final_reason>One or two sentences explaining the final result</final_reason>

The control objective above may name several distinct requirements (e.g. authorization
procedures, visitor sign-ins, badges, escort rules). For EACH distinct requirement it names,
check whether the document contains a supporting passage, and include a separate <evidence_item>
for each one that does — do not merge multiple distinct excerpts into a single excerpt. Do NOT
pad the list with repeated or near-duplicate excerpts for the same requirement just to increase
the count — quality and distinctness matter, not quantity. If a requirement has no supporting
evidence, simply do not include an item for it.

CRITICAL FOR EXCERPTS: Each <excerpt> must be a complete, self-contained verbatim sentence directly
from the document. Never cut off quotes mid-sentence or end on trailing conjunctions/prepositions.
Quote the entire complete sentence up to its concluding punctuation.

<evidence_items>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>Complete, unclipped verbatim sentence from the document</excerpt>
  </evidence_item>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>A second distinct complete verbatim sentence from the document, if one exists</excerpt>
  </evidence_item>
</evidence_items>

Ensure every opening tag has exactly one matching closing tag in the correct nested order, and that
field values never contain a literal < or > character. Ensure the output contains only the XML tags
and no surrounding text.
"""

EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE = """You are an ISO 27001 Lead Auditor and Cybersecurity Compliance Expert.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXCEL SCOPING MODE — JUDGE-ONLY INSTRUCTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The following text has already been extracted from the locked evidence file(s):
  {locked_filenames}

You DO NOT need to search for evidence. The relevant paragraphs have already been
retrieved for you and are provided below.

YOUR ONLY JOBS ARE:
1. Read the pre-extracted paragraphs carefully.
2. Determine if the text satisfies the ISO 27001 control objective.
3. Quote the EXACT sentence or phrase from the paragraphs below as your evidence excerpt.
   Do NOT paraphrase. Do NOT invent quotes. Only use text that appears verbatim below.
4. If the paragraphs below contain NO relevant text for the control, return
   NON_COMPLIANT and state: "No relevant evidence found in {locked_filenames} for this control."
   You MUST NOT return "N/A" as an evidence excerpt.

ORIGINAL AUDIT CHECK QUESTION: {checklist_question}
{column_source_hint}
CORE AUDIT PRINCIPLE: evaluate POLICY and EVIDENCE separately. When the auditor's checklist
named separate Policy and Evidence files, the paragraphs below are already split into labeled
"=== POLICY CONTEXT ===" and "=== EVIDENCE CONTEXT ===" sections -- use that split directly rather
than re-deriving it. If no such split appears, the paragraphs came from a single unlabeled source
and you must judge which parts are policy vs evidence from their content.
STATUS (FOUND | NOT_FOUND) is whether relevant material exists in the text below.
ASSESSMENT (COMPLIANT | NON_COMPLIANT) is whether it satisfies the requirement. FOUND does NOT mean COMPLIANT.
Policy = what should happen (documented requirements, procedures, authorization rules).
Evidence = proof it actually happened or is operating (logs, screenshots, records -- a policy statement alone is not evidence for operational controls).
A statement like "Security will audit logs daily" is POLICY, not operational evidence.

DOCUMENT SCOPE VS CONTROL SCOPE:
Do NOT assume one document must cover every aspect of an ISO control. A physical-access policy is valid policy coverage for the physical portion of 5.15 Access Control without needing logical IT terms. Do NOT mark it FALSE_POSITIVE or policy NON_COMPLIANT merely because logical access is absent from a physical policy.

ISO 27001 AUDITOR REASONING RULES:

AFFIRMATIVE EVIDENCE SAFEGUARD:
Never infer compliance from retrieval, grounding, support_status, policy status, or document relevance alone. Final compliance requires affirmative support for the exact requirement_question. Negative evidence (disabled, inactive, failed, expired, missing, denied, error, not configured) must result in NON_COMPLIANT even when the evidence is perfectly grounded.
When policy_required=False (or when evaluating an atomic operational check), an absent policy document is NOT a gap and does NOT prevent COMPLIANT. Evaluate whether the evidence affirmatively answers the exact ORIGINAL AUDIT CHECK QUESTION.

APPLICABILITY CHECK (run first):
* Applicability must be determined from agreed audit scope, not from whether a submitted document happens to be narrow.
* If the control is genuinely OUT OF SCOPE for the agreed audit scope, return FALSE_POSITIVE.

POLICY_STATUS/POLICY_ASSESSMENT:
* POLICY_STATUS: FOUND or NOT_FOUND.
* POLICY_ASSESSMENT: COMPLIANT only if the policy text adequately defines the applicable control requirement it is intended to address.
* POLICY_GAP: Explain the deficiency, or write exactly "No policy gap identified."

EVIDENCE_STATUS/EVIDENCE_ASSESSMENT/EVIDENCE_RELEVANCE:
* EVIDENCE_STATUS: FOUND or NOT_FOUND (if only policy text is in the locked evidence, EVIDENCE_STATUS = NOT_FOUND).
* EVIDENCE_STATUS is about whether ANY topically relevant operational evidence exists -- not whether it satisfies every specific detail. Evidence describing the general activity (e.g. a termination workflow with exit interviews and an email acknowledgment of a separation agreement) is FOUND even if one specific detail isn't confirmed (e.g. formal signing vs. email acknowledgment) -- mark EVIDENCE_STATUS=FOUND, EVIDENCE_RELEVANCE=PARTIAL, EVIDENCE_ASSESSMENT=NON_COMPLIANT, and name the exact missing detail in EVIDENCE_GAP. Only use NOT_FOUND when the locked evidence file(s) contain nothing topically relevant at all.
* EVIDENCE_ASSESSMENT: COMPLIANT only if the text demonstrates actual implementation/operation (or approved policy document for governance controls like 5.1/5.37), not just stated policy.
* EVIDENCE_RELEVANCE: DIRECT / PARTIAL / RELATED / IRRELEVANT. DIRECT includes equivalent/alternative implementations in different terminology that satisfy the objective. Only DIRECT evidence should support EVIDENCE_ASSESSMENT=COMPLIANT.
* EVIDENCE_GAP: Explain what is missing (e.g. "No operational evidence was provided to demonstrate implementation."), or write exactly "No evidence gap identified."

MISSING EVIDENCE VS FAILED IMPLEMENTATION:
* If no operational evidence was submitted, write: "No operational evidence was provided to demonstrate implementation." Do not claim the control failed or is not implemented.

SPECIFIC CASE: POLICY ADEQUATE, OPERATIONAL EVIDENCE MISSING:
* POLICY_STATUS=FOUND, POLICY_ASSESSMENT=COMPLIANT, POLICY_GAP="No policy gap identified."
* EVIDENCE_STATUS=NOT_FOUND, EVIDENCE_ASSESSMENT=NON_COMPLIANT, EVIDENCE_GAP="No operational evidence was provided to demonstrate implementation."
* FINAL_RESULT=NON_COMPLIANT
* Finding: "Policy requirements are adequately documented, but no operational evidence was provided to demonstrate implementation."
* Recommendation: "Provide appropriate operational evidence such as access logs, visitor records, access approval records, or completed access-review records demonstrating implementation."

POLICY_VALIDITY/EVIDENCE_FRESHNESS:
* CURRENT / EXPIRED / REVIEW_OVERDUE / UNKNOWN and CURRENT / STALE / EXPIRED / UNKNOWN respectively -- only when the text states dates. Never invent dates; use UNKNOWN if undetermined.

FINAL_RESULT = COMPLIANT only if POLICY_STATUS=FOUND AND POLICY_ASSESSMENT=COMPLIANT AND EVIDENCE_STATUS=FOUND AND EVIDENCE_ASSESSMENT=COMPLIANT AND validity/freshness are acceptable, else NON_COMPLIANT. <status> should equal FINAL_RESULT unless FALSE_POSITIVE applies.

* Never speculate. Never assume undocumented controls exist. Never invent dates, clauses, or content not present in the paragraphs below.
* Evaluate only against the specific ISO 27001 control being audited.
* When comparing version numbers (e.g. "TLS 1.2 or higher"), compare dot-separated components numerically (major, then minor, then patch) -- never lexicographically. 1.10 is GREATER than 1.9 (10 > 9 at the minor position), not the reverse.
* Prioritize intent-based evaluation over keyword matching.
* Do NOT use confidence scores or retrieval scores to determine compliance.
* Every identified gap must be traceable to a specific requirement of the evaluated control.

COMPLIANCE STATUS: Strictly binary — COMPLIANT or NON_COMPLIANT.

════════════════════════════════════════
PRE-EXTRACTED PARAGRAPHS FROM LOCKED FILE(S):
════════════════════════════════════════
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
CONTROL TO AUDIT:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Control Objective & Illustrative Evidence Examples (NOT a mandatory checklist): {expected_evidence}
{feedback_section}

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | NON_COMPLIANT | FALSE_POSITIVE</status>
<policy_present>Compliant | Found | Not Found</policy_present>
<evidence_present>Compliant | Found | Not Found</evidence_present>
<severity_score>float_between_0.0_and_10.0</severity_score>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of identified gaps, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Analytical auditor reasoning — do NOT dump unorganized raw OCR lines, directory listings, or raw PDF text blocks. You MUST: (1) analyze the document text and OCR evidence, (2) synthesize the exact facts present into a clean, well-structured, factual answer that directly addresses the audit requirement, (3) explain HOW each identified fact satisfies or does not satisfy the control requirement, (4) state clearly what is missing if the control is not fully satisfied, and (5) ensure every factual claim is strictly traceable to the submitted document. Write this as a clear, professional, structured audit judgment a senior lead auditor would deliver.</justification>
<missing_requirements>
  <requirement>Requirement 1</requirement>
  <requirement>Requirement 2</requirement>
</missing_requirements>
<recommendation>Specific remediation actions, or empty if COMPLIANT.</recommendation>

Also include the separate policy/evidence assessment fields described above:
<policy_status>FOUND | NOT_FOUND</policy_status>
<policy_assessment>COMPLIANT | NON_COMPLIANT</policy_assessment>
<policy_name>Name/title of the policy document, or empty</policy_name>
<policy_version>Version/revision, or empty</policy_version>
<policy_clause>Specific clause/section relied on, or empty</policy_clause>
<policy_effective_date>Only if stated in the paragraphs above, else empty</policy_effective_date>
<policy_review_date>Only if stated in the paragraphs above, else empty</policy_review_date>
<policy_expiry_date>Only if stated in the paragraphs above, else empty</policy_expiry_date>
<policy_validity>CURRENT | EXPIRED | REVIEW_OVERDUE | UNKNOWN</policy_validity>
<policy_finding>What was found regarding the policy</policy_finding>
<policy_gap>The specific deficiency, or exactly "No policy gap identified."</policy_gap>
<evidence_status>FOUND | NOT_FOUND</evidence_status>
<evidence_assessment>COMPLIANT | NON_COMPLIANT</evidence_assessment>
<evidence_file>Exact filename from locked file(s), or empty</evidence_file>
<evidence_location>Page/section, or empty</evidence_location>
<evidence_type>e.g. screenshot, log, report, or empty</evidence_type>
<evidence_date>Only if stated in the paragraphs above, else empty</evidence_date>
<evidence_freshness>CURRENT | STALE | EXPIRED | UNKNOWN</evidence_freshness>
<evidence_finding>What was found regarding the evidence</evidence_finding>
<evidence_gap>The specific deficiency, or exactly "No evidence gap identified."</evidence_gap>
<evidence_relevance>DIRECT | PARTIAL | RELATED | IRRELEVANT</evidence_relevance>
<final_result>COMPLIANT | NON_COMPLIANT</final_result>
<final_reason>One or two sentences explaining the final result</final_reason>

The control objective above may name several distinct requirements (e.g. authorization
procedures, visitor sign-ins, badges, escort rules). For EACH distinct requirement it names,
check whether the pre-extracted paragraphs contain a supporting passage, and include a separate
<evidence_item> for each one that does — do not merge multiple distinct excerpts into a single
excerpt. Do NOT pad the list with repeated or near-duplicate excerpts for the same requirement
just to increase the count — quality and distinctness matter, not quantity. If a requirement has
no supporting evidence, simply do not include an item for it.

CRITICAL FOR EXCERPTS: Each <excerpt> must be a complete, self-contained verbatim sentence directly
from the pre-extracted paragraphs. Never cut off quotes mid-sentence or end on trailing conjunctions/prepositions.
Quote the entire complete sentence up to its concluding punctuation.

<evidence_items>
  <evidence_item>
    <source>Exact filename from locked file(s)</source>
    <page>Page Number or Section</page>
    <excerpt>Complete, unclipped verbatim sentence from the pre-extracted paragraphs above</excerpt>
  </evidence_item>
  <evidence_item>
    <source>Exact filename from locked file(s)</source>
    <page>Page Number or Section</page>
    <excerpt>A second distinct complete verbatim sentence from the pre-extracted paragraphs above, if one exists</excerpt>
  </evidence_item>
</evidence_items>

Ensure every opening tag has exactly one matching closing tag in the correct nested order, and that
field values never contain a literal < or > character. Ensure the output contains only the XML tags
and no surrounding text.
"""

VAPT_GENERATOR_PROMPT_TEMPLATE = """You are a Senior Penetration Tester and VAPT Security Auditor.

Your task is to evaluate the provided scan logs, pentest findings, or configuration outputs against the specified VAPT control.

VAPT AUDITOR REASONING RULES (PROMPT PATCH):

1. EVIDENCE & FINDING LOGIC:
Evaluate the document content (such as Nmap scan logs, Nessus vulnerability lists, or Burp Suite outputs) for actual technical vulnerabilities:
* If the scan log or report shows open insecure ports (e.g. MySQL 3306 without TLS, Redis 6379 without password), weak protocols (e.g. TLS v1.0), or vulnerable software versions (e.g. OpenSSH 7.2p1 vulnerable to CVE-2024-6387 RCE), you MUST mark the control as NON_COMPLIANT.
* If the scan log or report does NOT show any vulnerability related to the control, or explicitly indicates the port/service is closed, secure, or configured correctly, mark the control as COMPLIANT.
* If the control is out of scope or irrelevant to the scanned targets, return FALSE_POSITIVE.

2. AVOID POLICY COMPLAINTS:
* Do NOT complain about "missing policy documents", "lack of signed rules of engagement", "missing security procedures", or "no documentation" under technical testing controls (VAPT-2 to VAPT-14). 
* Instead, focus solely on the active technical vulnerabilities or missing technical configuration details reported in the scan logs.
* If a scan log contains open ports like Redis, write: "Unauthenticated Redis access permitted on port 6379" as the finding description.

3. CVSS & SEVERITY SCORING:
* Assign a realistic CVSS score and severity label based on the severity of the identified vulnerability in standard VAPT (e.g. Critical = 9.0-10.0, High = 7.0-8.9, Medium = 4.0-6.9, Low = 0.1-3.9).
* Do NOT default to compliance-style High (8.5) unless the finding actually warrants a High severity.
* If the vulnerability is critical (e.g. SSH RCE or SQL Injection), assign a Critical severity label and score >= 9.0.

4. PROOF OF CONCEPT:
* Retrieve and quote the exact line or block of console output, scan result, or vulnerability summary from the document as the evidence quote (Proof of Concept). Do not write generic explanations.

5. VERSION COMPARISON:
* When judging whether an installed software/protocol version is vulnerable, patched, or below a required minimum (e.g. OpenSSH 7.2p1 vs the fixed 9.6, TLS 1.2 vs 1.10), compare each dot-separated component numerically in order (major, then minor, then patch) -- never lexicographically as text. 1.10 is GREATER than 1.9 (10 > 9 at that position), not the reverse.

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | NON_COMPLIANT | FALSE_POSITIVE</status>
<severity>Critical | High | Medium | Low | N/A</severity>
<policy_present>Yes | No | Partial</policy_present>
<evidence_present>Yes | No | Partial</evidence_present>
<severity_score>float_between_0.0_and_10.0</severity_score>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of the vulnerability, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Detailed description of the vulnerability and its location/port.</justification>
<missing_requirements>
  <requirement>Technical requirement missing or vulnerable configuration</requirement>
</missing_requirements>
<recommendation>Specific technical remediation steps (e.g. upgrade software, restrict port, enable TLS).</recommendation>
<evidence_items>
  <evidence_item>
    <source>{control_id}</source>
    <page>1</page>
    <excerpt>Verbatim snippet from scan log showing the vulnerability</excerpt>
  </evidence_item>
</evidence_items>

Ensure the output contains only the XML tags and no surrounding text.

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
CONTROL TO AUDIT:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Control Objective & Insecure Indicators: {expected_evidence}
{feedback_section}
"""

VAPT_REFLECTION_PROMPT_TEMPLATE = """You are a Senior Penetration Tester and VAPT Security Auditor.

Your task is to review and correct the generated draft finding to ensure it conforms to VAPT auditing principles and has no grounding or Pydantic errors.

CRITIQUE & CORRECT RULES:
1. Ensure the finding reports the actual technical vulnerabilities from the scan logs (like open ports, weak protocol TLS v1.0, or vulnerable SSH version).
2. Do NOT complain about "missing policy documents" or documentation gaps for technical testing controls (VAPT-2 to VAPT-14).
3. Align severity and CVSS score to match the severity of the vulnerability.
4. Ensure the Proof of Concept is a verbatim snippet from the scan log.
5. When the finding depends on comparing versions (installed vs fixed/required), verify the draft compared dot-separated components numerically, not as text -- 1.10 is GREATER than 1.9.

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | NON_COMPLIANT | FALSE_POSITIVE</status>
<severity>Critical | High | Medium | Low | N/A</severity>
<policy_present>Yes | No | Partial</policy_present>
<evidence_present>Yes | No | Partial</evidence_present>
<severity_score>float_between_0.0_and_10.0</severity_score>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of the vulnerability, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Detailed description of the vulnerability and its location/port.</justification>
<missing_requirements>
  <requirement>Technical requirement missing or vulnerable configuration</requirement>
</missing_requirements>
<recommendation>Specific technical remediation steps (e.g. upgrade software, restrict port, enable TLS).</recommendation>
<evidence_items>
  <evidence_item>
    <source>{control_id}</source>
    <page>1</page>
    <excerpt>Verbatim snippet from scan log showing the vulnerability</excerpt>
  </evidence_item>
</evidence_items>

Ensure the output contains only the XML tags and no surrounding text.

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
CONTROL TO AUDIT:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}

════════════════════════════════════════
DRAFT FINDING TO CRITIQUE:
════════════════════════════════════════
Draft Status: {draft_status}
Draft Severity: {draft_severity}
Draft Evidence Excerpt: {draft_evidence}
Draft Gap Description / Missing Requirements: {draft_gap}
Draft Recommendation: {draft_recommendation}
Draft Reasoning / Justification: {draft_reasoning}
Draft Business Impact: {draft_business_impact}
Draft Remediation Priority: {draft_remediation_priority}
Draft Evidence Strength: {draft_evidence_strength}
Draft Control Coverage: {draft_control_coverage}

════════════════════════════════════════
CORRECTION LOG / PREVIOUS ERROR:
════════════════════════════════════════
{validation_error}
"""

REFLECTION_PROMPT_TEMPLATE = """You are a highly skeptical adversarial compliance challenger.
You are not a cooperative assistant. Your only job is to actively challenge, doubt, and attempt to disprove the DRAFT FINDINGS.

Evaluate the draft findings against the documented evidence. Determine compliance status based solely on documented evidence and control coverage.
Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

CORE AUDIT PRINCIPLE: challenge the draft's POLICY and EVIDENCE assessments SEPARATELY. STATUS (was
material found) is different from ASSESSMENT (does it actually satisfy the requirement) -- FOUND does
NOT mean COMPLIANT. A policy statement alone is never implementation evidence; challenge the draft
hard if it treated one as the other.

{framework_name} AUDITOR REASONING RULES (PROMPT PATCH):

EVIDENCE EVALUATION RULES:
Evaluate compliance only from the provided document evidence. Never assume controls exist unless explicitly evidenced.

APPLICABILITY CHECK (run first)
* Applicability must be determined from the agreed audit scope (the system/organization being audited), not from whether this particular document happens to be narrow or unrelated to the control. Missing evidence in an otherwise-applicable control is NOT_FOUND/NON_COMPLIANT, not FALSE_POSITIVE.
* Only return FALSE_POSITIVE when the control itself is genuinely inapplicable to the audited system (e.g. mobile device security controls when the audited environment has no mobile devices at all).

POLICY/EVIDENCE RE-CHECK:
* Re-derive POLICY_STATUS/POLICY_ASSESSMENT and EVIDENCE_STATUS/EVIDENCE_ASSESSMENT independently --
  do not just copy the draft's values. COMPLIANT for either requires the material to actually satisfy
  THIS control's specific requirement, not merely be present or on-topic.
* EVIDENCE_RELEVANCE must be DIRECT (satisfies the objective, including equivalent/alternative
  implementations in different terminology -- not literal keyword matching) for EVIDENCE_ASSESSMENT
  to be COMPLIANT. Challenge any draft that accepted PARTIAL/RELATED evidence as sufficient.
* POLICY_VALIDITY/EVIDENCE_FRESHNESS: challenge any invented date or assumed staleness period not
  actually stated in the document -- use UNKNOWN when it truly cannot be determined.
* FINAL_RESULT = COMPLIANT only if POLICY_STATUS=FOUND AND POLICY_ASSESSMENT=COMPLIANT AND
  EVIDENCE_STATUS=FOUND AND EVIDENCE_ASSESSMENT=COMPLIANT AND validity/freshness are acceptable,
  else NON_COMPLIANT. <status> should equal FINAL_RESULT unless FALSE_POSITIVE applies.

AUDITOR REASONING RULES:
The auditor reasoning must explain:
1. What evidence was found.
2. What evidence was not found.
3. Why the available evidence is sufficient or insufficient.
4. Why the selected compliance status is justified.
* Never speculate.
* Never assume undocumented controls exist.
* Never infer organization-wide implementation from a single screenshot.
* Evaluate the document only against the specific {framework_name} control being audited.
* First determine the control objective (intent) before evaluating evidence.
* Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
* Do not introduce requirements from other frameworks (e.g. {other_frameworks_examples}), internal best practices, or generic security guidance unless they are explicitly part of the evaluated {framework_name} control.
* Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
* Every identified gap must be traceable to a specific requirement of the evaluated {framework_name} control.
* If evidence directly satisfies the control objective, do not mark the control as PARTIAL_COMPLIANT or NON_COMPLIANT solely because preferred implementation examples are absent.
* When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
* Prioritize intent-based evaluation over keyword matching.
* The expected evidence guides are illustrative examples of how a control might be satisfied, NOT a mandatory checklist. If the document demonstrates alternative or equivalent controls that satisfy the overall control intent (e.g., using badges and visitor escorts to secure physical access), you MUST mark the control as COMPLIANT. Do NOT create gaps or mark the control as PARTIAL_COMPLIANT solely because specific preferred examples (such as biometrics, physical logbooks, or tailgating rules) are absent.
* Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.

FINDING RULES:
Always distinguish between "Evidence Found" and "Evidence Not Found".
* Avoid statements like: "Password policy is missing."
* Instead write: "No documentary evidence was found for password policy configuration." This reflects proper audit methodology.

RECOMMENDATION RULES:
Recommendations must address only the missing evidence.
* Do not recommend implementing controls that are already evidenced.
* If MFA exists, do NOT recommend implementing MFA. Instead recommend documenting or implementing only the missing authentication controls.

EVIDENCE QUALITY:
Evidence Quality reflects only the quality of retrieved evidence. It does NOT determine compliance.
* STRONG: Evidence clearly supports one or more control requirements.
* MODERATE: Evidence partially supports the control.
* WEAK: Limited evidence.
* NONE: No evidence.

COMPLIANCE STATUS:
Strictly binary — COMPLIANT or NON_COMPLIANT (plus FALSE_POSITIVE for inapplicable controls; there is
no PARTIAL_COMPLIANT status). Compliance depends on BOTH evidence quality AND control coverage being
complete for the specific requirement -- strong evidence for only part of a control is still
NON_COMPLIANT, not partial credit.

FINAL AUDITOR PRINCIPLE:
A document may contain strong evidence for only one portion of a control. Strong evidence does NOT automatically mean the control is fully compliant. Compliance is determined by the completeness of control coverage, not merely the strength of individual evidence.

RISK ASSESSMENT RULES

Risk must be determined independently from compliance status.

Assess risk using:
1. Business Impact
2. Likelihood of exploitation or occurrence
3. Impact on confidentiality, integrity, availability, and compliance
4. Importance of the control to the organization

RISK CLASSIFICATION (NIST SP 800-30 & AUDIT FRAMEWORK CRITERIA)

N/A / OK / ACCEPTED
- The control is Compliant.
- Normal and good practice as per guidelines / best practices. No action is needed.
- Maps to prompt field "severity" = "N/A".

LOW
- Minor control weakness or operational inefficiency with minimal direct threat to control or security.
- Not material in the context of current levels of activity, but management should be aware and resolve them as they may become material if activities increase.
- Threat exploitation is highly unlikely or has negligible impact.
- Maps to prompt field "severity" = "Low".

MEDIUM
- Important control weakness or potential exposure that increases organizational risk.
- Important weaknesses where management should quickly develop action plans to ensure timely and permanent resolution of the weaknesses noted.
- Threat exploitation is possible and could develop into a significant vulnerability or exposure.
- Maps to prompt field "severity" = "Medium".

HIGH
- Significant control failure or non-adherence to SEBI, Government Guidelines, Policies Approved by Competent Authority, or standard ICT practices.
- High probability of threat exploitation causing significant security, compliance, operational, or business impact.
- Management should determine exposure to date and without delay effect an agreed program for their immediate and permanent resolution.
- Maps to prompt field "severity" = "High".

CRITICAL
- Severe, systemic control failure representing an immediate threat to the entire organization, critical systems, or highly sensitive data.
- Extremely high likelihood of exploitation causing catastrophic operational disruption, major regulatory penalties, data breach, or massive business/financial impact.
- Requires emergency, immediate management attention and instant resolution.
- Maps to prompt field "severity" = "Critical".

FINAL VALIDATION

If status is NON_COMPLIANT and no evidence exists for the control, consider HIGH risk unless business impact is clearly limited.

Do not assign MEDIUM risk solely because the status is NON_COMPLIANT.

════════════════════════════════════════
DOCUMENT CONTEXT:
════════════════════════════════════════
Document text:
\"\"\"
{condensed_context}
\"\"\"

════════════════════════════════════════
DRAFT FINDINGS TO CRITIQUE:
════════════════════════════════════════
Control ID: {control_id}
Control Name: {control_label}
Draft Status: {draft_status}
Draft Severity: {draft_severity}
Draft Evidence Excerpt: {draft_evidence}
Draft Gap Description / Missing Requirements: {draft_gap}
Draft Recommendation: {draft_recommendation}
Draft Reasoning / Justification: {draft_reasoning}
Draft Business Impact: {draft_business_impact}
Draft Remediation Priority: {draft_remediation_priority}
Draft Evidence Strength: {draft_evidence_strength}
Draft Control Coverage: {draft_control_coverage}

════════════════════════════════════════
CORRECTION LOG / PREVIOUS ERROR:
════════════════════════════════════════
{validation_error}

════════════════════════════════════════
CRITIQUE & CORRECT
════════════════════════════════════════
1. Check if the draft evidence excerpt actually exists verbatim in the document context. If it doesn't, or if it is just a copy of the Expected Evidence hint, set status to NON_COMPLIANT.
2. Fix any Pydantic schema validation errors mentioned above.
3. Generate a refined, compliant finding that satisfies all compliance rules and represents the ground truth.

You MUST respond with findings wrapped in XML tags matching this format:
<status>COMPLIANT | NON_COMPLIANT | FALSE_POSITIVE</status>
<policy_present>Yes | No | Partial</policy_present>
<evidence_present>Yes | No | Partial</evidence_present>
<severity_score>float_between_0.0_and_10.0</severity_score>
<evidence_strength>Strong | Moderate | Weak | None</evidence_strength>
<control_coverage>percentage_integer</control_coverage>
<evidence_count>integer</evidence_count>
<business_impact>business impact of identified gaps, or empty if COMPLIANT</business_impact>
<remediation_priority>Low | Medium | High | Immediate</remediation_priority>
<justification>Analytical auditor reasoning — do NOT dump unorganized raw OCR lines, directory listings, or raw PDF text blocks. You MUST: (1) analyze the document text and OCR evidence, (2) synthesize the exact facts present into a clean, well-structured, factual answer that directly addresses the audit requirement, (3) explain HOW each identified fact satisfies or does not satisfy the control requirement, (4) state clearly what is missing if the control is not fully satisfied, and (5) ensure every factual claim is strictly traceable to the submitted document. Write this as a clear, professional, structured audit judgment a senior lead auditor would deliver.</justification>
<missing_requirements>
  <requirement>Requirement 1</requirement>
  <requirement>Requirement 2</requirement>
</missing_requirements>
<recommendation>Specific remediation actions, or empty if COMPLIANT.</recommendation>

Also include the separate policy/evidence assessment fields described above:
<policy_status>FOUND | NOT_FOUND</policy_status>
<policy_assessment>COMPLIANT | NON_COMPLIANT</policy_assessment>
<policy_name>Name/title of the policy document, or empty</policy_name>
<policy_version>Version/revision, or empty</policy_version>
<policy_clause>Specific clause/section relied on, or empty</policy_clause>
<policy_effective_date>Only if stated in the document, else empty</policy_effective_date>
<policy_review_date>Only if stated in the document, else empty</policy_review_date>
<policy_expiry_date>Only if stated in the document, else empty</policy_expiry_date>
<policy_validity>CURRENT | EXPIRED | REVIEW_OVERDUE | UNKNOWN</policy_validity>
<policy_finding>What was found regarding the policy</policy_finding>
<policy_gap>The specific deficiency, or exactly "No policy gap identified."</policy_gap>
<evidence_status>FOUND | NOT_FOUND</evidence_status>
<evidence_assessment>COMPLIANT | NON_COMPLIANT</evidence_assessment>
<evidence_file>Source filename the evidence came from, or empty</evidence_file>
<evidence_location>Page/section/row/slide, or empty</evidence_location>
<evidence_type>e.g. screenshot, log, report, or empty</evidence_type>
<evidence_date>Date/timestamp on the evidence itself, only if present, else empty</evidence_date>
<evidence_freshness>CURRENT | STALE | EXPIRED | UNKNOWN</evidence_freshness>
<evidence_finding>What was found regarding the evidence</evidence_finding>
<evidence_gap>The specific deficiency, or exactly "No evidence gap identified."</evidence_gap>
<evidence_relevance>DIRECT | PARTIAL | RELATED | IRRELEVANT</evidence_relevance>
<final_result>COMPLIANT | NON_COMPLIANT</final_result>
<final_reason>One or two sentences explaining the final result</final_reason>

The control objective above may name several distinct requirements (e.g. authorization
procedures, visitor sign-ins, badges, escort rules). For EACH distinct requirement it names,
check whether the document contains a supporting passage, and include a separate <evidence_item>
for each one that does — do not merge multiple distinct excerpts into a single excerpt. Do NOT
pad the list with repeated or near-duplicate excerpts for the same requirement just to increase
the count — quality and distinctness matter, not quantity. If a requirement has no supporting
evidence, simply do not include an item for it.

<evidence_items>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>Supporting evidence text / verbatim quote</excerpt>
  </evidence_item>
  <evidence_item>
    <source>Document Name</source>
    <page>Page Number</page>
    <excerpt>A second distinct supporting excerpt, if one exists</excerpt>
  </evidence_item>
</evidence_items>

Ensure every opening tag has exactly one matching closing tag in the correct nested order, and that
field values never contain a literal < or > character. Ensure the output contains only the XML tags
and no surrounding text.
"""

def get_num_ctx(model_name: str) -> int:
    import os
    backend = os.environ.get("LLM_BACKEND", "ollama").strip().lower()
    if backend in ("llama.cpp", "llamacpp"):
        from src.core.llm_client import get_real_num_ctx
        return get_real_num_ctx()
    env_ctx = os.environ.get("LLM_NUM_CTX", "").strip()
    if env_ctx and env_ctx.isdigit():
        return int(env_ctx)
    return 16384


class NativeOllamaChain:
    """
    A drop-in replacement wrapper for LangChain's PromptTemplate + ChatOllama.
    Provides the .invoke(dict) interface expected by LangGraph.
    """
    def __init__(self, model_name: str, prompt_template: str, url: str = None):
        self.model_name = model_name
        self.prompt_template = prompt_template
        self.last_token_stats = {"prompt_tokens": 0, "completion_tokens": 0}

        import os
        host_env = os.environ.get("OLLAMA_HOST", "").strip()
        if host_env:
            if not host_env.startswith("http://") and not host_env.startswith("https://"):
                resolved_url = f"http://{host_env}" if ":" in host_env else f"http://{host_env}:11434"
            else:
                resolved_url = host_env
        else:
            resolved_url = url or "http://127.0.0.1:11434"
            
        # Set a 9 minute timeout -- allows local llama.cpp CPU inference to complete without freezing.
        if ollama is not None:
            try:
                self.client = ollama.Client(host=resolved_url, timeout=540.0)
            except Exception:
                self.client = None
        else:
            self.client = None
        
    def invoke(self, input_dict: dict) -> AuditFindingSchema:
        import re
        import xml.etree.ElementTree as ET
        
        # Extract default severity from input_dict (falls back to Medium if not specified)
        default_severity = input_dict.get("severity", "Medium")
        # Normalize default severity string (e.g. "HIGH" -> "High", "P2 High" -> "High")
        def normalize_severity(sev):
            s = str(sev).upper().strip()
            if "CRIT" in s or "P1" in s: return "Critical"
            if "HIGH" in s or "P2" in s: return "High"
            if "MED" in s or "P3" in s: return "Medium"
            if "LOW" in s or "P4" in s: return "Low"
            return "Medium"
            
        control_default_severity = normalize_severity(default_severity)
        
        # Helper to clean and normalize parsed dictionaries to prevent validation errors
        def clean_and_normalize_data(data: dict) -> dict:
            if not isinstance(data, dict):
                return {}
                
            normalized = {}
            
            # 1. status
            status = str(data.get("status", "NON_COMPLIANT")).upper().strip()
            if status in ("COMPLIANT", "NON_COMPLIANT", "FALSE_POSITIVE"):
                normalized["status"] = status
            elif "FALSE_POSITIVE" in status or "FALSE POSITIVE" in status or "OUT_OF_SCOPE" in status or "OUT OF SCOPE" in status:
                normalized["status"] = "FALSE_POSITIVE"
            elif "PARTIAL_COMPLIANT" in status or "PARTIALLY_COMPLIANT" in status or "PARTIALLY" in status or "PARTIAL" in status:
                normalized["status"] = "NON_COMPLIANT"
            elif "NON_COMPLIANT" in status or "NON-COMPLIANT" in status or "FAIL" in status:
                normalized["status"] = "NON_COMPLIANT"
            elif "COMPLIANT" in status or "PASS" in status:
                normalized["status"] = "COMPLIANT"
            else:
                normalized["status"] = "NON_COMPLIANT"
                
            # 2. severity
            # If status is COMPLIANT or FALSE_POSITIVE, severity is always N/A
            if normalized["status"] in ("COMPLIANT", "FALSE_POSITIVE"):
                normalized["severity"] = "N/A"
            else:
                # Respect LLM/model explicitly returned severity if valid
                model_sev = str(data.get("severity", "")).strip().capitalize()
                if model_sev in ("Critical", "High", "Medium", "Low"):
                    normalized["severity"] = model_sev
                else:
                    # Assign default control severity
                    normalized["severity"] = control_default_severity

                    
            # 3. evidence_strength
            strength = str(data.get("evidence_strength", "None")).strip()
            str_upper = strength.upper()
            if str_upper in ("STRONG", "MODERATE", "WEAK", "NONE"):
                normalized["evidence_strength"] = str_upper.capitalize()
            else:
                normalized["evidence_strength"] = "None"
                
            # 4. control_coverage
            try:
                coverage = int(str(data.get("control_coverage", 0)).strip())
                normalized["control_coverage"] = max(0, min(100, coverage))
            except (TypeError, ValueError):
                # Try to extract any digits if LLM returned text like "65%"
                digits = re.findall(r'\d+', str(data.get("control_coverage", "")))
                if digits:
                    normalized["control_coverage"] = max(0, min(100, int(digits[0])))
                else:
                    normalized["control_coverage"] = 0
                
            # 5. evidence
            evidence = data.get("evidence", [])
            if not isinstance(evidence, list):
                if isinstance(evidence, dict):
                    evidence = [evidence]
                else:
                    evidence = []
                    
            root_excerpt = data.get("evidence_quote") or data.get("evidence_snippet") or data.get("excerpt") or ""
            root_source = data.get("evidence_source") or data.get("source") or "Policy Document"
            root_page = data.get("page") or data.get("page_number") or "N/A"
            
            normalized_evidence = []
            for item in evidence:
                if isinstance(item, dict):
                    src = item.get("source") or item.get("document") or root_source or "Policy Document"
                    pg = item.get("page") or item.get("page_number") or root_page or "N/A"
                    exc = item.get("excerpt") or item.get("quote") or item.get("text") or root_excerpt or ""
                    if exc:
                        normalized_evidence.append({
                            "source": str(src),
                            "page": str(pg),
                            "excerpt": str(exc)
                        })
                        
            if not normalized_evidence and root_excerpt:
                normalized_evidence.append({
                    "source": str(root_source),
                    "page": str(root_page),
                    "excerpt": str(root_excerpt)
                })
                
            normalized["evidence"] = normalized_evidence
            
            # 6. evidence_count
            try:
                count = int(str(data.get("evidence_count", len(normalized["evidence"]))).strip())
                normalized["evidence_count"] = max(0, count)
            except (TypeError, ValueError):
                normalized["evidence_count"] = len(normalized["evidence"])
                
            # 7. business_impact
            normalized["business_impact"] = str(data.get("business_impact") or data.get("impact") or "")
            
            # 8. remediation_priority
            priority = str(data.get("remediation_priority", "Medium")).strip().upper()
            if priority in ("LOW", "MEDIUM", "HIGH", "IMMEDIATE"):
                normalized["remediation_priority"] = priority.capitalize()
            else:
                if "IMM" in priority:
                    normalized["remediation_priority"] = "Immediate"
                elif "HIGH" in priority:
                    normalized["remediation_priority"] = "High"
                elif "LOW" in priority:
                    normalized["remediation_priority"] = "Low"
                else:
                    normalized["remediation_priority"] = "Medium"
                    
            # 9. justification
            normalized["justification"] = str(data.get("justification") or data.get("reasoning") or data.get("explanation") or "")
            if not normalized["justification"].strip():
                normalized["justification"] = "No compliance justification was provided by the model."
                
            # 10. missing_requirements
            missing = data.get("missing_requirements", [])
            if isinstance(missing, str):
                missing = [missing]
            elif not isinstance(missing, list):
                missing = []
            normalized["missing_requirements"] = [str(m) for m in missing]
            
            # 11. recommendation
            normalized["recommendation"] = str(data.get("recommendation") or data.get("suggested_action") or "")
            
            # 12. policy_present
            p_pres = str(data.get("policy_present") or "No").strip()
            p_pres_lower = p_pres.lower()
            if "found" in p_pres_lower and "not" not in p_pres_lower:
                p_pres = "Found"
            elif "not" in p_pres_lower or "absent" in p_pres_lower or "no" in p_pres_lower:
                p_pres = "Not Found"
            elif "compliant" in p_pres_lower or "yes" in p_pres_lower or "pass" in p_pres_lower:
                p_pres = "Compliant"
            else:
                p_pres = "Not Found"
            normalized["policy_present"] = p_pres

            # 13. evidence_present
            e_pres = str(data.get("evidence_present") or "No").strip()
            e_pres_lower = e_pres.lower()
            if "found" in e_pres_lower and "not" not in e_pres_lower:
                e_pres = "Found"
            elif "not" in e_pres_lower or "absent" in e_pres_lower or "no" in e_pres_lower:
                e_pres = "Not Found"
            elif "compliant" in e_pres_lower or "yes" in e_pres_lower or "pass" in e_pres_lower:
                e_pres = "Compliant"
            else:
                e_pres = "Not Found"
            normalized["evidence_present"] = e_pres

            # 14. severity_score
            try:
                sev_score_str = str(data.get("severity_score") or "0.0").strip()
                matches = re.findall(r'\d+\.\d+|\d+', sev_score_str)
                if matches:
                    normalized["severity_score"] = float(matches[0])
                else:
                    normalized["severity_score"] = 0.0
            except Exception:
                normalized["severity_score"] = 0.0

            # ── 15-24. Policy vs Evidence split (Phase 5) ───────────────────────
            def _norm_found(raw, default="NOT_FOUND"):
                v = str(raw or "").strip().lower()
                if "not" in v or "absent" in v or "missing" in v or not v:
                    return "NOT_FOUND"
                if "found" in v or "present" in v or "yes" in v:
                    return "FOUND"
                return default

            def _norm_compliant(raw, default="NON_COMPLIANT"):
                v = str(raw or "").strip().lower()
                if "non" in v or "not compliant" in v or "no" in v:
                    return "NON_COMPLIANT"
                if "compliant" in v or "yes" in v:
                    return "COMPLIANT"
                return default

            def _norm_enum(raw, allowed, default):
                v = str(raw or "").strip().upper().replace(" ", "_").replace("-", "_")
                return v if v in allowed else default

            normalized["policy_status"] = _norm_found(data.get("policy_status"))
            normalized["policy_assessment"] = _norm_compliant(data.get("policy_assessment"))
            normalized["policy_name"] = str(data.get("policy_name") or "")
            normalized["policy_version"] = str(data.get("policy_version") or "")
            normalized["policy_clause"] = str(data.get("policy_clause") or "")
            normalized["policy_effective_date"] = str(data.get("policy_effective_date") or "")
            normalized["policy_review_date"] = str(data.get("policy_review_date") or "")
            normalized["policy_expiry_date"] = str(data.get("policy_expiry_date") or "")
            normalized["policy_validity"] = _norm_enum(
                data.get("policy_validity"), {"CURRENT", "EXPIRED", "REVIEW_OVERDUE", "UNKNOWN"}, "UNKNOWN"
            )
            normalized["policy_finding"] = str(data.get("policy_finding") or "")
            normalized["policy_gap"] = str(data.get("policy_gap") or "").strip() or "No policy gap identified."

            normalized["evidence_status"] = _norm_found(data.get("evidence_status"))
            normalized["evidence_assessment"] = _norm_compliant(data.get("evidence_assessment"))
            normalized["evidence_file"] = str(data.get("evidence_file") or "")
            normalized["evidence_location"] = str(data.get("evidence_location") or "")
            normalized["evidence_type"] = str(data.get("evidence_type") or "")
            normalized["evidence_date"] = str(data.get("evidence_date") or "")
            normalized["evidence_freshness"] = _norm_enum(
                data.get("evidence_freshness"), {"CURRENT", "STALE", "EXPIRED", "UNKNOWN"}, "UNKNOWN"
            )
            normalized["evidence_finding"] = str(data.get("evidence_finding") or "")
            normalized["evidence_gap"] = str(data.get("evidence_gap") or "").strip() or "No evidence gap identified."
            normalized["evidence_relevance"] = _norm_enum(
                data.get("evidence_relevance"), {"DIRECT", "PARTIAL", "RELATED", "IRRELEVANT"}, "IRRELEVANT"
            )

            normalized["final_result"] = _norm_compliant(data.get("final_result"), default="NON_COMPLIANT")
            normalized["final_reason"] = str(data.get("final_reason") or "")

            return normalized

        # Parse XML helper
        def parse_xml_to_dict(xml_text: str) -> dict:
            parsed_data = {}
            expected_tags = ["status", "severity", "evidence_strength", "control_coverage", "evidence_count",
                             "business_impact", "remediation_priority", "justification", "recommendation",
                             "policy_present", "evidence_present", "severity_score",
                             # Policy vs Evidence split (Phase 5)
                             "policy_status", "policy_assessment", "policy_name", "policy_version",
                             "policy_clause", "policy_effective_date", "policy_review_date",
                             "policy_expiry_date", "policy_validity", "policy_finding", "policy_gap",
                             "evidence_status", "evidence_assessment", "evidence_file", "evidence_location",
                             "evidence_type", "evidence_date", "evidence_freshness", "evidence_finding",
                             "evidence_gap", "evidence_relevance", "final_result", "final_reason"]

            
            # Tag Repair Logic (pre-processing unclosed tags)
            repaired_text = xml_text.strip()
            
            for tag in expected_tags:
                if f"<{tag}>" in repaired_text and f"</{tag}>" not in repaired_text:
                    start_pos = repaired_text.find(f"<{tag}>") + len(tag) + 2
                    next_tag_pos = repaired_text.find("<", start_pos)
                    if next_tag_pos != -1:
                        repaired_text = repaired_text[:next_tag_pos] + f"</{tag}>" + repaired_text[next_tag_pos:]
                    else:
                        repaired_text = repaired_text + f"</{tag}>"

            if "<requirement>" in repaired_text and "</requirement>" not in repaired_text:
                repaired_text = re.sub(r'<requirement>([^<]+)(?!</requirement>)', r'<requirement>\1</requirement>', repaired_text)
                
            # Wrap in single root tag to parse with ElementTree
            xml_body = repaired_text
            first_tag_idx = xml_body.find("<")
            if first_tag_idx != -1:
                xml_body = xml_body[first_tag_idx:]
            last_tag_idx = xml_body.rfind(">")
            if last_tag_idx != -1:
                xml_body = xml_body[:last_tag_idx+1]
                
            root_wrapped = f"<root>{xml_body}</root>"
            
            def regex_get_tag(t, txt):
                m = re.search(rf'<{t}>(.*?)</{t}>', txt, re.DOTALL)
                if m:
                    return m.group(1).strip()
                # Fallback: if closing tag is missing, match up to the next tag or end of string
                m_fallback = re.search(rf'<{t}>(.*?)(?:<|\Z)', txt, re.DOTALL)
                if m_fallback:
                    return m_fallback.group(1).strip()
                return ""
                
            parsed_successfully = False
            try:
                root_el = ET.fromstring(root_wrapped)
                parsed_successfully = True
                
                for tag in expected_tags:
                    el = root_el.find(tag)
                    parsed_data[tag] = el.text.strip() if (el is not None and el.text) else ""
                    
                missing_reqs = []
                mr_el = root_el.find("missing_requirements")
                if mr_el is not None:
                    for req in mr_el.findall("requirement"):
                        if req.text:
                            missing_reqs.append(req.text.strip())
                else:
                    for req in root_el.findall("requirement"):
                        if req.text:
                            missing_reqs.append(req.text.strip())
                parsed_data["missing_requirements"] = missing_reqs
                
                evidence_items = []
                ei_el = root_el.find("evidence_items")
                targets = ei_el.findall("evidence_item") if ei_el is not None else root_el.findall("evidence_item")
                for item in targets:
                    src = item.find("source")
                    pg = item.find("page")
                    exc = item.find("excerpt")
                    if exc is None:
                        exc = item.find("quote")
                    src_txt = src.text.strip() if (src is not None and src.text) else ""
                    pg_txt = pg.text.strip() if (pg is not None and pg.text) else ""
                    exc_txt = exc.text.strip() if (exc is not None and exc.text) else ""
                    if exc_txt:
                        evidence_items.append({
                            "source": src_txt,
                            "page": pg_txt,
                            "excerpt": exc_txt
                        })
                parsed_data["evidence"] = evidence_items
                
            except Exception as e:
                print(f"[XML PARSER WARNING] ElementTree failed ({e}). Falling back to pure regex parser...", flush=True)
                
            if not parsed_successfully or not any(parsed_data.values()):
                for tag in expected_tags:
                    parsed_data[tag] = regex_get_tag(tag, repaired_text)
                    
                missing_reqs = re.findall(r'<requirement>(.*?)</requirement>', repaired_text, re.DOTALL)
                parsed_data["missing_requirements"] = [r.strip() for r in missing_reqs]
                
                evidence_items = []
                items_raw = re.findall(r'<evidence_item>(.*?)</evidence_item>', repaired_text, re.DOTALL)
                for item in items_raw:
                    src = regex_get_tag("source", item)
                    pg = regex_get_tag("page", item)
                    exc = regex_get_tag("excerpt", item) or regex_get_tag("quote", item)
                    if exc:
                        evidence_items.append({
                            "source": src,
                            "page": pg,
                            "excerpt": exc
                        })
                parsed_data["evidence"] = evidence_items
                
            return parsed_data

        # Format the prompt using standard-specific templates if framework is VAPT
        is_vapt = "VAPT" in str(input_dict.get("standard", "")) or "vapt" in str(input_dict.get("control_id", "")).lower()
        active_template = self.prompt_template
        if is_vapt:
            if self.prompt_template == GENERATOR_PROMPT_TEMPLATE:
                active_template = VAPT_GENERATOR_PROMPT_TEMPLATE
            elif self.prompt_template == REFLECTION_PROMPT_TEMPLATE:
                active_template = VAPT_REFLECTION_PROMPT_TEMPLATE

        # GENERATOR_PROMPT_TEMPLATE/REFLECTION_PROMPT_TEMPLATE are framework-parameterized
        # (persona, "evaluate against {framework_name} control", etc.) so the same templates
        # serve ISO 27001, NIST CSF 2.0, and future frameworks without a separate copy each.
        # Unrecognized/empty standard values fall back to "ISO 27001" -- today's exact wording
        # -- so this is a no-op for every existing ISO 27001 audit. VAPT_* templates don't
        # reference these keys, so passing them is harmless there (str.format ignores unused
        # kwargs).
        # USE_CASES stores the short dropdown-value form ("SOC2", "DPDP", "BCMS", "XBOM") as
        # `standard` so app.js's category filters keep working -- expand it to a readable
        # display name here so the persona line doesn't read "specializing in XBOM".
        _framework_display_names = {
            "SOC2": "SOC 2 Type II", "DPDP": "DPDP / GDPR",
            "BCMS": "ISO 22301 BCMS", "XBOM": "X-BOM / SBOM",
            "PQC": "Post-Quantum Cryptography (PQC) Readiness",
        }
        _raw_standard = str(input_dict.get("standard") or "").strip()
        framework_name = _framework_display_names.get(_raw_standard.upper(), _raw_standard) or "ISO 27001"
        _other_framework_candidates = ["NIST", "CIS Controls", "SOC 2", "PCI DSS"]
        # Compare with whitespace stripped -- USE_CASES stores standard values like "SOC2"
        # (no space) while the example list reads "SOC 2" (with space); a plain substring
        # check on either side misses that match and would tell a SOC2 audit not to
        # introduce "SOC 2" requirements while auditing SOC 2.
        _fw_norm = framework_name.upper().replace(" ", "")
        other_frameworks_examples = ", ".join(
            f for f in _other_framework_candidates
            if f.upper().replace(" ", "") not in _fw_norm and _fw_norm not in f.upper().replace(" ", "")
        ) or "other unrelated frameworks"
        input_dict = {**input_dict, "framework_name": framework_name, "other_frameworks_examples": other_frameworks_examples}

        prompt = active_template.format(**input_dict)

        # ── Final real backstop ──────────────────────────────────────────────
        # _calculate_dynamic_context_budget() (retrieval.py) already sizes evidence
        # to fit, but that's a calculation done BEFORE this exact prompt is
        # assembled -- verify the REAL, fully-built prompt against the actual
        # tokenizer here, and trim evidence further if it's still somehow over,
        # instead of trusting the earlier estimate and risking the server's
        # "exceed_context_size_error" 400 response.
        try:
            from src.core.llm_client import count_tokens, get_real_num_ctx
            real_ctx = get_real_num_ctx()
            completion_reserve = min(1536, max(768, int(real_ctx * 0.2)))
            MAX_PROMPT_TOKENS = max(3000, real_ctx - completion_reserve - 200)
            _trim_attempts = 0
            while count_tokens(prompt) > MAX_PROMPT_TOKENS and _trim_attempts < 15:
                ctx = input_dict.get("condensed_context") or ""
                if not ctx:
                    break  # nothing left to trim
                current_tokens = count_tokens(prompt)
                excess = current_tokens - MAX_PROMPT_TOKENS
                chars_to_remove = max(100, int(excess * 4.2))
                new_len = max(0, len(ctx) - chars_to_remove)
                input_dict["condensed_context"] = ctx[:new_len]
                prompt = active_template.format(**input_dict)
                _trim_attempts += 1
            if _trim_attempts > 0:
                print(
                    f"[TOKEN BUDGET] Trimmed evidence {_trim_attempts}x for control "
                    f"{input_dict.get('control_id', 'unknown')} to fit the real context size "
                    f"(final: {count_tokens(prompt)} tokens).",
                    flush=True
                )
        except Exception as e:
            print(f"[TOKEN BUDGET] Final backstop check failed, proceeding without it: {e}", flush=True)

        print(f"[LLM CHAIN] Querying '{self.model_name}' for {input_dict.get('control_id', 'unknown')}...", flush=True)
        try:
            from src.core.llm_client import query_llm
            _stats = {}
            # session_id (== bg_key) threaded through so port_pool.py's live queue
            # notice has something to key into -- previously this was never passed
            # here, so every CPU-queue log/notice was always session_id=None for the
            # main generator/reflection/excel-scoping path (the overwhelming majority
            # of real usage), silently defeating any per-session queue visibility.
            content = query_llm(
                prompt=prompt,
                model=self.model_name,
                num_ctx=get_num_ctx(self.model_name),
                temperature=0.0,
                token_stats=_stats,
                session_id=input_dict.get("session_id"),
                # Match the actual HTTP request's timeout to the caller's own
                # wait budget (audit_graph.py's _calculate_adaptive_timeout()).
                # Previously this was never passed, so query_llm/port_pool computed
                # their own independent adaptive timeout -- when the two diverged,
                # the graph gave up and moved on while this thread kept running
                # and kept holding its port_pool concurrency slot until its own,
                # separately-computed timeout expired.
                timeout=input_dict.get("timeout")
            )
            self.last_token_stats = _stats
            if not content or not content.strip():
                raise ValueError("Backend returned an empty response.")
                
            content_clean = content.strip()
            
            # Check if response is JSON (fallback support)
            if content_clean.startswith("{") or (content_clean.startswith("```json") and "{" in content_clean):
                print(f"[LLM CHAIN] Model returned JSON instead of XML. Parsing as JSON...", flush=True)
                json_str = content_clean
                if "```" in json_str:
                    blocks = re.findall(r'```(?:json)?\s*(.*?)\s*```', json_str, re.DOTALL)
                    if blocks:
                        json_str = blocks[0]
                if not (json_str.startswith("{") and json_str.endswith("}")):
                    start_idx = json_str.find("{")
                    end_idx = json_str.rfind("}")
                    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                        json_str = json_str[start_idx:end_idx+1]
                data = json.loads(json_str)
            else:
                # Parse as XML (primary strategy)
                data = parse_xml_to_dict(content_clean)
                
            normalized_data = clean_and_normalize_data(data)
            return AuditFindingSchema(**normalized_data)
            
        except Exception as e:
            print(f"[LLM CHAIN ERROR] Parse failed for {input_dict.get('control_id', 'unknown')}: {e}", flush=True)
            control_id_str = str(input_dict.get('control_id', 'unknown'))

            # A parse/validation failure always falls through to an honest NON_COMPLIANT
            # finding below — never inferred as compliant from raw, un-vetted context text.

            # Detect if it's a validation gate failure (compliant status with no evidence)
            err_msg = str(e)
            if _stats.get("truncated"):
                # LLM response was cut off before completing, even after the 4096-token
                # retry in llm_client.py -- distinct from a genuine compliance gap, so
                # don't let it masquerade as one. requires_human_review is set below so
                # this is actually visible to the auditor rather than silently dropped.
                business_impact = (
                    f"Unable to determine compliance for {control_id_str}: the AI's response was cut off "
                    "before completing, even after retrying with a larger token budget."
                )
                justification = (
                    f"Response generation for {control_id_str} was truncated (token budget exceeded). "
                    "This is a generation issue, not evidence of a compliance gap."
                )
                missing_requirements = [
                    f"Re-run this control for {control_id_str} -- the previous attempt did not finish generating."
                ]
                recommendation = (
                    "Re-run this control. If it repeatedly truncates, the evidence context for this control "
                    "may be unusually large -- consider narrowing the uploaded evidence for this control."
                )
            elif "status cannot be set to 'COMPLIANT' if no evidence is found" in err_msg or "NO_EVIDENCE" in err_msg:
                business_impact = (
                    f"No evidence or configuration statement was found in the document to support control {control_id_str}. "
                    "This creates a compliance gap that may fail standard audits."
                )
                justification = (
                    f"The control was assessed as Non-Compliant because no relevant quotes, configuration proofs, "
                    "or policy statements were located in the uploaded document."
                )
                missing_requirements = [
                    f"Official policy documentation or implementation logs for {control_id_str} are missing."
                ]
                recommendation = (
                    f"Please upload supporting evidence such as system configuration screenshots, "
                    f"employee training records, or sign-off sheets for control {control_id_str} to satisfy compliance."
                )
            else:
                # General JSON / Formatting failure
                business_impact = (
                    f"Unable to automatically verify control {control_id_str} due to unstructured document context. "
                    "Manual verification is recommended to ensure compliance."
                )
                justification = (
                    f"The system did not locate clear, structured statements in the document relating to control {control_id_str}."
                )
                missing_requirements = [
                    f"Manual document validation required for control {control_id_str}."
                ]
                recommendation = (
                    "Upload a revised version containing explicit statements regarding this control."
                )

            # Map severity_score based on default severity for fallback
            fallback_score = 5.5
            if control_default_severity == "Critical":
                fallback_score = 9.5
            elif control_default_severity == "High":
                fallback_score = 8.0
            elif control_default_severity == "Medium":
                fallback_score = 5.5
            elif control_default_severity == "Low":
                fallback_score = 2.0

            return AuditFindingSchema(
                status="NON_COMPLIANT",
                severity=control_default_severity,
                evidence_strength="None",
                control_coverage=0,
                evidence_count=0,
                business_impact=business_impact,
                remediation_priority="High" if control_default_severity in ("High", "Critical") else "Medium",
                justification=justification,
                missing_requirements=missing_requirements,
                recommendation=recommendation,
                evidence=[],
                policy_present="No",
                evidence_present="No",
                severity_score=fallback_score
            )

def get_generator_chain(model_name: str, url: str = None):
    """
    Returns a native Ollama chain for generating the initial draft finding.
    """
    return NativeOllamaChain(model_name, GENERATOR_PROMPT_TEMPLATE, url)

def get_reflection_chain(model_name: str, url: str = None):
    """
    Returns a native Ollama chain for critique and self-correction reflection.
    """
    return NativeOllamaChain(model_name, REFLECTION_PROMPT_TEMPLATE, url)

def get_excel_scoping_chain(model_name: str, url: str = None):
    """
    Returns a native Ollama chain for the Two-Phase Excel Scoping mode.
    Uses EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE — the LLM acts as a judge-only,
    receiving pre-extracted paragraphs from locked files. It never searches.
    This eliminates N/A evidence and wrong-file citations structurally.
    """
    return NativeOllamaChain(model_name, EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE, url)
