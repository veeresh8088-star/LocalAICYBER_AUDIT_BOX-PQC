# Workspace Audit Reasoning Rules

All audit findings and evaluations in this workspace must follow these reasoning rules. This file
must stay in sync with the live prompts in `src/ai/audit_chains.py` (`GENERATOR_PROMPT_TEMPLATE`,
`EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE`) — if you change the reasoning rules baked into those prompts,
update this file to match, and vice versa.

## Core audit principle: Policy vs Evidence

For every control there are two different concepts:
- **STATUS** = whether the relevant material was found at all.
- **ASSESSMENT** = whether the material actually satisfies the control's specific requirement.

FOUND does NOT mean COMPLIANT. A policy or evidence item can be found and still fail its assessment.

- **Policy** = what should happen (a documented requirement/procedure/standard).
- **Evidence** = proof that it actually happened (logs, screenshots, reports, records — operational
  proof, not just a restated policy). A policy document alone is never implementation evidence.

## Applicability check (run first)

If the control is NOT applicable to the scope of the document (e.g. mobile device security controls
when auditing a document that only covers physical server rooms), return status `FALSE_POSITIVE`.

## Policy status / assessment

- `POLICY_STATUS`: `FOUND` or `NOT_FOUND` only. FOUND = a relevant policy, procedure, standard, or
  documented requirement related to the control was located.
- `POLICY_ASSESSMENT`: `COMPLIANT` or `NON_COMPLIANT` only. COMPLIANT only when the policy actually
  addresses the SPECIFIC control requirement adequately — not merely a related topic.
- `POLICY_GAP`: never just "Yes"/"No" — explain the actual deficiency, or write exactly "No policy
  gap identified." if there is none.

## Evidence status / assessment / relevance

- `EVIDENCE_STATUS`: `FOUND` or `NOT_FOUND` only. For operational technical controls (e.g. backups, clock sync),
  a policy document alone is NOT implementation evidence — e.g. "Administrators must perform periodic backups"
  is policy; "Backup job completed successfully on 10-Aug-2026" is evidence. For governance/documentation
  controls (such as 5.1 Policies for Information Security, 5.37 Documented Operating Procedures, or when
  an audit checklist question asks for an approved policy document/version/date), the approved, versioned
  policy document itself serves as the valid documentary evidence. FOUND vs NOT_FOUND turns on whether ANY
  topically relevant operational evidence exists, not whether it satisfies every specific detail — evidence
  describing the general activity (e.g. a termination workflow with an email acknowledging a separation
  agreement) is FOUND even if one specific detail is unconfirmed (e.g. formal signing vs. email
  acknowledgment); mark that case `EVIDENCE_RELEVANCE=PARTIAL` + `EVIDENCE_ASSESSMENT=NON_COMPLIANT` with the
  exact missing detail in `EVIDENCE_GAP`, not `EVIDENCE_STATUS=NOT_FOUND`. Reserve `NOT_FOUND` for when the
  evidence contains nothing topically relevant at all — confirmed on a real audit run where a termination
  control's evidence (exit interview, asset return, email confirming the separation agreement) was correctly
  judged insufficient to prove *signing* specifically, but got recorded as `NOT_FOUND` instead of
  `FOUND`+`NON_COMPLIANT`, hiding from the auditor that real, partially-responsive evidence existed.
- `EVIDENCE_ASSESSMENT`: `COMPLIANT` or `NON_COMPLIANT` only. COMPLIANT only when the evidence (1)
  directly relates to this specific control, (2) demonstrates actual implementation/operation (or approved
  policy document for governance controls), (3) covers the control objective, (4) contains enough information
  to verify the claim, (5) is reasonably current, and (6) requires no unsupported assumptions to accept.
- `EVIDENCE_RELEVANCE`: `DIRECT`, `PARTIAL`, `RELATED`, or `IRRELEVANT`. DIRECT includes equivalent
  or alternative implementations described in different terminology than the control's illustrative
  examples — DIRECT means "satisfies the objective," not "matches specific preferred technical
  terms." Only DIRECT evidence should normally support `EVIDENCE_ASSESSMENT = COMPLIANT`.
- `EVIDENCE_GAP`: never just "Yes"/"No" — explain what is actually missing, or write exactly "No
  evidence gap identified." if there is none.

## Policy validity / evidence freshness

Extract effective/review/expiry dates only when the document states them.
- `POLICY_VALIDITY`: `CURRENT`, `EXPIRED`, `REVIEW_OVERDUE`, or `UNKNOWN`. Never invent a date or
  assume a fixed expiry period unless the document itself states it — if undetermined, use UNKNOWN.
- `EVIDENCE_FRESHNESS`: `CURRENT`, `STALE`, `EXPIRED`, or `UNKNOWN`. There is no universal 30/60/90-day
  staleness rule — base it on the control's own requirement or the organization's stated frequency;
  if undetermined, use UNKNOWN, never a guessed period.

## Final result (deterministic — enforced downstream in code and prompts)

`FINAL_RESULT = COMPLIANT` ONLY when ALL 4 criteria are affirmatively satisfied:
1. `POLICY_STATUS = FOUND`
2. `POLICY_ASSESSMENT = COMPLIANT`
3. `EVIDENCE_STATUS = FOUND`
4. `EVIDENCE_ASSESSMENT = COMPLIANT`
(and `POLICY_VALIDITY` / `EVIDENCE_FRESHNESS` are acceptable, with no contradictory evidence).

There are **NO exceptions** for `NOT_REQUIRED` or `NOT_APPLICABLE`. If ANY of policy or evidence is missing (`NOT_FOUND`) or failed (`NON_COMPLIANT`), `FINAL_RESULT` MUST equal `NON_COMPLIANT`.

This formula is re-applied deterministically in Python (`src/core/validator.py`) after generation, overriding the LLM's own self-reported status if the two disagree.

## Version / numeric threshold comparison

When a control requires comparing version numbers (e.g. "TLS 1.2 or higher", installed vs fixed
software/patch versions in VAPT findings), compare each dot-separated component numerically in
order (major, then minor, then patch) — never lexicographically as text. `1.10` is GREATER than
`1.9` (10 > 9 at the minor position), not the reverse as plain string comparison would suggest.
This is prompt-level guidance only — there is no deterministic code-level check enforcing it (see
`GENERATOR_PROMPT_TEMPLATE`, `EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE`, `VAPT_GENERATOR_PROMPT_TEMPLATE`,
`VAPT_REFLECTION_PROMPT_TEMPLATE` in `src/ai/audit_chains.py`).

## Never invent

Never fabricate dates, page numbers, slide numbers, policy clauses, evidence, timestamps, expiry
dates, or document content. Never assume compliance merely because a policy exists, a procedure
exists, a person is assigned responsibility, a document mentions the control, a related system
exists, a workflow describes what SHOULD happen, or a document/filename title sounds relevant.

## General reasoning rules

1. **Specific Control Scope**: Evaluate the document only against the specific ISO 27001 control being audited.
2. **Intent Determination**: First determine the control objective (intent) before evaluating evidence.
3. **Intent-Based Assessment**: Assess whether the documented evidence satisfies the control objective, not whether it matches specific keywords.
4. **No Framework Creep**: Do not introduce requirements from NIST, CIS Controls, SOC 2, PCI DSS, internal best practices, or generic security frameworks unless they are explicitly part of the evaluated ISO control.
5. **No Hallucinated Gaps**: Do not create gaps for controls, processes, forms, technologies, or procedures that are not explicitly required by the evaluated control.
6. **Equivalent Terms**: A requirement may be satisfied through equivalent controls, processes, or documented procedures even if different terminology is used.
7. **Traceable Gaps**: Every identified gap must be traceable to a specific requirement of the evaluated ISO control.
8. **Conservative Acceptability**: If evidence directly satisfies the control objective, do not mark the control as NON_COMPLIANT solely because preferred implementation examples are absent — but this does NOT waive the Policy+Evidence dual requirement above; a control still needs both sides found and compliant.
9. **Ambiguity Resolution**: When evidence is ambiguous, explain the uncertainty and choose the most conservative evidence-based conclusion.
10. **Evidence Grounding**: Auditor reasoning must reference documented evidence and explain how it supports or fails to support the control objective.
11. **Substantiated Absences**: Missing requirements must be supported by evidence showing that the requirement is absent, not merely that a specific keyword was not found.
12. **Intent Over Keywords**: Prioritize intent-based evaluation over keyword matching.
13. **Never infer organization-wide implementation from a single screenshot.**
14. **Do NOT use confidence scores, relevance scores, similarity scores, retrieval scores, or model certainty to determine compliance status.**

## Finding & recommendation phrasing

- Always distinguish "Evidence Found" from "Evidence Not Found". Avoid "Password policy is missing."
  Instead write "No documentary evidence was found for password policy configuration."
- Recommendations must address only the missing evidence — do not recommend implementing controls
  that are already evidenced. If MFA exists, do NOT recommend implementing MFA; recommend only what's
  actually missing (e.g. the policy statement, if evidence exists but policy doesn't).

## Excel scoping mode: auditor column-source hint

When an uploaded Excel checklist has separately named Policy and Evidence columns, the locked file(s)
from each column are passed to the LLM as a hint of the auditor's own intent (e.g. "the auditor's
checklist lists X.pdf under the POLICY column"). Treat this as a **strong prior, not proof** — still
verify the actual content of the locked file(s) supports the objective before marking COMPLIANT. Do
not blindly trust the column label if the content doesn't back it up (see `column_source_hint` in
`src/ai/audit_graph.py::generate_node` and `EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE` in `audit_chains.py`).

### Example (ISO 27001 5.15 Access Control)

- **Intent**: Ensure access to facilities, systems, information, and assets is authorized and controlled.
- If the document demonstrates badge controls, visitor management, escort procedures, access authorization, and physical access restrictions, the control objective may be satisfied even if specific terms such as RBAC, PAM, access request forms, or access recertification are not present — **but only if the document supplies both a policy-side statement (the rule) and a distinct evidence-side artifact (proof it's followed)**. A single paragraph combining a present-tense operational description with the control's stated requirement can satisfy both simultaneously; a document containing only one side satisfies only half the formula.

---

# Project Engineering Rules

## Core rule
Never guess. Inspect the existing codebase before implementing.

## Architecture
- Reuse existing services, utilities, API clients and patterns.
- Do not introduce duplicate implementations.
- Do not modify unrelated files.
- Preserve backward compatibility unless explicitly instructed otherwise.

## APIs
- Never invent API endpoints.
- Never assume HTTP methods.
- Inspect existing API clients, route definitions, OpenAPI specs, environment configuration, documentation and tests.
- Verify endpoint, method, authentication, request schema and response schema before implementation.
- Never hardcode secrets or environment-specific URLs.

## Database
- Inspect existing models and migrations before changing schemas.
- Never silently change existing data contracts.
- Create migrations when required.
- Test both existing and new database behavior.

## Frontend
- Reuse existing components and design system.
- Do not create duplicate components when an existing component can be reused.
- Verify loading, error, empty and success states.

## Backend
- Validate inputs.
- Preserve existing response contracts.
- Handle errors explicitly.
- Add/update tests for changed behavior.

## Implementation workflow
1. Explore
2. Plan
3. Implement
4. Test
5. Debug
6. Re-test
7. Final verification

## Verification
A task is NOT complete until:
- tests pass
- lint/type checking passes
- build passes where applicable
- relevant API endpoints are verified
- no unrelated functionality is broken

## Mandatory Error Prevention Rules
1. **Zero Duplicate Declarations**: Never duplicate variable, function, or block-scoped (`let`, `const`) declarations across function blocks or control flows. Always check existing variable scopes before introducing new bindings.
2. **Mandatory Syntax & Compilation Verification**: Before declaring any change completed:
   - Run `node --check <file.js>` on all modified JavaScript files.
   - Run python compilation/syntax checks on all modified Python files.
3. **No Unintended Side Effects**: Ensure CSS or HTML structural changes do not alter JS logic, variable names, or event handler bindings.
4. **Automated Test Runner Requirement**: Run relevant automated test suites (e.g. `test_card_layout.py`, `test_scoping_modes.py`, `test_validator_rules.py`) to verify that no existing features or card renderings break.
5. **Production Build Asset Sync**: Always sync modified `src/api/static/` files (`app.js`, `index.html`, `style.css`) to `dist/AICyberAuditBox/_internal/src/api/static/` and verify integrity.

Never report "completed successfully" without actual verification.

If something cannot be verified, explicitly report:
`NOT VERIFIED: <reason>`

