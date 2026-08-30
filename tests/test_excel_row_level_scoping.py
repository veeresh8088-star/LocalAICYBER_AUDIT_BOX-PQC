# -*- coding: utf-8 -*-
import pytest
from src.core.bg_worker import _build_controls_for_audit, generate_ollama_findings

def test_same_control_id_multiple_rows_strict_isolation():
    """
    Test that two Excel rows with the same ISO control ID (e.g. 8.5) but different
    questions/files evaluate with strict row-level isolation and NEVER borrow each
    other's files.
    """
    custom_evidence = {
        "excel_items": [
            {
                "row_index": 5,
                "control_id": "8.5",
                "control_name": "Secure Authentication",
                "control_label": "8.5 Secure Authentication",
                "question": "Whether multifactor authentification enabled or implemented?",
                "requirement_question": "Whether multifactor authentification enabled or implemented?",
                "files": ["MFA.docx"],
                "raw_file_refs": ["MFA.docx"],
                "expected_evidence": "MFA configuration",
                "severity": "CRITICAL"
            },
            {
                "row_index": 7,
                "control_id": "8.5",
                "control_name": "Secure Authentication",
                "control_label": "8.5 Secure Authentication",
                "question": "How is the Authentication done?",
                "requirement_question": "How is the Authentication done?",
                "files": ["Authentication.txt"],
                "raw_file_refs": ["Authentication.txt"],
                "expected_evidence": "Authentication remark",
                "severity": "CRITICAL"
            }
        ]
    }

    file_names_list = ["MFA.docx", "Authentication.txt", "Unrelated_Server_Log.log"]
    file_registry = {
        "MFA.docx": "MFA is enforced for all admin logins.",
        "Authentication.txt": "Authentication uses local active directory.",
        "Unrelated_Server_Log.log": "Server started successfully."
    }

    captured_scopes = {}
    controls = _build_controls_for_audit(custom_evidence=custom_evidence)

    assert len(controls) == 2

    import unittest.mock as mock
    with mock.patch("src.core.bg_worker._resolve_llm_model", return_value="gemma:2b"), \
         mock.patch("src.core.bg_worker.save_document_chunks"), \
         mock.patch("src.core.resource_guard.check_memory_pressure", return_value={"status": "OK"}), \
         mock.patch("src.core.bg_worker.audit_graph") as mock_graph:

        def capture_invoke(state_input, config=None):
            ctrl_label = state_input.get("control_id")
            captured_scopes[ctrl_label] = state_input.get("file_names_list")
            return {
                "final_finding": {
                    "control_id": ctrl_label,
                    "control": ctrl_label,
                    "status": "COMPLIANT",
                    "evidence_found": "Found: Compliant",
                    "findings_summary": "Compliant evidence found.",
                    "policy_gap": "No policy gap identified.",
                    "evidence_gap": "No evidence gap identified.",
                    "retrieved_docs": []
                },
                "retrieved_context": "dummy"
            }

        mock_graph.invoke.side_effect = capture_invoke

        generate_ollama_findings(
            context="Dummy context",
            file_names_list=file_names_list,
            selected_sls=None,
            model_choice="gemma:2b",
            custom_evidence=custom_evidence,
            file_registry=file_registry
        )

    # Verify Row 5 (MFA Question) got ONLY ['MFA.docx']
    mfa_key = next(k for k in captured_scopes if "multifactor" in k.lower())
    assert captured_scopes[mfa_key] == ["MFA.docx"]
    assert "Authentication.txt" not in captured_scopes[mfa_key]

    # Verify Row 7 (Auth Method Question) got ONLY ['Authentication.txt']
    auth_key = next(k for k in captured_scopes if "how is the authentication done" in k.lower())
    assert captured_scopes[auth_key] == ["Authentication.txt"]
    assert "MFA.docx" not in captured_scopes[auth_key]


def test_unique_control_id_normal_matching():
    """Test that a unique control ID in excel_items resolves normally."""
    custom_evidence = {
        "excel_items": [
            {
                "row_index": 10,
                "control_id": "8.6",
                "control_name": "Capacity Management",
                "control_label": "8.6 Capacity Management",
                "question": "CPU, memory and disk utilization",
                "files": ["Monitoring.docx"],
                "raw_file_refs": ["Monitoring.docx"],
            }
        ]
    }
    file_names_list = ["Monitoring.docx"]
    controls = _build_controls_for_audit(custom_evidence=custom_evidence)
    assert len(controls) == 1

    import unittest.mock as mock
    captured = {}
    with mock.patch("src.core.bg_worker._resolve_llm_model", return_value="gemma:2b"), \
         mock.patch("src.core.bg_worker.save_document_chunks"), \
         mock.patch("src.core.resource_guard.check_memory_pressure", return_value={"status": "OK"}), \
         mock.patch("src.core.bg_worker.audit_graph") as mock_graph:

        def capture_invoke(state_input, config=None):
            ctrl_id = state_input["control_id"]
            captured[ctrl_id] = state_input["file_names_list"]
            return {
                "final_finding": {
                    "control_id": ctrl_id,
                    "control": ctrl_id,
                    "status": "COMPLIANT",
                    "evidence_found": "Found"
                },
                "retrieved_context": "dummy"
            }

        mock_graph.invoke.side_effect = capture_invoke

        generate_ollama_findings(
            context="Dummy",
            file_names_list=file_names_list,
            selected_sls=None,
            model_choice="gemma:2b",
            custom_evidence=custom_evidence
        )

    key = next(k for k in captured if "8.6" in k)
    assert captured[key] == ["Monitoring.docx"]


def test_same_control_id_ambiguous_question_handling(capsys):
    """
    Test that when multiple Excel rows share the same control ID but an ambiguous
    control object has no row_index and no matching question text, it logs
    [SCOPING AMBIGUITY] and safely leaves the file scope empty without borrowing
    another row's files.

    The ambiguity was always detected -- _match_excel_row() returned (None, True) and
    logged -- but the flag was never read. With no row matched, no Tier 1 refs were
    collected, so the Tier 2/3 cascade ran and ended at the "no filename/keyword
    match" fallback that hands the control EVERY uploaded file. The control was then
    audited against evidence belonging to other rows' questions.

    The control is now short-circuited before retrieval rather than invoked with an
    empty list, so the graph is never called for it -- there is nothing to search and
    no reason to spend an LLM call arriving at the same answer.
    """
    custom_evidence = {
        "excel_items": [
            {
                "row_index": 1,
                "control_id": "8.5",
                "question": "Question Alpha",
                "files": ["Alpha.pdf"]
            },
            {
                "row_index": 2,
                "control_id": "8.5",
                "question": "Question Beta",
                "files": ["Beta.pdf"]
            }
        ]
    }
    ambiguous_c = {
        "control_id": "8.5",
        "control": "8.5 Secure Authentication — Unrelated Question Gamma",
        "label": "8.5 Secure Authentication — Unrelated Question Gamma",
        "requirement_question": "Unrelated Question Gamma",
        "expected": "Expected evidence",
        "prompt_hint": "Hint",
        "severity": "MEDIUM"
    }

    from src.core.bg_worker import generate_ollama_findings
    captured = {}
    import unittest.mock as mock
    with mock.patch("src.core.bg_worker._resolve_llm_model", return_value="gemma:2b"), \
         mock.patch("src.core.bg_worker.save_document_chunks"), \
         mock.patch("src.core.resource_guard.check_memory_pressure", return_value={"status": "OK"}), \
         mock.patch("src.core.bg_worker._build_controls_for_audit", return_value=[ambiguous_c]), \
         mock.patch("src.core.bg_worker.audit_graph") as mock_graph:

        def capture_invoke(state_input, config=None):
            ctrl_id = state_input["control_id"]
            captured[ctrl_id] = state_input["file_names_list"]
            return {
                "final_finding": {
                    "control_id": ctrl_id,
                    "control": ctrl_id,
                    "status": "NON_COMPLIANT"
                },
                "retrieved_context": ""
            }

        mock_graph.invoke.side_effect = capture_invoke

        generate_ollama_findings(
            context="Dummy",
            file_names_list=["Alpha.pdf", "Beta.pdf"],
            selected_sls=None,
            model_choice="gemma:2b",
            custom_evidence=custom_evidence
        )

    out = capsys.readouterr().out
    assert "[SCOPING AMBIGUITY]" in out
    # Never handed another row's files -- the whole point of the guard.
    assert ambiguous_c["control"] not in captured, (
        f"control was audited against borrowed files: {captured.get(ambiguous_c['control'])}"
    )
    assert "scope left EMPTY" in out
    # The final resolved scope for this control must be exactly empty. (Alpha.pdf
    # still appears in the session_files debug line -- that lists what was uploaded,
    # not what this control was given -- so assert on the scope line itself.)
    scope_lines = [l for l in out.splitlines()
                   if "[CONTROL FILE SCOPE]" in l and l.rstrip().endswith("[]")]
    assert scope_lines, "no empty-scope line found; scope was not blocked"


def test_missing_referenced_file_warning_preserved(capsys):
    """
    Test that when an Excel row references a file not found in uploaded session files,
    it emits [SCOPING WARNING] and stops with scope = [].
    """
    custom_evidence = {
        "excel_items": [
            {
                "row_index": 8,
                "control_id": "8.2",
                "control_label": "8.2 Privileged Access Rights",
                "question": "PAM evidence",
                "files": ["43_PAM_Missing_File.pdf"]
            }
        ]
    }
    captured = {}
    import unittest.mock as mock
    with mock.patch("src.core.bg_worker._resolve_llm_model", return_value="gemma:2b"), \
         mock.patch("src.core.bg_worker.save_document_chunks"), \
         mock.patch("src.core.resource_guard.check_memory_pressure", return_value={"status": "OK"}), \
         mock.patch("src.core.bg_worker.audit_graph") as mock_graph:

        def capture_invoke(state_input, config=None):
            ctrl_id = state_input["control_id"]
            captured[ctrl_id] = state_input["file_names_list"]
            return {
                "final_finding": {
                    "control_id": ctrl_id,
                    "control": ctrl_id,
                    "status": "NON_COMPLIANT"
                },
                "retrieved_context": ""
            }

        mock_graph.invoke.side_effect = capture_invoke

        generate_ollama_findings(
            context="Dummy",
            file_names_list=["Some_Other_File.docx"],
            selected_sls=None,
            model_choice="gemma:2b",
            custom_evidence=custom_evidence
        )

    out = capsys.readouterr().out
    assert "[SCOPING WARNING]" in out
