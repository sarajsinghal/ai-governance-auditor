import json

from auditor.evaluation import deterministic_check, evaluate
from auditor.reporting import csv_bytes
from auditor.rules import load_catalog
from auditor.storage import get_findings, get_log, init_db, list_audits, save_audit


def test_catalog_has_unique_versioned_rules_and_all_frameworks():
    version, reviewed, rules = load_catalog()
    assert version and reviewed and len(rules) >= 10
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.version and len(r.frameworks) == 4 for r in rules)


def test_no_evidence_is_needs_review():
    _, _, rules = load_catalog()
    assert deterministic_check(rules[0], "")["status"] == "needs-review"


def test_review_kind_cannot_pass_from_keyword_match():
    _, _, rules = load_catalog()
    rule = next(r for r in rules if r.kind == "review")
    assert deterministic_check(rule, "provider deployer risk classification intended purpose EU AI Act")["status"] == "needs-review"


def test_hybrid_does_not_convert_thin_evidence_into_pass(monkeypatch):
    import auditor.evaluation as evaluation
    _, _, rules = load_catalog()
    monkeypatch.setattr(evaluation, "assess_with_llm", lambda *a, **k: {"status": "pass", "rationale": "model says yes", "method": "llm-assisted"})
    result = evaluate(rules[0], "AI system", "Hybrid (Python + LLM)")
    assert result["status"] == "needs-review"


def test_audit_storage_and_log(tmp_path):
    db = tmp_path / "audit.sqlite"
    init_db(db)
    _, _, rules = load_catalog()
    finding = evaluate(rules[0], "Owner accountable human oversight escalation documented", "Deterministic only")
    audit_id = save_audit("Example", "Pilot", "Deterministic only", "test", "Reviewer", [finding], db)
    assert list_audits(db)[0]["id"] == audit_id
    assert get_findings(audit_id, db)[0]["rule_version"] == "1.0.0"
    assert get_log(audit_id, db)[0]["event"] == "audit.created"


def test_csv_exports_evidence():
    raw = csv_bytes([{"rule_id":"X","rule_version":"1","title":"T","domain":"D","severity":"Low","status":"pass","method":"deterministic","rationale":"ok","evidence":"proof","frameworks":{"NIST AI RMF":"GOVERN"}}]).decode("utf-8-sig")
    assert "proof" in raw and "NIST AI RMF" in raw
