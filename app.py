from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from auditor.evaluation import evaluate
from auditor.reporting import csv_bytes, pdf_bytes
from auditor.rules import load_catalog
from auditor.storage import dashboard_summary, get_findings, get_log, init_db, list_audits, save_audit

st.set_page_config(page_title="Governance Auditor", page_icon="◈", layout="wide")
catalog_version, reviewed_on, RULES = load_catalog()
init_db()
SOURCES = {
    "NIST": ("NIST AI RMF 1.0 (voluntary; under revision)", "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10"),
    "ISO": ("ISO/IEC 42001:2023", "https://www.iso.org/standard/42001.html"),
    "EU": ("EU Artificial Intelligence Act, Regulation (EU) 2024/1689", "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng"),
    "EU timeline": ("European Commission AI Act implementation and application", "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai"),
    "OWASP": ("OWASP Top 10 for LLM Applications 2026", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"),
}

st.title("AI governance program")
st.caption("Evidence-led assessments across governance, risk, security, data, transparency, and operations.")
st.caption(f"Control catalog {catalog_version} · reviewed {reviewed_on} · Sample controls require local validation before operational use.")
st.warning("This tool is an assessment aid. It does not provide legal advice, independent assurance, certification, or a definitive compliance decision. Framework applicability and legal duties depend on context.")

tab_dashboard, tab_assess, tab_catalog, tab_history, tab_sources = st.tabs(["Dashboard", "New assessment", "Control catalog", "Audit history", "Framework sources"])

with tab_dashboard:
    overview = dashboard_summary()
    status_counts = overview["latest_status_counts"]
    open_items = sum(overview["open_severity_counts"].values())
    assessed_systems = overview["system_count"]
    latest_review = status_counts.get("pass", 0) + status_counts.get("fail", 0) + status_counts.get("needs-review", 0) + status_counts.get("not-applicable", 0)
    with st.container(horizontal=True):
        st.metric("AI systems assessed", assessed_systems, border=True, help="Distinct system names with at least one saved audit.")
        st.metric("Governance coverage", f"{(status_counts.get('pass', 0) / latest_review * 100):.0f}%" if latest_review else "—", border=True, help="Share of applicable controls marked pass in the latest audit per system; not a compliance score.")
        st.metric("Open review items", open_items, border=True, help="Findings marked fail or needs-review across each system's latest audit.")
        st.metric("Controls reviewed", latest_review, border=True, help="Controls included in each system's latest audit, including not applicable.")

    chart_col, actions_col = st.columns([0.9, 1.6])
    with chart_col:
        with st.container(border=True):
            st.subheader("Open items by severity")
            risk_data = pd.DataFrame({"Severity": ["Critical", "High", "Medium", "Low"], "Open findings": [overview["open_severity_counts"][x] for x in ("Critical", "High", "Medium", "Low")]})
            if open_items:
                st.bar_chart(risk_data, x="Severity", y="Open findings", color="#F39A38", horizontal=True, alt="Open findings by severity")
            else:
                st.info("No open items in saved assessments yet.")
            st.caption("Open means fail or needs review. This summarizes the latest saved audit for each system name.")
    with actions_col:
        with st.container(border=True):
            st.subheader("Recent governance actions")
            recent = overview["recent"]
            if recent:
                action_df = pd.DataFrame([{
                    "Action": "Assessment",
                    "AI system": r["system_name"],
                    "Status": "Needs follow-up" if (r["failed_count"] or 0) + (r["review_count"] or 0) else "Reviewed",
                    "Reviewer": r["reviewer"] or "—",
                    "Date": r["created_at"][:10],
                    "Controls": r["control_count"],
                } for r in recent])
                st.dataframe(action_df, hide_index=True, alt="Recent saved AI governance assessments")
            else:
                st.info("No assessments saved yet. Start with New assessment to populate this dashboard.")
    st.caption("Dashboard metrics summarize the latest saved audit for each system name. They are operational summaries, not legal or certification conclusions.")

with tab_assess:
    left, right = st.columns([1, 1])
    with left:
        system_name = st.text_input("AI system / project name", placeholder="e.g., Customer support assistant")
        scope = st.text_area("Assessment scope and context", placeholder="Intended purpose, users, jurisdictions, deployment stage, and use context", height=120)
        reviewer = st.text_input("Reviewer / owner (optional)")
    with right:
        mode = st.selectbox("Evaluation mode", ["Hybrid (Python + LLM)", "Deterministic only"])
        selected_frameworks = st.multiselect("Frameworks to display", list(RULES[0].frameworks), default=list(RULES[0].frameworks))
        provider_enabled = st.checkbox("Use configured OpenAI-compatible provider for contextual assessment", value=False, disabled=(mode == "Deterministic only"))
        if provider_enabled:
            st.caption("The evidence text below is sent to the provider configured in environment variables. Avoid uploading confidential or personal data unless your provider and processing terms are approved.")
            with st.expander("Provider configuration", expanded=False):
                st.write(f"Base URL: {os.getenv('LLM_BASE_URL') or 'not configured'}")
                st.write(f"Model: {os.getenv('LLM_MODEL') or 'not configured'}")
                st.write(f"API key: {'configured' if os.getenv('LLM_API_KEY') else 'not configured'}")
    st.markdown("#### Evidence by control")
    st.caption("Paste concise evidence references or excerpts; do not treat keywords or model output as proof. Use N/A only when the reviewer can justify non-applicability.")
    include_na = st.checkbox("Allow reviewer to mark controls not applicable", value=True)
    evidence_by_id: dict[str, str] = {}
    statuses: dict[str, str] = {}
    for rule in RULES:
        with st.expander(f"{rule.id} · {rule.title}  |  {rule.severity} · {rule.domain}"):
            st.write(rule.requirement)
            st.caption(f"Applies to: {rule.applicability}")
            shown_frameworks = {k: v for k, v in rule.frameworks.items() if not selected_frameworks or k in selected_frameworks}
            st.caption("Mappings: " + " | ".join(f"{k}: {v}" for k, v in shown_frameworks.items()))
            evidence_by_id[rule.id] = st.text_area("Evidence / reference", key=f"evidence_{rule.id}", height=90, placeholder="Evidence excerpt, record ID, link, test result, or explanation")
            if include_na:
                statuses[rule.id] = st.selectbox("Applicability", ["Applicable", "Not applicable"], key=f"applies_{rule.id}")
            else:
                statuses[rule.id] = "Applicable"
    if st.button("Run assessment and save audit", type="primary", use_container_width=True):
        if not system_name.strip():
            st.error("Enter a system name to create an audit record.")
        else:
            findings = []
            for rule in RULES:
                if statuses[rule.id] == "Not applicable":
                    findings.append({"rule_id":rule.id,"rule_version":rule.version,"title":rule.title,"domain":rule.domain,"severity":rule.severity,"requirement":rule.requirement,"frameworks":rule.frameworks,"evidence":evidence_by_id[rule.id],"status":"not-applicable","method":"reviewer","rationale":"Marked not applicable by reviewer; rationale must be recorded in the evidence field."})
                else:
                    findings.append(evaluate(rule, evidence_by_id[rule.id], mode, {"base_url":os.getenv("LLM_BASE_URL", ""),"api_key":os.getenv("LLM_API_KEY", ""),"model":os.getenv("LLM_MODEL", "")} if provider_enabled else {}))
            audit_id = save_audit(system_name.strip(), scope.strip(), mode, catalog_version, reviewer.strip(), findings)
            st.session_state["latest_audit_id"] = audit_id
            st.success(f"Assessment saved · {audit_id}")

    audit_id = st.session_state.get("latest_audit_id")
    if audit_id:
        audits = {a["id"]: a for a in list_audits()}
        audit = audits.get(audit_id)
        findings = get_findings(audit_id)
        if audit:
            st.markdown("#### Latest results")
            counts = {s: sum(f["status"] == s for f in findings) for s in ("pass", "fail", "needs-review", "not-applicable")}
            cols = st.columns(4)
            for c, s in zip(cols, counts): c.metric(s.replace("-", " ").title(), counts[s])
            df = pd.DataFrame([{k:f[k] for k in ("rule_id","title","domain","severity","status","method","rationale")} for f in findings])
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("Download CSV", csv_bytes(findings), file_name=f"audit-{audit_id[:8]}.csv", mime="text/csv")
            try:
                report = pdf_bytes(audit["system_name"], audit["scope"], audit_id, findings)
                st.download_button("Download PDF report", report, file_name=f"audit-{audit_id[:8]}.pdf", mime="application/pdf")
            except (RuntimeError, ValueError, KeyError) as exc:
                st.error(f"PDF report could not be generated: {exc}")

with tab_catalog:
    st.markdown(f"**Catalog version:** `{catalog_version}` · **review date:** {reviewed_on}")
    for rule in RULES:
        with st.expander(f"{rule.id} · {rule.title} ({rule.severity})"):
            st.write(rule.requirement)
            st.write(f"Applicability: {rule.applicability}")
            st.write(f"Version: {rule.version} · Type: {rule.kind}")
            st.json(rule.frameworks)
    st.info("Controls are curated sample translations and crosswalks, not full reproductions of source frameworks. Version changes should be reviewed and recorded by maintainers.")

with tab_history:
    audits = list_audits()
    if not audits:
        st.info("No saved audits yet.")
    else:
        st.dataframe(pd.DataFrame(audits), use_container_width=True, hide_index=True)
        chosen = st.selectbox("Inspect audit", [a["id"] for a in audits], format_func=lambda x: f"{next(a['system_name'] for a in audits if a['id']==x)} · {x[:8]}")
        if chosen:
            st.dataframe(pd.DataFrame(get_findings(chosen)), use_container_width=True, hide_index=True)
            st.caption("Audit log")
            st.json(get_log(chosen))

with tab_sources:
    st.markdown("### Source character")
    st.write("**Binding law:** EU AI Act (Regulation (EU) 2024/1689) is binding law. Applicability and duties vary by role, system, use, territory, provision, and staged application dates. This sample catalog is not an EU legal classifier.")
    st.write("**Voluntary framework:** NIST AI RMF 1.0 is voluntary and NIST reports it is being revised.")
    st.write("**Standard:** ISO/IEC 42001:2023 is a published management-system standard. This app cannot assess conformity or grant certification.")
    st.write("**Security guidance:** OWASP Top 10 for LLM Applications is community-developed risk guidance, not law or a certification scheme.")
    for label, (title, url) in SOURCES.items():
        st.markdown(f"- [{title}]({url})")
    st.caption("Sources checked 8 Nov 2026. Verify the latest text, corrigenda, standards editions, guidance, and application dates before reliance.")

st.divider()
st.caption("© 2026 · Local SQLite by default · LLM assessment is optional and provider-configurable")
