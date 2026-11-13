# AI Governance & Compliance Auditor

A Streamlit application for organizing evidence reviews against the NIST AI Risk Management Framework, ISO/IEC 42001, the EU AI Act, and the OWASP Top 10 for LLM Applications. It combines deterministic indicators with an optional configurable OpenAI-compatible assessment, stores audit records in SQLite, and exports CSV and PDF reports.

**Live app:** https://ai-governance-auditor.streamlit.app/

> **Assessment aid only.** This software does not provide legal advice, independent assurance, certification, conformity assessment, or a definitive compliance result. A control's `pass` means only that the configured assessment judged the supplied evidence supportive. Review original artifacts with competent domain, standards, security, and legal professionals.

## Scope

The application provides evidence management, framework traceability, and audit reporting. It is maintained as a standalone project.

## Capabilities

- 12 versioned sample controls in `rules.json`, each with applicability, severity, requirement text, and mappings to all four frameworks.
- Deterministic Python indicator checks. These are intentionally conservative: no evidence yields `needs-review`; keyword presence is explicitly not proof of effectiveness.
- Optional LLM-assisted assessment through an OpenAI-compatible `/chat/completions` endpoint. Provider base URL, API key, and model are configuration values; no vendor is assumed. Provider failures return `needs-review`. LLM responses do not promote sparse deterministic evidence to `pass`.
- Statuses: `pass`, `fail`, `needs-review`, and reviewer-selected `not-applicable`. N/A rationale belongs in the evidence field and should be reviewed.
- SQLite audit, findings, control versions, and append-only creation event records.
- Assessment dashboard, saved-audit history, CSV export, PDF report, source inventory, and clear limitations.
- Dockerfile and Streamlit Community Cloud deployment notes.

## Architecture

```text
Streamlit UI (app.py)
  ├── Control catalog (rules.json → auditor/rules.py)
  ├── Hybrid evaluation (auditor/evaluation.py)
  │     ├── deterministic presence indicators
  │     └── optional OpenAI-compatible provider
  ├── SQLite repository (auditor/storage.py)
  └── CSV/PDF report rendering (auditor/reporting.py)
```

Controls are curated interpretations and crosswalks. Framework references are not complete requirements inventories. Version the catalog and review it when frameworks, laws, or intended uses change.

## Framework character and authoritative sources

- **NIST AI RMF 1.0:** voluntary risk-management framework; NIST says it is being revised. [NIST publication](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10) · [NIST AI RMF page](https://www.nist.gov/itl/ai-risk-management-framework)
- **ISO/IEC 42001:2023:** published AI management-system standard. The standard is copyrighted; this project includes only short clause references and does not reproduce its text. [ISO catalog page](https://www.iso.org/standard/42001.html)
- **EU AI Act:** Regulation (EU) 2024/1689 is binding law with role-specific duties and staged application. Classification and applicability are legal/contextual determinations; control `EU-001` is deliberately always a human-review item. [EUR-Lex official text](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) · [European Commission implementation page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- **OWASP Top 10 for LLM Applications 2026:** community-developed security guidance, not legislation or certification. [OWASP resource](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

Sources reviewed 8 November 2026. Confirm current official texts, editions, corrigenda, and transitional dates before operational use.

## Local setup

Python 3.10+ recommended (Docker uses 3.12).

```powershell
cd project8_governance_auditor
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

On macOS/Linux, activate with `source .venv/bin/activate`. PDF export uses ReportLab, included in `requirements.txt`; CSV works without it. The database is created at `data/auditor.db` on first run. Set `AUDITOR_DB_PATH` to choose another writable location.

## Optional LLM provider

Copy `.env.example` to `.env` for your own process manager, or set environment variables in the hosting platform's secret manager. Streamlit does not load `.env` by default; use your shell/session manager or add `python-dotenv` if desired. Required values are:

```text
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=your-secret
LLM_MODEL=provider-model-id
```

Any provider implementing the OpenAI-compatible chat completions endpoint and JSON object response format may work. Compatibility varies. Keep credentials out of source control, verify provider retention/processing settings, and do not send sensitive evidence without authorization. Provider output is untrusted and should be verified against source evidence.

## Tests

```powershell
python -m pytest -q
```

Tests cover catalog integrity, conservative states, LLM non-promotion behavior, SQLite persistence/audit log, and CSV output. Network provider calls are not required by the test suite.

## Deployment

### Streamlit Community Cloud

1. Push this directory to a repository you control.
2. Create a Streamlit app pointing to `app.py`; use `requirements.txt`.
3. Add any LLM values under app secrets/environment configuration.
4. Set `AUDITOR_DB_PATH` to persistent storage only if the platform offers it. Ephemeral container filesystems can lose SQLite data on restart; export reports or use a managed database for real audit retention.
5. Restrict access before uploading real evidence. Community Cloud is suitable for demos, not assumed to be a compliant evidence repository.

### Docker

```powershell
docker build -t governance-auditor .
docker run --rm -p 8501:8501 -v auditor-data:/app/data governance-auditor
```

Pass provider credentials through your orchestrator's secret mechanism. Avoid placing secrets directly on a shared command line. Add authentication, TLS termination, backup/restore, retention controls, access logging, and tenant isolation before organizational deployment. The sample MVP has no user login, role-based access, encryption-at-rest management, or multi-tenant isolation.

### Production hardening backlog

- Authentication, authorization, and reviewer/approver separation.
- Immutable/cryptographically chained audit events and explicit edits/review sign-off.
- Evidence file storage with malware scanning, access controls, retention, and redaction.
- Data migration/version migration framework and catalog approval workflow.
- Tenant isolation, backups, encryption, monitoring, and deployment threat model.
- Legal change monitoring and approved mapping review by qualified experts.
- Evaluation of LLM-provider behavior, prompt-injection resistance, and structured response validation.

## Data model

- `audits`: system, scope, evaluation mode, reviewer, catalog version, timestamp.
- `findings`: rule ID/version snapshot, severity, state, rationale, supplied evidence, framework mapping, method, and raw assessment JSON.
- `audit_log`: audit creation event and metadata. The current MVP records creation; it does not claim tamper resistance.

## Clear limitations

1. Keyword checks can produce false matches and cannot verify implementation, context, or effectiveness.
2. LLM judgments can hallucinate, misread evidence, and be influenced by malicious content. `pass` is provisional and requires human validation.
3. Framework mappings are sample crosswalks, not official mappings or comprehensive clause coverage.
4. The app does not classify EU AI Act risk or determine territorial scope, operator role, legal duty, or conformity.
5. ISO/IEC standard conformity and certification require appropriate processes and competent assessment.
6. SQLite and the UI are a single-user demo foundation; no authentication, authorization, encryption policy, or multi-tenant controls are included.
7. Reports are informational and reflect only the provided evidence and rules catalog at assessment time.

## Project layout

```text
app.py
auditor/             # rule loading, evaluation, persistence, reports
rules.json           # versioned sample control catalog
tests/               # unit and persistence checks
requirements.txt
Dockerfile
```
