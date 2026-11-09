from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any


def csv_bytes(findings: list[dict[str, Any]]) -> bytes:
    out = io.StringIO(newline="")
    fields = ["rule_id", "rule_version", "title", "domain", "severity", "status", "method", "rationale", "evidence", "frameworks"]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for row in findings:
        writer.writerow({key: json.dumps(row.get("frameworks", {}), ensure_ascii=False) if key == "frameworks" else row.get(key, "") for key in fields})
    return out.getvalue().encode("utf-8-sig")


def pdf_bytes(system_name: str, scope: str, audit_id: str, findings: list[dict[str, Any]]) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    except ImportError as exc:
        raise RuntimeError("Install reportlab to export PDF reports") from exc
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=letter, rightMargin=0.55*inch, leftMargin=0.55*inch, topMargin=0.6*inch, bottomMargin=0.6*inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10, spaceAfter=3))
    styles.add(ParagraphStyle(name="ReportSubtitle", parent=styles["BodyText"], fontSize=10, leading=13, textColor=colors.HexColor("#42646b"), spaceAfter=5))
    story = [Paragraph("AI Governance &amp; Compliance Auditor", styles["Title"]), Paragraph("Assessment evidence report · informational aid, not certification", styles["ReportSubtitle"]), Spacer(1, 10)]
    story += [Paragraph(f"<b>System:</b> {html.escape(system_name)}", styles["BodyText"]), Paragraph(f"<b>Scope:</b> {html.escape(scope)}", styles["BodyText"]), Paragraph(f"<b>Audit ID:</b> {html.escape(audit_id)}", styles["BodyText"]), Paragraph(f"<b>Generated (UTC):</b> {datetime.now(timezone.utc).isoformat(timespec='seconds')}", styles["BodyText"]), Spacer(1, 10)]
    counts = {s: sum(1 for f in findings if f["status"] == s) for s in ("pass", "fail", "needs-review", "not-applicable")}
    story.append(Paragraph("<b>Outcome counts:</b> " + " · ".join(f"{k}: {v}" for k, v in counts.items()), styles["BodyText"]))
    story.append(Paragraph("A pass is a limited evidence assessment, not proof of effectiveness. A fail or needs-review result requires competent review. Not-applicable decisions must be justified by the reviewer. NIST AI RMF and OWASP are guidance, ISO/IEC 42001 is a standard, and the EU AI Act contains binding obligations whose scope and dates depend on role, system, jurisdiction, and provision.", styles["Small"]))
    story.append(Spacer(1, 12))
    for f in findings:
        block = [Paragraph(f"<b>{html.escape(f['rule_id'])} · {html.escape(f['title'])}</b> &nbsp; ({html.escape(f['severity'])} / {html.escape(f['status'])})", styles["Heading3"]), Paragraph(f"<b>Requirement:</b> {html.escape(f['requirement'])}", styles["Small"]), Paragraph(f"<b>Assessment:</b> {html.escape(f['rationale'])}", styles["Small"]), Paragraph(f"<b>Evidence:</b> {html.escape(f.get('evidence') or 'No evidence supplied')}", styles["Small"]), Paragraph(f"<b>Framework mappings:</b> {html.escape(json.dumps(f.get('frameworks', {}), ensure_ascii=False))}", styles["Small"]), Spacer(1, 7)]
        story.append(KeepTogether(block))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Limitations: This report is generated from user-submitted evidence and configured sample controls. It is not legal advice, an independent audit, conformity assessment, certification, or a guarantee of compliance. Validate sources and mappings against current authoritative materials and seek qualified legal, standards, and domain expertise.", styles["Small"]))
    doc.build(story)
    return out.getvalue()
