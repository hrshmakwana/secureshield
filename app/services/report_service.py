import os
from datetime import datetime
from typing import Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_scan_report(output_folder: str, scan: Dict) -> str:
    os.makedirs(output_folder, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.pdf"
    path = os.path.join(output_folder, filename)

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SecureShield Scan Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    meta_table = Table(
        [
            ["Scan Date", scan.get("scan_date", "-")],
            ["Target URL", scan.get("target_url", "-")],
            ["Severity", scan.get("severity", "Low")],
        ],
        colWidths=[120, 360],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 16))

    findings = [
        ["SQL Injection", "Vulnerable" if scan.get("sqli") else "Safe"],
        ["Cross-Site Scripting", "Vulnerable" if scan.get("xss") else "Safe"],
    ]
    findings_table = Table(findings, colWidths=[200, 280])
    findings_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey)]))
    elements.append(findings_table)
    elements.append(Spacer(1, 16))

    recommendation = scan.get(
        "recommendation",
        "Review input validation, parameterized queries, and output encoding to mitigate risks.",
    )
    elements.append(Paragraph("Recommendations", styles["Heading2"]))
    elements.append(Paragraph(recommendation, styles["BodyText"]))

    doc.build(elements)
    return path
