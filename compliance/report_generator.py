"""
SecureBridge Compliance Report Generator
Generates professional PDF compliance reports for OT security assessments
Sandy Lukita | PT Optima Sarana Instrument

Output:
1. Technical Report (English) - for IT/security team
2. Executive Summary (Bahasa Indonesia) - for board/management
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
from compliance.iec62443_mapper import (
    FINDING_TO_IEC, IEC62443_REQUIREMENTS,
    calculate_compliance_score, get_priority_findings
)

# ─────────────────────────────────────────────
# Color Palette
# ─────────────────────────────────────────────

NAVY = colors.HexColor('#1a2744')
TEAL = colors.HexColor('#0d7377')
LIGHT_TEAL = colors.HexColor('#e8f4f8')
RED = colors.HexColor('#c0392b')
ORANGE = colors.HexColor('#e67e22')
GREEN = colors.HexColor('#27ae60')
LIGHT_GRAY = colors.HexColor('#f5f6fa')
MID_GRAY = colors.HexColor('#95a5a6')
DARK_GRAY = colors.HexColor('#2c3e50')
WHITE = colors.white


def severity_color(severity: str):
    return {
        "CRITICAL": RED,
        "HIGH": ORANGE,
        "MEDIUM": colors.HexColor('#f39c12'),
        "LOW": GREEN
    }.get(severity, MID_GRAY)


def status_color(status: str):
    return {
        "NON_COMPLIANT": RED,
        "PARTIAL": ORANGE,
        "COMPLIANT": GREEN,
        "IN_PROGRESS": ORANGE
    }.get(status, MID_GRAY)


# ─────────────────────────────────────────────
# Styles
# ─────────────────────────────────────────────

def build_styles():
    styles = getSampleStyleSheet()

    custom = {
        "Cover_Title": ParagraphStyle(
            "Cover_Title", parent=styles["Title"],
            fontSize=28, textColor=WHITE,
            spaceAfter=8, alignment=TA_CENTER, leading=34
        ),
        "Cover_Sub": ParagraphStyle(
            "Cover_Sub", parent=styles["Normal"],
            fontSize=13, textColor=colors.HexColor('#b2dfdb'),
            spaceAfter=4, alignment=TA_CENTER
        ),
        "Cover_Meta": ParagraphStyle(
            "Cover_Meta", parent=styles["Normal"],
            fontSize=10, textColor=colors.HexColor('#e0f2f1'),
            spaceAfter=2, alignment=TA_CENTER
        ),
        "Section_Header": ParagraphStyle(
            "Section_Header", parent=styles["Heading1"],
            fontSize=14, textColor=WHITE,
            spaceBefore=4, spaceAfter=10, leading=18,
            backColor=NAVY, leftIndent=-10, rightIndent=-10,
            borderPadding=(6, 10, 6, 10)
        ),
        "Sub_Header": ParagraphStyle(
            "Sub_Header", parent=styles["Heading2"],
            fontSize=11, textColor=NAVY,
            spaceBefore=12, spaceAfter=6, leading=14
        ),
        "Body": ParagraphStyle(
            "Body", parent=styles["Normal"],
            fontSize=9.5, textColor=DARK_GRAY,
            spaceAfter=6, leading=14, alignment=TA_JUSTIFY
        ),
        "Body_Bold": ParagraphStyle(
            "Body_Bold", parent=styles["Normal"],
            fontSize=9.5, textColor=DARK_GRAY,
            spaceAfter=4, leading=14, fontName="Helvetica-Bold"
        ),
        "Finding_Title": ParagraphStyle(
            "Finding_Title", parent=styles["Normal"],
            fontSize=10, textColor=DARK_GRAY,
            fontName="Helvetica-Bold", spaceAfter=3
        ),
        "Finding_Body": ParagraphStyle(
            "Finding_Body", parent=styles["Normal"],
            fontSize=9, textColor=DARK_GRAY,
            spaceAfter=3, leading=13
        ),
        "Table_Header": ParagraphStyle(
            "Table_Header", parent=styles["Normal"],
            fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER
        ),
        "Table_Cell": ParagraphStyle(
            "Table_Cell", parent=styles["Normal"],
            fontSize=8.5, textColor=DARK_GRAY, leading=12
        ),
        "Caption": ParagraphStyle(
            "Caption", parent=styles["Normal"],
            fontSize=8, textColor=MID_GRAY,
            spaceAfter=4, alignment=TA_CENTER, fontName="Helvetica-Oblique"
        ),
        "Score_Big": ParagraphStyle(
            "Score_Big", parent=styles["Normal"],
            fontSize=48, textColor=NAVY,
            fontName="Helvetica-Bold", alignment=TA_CENTER
        ),
        "Footer": ParagraphStyle(
            "Footer", parent=styles["Normal"],
            fontSize=8, textColor=MID_GRAY, alignment=TA_CENTER
        ),
        "ID_Tag": ParagraphStyle(
            "ID_Tag", parent=styles["Normal"],
            fontSize=8, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER
        ),
        "Bahasa_Title": ParagraphStyle(
            "Bahasa_Title", parent=styles["Normal"],
            fontSize=12, textColor=NAVY,
            fontName="Helvetica-Bold", spaceAfter=6, spaceBefore=10
        ),
        "Bahasa_Body": ParagraphStyle(
            "Bahasa_Body", parent=styles["Normal"],
            fontSize=10, textColor=DARK_GRAY,
            spaceAfter=6, leading=15, alignment=TA_JUSTIFY
        ),
    }
    for name, style in custom.items():
        styles.add(style)
    return styles


# ─────────────────────────────────────────────
# Helper Components
# ─────────────────────────────────────────────

def section_header(text, styles):
    return [
        Spacer(1, 10),
        Table(
            [[Paragraph(text, styles["Section_Header"])]],
            colWidths=[170 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [NAVY]),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        ),
        Spacer(1, 8),
    ]


def severity_badge(severity, styles):
    color = severity_color(severity)
    return Table(
        [[Paragraph(severity, styles["ID_Tag"])]],
        colWidths=[18 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [color]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("ROUNDEDCORNERS", (0, 0), (-1, -1), [3, 3, 3, 3]),
        ])
    )


def info_box(label, value, styles, color=LIGHT_TEAL):
    return Table(
        [[
            Paragraph(f"<b>{label}</b>", styles["Body"]),
            Paragraph(str(value), styles["Body"])
        ]],
        colWidths=[45 * mm, 120 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, WHITE),
        ])
    )


# ─────────────────────────────────────────────
# Cover Page
# ─────────────────────────────────────────────

def build_cover(story, client_data, styles):
    # Header bar
    story.append(Table(
        [[Paragraph("SecureBridge", styles["Cover_Title"])]],
        colWidths=[170 * mm],
        rowHeights=[20 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), NAVY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ])
    ))

    # Teal accent strip
    story.append(Table(
        [[Paragraph("OT/ICS Security Assessment Report", styles["Cover_Sub"])]],
        colWidths=[170 * mm],
        rowHeights=[12 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), TEAL),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ])
    ))

    story.append(Spacer(1, 20))

    # Client info block
    story.append(Table(
        [
            [Paragraph("CLIENT", styles["Caption"]),
             Paragraph("REPORT DATE", styles["Caption"]),
             Paragraph("CLASSIFICATION", styles["Caption"])],
            [Paragraph(f"<b>{client_data['client_name']}</b>", styles["Sub_Header"]),
             Paragraph(f"<b>{client_data['report_date']}</b>", styles["Sub_Header"]),
             Paragraph("<b>CONFIDENTIAL</b>", styles["Sub_Header"])],
        ],
        colWidths=[60 * mm, 55 * mm, 55 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, WHITE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    ))

    story.append(Spacer(1, 16))

    # Engagement summary box
    engagement_rows = [
        ["Consultant", client_data.get("consultant", "Sandy Lukita")],
        ["Company", client_data.get("consulting_firm", "PT Optima Sarana Instrument")],
        ["Scope", client_data.get("scope", "IT/OT Security Assessment")],
        ["Framework", "IEC 62443 | Purdue Model | NIST CSF"],
        ["Assessment Period", client_data.get("period", "")],
    ]

    for label, value in engagement_rows:
        story.append(info_box(label, value, styles))

    story.append(Spacer(1, 16))

    # Risk level summary
    risk = client_data.get("risk_level", "CRITICAL")
    risk_color = severity_color(risk)

    story.append(Table(
        [[
            Paragraph("OVERALL RISK LEVEL", styles["Cover_Sub"]),
            Paragraph(risk, ParagraphStyle(
                "Risk", fontSize=24, textColor=WHITE,
                fontName="Helvetica-Bold", alignment=TA_CENTER
            ))
        ]],
        colWidths=[85 * mm, 85 * mm],
        rowHeights=[18 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), NAVY),
            ("BACKGROUND", (1, 0), (1, 0), risk_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    ))

    story.append(Spacer(1, 14))

    # Footer note
    story.append(Paragraph(
        "This report contains confidential information prepared exclusively for the named client. "
        "Distribution to third parties requires written consent from PT Optima Sarana Instrument.",
        styles["Caption"]
    ))

    story.append(PageBreak())


# ─────────────────────────────────────────────
# Executive Summary
# ─────────────────────────────────────────────

def build_executive_summary(story, client_data, compliance_score, styles):
    story += section_header("1. EXECUTIVE SUMMARY", styles)

    story.append(Paragraph(
        f"PT Optima Sarana Instrument was engaged by <b>{client_data['client_name']}</b> "
        f"to conduct a comprehensive IT/OT security assessment of their industrial "
        f"instrumentation environment. This assessment was conducted in accordance with "
        f"IEC 62443 industrial cybersecurity standards and the Purdue Model for "
        f"Industrial Control System (ICS) security.",
        styles["Body"]
    ))

    story.append(Spacer(1, 8))

    # Score display
    story.append(Table(
        [[
            Table(
                [[Paragraph(
                    f"{compliance_score['overall_score']}%",
                    styles["Score_Big"]
                )],
                 [Paragraph("IEC 62443 Compliance Score", styles["Caption"])]],
                colWidths=[55 * mm],
                style=TableStyle([
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ])
            ),
            Table(
                [
                    [Paragraph("Security Level Achieved", styles["Body_Bold"])],
                    [Paragraph(compliance_score["security_level"], ParagraphStyle(
                        "SL", fontSize=16, textColor=TEAL,
                        fontName="Helvetica-Bold", spaceBefore=4
                    ))],
                    [Spacer(1, 8)],
                    [Paragraph(
                        f"<b>{compliance_score['compliant_requirements']}</b> of "
                        f"<b>{compliance_score['total_requirements']}</b> "
                        f"IEC 62443 requirements met",
                        styles["Body"]
                    )],
                ],
                colWidths=[110 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_TEAL),
                    ("LEFTPADDING", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ])
            ),
        ]],
        colWidths=[60 * mm, 110 * mm],
        style=TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#dce1e7')),
        ])
    ))

    story.append(Spacer(1, 14))

    # Key findings summary
    story.append(Paragraph("Key Findings Summary", styles["Sub_Header"]))

    findings = get_priority_findings(FINDING_TO_IEC)
    critical = [f for _, f in findings if f["severity"] == "CRITICAL"]
    high = [f for _, f in findings if f["severity"] == "HIGH"]
    medium = [f for _, f in findings if f["severity"] == "MEDIUM"]

    summary_data = [
        [Paragraph("Severity", styles["Table_Header"]),
         Paragraph("Count", styles["Table_Header"]),
         Paragraph("Immediate Action Required", styles["Table_Header"])],
        [Paragraph("CRITICAL", styles["Table_Cell"]),
         Paragraph(str(len(critical)), styles["Table_Cell"]),
         Paragraph("YES — Within 48 hours", styles["Table_Cell"])],
        [Paragraph("HIGH", styles["Table_Cell"]),
         Paragraph(str(len(high)), styles["Table_Cell"]),
         Paragraph("YES — Within 2 weeks", styles["Table_Cell"])],
        [Paragraph("MEDIUM", styles["Table_Cell"]),
         Paragraph(str(len(medium)), styles["Table_Cell"]),
         Paragraph("Within 4 weeks", styles["Table_Cell"])],
    ]

    story.append(Table(
        summary_data,
        colWidths=[40 * mm, 25 * mm, 105 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor('#fdecea')),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor('#fff3e0')),
            ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor('#fffde7')),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (0, 1), RED),
            ("TEXTCOLOR", (0, 2), (0, 2), ORANGE),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#dce1e7')),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    ))

    story.append(Spacer(1, 14))

    # Assessment conclusion
    story.append(Paragraph(
        "The assessment identified critical security gaps that require immediate attention. "
        "The most urgent concern is the absence of network segmentation between IT and OT "
        "environments, combined with evidence of active threat actor reconnaissance via "
        "targeted spear phishing. Without remediation, the organization faces significant "
        "risk of ransomware attack or data breach — similar to incidents experienced by "
        "competitors in the same sector.",
        styles["Body"]
    ))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Following completion of the remediation roadmap outlined in this report, the "
        "organization will achieve IEC 62443 Security Level 2 compliance — meeting the "
        "cybersecurity requirements mandated by PT Energi Nusantara for contract renewal.",
        styles["Body"]
    ))

    story.append(PageBreak())


# ─────────────────────────────────────────────
# Detailed Findings
# ─────────────────────────────────────────────

def build_findings(story, styles):
    story += section_header("2. DETAILED FINDINGS", styles)

    findings = get_priority_findings(FINDING_TO_IEC)

    for idx, (vuln_id, finding) in enumerate(findings, 1):
        sev = finding["severity"]
        sev_color = severity_color(sev)

        # Finding header
        header_row = [[
            Paragraph(f"FINDING {idx:02d}", ParagraphStyle(
                "FH", fontSize=8, textColor=WHITE,
                fontName="Helvetica-Bold", alignment=TA_CENTER
            )),
            Paragraph(finding["title"], ParagraphStyle(
                "FT", fontSize=10, textColor=WHITE,
                fontName="Helvetica-Bold"
            )),
            Paragraph(sev, ParagraphStyle(
                "FS", fontSize=9, textColor=WHITE,
                fontName="Helvetica-Bold", alignment=TA_RIGHT
            )),
        ]]

        story.append(KeepTogether([
            Table(
                header_row,
                colWidths=[20 * mm, 120 * mm, 30 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), sev_color),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ])
            ),

            # Finding details
            Table(
                [
                    [
                        Paragraph("<b>IEC 62443 Requirements:</b>", styles["Finding_Body"]),
                        Paragraph(
                            ", ".join([
                                IEC62443_REQUIREMENTS.get(r, {}).get("code", r)
                                for r in finding["requirements"]
                            ]),
                            styles["Finding_Body"]
                        )
                    ],
                    [
                        Paragraph("<b>Compliance Status:</b>", styles["Finding_Body"]),
                        Paragraph(
                            finding["status"].replace("_", " "),
                            ParagraphStyle(
                                "CS", fontSize=9,
                                textColor=status_color(finding["status"]),
                                fontName="Helvetica-Bold"
                            )
                        )
                    ],
                    [
                        Paragraph("<b>Remediation:</b>", styles["Finding_Body"]),
                        Paragraph(finding["remediation"], styles["Finding_Body"])
                    ],
                    [
                        Paragraph("<b>Effort:</b>", styles["Finding_Body"]),
                        Paragraph(
                            f"{finding['effort']} | Target: {finding['timeline']}",
                            styles["Finding_Body"]
                        )
                    ],
                ],
                colWidths=[38 * mm, 132 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor('#eef0f5')),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor('#dce1e7')),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            ),
            Spacer(1, 10),
        ]))


# ─────────────────────────────────────────────
# IEC 62443 Requirements Map
# ─────────────────────────────────────────────

def build_compliance_map(story, styles):
    story += section_header("3. IEC 62443 COMPLIANCE MAP", styles)

    story.append(Paragraph(
        "The following table maps all IEC 62443 Security Requirements relevant to this "
        "engagement against the current compliance status of PT Nusantara Instrumen.",
        styles["Body"]
    ))
    story.append(Spacer(1, 8))

    headers = [
        Paragraph("Code", styles["Table_Header"]),
        Paragraph("Requirement", styles["Table_Header"]),
        Paragraph("Category", styles["Table_Header"]),
        Paragraph("Status", styles["Table_Header"]),
    ]

    rows = [headers]

    # Determine status per requirement
    req_status = {}
    for vuln_id, finding in FINDING_TO_IEC.items():
        for req_id in finding["requirements"]:
            if req_id not in req_status:
                req_status[req_id] = finding["status"]

    for req_id, req in IEC62443_REQUIREMENTS.items():
        status = req_status.get(req_id, "NON_COMPLIANT")
        s_color = status_color(status)

        rows.append([
            Paragraph(req["code"], ParagraphStyle(
                "RC", fontSize=8.5, fontName="Helvetica-Bold",
                textColor=NAVY, alignment=TA_CENTER
            )),
            Paragraph(req["title"], styles["Table_Cell"]),
            Paragraph(req["category"], styles["Table_Cell"]),
            Paragraph(
                status.replace("_", " "),
                ParagraphStyle(
                    "RS", fontSize=8, textColor=s_color,
                    fontName="Helvetica-Bold", alignment=TA_CENTER
                )
            ),
        ])

    col_styles = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor('#dce1e7')),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [WHITE, colors.HexColor('#f8f9fa')]),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (3, 0), (3, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])

    story.append(Table(
        rows,
        colWidths=[18 * mm, 82 * mm, 38 * mm, 32 * mm],
        style=col_styles,
        repeatRows=1
    ))

    story.append(PageBreak())


# ─────────────────────────────────────────────
# Remediation Roadmap
# ─────────────────────────────────────────────

def build_roadmap(story, styles):
    story += section_header("4. REMEDIATION ROADMAP", styles)

    phases = [
        {
            "title": "PHASE 1 — Immediate (Week 1)",
            "color": RED,
            "items": [
                ("Change WiFi password", "1 day", "Sandy + Client IT"),
                ("Investigate spear phishing incident", "2 days", "Sandy"),
                ("Verify server backup status", "1 day", "Sandy + Client IT"),
                ("Brief all staff on phishing awareness", "1 day", "Client MD"),
            ]
        },
        {
            "title": "PHASE 2 — Short Term (Week 2-3)",
            "color": ORANGE,
            "items": [
                ("Network segmentation — Purdue Model design", "3 days", "Sandy"),
                ("Deploy Nozomi Networks for OT monitoring", "2 days", "Sandy"),
                ("Implement engineer laptop security policy", "3 days", "Sandy"),
                ("Develop incident response procedure", "2 days", "Sandy"),
            ]
        },
        {
            "title": "PHASE 3 — Medium Term (Week 3-4)",
            "color": colors.HexColor('#f39c12'),
            "items": [
                ("Complete asset inventory (IT + OT)", "2 days", "Sandy + Client"),
                ("Implement password policy", "1 day", "Client IT"),
                ("Establish patch management process", "3 days", "Sandy"),
                ("OT security awareness training for engineers", "1 day", "Sandy"),
            ]
        },
        {
            "title": "PHASE 4 — Compliance Documentation (Week 4-5)",
            "color": GREEN,
            "items": [
                ("IEC 62443 compliance documentation package", "3 days", "Sandy"),
                ("Evidence collection for PT Energi Nusantara audit", "2 days", "Sandy"),
                ("Final security assessment report", "2 days", "Sandy"),
                ("Compliance presentation to client management", "1 day", "Sandy"),
            ]
        },
    ]

    for phase in phases:
        # Phase header
        story.append(Table(
            [[Paragraph(phase["title"], ParagraphStyle(
                "PH", fontSize=10, textColor=WHITE,
                fontName="Helvetica-Bold"
            ))]],
            colWidths=[170 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), phase["color"]),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ])
        ))

        # Phase items
        for task, duration, owner in phase["items"]:
            story.append(Table(
                [[
                    Paragraph(f"• {task}", styles["Table_Cell"]),
                    Paragraph(duration, styles["Table_Cell"]),
                    Paragraph(owner, styles["Table_Cell"]),
                ]],
                colWidths=[100 * mm, 25 * mm, 45 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                    ("GRID", (0, 0), (-1, -1), 0.3, WHITE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
            ))

        story.append(Spacer(1, 8))

    story.append(PageBreak())


# ─────────────────────────────────────────────
# Executive Summary — Bahasa Indonesia
# ─────────────────────────────────────────────

def build_bahasa_summary(story, client_data, compliance_score, styles):
    story += section_header("5. RINGKASAN EKSEKUTIF (BAHASA INDONESIA)", styles)

    story.append(Paragraph(
        "Ringkasan ini disiapkan untuk manajemen PT Nusantara Instrumen "
        "dan dapat digunakan dalam presentasi kepada klien atau mitra bisnis.",
        styles["Caption"]
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Latar Belakang", styles["Bahasa_Title"]))
    story.append(Paragraph(
        f"PT Optima Sarana Instrument telah melakukan penilaian keamanan IT/OT "
        f"menyeluruh terhadap infrastruktur {client_data['client_name']}. "
        f"Penilaian ini dilakukan sebagai persiapan untuk memenuhi persyaratan "
        f"keamanan siber yang diwajibkan oleh klien utama perusahaan dalam "
        f"proses perpanjangan kontrak.",
        styles["Bahasa_Body"]
    ))

    story.append(Paragraph("Temuan Utama", styles["Bahasa_Title"]))
    story.append(Paragraph(
        "Dari hasil penilaian, ditemukan 12 kerentanan keamanan dengan rincian sebagai berikut:",
        styles["Bahasa_Body"]
    ))

    findings = get_priority_findings(FINDING_TO_IEC)
    critical_count = len([f for _, f in findings if f["severity"] == "CRITICAL"])
    high_count = len([f for _, f in findings if f["severity"] == "HIGH"])
    medium_count = len([f for _, f in findings if f["severity"] == "MEDIUM"])

    story.append(Table(
        [
            [Paragraph("Tingkat Risiko", styles["Table_Header"]),
             Paragraph("Jumlah", styles["Table_Header"]),
             Paragraph("Contoh Temuan", styles["Table_Header"])],
            [Paragraph("KRITIS", ParagraphStyle(
                "KR", fontSize=9, textColor=RED, fontName="Helvetica-Bold",
                alignment=TA_CENTER
            )),
             Paragraph(str(critical_count), styles["Table_Cell"]),
             Paragraph(
                 "Tidak ada pemisahan jaringan IT dan OT; "
                 "upaya phishing aktif terdeteksi",
                 styles["Table_Cell"]
             )],
            [Paragraph("TINGGI", ParagraphStyle(
                "TG", fontSize=9, textColor=ORANGE, fontName="Helvetica-Bold",
                alignment=TA_CENTER
            )),
             Paragraph(str(high_count), styles["Table_Cell"]),
             Paragraph(
                 "Tidak ada pemantauan keamanan OT; "
                 "laptop engineer terhubung langsung ke jaringan klien",
                 styles["Table_Cell"]
             )],
            [Paragraph("SEDANG", ParagraphStyle(
                "SD", fontSize=9, textColor=colors.HexColor('#f39c12'),
                fontName="Helvetica-Bold", alignment=TA_CENTER
            )),
             Paragraph(str(medium_count), styles["Table_Cell"]),
             Paragraph(
                 "Tidak ada inventaris aset; "
                 "kebijakan kata sandi yang lemah",
                 styles["Table_Cell"]
             )],
        ],
        colWidths=[35 * mm, 20 * mm, 115 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor('#dce1e7')),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor('#fdecea'),
              colors.HexColor('#fff3e0'),
              colors.HexColor('#fffde7')]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 1), (1, -1), 6),
            ("ALIGN", (2, 1), (2, -1), "LEFT"),
        ])
    ))

    story.append(Spacer(1, 10))

    story.append(Paragraph("Risiko Bisnis", styles["Bahasa_Title"]))
    story.append(Paragraph(
        "Kondisi keamanan saat ini menempatkan perusahaan pada risiko bisnis yang signifikan: "
        "pertama, kemungkinan serangan ransomware — serupa dengan yang dialami kompetitor "
        "yang mengakibatkan kerugian lebih dari $50,000 dan terhentinya operasional selama "
        "3 minggu; kedua, risiko tidak terpenuhinya persyaratan keamanan siber untuk "
        "perpanjangan kontrak dengan klien utama, yang mewakili 60% pendapatan perusahaan.",
        styles["Bahasa_Body"]
    ))

    story.append(Paragraph("Langkah Selanjutnya", styles["Bahasa_Title"]))
    story.append(Paragraph(
        "PT Optima Sarana Instrument telah menyiapkan rencana remediasi terstruktur dalam "
        "4 fase yang dapat diselesaikan dalam 5 minggu. Setelah remediasi selesai, "
        "perusahaan akan memenuhi standar keamanan IEC 62443 Security Level 2 dan "
        "siap untuk proses audit dari PT Energi Nusantara.",
        styles["Bahasa_Body"]
    ))

    story.append(Spacer(1, 10))

    # Compliance target
    story.append(Table(
        [[
            Paragraph(
                "Target Setelah Remediasi:\n"
                "IEC 62443 Security Level 2\n"
                "Siap Audit Q1 2027",
                ParagraphStyle(
                    "Target", fontSize=11, textColor=WHITE,
                    fontName="Helvetica-Bold", alignment=TA_CENTER,
                    leading=18
                )
            )
        ]],
        colWidths=[170 * mm],
        rowHeights=[25 * mm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), TEAL),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ])
    ))

    story.append(Spacer(1, 14))

    # Consultant sign-off
    story.append(Table(
        [[
            Table(
                [
                    [Paragraph("Prepared by:", styles["Body_Bold"])],
                    [Paragraph("Sandy Lukita", ParagraphStyle(
                        "SN", fontSize=12, textColor=NAVY,
                        fontName="Helvetica-Bold"
                    ))],
                    [Paragraph("IT & OT Security Consultant", styles["Body"])],
                    [Paragraph("PT Optima Sarana Instrument", styles["Body"])],
                    [Paragraph(f"Date: {client_data['report_date']}", styles["Body"])],
                ],
                colWidths=[85 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LINEABOVE", (0, 0), (-1, 0), 3, TEAL),
                ])
            ),
            Table(
                [
                    [Paragraph("Contact:", styles["Body_Bold"])],
                    [Paragraph("sandylukita@gmail.com", styles["Body"])],
                    [Spacer(1, 6)],
                    [Paragraph("This report is valid for 90 days from issue date.", styles["Caption"])],
                    [Paragraph(
                        "PT Optima Sarana Instrument provides no warranty "
                        "beyond the scope defined herein.",
                        styles["Caption"]
                    )],
                ],
                colWidths=[85 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LINEABOVE", (0, 0), (-1, 0), 3, NAVY),
                ])
            ),
        ]],
        colWidths=[85 * mm, 85 * mm],
        style=TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, WHITE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    ))


# ─────────────────────────────────────────────
# Main Generator
# ─────────────────────────────────────────────

def generate_report(client_data: dict, output_path: str):
    """
    Generate complete IEC 62443 compliance report as PDF

    Args:
        client_data: dict with client info
        output_path: path to save PDF
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"OT Security Assessment — {client_data.get('client_name', 'Client')}",
        author="Sandy Lukita | PT Optima Sarana Instrument",
        subject="IEC 62443 Compliance Assessment Report"
    )

    styles = build_styles()
    story = []

    # Calculate compliance score
    compliance_score = calculate_compliance_score(FINDING_TO_IEC)

    # Build all sections
    build_cover(story, client_data, styles)
    build_executive_summary(story, client_data, compliance_score, styles)
    build_findings(story, styles)
    build_compliance_map(story, styles)
    build_roadmap(story, styles)
    build_bahasa_summary(story, client_data, compliance_score, styles)

    # Build PDF
    doc.build(story)
    print(f"\n[OK] Report generated: {output_path}")
    print(f"   Client: {client_data['client_name']}")
    print(f"   Compliance Score: {compliance_score['overall_score']}%")
    print(f"   Security Level: {compliance_score['security_level']}")
    print(f"   Total findings: {len(FINDING_TO_IEC)}")


# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────

if __name__ == "__main__":
    client_data = {
        "client_name": "PT Nusantara Instrumen",
        "consultant": "Sandy Lukita",
        "consulting_firm": "PT Optima Sarana Instrument",
        "report_date": datetime.now().strftime("%d %B %Y"),
        "scope": "IT/OT Security Assessment — Office & Field Site",
        "period": "July 2026",
        "risk_level": "CRITICAL",
        "contract_requirement": "PT Energi Nusantara — Q1 2027 Compliance Deadline",
    }

    generate_report(client_data, "/home/claude/securebridge_compliance_report.pdf")
