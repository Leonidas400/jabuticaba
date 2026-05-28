"""
PDF Report Generator — FortiGate CIS Benchmark
Professional multi-page report using ReportLab
"""

import io
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# ── PALETTE ──────────────────────────────────────────────────
C_BG        = colors.HexColor("#0a0e17")
C_PANEL     = colors.HexColor("#0f1623")
C_ACCENT    = colors.HexColor("#00d4ff")
C_ACCENT2   = colors.HexColor("#ff6b2b")
C_TEXT      = colors.HexColor("#c8d8ea")
C_MUTED     = colors.HexColor("#4a6080")
C_PASS      = colors.HexColor("#22c55e")
C_FAIL      = colors.HexColor("#ef4444")
C_WARN      = colors.HexColor("#f59e0b")
C_CRIT      = colors.HexColor("#dc2626")
C_HIGH      = colors.HexColor("#ef4444")
C_MED       = colors.HexColor("#f59e0b")
C_LOW       = colors.HexColor("#6366f1")
C_WHITE     = colors.white
C_BORDER    = colors.HexColor("#1e2d45")

SEV_COLORS = {"Critical": C_CRIT, "High": C_HIGH, "Medium": C_MED, "Low": C_LOW}
STATUS_COLORS = {"PASS": C_PASS, "FAIL": C_FAIL}

W, H = A4


def _sev_color(sev):
    return SEV_COLORS.get(sev, C_MUTED)


def _risk_color(level):
    m = {"BAIXO": C_PASS, "MÉDIO": C_WARN, "ALTO": C_FAIL, "CRÍTICO": C_CRIT}
    return m.get(level, C_MUTED)


# ── PAGE TEMPLATE ─────────────────────────────────────────────
def _on_page(canvas, doc, company, timestamp, benchmark):
    canvas.saveState()
    # Background
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)

    # Top bar
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, H - 18*mm, W, 18*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, H - 18*mm, W, 0.8*mm, fill=1, stroke=0)

    # Header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_ACCENT)
    canvas.drawString(20*mm, H - 12*mm, "FORTIGATE CIS BENCHMARK REPORT")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawRightString(W - 20*mm, H - 12*mm, company)

    # Footer
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(C_BORDER)
    canvas.rect(0, 12*mm, W, 0.4*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(20*mm, 4*mm, f"{benchmark}  ·  Gerado em {timestamp}")
    canvas.drawRightString(W - 20*mm, 4*mm, f"Página {doc.page}")

    canvas.restoreState()


# ── SCORE DONUT DRAWING ───────────────────────────────────────
def _score_donut(score, risk_level):
    d = Drawing(120, 120)
    cx, cy, r_outer, r_inner = 60, 60, 52, 36

    # Background ring
    d.add(Circle(cx, cy, r_outer, fillColor=C_BORDER, strokeColor=None))
    d.add(Circle(cx, cy, r_inner, fillColor=C_BG, strokeColor=None))

    # Score text
    rc = _risk_color(risk_level)
    d.add(String(cx, cy + 6, str(score), fontSize=22, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    d.add(String(cx, cy - 8, "/ 100", fontSize=8, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    d.add(String(cx, cy - 20, risk_level, fontSize=7, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    return d


# ── CATEGORY BAR CHART ────────────────────────────────────────
def _category_chart(by_category):
    cats = list(by_category.keys())
    scores = [by_category[c]["score"] for c in cats]
    short = [c.replace(" & ", "\n").replace(" ", "\n") if len(c) > 14 else c for c in cats]

    w, h = 460, 160
    d = Drawing(w, h)

    bar_w = w / max(len(cats), 1) * 0.55
    gap   = w / max(len(cats), 1)

    for i, (score, label) in enumerate(zip(scores, short)):
        x = gap * i + gap * 0.22
        bar_h = max(4, score / 100 * 110)
        col = C_PASS if score >= 85 else (C_WARN if score >= 65 else C_FAIL)
        d.add(Rect(x, 20, bar_w, bar_h, fillColor=col, strokeColor=None))
        d.add(String(x + bar_w / 2, bar_h + 24, f"{score}%",
                     fontSize=7, fontName="Helvetica-Bold", fillColor=C_TEXT, textAnchor="middle"))
        for line_no, line in enumerate(label.split("\n")):
            d.add(String(x + bar_w / 2, 14 - line_no * 8, line,
                         fontSize=6, fontName="Helvetica", fillColor=C_MUTED, textAnchor="middle"))
    return d


# ── SEVERITY PIE ──────────────────────────────────────────────
def _severity_pie(by_severity):
    d = Drawing(140, 100)
    fails = [(sev, by_severity[sev]["fail"]) for sev in ["Critical", "High", "Medium", "Low"] if by_severity[sev]["fail"] > 0]
    if not fails:
        d.add(Circle(50, 50, 40, fillColor=C_PASS, strokeColor=None))
        d.add(String(50, 46, "100%", fontSize=10, fontName="Helvetica-Bold",
                     fillColor=C_WHITE, textAnchor="middle"))
        return d

    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 5, 10, 80, 80
    pie.data = [f[1] for f in fails]
    pie.labels = [f[0] for f in fails]
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = C_BG
    for i, (sev, _) in enumerate(fails):
        pie.slices[i].fillColor = _sev_color(sev)
    d.add(pie)

    # Legend
    ly = 90
    for i, (sev, cnt) in enumerate(fails):
        lx = 95
        dy = ly - i * 14
        d.add(Rect(lx, dy, 8, 8, fillColor=_sev_color(sev), strokeColor=None))
        d.add(String(lx + 11, dy + 1, f"{sev}: {cnt}", fontSize=7,
                     fontName="Helvetica", fillColor=C_WHITE))
    return d


# ── MAIN BUILDER ─────────────────────────────────────────────
def generate_pdf(data: dict) -> bytes:
    company   = data.get("company", "Organização")
    benchmark = data.get("benchmark", "CIS FortiGate 7.0 Benchmark v1.3.0")
    ts_raw    = data.get("timestamp", datetime.utcnow().isoformat())
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "")).strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        ts = ts_raw
    risk    = data["risk"]
    checks  = data["checks"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=24*mm, bottomMargin=18*mm,
        title=f"CIS Report — {company}",
        author="FortiGate CIS Analyzer",
    )

    on_page = lambda c, d: _on_page(c, d, company, ts, benchmark)

    # ── STYLES ────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    s_h1   = S("h1",   fontSize=22, fontName="Helvetica-Bold",   textColor=C_ACCENT, spaceBefore=14, spaceAfter=15)
    s_h2   = S("h2",   fontSize=14, fontName="Helvetica-Bold",   textColor=C_TEXT,    spaceBefore=14, spaceAfter=10)
    s_h3   = S("h3",   fontSize=10, fontName="Helvetica-Bold",   textColor=C_ACCENT,  spaceBefore=8,  spaceAfter=10)
    s_body = S("body", fontSize=9,  fontName="Helvetica",        textColor=C_TEXT,    leading=14)
    s_muted= S("mut",  fontSize=8,  fontName="Helvetica",        textColor=C_MUTED)
    s_mono = S("mono", fontSize=8,  fontName="Courier",          textColor=C_ACCENT,  backColor=C_PANEL, leftIndent=6, rightIndent=6)
    s_ctr  = S("ctr",  fontSize=9,  fontName="Helvetica",        textColor=C_TEXT,    alignment=TA_CENTER)

    story = []

    # ════════════════════════════════════════════
    # COVER PAGE
    # ════════════════════════════════════════════
    story.append(Spacer(1, 18*mm))

    # Title block
    story.append(Paragraph("🛡️ FortiGate CIS Benchmark", s_h1))
    story.append(Paragraph("Relatório de Análise de Segurança", S("sub", fontSize=16,
        fontName="Helvetica", textColor=C_TEXT, spacebefore=10, spaceAfter=10)))
    story.append(Spacer(1, 2*mm))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT))
    story.append(Spacer(1, 6*mm))

    # Meta info table
    meta = [
        ["Empresa",    company],
        ["Benchmark",  benchmark],
        ["Data/Hora",  ts],
        ["Total de Controles", str(risk["total_checks"])],
    ]
    meta_t = Table(meta, colWidths=[50*mm, 120*mm])
    meta_t.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 9),
        ("TEXTCOLOR", (0,0), (0,-1), C_MUTED),
        ("TEXTCOLOR", (1,0), (1,-1), C_TEXT),
        ("FONTNAME",  (1,0), (1,-1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_PANEL, C_BG]),
        ("TOPPADDING",  (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 10*mm))

    # Score + donut side by side
    rc = _risk_color(risk["risk_level"])
    score_info = [
        [_score_donut(risk["score"], risk["risk_level"]),
         Table([
             [Paragraph(f'<font color="#{rc.hexval()[2:]}"><b>{risk["risk_level"]}</b></font>',
                        S("rl", fontSize=28, fontName="Helvetica-Bold", textColor=rc, spaceAfter=35*mm))],
             [Spacer(1, 8 * mm)],
             [Paragraph(f'<font color="#4a6080">{risk["passed"]} aprovados  ·  {risk["failed"]} reprovados  ·  {risk["total_checks"]} total</font>',
                        S("sm", fontSize=9, fontName="Helvetica", textColor=C_MUTED, spaceBefore=15*mm))],
         ], colWidths=[100*mm])
        ]
    ]
    score_t = Table(score_info, colWidths=[40*mm, 120*mm])
    score_t.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(score_t)

    # Severity summary boxes
    story.append(Spacer(1, 8*mm))
    sev_data = []
    sev_row  = []
    for sev in ["Critical", "High", "Medium", "Low"]:
        s = risk["by_severity"].get(sev, {})
        sc = _sev_color(sev)
        cell = Table([
            [Paragraph(sev.upper(), S(f"s{sev}", fontSize=7, fontName="Helvetica-Bold",
                                      textColor=sc, alignment=TA_CENTER))],
            [Paragraph(str(s.get("fail", 0)), S(f"sv{sev}", fontSize=20, fontName="Helvetica-Bold",
                                                 textColor=sc, alignment=TA_CENTER))],
            [Paragraph(f'de {s.get("total",0)}', S("sm2", fontSize=7, fontName="Helvetica",
                                                     textColor=C_MUTED, alignment=TA_CENTER))],
        ], colWidths=[38*mm])
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_PANEL),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("ROUNDEDCORNERS", [6]),
        ]))
        sev_row.append(cell)
    sev_row_t = Table([sev_row], colWidths=[40*mm]*4, hAlign="LEFT")
    sev_row_t.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),2),("RIGHTPADDING",(0,0),(-1,-1),2)]))
    story.append(sev_row_t)

    story.append(PageBreak())

    # ════════════════════════════════════════════
    # PAGE 2 — CHARTS
    # ════════════════════════════════════════════
    story.append(Paragraph("Análise por Domínio", s_h2))
    story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
    story.append(Spacer(1, 4*mm))
    story.append(_category_chart(risk["by_category"]))
    story.append(Spacer(1, 8*mm))

    # Category table
    story.append(Paragraph("Score por Domínio CIS", s_h3))
    cat_rows = [["Domínio", "Total", "Aprovados", "Reprovados", "Score"]]
    for cat, d in risk["by_category"].items():
        sc = d["score"]
        col = "#22c55e" if sc >= 85 else ("#f59e0b" if sc >= 65 else "#ef4444")
        cat_rows.append([
            Paragraph(cat, S("ct", fontSize=8, fontName="Helvetica", textColor=C_TEXT)),
            str(d["total"]),
            Paragraph(str(d["pass"]), S("p", fontSize=8, fontName="Helvetica-Bold", textColor=C_PASS)),
            Paragraph(str(d["fail"]), S("f", fontSize=8, fontName="Helvetica-Bold", textColor=C_FAIL)),
            Paragraph(f'{sc}%', S("s", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor(col))),
        ])
    cat_t = Table(cat_rows, colWidths=[80*mm, 22*mm, 28*mm, 28*mm, 22*mm])
    cat_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_ACCENT),
        ("TEXTCOLOR",     (0,0), (-1,0), C_BG),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_PANEL, C_BG]),
        ("TEXTCOLOR",     (1,1), (-2,-1), C_TEXT),
        ("FONTNAME",      (1,1), (-2,-1), "Helvetica"),
        ("FONTSIZE",      (1,1), (-2,-1), 8),
        ("ALIGN",         (1,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (0,-1),  8),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
    ]))
    story.append(cat_t)

    # Severity breakdown chart
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("Distribuição de Falhas por Severidade", s_h3))
    story.append(_severity_pie(risk["by_severity"]))

    story.append(PageBreak())

    # ════════════════════════════════════════════
    # PAGE 3+ — DETAILED CHECKS
    # ════════════════════════════════════════════
    story.append(Paragraph("Detalhamento dos Controles CIS", s_h2))
    story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
    story.append(Spacer(1, 4*mm))

    # Group by category
    from itertools import groupby
    sorted_checks = sorted(checks, key=lambda x: (x["category"], x["id"]))
    from itertools import groupby as gb
    for cat, group in gb(sorted_checks, key=lambda x: x["category"]):
        story.append(Paragraph(cat, s_h3))
        rows = [["ID", "Controle", "Status", "Detalhe", "Sev."]]
        for c in group:
            sc = _sev_color(c["severity"])
            stc = C_PASS if c["status"] == "PASS" else C_FAIL
            rows.append([
                Paragraph(c["id"], S("id", fontSize=7, fontName="Courier", textColor=C_MUTED)),
                Paragraph(c["title"], S("tt", fontSize=8, fontName="Helvetica", textColor=C_TEXT)),
                Paragraph(c["status"], S("st", fontSize=7, fontName="Helvetica-Bold", textColor=stc)),
                Paragraph(c["detail"][:80] + ("…" if len(c["detail"]) > 80 else ""),
                          S("dt", fontSize=7, fontName="Helvetica", textColor=C_MUTED)),
                Paragraph(c["severity"], S("sv", fontSize=7, fontName="Helvetica-Bold", textColor=sc)),

            ])
        t = Table(rows, colWidths=[12*mm, 60*mm, 14*mm, 66*mm,  18*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_ACCENT),
            ("TEXTCOLOR",     (0,0), (-1,0), C_BG),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_PANEL, C_BG]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        story.append(KeepTogether([t, Spacer(1, 4*mm)]))

    # ── FAILED CHECKS — RECOMMENDATIONS ─────────────────────
    failed = [c for c in checks if c["status"] == "FAIL"]
    if failed:
        story.append(PageBreak())
        story.append(Paragraph("Plano de Remediação", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(
            "Os controles abaixo falharam na análise. Implemente as recomendações em ordem de severidade.",
            s_body))
        story.append(Spacer(1, 4*mm))

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        for c in sorted(failed, key=lambda x: sev_order.get(x["severity"], 9)):
            sc = _sev_color(c["severity"])
            block = KeepTogether([
                Table([[
                    Paragraph(f'[{c["id"]}] {c["title"]}',
                              S("ft", fontSize=9, fontName="Helvetica-Bold", textColor=C_TEXT)),
                    Paragraph(c["severity"],
                              S("ftsev", fontSize=8, fontName="Helvetica-Bold",
                                textColor=sc, alignment=TA_RIGHT)),
                ]], colWidths=[140*mm, 30*mm]),
                Paragraph(c["description"], S("fd", fontSize=8, fontName="Helvetica",
                                               textColor=C_MUTED, leftIndent=6)),
                Spacer(1, 2*mm),
                Paragraph("→ " + c["recommendation"],
                          S("fr", fontSize=8, fontName="Courier", textColor=C_ACCENT, leftIndent=6)),
                HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=4),
                Spacer(1, 2*mm),
            ])
            story.append(block)

    # Build
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
