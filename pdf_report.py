"""
pdf_report.py — CIS Analyzer v4 — Multi-vendor PDF Report
Theme-aware: dark (teal), light (clean), modern (indigo).
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics.charts.piecharts import Pie

W, H = A4
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ── THEME PALETTES ──────────────────────────────────────────
def _palette(theme: str) -> dict:
    if theme == "light":
        return dict(
            bg=colors.HexColor("#f0f4f7"),
            bg2=colors.HexColor("#ffffff"),
            panel=colors.HexColor("#f5f8fa"),
            accent=colors.HexColor("#1a7080"),
            accent2=colors.HexColor("#2295ab"),
            text=colors.HexColor("#111827"),
            text2=colors.HexColor("#374151"),
            muted=colors.HexColor("#6b7280"),
            border=colors.HexColor("#d1dde3"),
            border2=colors.HexColor("#b0c6cf"),
            passc=colors.HexColor("#047857"),
            fail=colors.HexColor("#c81c1c"),
            warn=colors.HexColor("#b45309"),
            crit=colors.HexColor("#991b1b"),
            low=colors.HexColor("#1a7080"),
            header_bg=colors.HexColor("#1a7080"),
            header_text=colors.white,
            row_alt=[colors.HexColor("#ffffff"), colors.HexColor("#f5f8fa")],
            card_bg=colors.HexColor("#ffffff"),
            card_border=colors.HexColor("#d1dde3"),
            bar_bg=colors.HexColor("#e2ebee"),
        )
    elif theme == "modern":
        return dict(
            bg=colors.HexColor("#0f172a"),
            bg2=colors.HexColor("#1e293b"),
            panel=colors.HexColor("#1e293b"),
            accent=colors.HexColor("#6366f1"),
            accent2=colors.HexColor("#818cf8"),
            text=colors.HexColor("#e2e8f0"),
            text2=colors.HexColor("#94a3b8"),
            muted=colors.HexColor("#64748b"),
            border=colors.HexColor("#334155"),
            border2=colors.HexColor("#475569"),
            passc=colors.HexColor("#34d399"),
            fail=colors.HexColor("#f87171"),
            warn=colors.HexColor("#fbbf24"),
            crit=colors.HexColor("#ef4444"),
            low=colors.HexColor("#818cf8"),
            header_bg=colors.HexColor("#6366f1"),
            header_text=colors.white,
            row_alt=[colors.HexColor("#1e293b"), colors.HexColor("#0f172a")],
            card_bg=colors.HexColor("#1e293b"),
            card_border=colors.HexColor("#334155"),
            bar_bg=colors.HexColor("#334155"),
        )
    else:  # dark
        return dict(
            bg=colors.HexColor("#111518"),
            bg2=colors.HexColor("#161b20"),
            panel=colors.HexColor("#161b20"),
            accent=colors.HexColor("#2a8f9e"),
            accent2=colors.HexColor("#38bbd0"),
            text=colors.HexColor("#e0e4e8"),
            text2=colors.HexColor("#8a9aaa"),
            muted=colors.HexColor("#6a7280"),
            border=colors.HexColor("#2a3035"),
            border2=colors.HexColor("#3a4550"),
            passc=colors.HexColor("#22c55e"),
            fail=colors.HexColor("#ef4444"),
            warn=colors.HexColor("#f59e0b"),
            crit=colors.HexColor("#dc2626"),
            low=colors.HexColor("#38bbd0"),
            header_bg=colors.HexColor("#2a8f9e"),
            header_text=colors.HexColor("#111518"),
            row_alt=[colors.HexColor("#161b20"), colors.HexColor("#111518")],
            card_bg=colors.HexColor("#161b20"),
            card_border=colors.HexColor("#2a3035"),
            bar_bg=colors.HexColor("#2a3035"),
        )


def _hex(c):
    return "#" + c.hexval()[2:] if hasattr(c, "hexval") else "#6a7280"


SEV_KEYS = {"Critical": "crit", "High": "fail", "Medium": "warn", "Low": "low"}


def _sev_color(p, sev):
    return p.get(SEV_KEYS.get(sev, "muted"), p["muted"])


def _risk_color(p, level):
    return {"BAIXO": p["passc"], "MÉDIO": p["warn"], "ALTO": p["fail"], "CRÍTICO": p["crit"]}.get(level, p["muted"])


def S(name, **kw):
    return ParagraphStyle(name, **kw)


# ── PAGE TEMPLATE ───────────────────────────────────────────
def _on_page(canvas, doc, p, company, timestamp, benchmark):
    canvas.saveState()
    # Full page background
    canvas.setFillColor(p["bg"])
    canvas.rect(0, 0, W, H, fill=1, stroke=0)

    # Top bar
    canvas.setFillColor(p["panel"])
    canvas.rect(0, H - 16 * mm, W, 16 * mm, fill=1, stroke=0)
    # Accent line
    canvas.setFillColor(p["accent"])
    canvas.rect(0, H - 16 * mm, W, 0.6 * mm, fill=1, stroke=0)
    # Header text
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(p["accent"])
    canvas.drawString(18 * mm, H - 10.5 * mm, "CIS BENCHMARK REPORT")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(p["muted"])
    canvas.drawRightString(W - 18 * mm, H - 10.5 * mm, company)

    # Footer
    canvas.setFillColor(p["panel"])
    canvas.rect(0, 0, W, 11 * mm, fill=1, stroke=0)
    canvas.setFillColor(p["border"])
    canvas.rect(0, 11 * mm, W, 0.3 * mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(p["muted"])
    canvas.drawString(18 * mm, 4 * mm, f"{benchmark}  |  {timestamp}")
    canvas.drawRightString(W - 18 * mm, 4 * mm, f"Pagina {doc.page}")
    canvas.restoreState()


# ── SCORE DONUT ─────────────────────────────────────────────
def _score_donut(p, score, risk_level):
    d = Drawing(130, 130)
    rc = _risk_color(p, risk_level)
    # Outer ring
    d.add(Circle(65, 65, 56, fillColor=p["bar_bg"], strokeColor=None))
    # Inner cutout
    d.add(Circle(65, 65, 40, fillColor=p["bg"], strokeColor=None))
    # Score arc indicator (simplified as colored ring segment)
    d.add(Circle(65, 65, 56, fillColor=None, strokeColor=rc, strokeWidth=6))
    d.add(Circle(65, 65, 43, fillColor=p["bg"], strokeColor=None))
    # Text
    d.add(String(65, 73, str(score), fontSize=28, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    d.add(String(65, 58, "/ 100", fontSize=8, fontName="Helvetica",
                 fillColor=p["muted"], textAnchor="middle"))
    d.add(String(65, 44, risk_level, fontSize=7.5, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    return d


# ── CATEGORY BAR CHART ──────────────────────────────────────
def _category_chart(p, by_category):
    cats = list(by_category.keys())
    scores = [by_category[c]["score"] for c in cats]
    n = max(len(cats), 1)
    w, h = 460, 170
    d = Drawing(w, h)
    gap = w / n
    bar_w = gap * 0.52

    # Background grid lines
    for pct in [25, 50, 75, 100]:
        y = 28 + (pct / 100) * 115
        d.add(Line(0, y, w, y, strokeColor=p["border"], strokeWidth=0.3))
        d.add(String(w + 2, y - 3, f"{pct}", fontSize=5, fontName="Helvetica",
                     fillColor=p["muted"]))

    for i, (score, cat) in enumerate(zip(scores, cats)):
        x = gap * i + gap * 0.24
        bar_h = max(5, score / 100 * 115)
        col = p["passc"] if score >= 85 else (p["warn"] if score >= 65 else p["fail"])

        # Bar shadow
        d.add(Rect(x + 1, 27, bar_w, bar_h, fillColor=colors.HexColor("#00000033"),
                   strokeColor=None))
        # Bar
        d.add(Rect(x, 28, bar_w, bar_h, fillColor=col, strokeColor=None, rx=2, ry=2))
        # Score label
        d.add(String(x + bar_w / 2, bar_h + 32, f"{score}%",
                     fontSize=7, fontName="Helvetica-Bold", fillColor=p["text"], textAnchor="middle"))
        # Category label
        label = cat[:16] + "..." if len(cat) > 16 else cat
        for ln, line in enumerate(label.replace(" & ", "\n").replace(" ", "\n").split("\n")):
            d.add(String(x + bar_w / 2, 18 - ln * 8, line,
                         fontSize=5.5, fontName="Helvetica", fillColor=p["muted"], textAnchor="middle"))
    return d


# ── SEVERITY PIE ────────────────────────────────────────────
def _severity_pie(p, by_severity):
    d = Drawing(220, 120)
    fails = [(sev, by_severity[sev]["fail"]) for sev in ["Critical", "High", "Medium", "Low"]
             if by_severity.get(sev, {}).get("fail", 0) > 0]

    if not fails:
        d.add(Circle(60, 60, 50, fillColor=p["passc"], strokeColor=None))
        d.add(String(60, 56, "100%", fontSize=13, fontName="Helvetica-Bold",
                     fillColor=colors.white, textAnchor="middle"))
        return d

    pie = Pie()
    pie.x, pie.y = 8, 12
    pie.width = pie.height = 96
    pie.data = [f[1] for f in fails]
    pie.labels = [""] * len(fails)
    pie.slices.strokeWidth = 1
    pie.slices.strokeColor = p["bg"]
    for i, (sev, _) in enumerate(fails):
        pie.slices[i].fillColor = _sev_color(p, sev)
    d.add(pie)

    for i, (sev, cnt) in enumerate(fails):
        lx, dy = 118, 98 - i * 20
        d.add(Rect(lx, dy, 10, 10, fillColor=_sev_color(p, sev), strokeColor=None, rx=2, ry=2))
        d.add(String(lx + 14, dy + 1, f"{sev}: {cnt} falha(s)", fontSize=7.5,
                     fontName="Helvetica", fillColor=p["text"]))
    return d


# ── SEVERITY SUMMARY CARDS ──────────────────────────────────
def _sev_cards(p, risk):
    s_lbl = S("s_lbl", fontSize=6.5, fontName="Helvetica-Bold", textColor=p["muted"], alignment=TA_CENTER)
    s_val = S("s_val", fontSize=20, fontName="Helvetica-Bold", textColor=p["muted"], alignment=TA_CENTER)
    s_tot = S("s_tot", fontSize=6.5, fontName="Helvetica", textColor=p["muted"], alignment=TA_CENTER)

    cells = []
    for sev in ["Critical", "High", "Medium", "Low"]:
        s = risk.get("by_severity", {}).get(sev, {})
        sc = _sev_color(p, sev)
        h = _hex(sc)
        cell = Table([
            [Paragraph(f'<font color="{h}"><b>{sev.upper()}</b></font>', s_lbl)],
            [Paragraph(f'<font color="{h}"><b>{s.get("fail", 0)}</b></font>', s_val)],
            [Paragraph(f'de {s.get("total", 0)}', s_tot)],
        ], colWidths=[38 * mm])
        cell.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), p["card_bg"]),
            ("BOX", (0, 0), (-1, -1), 0.5, p["card_border"]),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        cells.append(cell)

    t = Table([cells], colWidths=[40 * mm] * 4, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


# ── MAIN ────────────────────────────────────────────────────
def generate_pdf(data: dict) -> bytes:
    theme = data.get("theme", "dark")
    p = _palette(theme)

    company = data.get("company", "Organizacao")
    vendor_nm = data.get("vendor_name", data.get("vendor", "Firewall").title())
    benchmark = data.get("benchmark", f"{vendor_nm} CIS Benchmark")
    ts_raw = data.get("timestamp", datetime.utcnow().isoformat())
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "")).strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        ts = ts_raw

    risk = data.get("risk", {})
    checks = (data.get("cis_checks") or []) + (data.get("rule_checks") or [])
    if not checks:
        checks = data.get("checks", [])
    for c in checks:
        if "id" not in c:
            c["id"] = c.get("cid", "")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=22 * mm, bottomMargin=16 * mm,
        title=f"CIS Report - {company}",
        author="CIS Analyzer v4",
    )
    on_page = lambda c, d: _on_page(c, d, p, company, ts, benchmark)

    # Styles
    s_h1 = S("h1", fontSize=22, fontName="Helvetica-Bold", textColor=p["accent"], spaceAfter=4)
    s_h1sub = S("h1sub", fontSize=14, fontName="Helvetica", textColor=p["text"], spaceAfter=2)
    s_h2 = S("h2", fontSize=13, fontName="Helvetica-Bold", textColor=p["text"], spaceBefore=14, spaceAfter=6)
    s_h3 = S("h3", fontSize=10, fontName="Helvetica-Bold", textColor=p["accent"], spaceBefore=10, spaceAfter=5)
    s_body = S("body", fontSize=9, fontName="Helvetica", textColor=p["text"], leading=14)
    s_cid = S("s_cid", fontSize=6.5, fontName="Courier", textColor=p["muted"])
    s_tt = S("s_tt", fontSize=8, fontName="Helvetica", textColor=p["text"], leading=11)
    s_dt = S("s_dt", fontSize=7, fontName="Helvetica", textColor=p["muted"], leading=10)
    s_fd = S("s_fd", fontSize=8, fontName="Helvetica", textColor=p["text2"], leftIndent=6, leading=12)
    s_fr = S("s_fr", fontSize=8, fontName="Courier", textColor=p["accent"], leftIndent=6, leading=12)

    story = []

    # ── COVER PAGE ──────────────────────────────────────────
    story.append(Spacer(1, 20 * mm))

    # Title block
    story.append(Paragraph(f"{vendor_nm} CIS Benchmark", s_h1))
    story.append(Paragraph("Relatorio de Analise de Seguranca", s_h1sub))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", thickness=1.2, color=p["accent"]))
    story.append(Spacer(1, 8 * mm))

    # Meta info — styled cards
    meta_data = [
        ["Empresa", company],
        ["Benchmark", benchmark],
        ["Data/Hora", ts],
        ["Fonte", data.get("version_label", "API Live")],
        ["Total de Controles", str(risk.get("total_checks", len(checks)))],
    ]
    meta_t = Table(meta_data, colWidths=[45 * mm, 125 * mm])
    meta_t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), p["muted"]),
        ("TEXTCOLOR", (1, 0), (1, -1), p["text"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), p["row_alt"]),
        ("BOX", (0, 0), (-1, -1), 0.5, p["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, p["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 12 * mm))

    # Score donut + risk level
    rc = _risk_color(p, risk.get("risk_level", ""))
    rch = _hex(rc)
    score_info = Table([
        [Paragraph(f'<font color="{rch}" size="24"><b>{risk.get("risk_level", "-")}</b></font>',
                   S("rl", fontSize=24, fontName="Helvetica-Bold", textColor=rc))],
        [Spacer(1, 2 * mm)],
        [Paragraph(
            f'<font color="{_hex(p["passc"])}"><b>{risk.get("passed", 0)}</b></font> aprovados  |  '
            f'<font color="{_hex(p["fail"])}"><b>{risk.get("failed", 0)}</b></font> reprovados  |  '
            f'{risk.get("total_checks", 0)} total',
            S("sm", fontSize=9, fontName="Helvetica", textColor=p["muted"]))],
    ], colWidths=[110 * mm])

    score_t = Table([[
        _score_donut(p, risk.get("score", 0), risk.get("risk_level", "")),
        score_info,
    ]], colWidths=[42 * mm, 120 * mm])
    score_t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(score_t)
    story.append(Spacer(1, 10 * mm))

    # Severity cards
    story.append(_sev_cards(p, risk))
    story.append(PageBreak())

    # ── PAGE 2 — CHARTS ─────────────────────────────────────
    story.append(Paragraph("Analise por Dominio", s_h2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=p["accent"]))
    story.append(Spacer(1, 5 * mm))

    by_cat = risk.get("by_category", {})
    if by_cat:
        story.append(_category_chart(p, by_cat))
        story.append(Spacer(1, 10 * mm))

        # Category table
        story.append(Paragraph("Score por Dominio CIS", s_h3))
        cat_rows = [["Dominio", "Total", "Pass", "Fail", "Score"]]
        for cat, dc in by_cat.items():
            sv = dc["score"]
            col = _hex(p["passc"]) if sv >= 85 else (_hex(p["warn"]) if sv >= 65 else _hex(p["fail"]))
            cat_rows.append([
                Paragraph(cat, S("_ct", fontSize=8, fontName="Helvetica", textColor=p["text"])),
                str(dc["total"]),
                Paragraph(f'<font color="{_hex(p["passc"])}"><b>{dc["pass"]}</b></font>',
                          S("_cp", fontSize=8, fontName="Helvetica-Bold", textColor=p["passc"])),
                Paragraph(f'<font color="{_hex(p["fail"])}"><b>{dc["fail"]}</b></font>',
                          S("_cf", fontSize=8, fontName="Helvetica-Bold", textColor=p["fail"])),
                Paragraph(f'<font color="{col}"><b>{sv}%</b></font>',
                          S("_cs", fontSize=8, fontName="Helvetica-Bold", textColor=p["text"])),
            ])
        cat_t = Table(cat_rows, colWidths=[80 * mm, 22 * mm, 28 * mm, 28 * mm, 22 * mm])
        cat_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), p["header_bg"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), p["header_text"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), p["row_alt"]),
            ("TEXTCOLOR", (1, 1), (-2, -1), p["text"]),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (0, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.5, p["border"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, p["border"]),
        ]))
        story.append(cat_t)

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Distribuicao de Falhas por Severidade", s_h3))
    story.append(_severity_pie(p, risk.get("by_severity", {})))
    story.append(PageBreak())

    # ── PAGE 3+ — DETAILED CHECKS ───────────────────────────
    story.append(Paragraph("Detalhamento dos Controles CIS", s_h2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=p["accent"]))
    story.append(Spacer(1, 4 * mm))

    # Summary line
    total = risk.get("total_checks", len(checks))
    passed = risk.get("passed", 0)
    failed_n = risk.get("failed", 0)
    story.append(Paragraph(
        f'<b>{total}</b> controles verificados  |  '
        f'<font color="{_hex(p["passc"])}"><b>{passed} aprovados</b></font>  |  '
        f'<font color="{_hex(p["fail"])}"><b>{failed_n} reprovados</b></font>',
        S("sum", fontSize=9, fontName="Helvetica", textColor=p["text"], spaceAfter=6)))
    story.append(Spacer(1, 3 * mm))

    sorted_checks = sorted(checks, key=lambda x: (x.get("category", ""), str(x.get("cid", ""))))
    current_cat = None
    rows_buffer = []

    def _flush(cat_name, rows):
        if not rows:
            return []
        t = Table(rows, colWidths=[12 * mm, 64 * mm, 20 * mm, 62 * mm, 12 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), p["header_bg"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), p["header_text"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), p["row_alt"]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("BOX", (0, 0), (-1, -1), 0.5, p["border"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, p["border"]),
        ]))
        return [Paragraph(cat_name, s_h3), KeepTogether([t, Spacer(1, 4 * mm)])]

    blocks = []
    for c in sorted_checks:
        cat = c.get("category", "Geral")
        if cat != current_cat:
            blocks += _flush(current_cat or "", rows_buffer)
            current_cat = cat
            rows_buffer = [["ID", "Controle", "Severidade", "Detalhes", "Status"]]

        sc = _sev_color(p, c.get("severity", ""))
        stc = p["passc"] if c.get("status") == "PASS" else p["fail"]
        cur = str(c.get("current_value") or "-")[:30]
        det = str(c.get("detail", ""))
        detail_txt = f'{det[:60]}{"..." if len(det) > 60 else ""}'
        if cur and cur not in ("-", "ausente", "nao encontrado", "off", "on"):
            detail_txt = f"Atual: {cur}\n{detail_txt}"

        rows_buffer.append([
            Paragraph(str(c.get("cid", c.get("id", ""))), s_cid),
            Paragraph(c.get("title", ""), s_tt),
            Paragraph(f'<font color="{_hex(sc)}"><b>{c.get("severity", "")}</b></font>', s_dt),
            Paragraph(detail_txt, s_dt),
            Paragraph(f'<font color="{_hex(stc)}"><b>{c.get("status", "")}</b></font>', s_dt),
        ])

    blocks += _flush(current_cat or "", rows_buffer)
    story += blocks

    # ── REMEDIATION PAGE ────────────────────────────────────
    failed = [c for c in checks if c.get("status") == "FAIL"]
    if failed:
        story.append(PageBreak())
        story.append(Paragraph("Plano de Remediacao", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=p["accent"]))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            "Os controles abaixo falharam na analise. "
            "Implemente as recomendacoes em ordem de severidade.",
            s_body))
        story.append(Spacer(1, 5 * mm))

        for c in sorted(failed, key=lambda x: SEV_ORDER.get(x.get("severity", ""), 9)):
            sc = _sev_color(p, c.get("severity", ""))
            cid = str(c.get("cid", c.get("id", "")))

            # Header row with severity badge
            head_t = Table([[
                Paragraph(f'<font color="{_hex(p["accent"])}"><b>[{cid}]</b></font> {c.get("title", "")}',
                          S("_ft", fontSize=9, fontName="Helvetica-Bold", textColor=p["text"])),
                Paragraph(f'<font color="{_hex(sc)}"><b>{c.get("severity", "")}</b></font>',
                          S("_fs", fontSize=8, fontName="Helvetica-Bold", textColor=sc, alignment=TA_RIGHT)),
            ]], colWidths=[138 * mm, 32 * mm])
            head_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), p["card_bg"]),
                ("BOX", (0, 0), (-1, -1), 0.3, p["border"]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))

            block = KeepTogether([
                head_t,
                Spacer(1, 1 * mm),
                Paragraph(c.get("description", ""), s_fd),
                Spacer(1, 2 * mm),
                Paragraph(f'<font color="{_hex(p["accent"])}">&#9654;</font> {c.get("recommendation", "")}', s_fr),
                Spacer(1, 4 * mm),
            ])
            story.append(block)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
