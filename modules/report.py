import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

RISK_COLOURS = {
    "HIGH":   "#c0392b",
    "MEDIUM": "#f39c12",
    "LOW":    "#27ae60",
    "INFO":   "#2980b9",
}

RISK_BG = {
    "HIGH":   "#fdf0f0",
    "MEDIUM": "#fefdf0",
    "LOW":    "#f0fdf4",
    "INFO":   "#f0f8ff",
}

def generate_report(audit_data=None, phishing_data=None, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    env      = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"securecheck_report_{timestamp}.html"
    filepath  = os.path.join(output_dir, filename)
    html = template.render(
        audit=audit_data,
        phishing=phishing_data,
        risk_colours=RISK_COLOURS,
        risk_bg=RISK_BG,
        generated_at=datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
        has_audit=audit_data is not None,
        has_phishing=phishing_data is not None,
    )
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n✅ Report saved: {filepath}")
    return filepath

def generate_pdf_report(audit_data=None, phishing_data=None, output_dir="output"):
    """
    Generates a PDF version of the scan report using reportlab.

    reportlab works by drawing content onto a Canvas — a virtual
    page. Unlike HTML, there is no automatic layout engine — we
    manually specify X/Y coordinates for everything.

    Key reportlab concepts:
      canvas.drawString(x, y, text) — draws text at coordinates.
      Coordinates start from BOTTOM-LEFT (0,0). Page height is
      letter[1] = 792 points for US Letter size.
      We track a cursor variable 'y' and decrement it as we
      add content, starting from the top.

      canvas.setFillColor() — sets text/fill colour.
      canvas.setFont(name, size) — sets active font.
      canvas.rect(x, y, w, h, fill=1) — draws a rectangle.
      canvas.showPage() — finalises current page, starts a new one.
      canvas.save() — writes the PDF to disk.

    Points vs pixels: reportlab uses points (1 point = 1/72 inch).
    A US Letter page is 612 x 792 points.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.units import inch
    import os
    from datetime import datetime

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"securecheck_report_{timestamp}.pdf"
    filepath  = os.path.join(output_dir, filename)

    PAGE_W, PAGE_H = letter  # 612 x 792 points
    MARGIN         = 48
    CONTENT_W      = PAGE_W - (MARGIN * 2)

    # Colours
    COL_DARK   = colors.HexColor("#0d2d4f")
    COL_RED    = colors.HexColor("#c0392b")
    COL_YELLOW = colors.HexColor("#f39c12")
    COL_GREEN  = colors.HexColor("#27ae60")
    COL_BLUE   = colors.HexColor("#2980b9")
    COL_WHITE  = colors.white
    COL_LIGHT  = colors.HexColor("#f4f4f4")
    COL_GRAY   = colors.HexColor("#666666")
    COL_TEXT   = colors.HexColor("#222222")

    RISK_COLS = {
        "HIGH":   COL_RED,
        "MEDIUM": COL_YELLOW,
        "LOW":    COL_GREEN,
        "INFO":   COL_BLUE,
    }

    c   = rl_canvas.Canvas(filepath, pagesize=letter)
    y   = PAGE_H - MARGIN

    def check_page_break(needed=60):
        """Start a new page if we don't have enough vertical space."""
        nonlocal y
        if y < needed + MARGIN:
            c.showPage()
            y = PAGE_H - MARGIN
            draw_page_header()

    def draw_page_header():
        """Draws a small header bar at the top of continuation pages."""
        nonlocal y
        c.setFillColor(COL_DARK)
        c.rect(0, PAGE_H - 28, PAGE_W, 28, fill=1, stroke=0)
        c.setFillColor(COL_WHITE)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN, PAGE_H - 18, "SecureCheck — Security Report")
        c.setFillColor(COL_TEXT)

    def draw_finding(finding):
        """Draws a single risk-rated finding card."""
        nonlocal y
        check_page_break(70)

        risk    = finding.get("risk", "INFO")
        colour  = RISK_COLS.get(risk, COL_BLUE)
        check   = finding.get("check", finding.get("detail", "Finding"))
        explain = finding.get("explanation", "")

        # Card background
        card_h = 52
        c.setFillColor(colors.HexColor("#f9f9f9"))
        c.setStrokeColor(colour)
        c.setLineWidth(0.5)
        c.roundRect(MARGIN, y - card_h, CONTENT_W, card_h,
                    4, fill=1, stroke=1)

        # Risk badge
        c.setFillColor(colour)
        c.roundRect(MARGIN + 6, y - card_h + 6,
                    52, 18, 3, fill=1, stroke=0)
        c.setFillColor(COL_WHITE)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(MARGIN + 32, y - card_h + 13, risk)

        # Finding title
        c.setFillColor(COL_TEXT)
        c.setFont("Helvetica-Bold", 9)
        # Truncate long titles
        title = check[:72] + "..." if len(check) > 72 else check
        c.drawString(MARGIN + 66, y - card_h + 30, title)

        # Explanation
        c.setFont("Helvetica", 8)
        c.setFillColor(COL_GRAY)
        exp = explain[:100] + "..." if len(explain) > 100 else explain
        c.drawString(MARGIN + 66, y - card_h + 14, exp)

        y -= card_h + 6

    # ── COVER PAGE ──────────────────────────────────────────────────────
    # Dark header block
    c.setFillColor(COL_DARK)
    c.rect(0, PAGE_H - 140, PAGE_W, 140, fill=1, stroke=0)

    c.setFillColor(COL_RED)
    c.rect(0, PAGE_H - 144, PAGE_W, 4, fill=1, stroke=0)

    c.setFillColor(COL_WHITE)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(MARGIN, PAGE_H - 60, "SecureCheck")

    c.setFont("Helvetica", 14)
    c.setFillColor(colors.HexColor("#8db4d8"))
    c.drawString(MARGIN, PAGE_H - 82, "Security Audit & Phishing Analysis Report")

    c.setFont("Helvetica", 10)
    c.drawString(MARGIN, PAGE_H - 104,
                 f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}")

    y = PAGE_H - 165

    # ── KPI SUMMARY ─────────────────────────────────────────────────────
    kpis = []
    if audit_data:
        s = audit_data["summary"]
        kpis += [
            (str(s["high"]),   "HIGH Risk",     COL_RED),
            (str(s["medium"]), "MEDIUM Risk",   COL_YELLOW),
            (str(s["total"]),  "Audit Findings",COL_BLUE),
        ]
    if phishing_data and "error" not in phishing_data:
        kpis.append((
            f"{phishing_data['score']}/100",
            "Phishing Score",
            COL_RED if phishing_data["score"] >= 51 else
            (COL_YELLOW if phishing_data["score"] >= 26 else COL_GREEN)
        ))

    if kpis:
        box_w  = CONTENT_W / len(kpis) - 8
        box_h  = 60
        for i, (val, label, colour) in enumerate(kpis):
            bx = MARGIN + i * (box_w + 8)
            c.setFillColor(colors.HexColor("#f0f4f8"))
            c.setStrokeColor(colour)
            c.setLineWidth(1)
            c.roundRect(bx, y - box_h, box_w, box_h, 4, fill=1, stroke=1)
            c.setFillColor(colour)
            c.setFont("Helvetica-Bold", 20)
            c.drawCentredString(bx + box_w / 2, y - 30, val)
            c.setFillColor(COL_GRAY)
            c.setFont("Helvetica", 8)
            c.drawCentredString(bx + box_w / 2, y - 46, label)
        y -= box_h + 20

    # ── AUDIT FINDINGS ───────────────────────────────────────────────────
    if audit_data:
        check_page_break(80)

        c.setFillColor(COL_DARK)
        c.rect(MARGIN, y - 26, CONTENT_W, 26, fill=1, stroke=0)
        c.setFillColor(COL_WHITE)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN + 10, y - 17, "Security Audit Findings")
        y -= 34

        # System info
        si = audit_data["system_info"]
        c.setFillColor(colors.HexColor("#f0f4f8"))
        c.rect(MARGIN, y - 36, CONTENT_W, 36, fill=1, stroke=0)
        c.setFillColor(COL_TEXT)
        c.setFont("Helvetica", 9)
        c.drawString(MARGIN + 8, y - 14,
                     f"Host: {si['hostname']}  |  IP: {si['local_ip']}  "
                     f"|  OS: {si['os']} {si['os_version']}  "
                     f"|  Scanned: {si['scan_time']}")
        y -= 44

        for finding in audit_data.get("all_findings", []):
            draw_finding(finding)

    # ── PHISHING FINDINGS ────────────────────────────────────────────────
    if phishing_data and "error" not in phishing_data:
        check_page_break(80)
        c.showPage()
        y = PAGE_H - MARGIN
        draw_page_header()
        y -= 20

        c.setFillColor(COL_DARK)
        c.rect(MARGIN, y - 26, CONTENT_W, 26, fill=1, stroke=0)
        c.setFillColor(COL_WHITE)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN + 10, y - 17, "Phishing Email Analysis")
        y -= 34

        score      = phishing_data["score"]
        score_col  = (COL_RED if score >= 51 else
                      (COL_YELLOW if score >= 26 else COL_GREEN))
        c.setFillColor(colors.HexColor("#f0f4f8"))
        c.rect(MARGIN, y - 50, CONTENT_W, 50, fill=1, stroke=0)
        c.setFillColor(score_col)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(MARGIN + 12, y - 32, f"{score}/100")
        c.setFillColor(COL_TEXT)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN + 80, y - 22, phishing_data["risk_label"])
        c.setFont("Helvetica", 9)
        c.setFillColor(COL_GRAY)
        c.drawString(MARGIN + 80, y - 36,
                     f"From: {phishing_data['from'][:60]}")
        y -= 58

        for finding in phishing_data.get("findings", []):
            draw_finding(finding)

    # ── FOOTER ────────────────────────────────────────────────────────────
    c.showPage()
    c.setFillColor(COL_DARK)
    c.rect(0, 0, PAGE_W, 36, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#4a7aaa"))
    c.setFont("Helvetica", 8)
    c.drawCentredString(PAGE_W / 2, 14,
                        "SecureCheck  ·  Juan Lacia  ·  2026  "
                        "·  github.com/el-vagabundoooo/SecureCheck")

    c.save()
    print(f"\n✅ PDF report saved: {filepath}")
    return filepath