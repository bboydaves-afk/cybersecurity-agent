"""Convert business template markdown files to styled PDFs using fpdf2 with Unicode support."""

import re
from pathlib import Path
from fpdf import FPDF


# Windows system font path
FONT_DIR = Path("C:/Windows/Fonts")


class TemplatePDF(FPDF):
    """Styled PDF generator with Unicode TTF font support."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)

        # Register Arial Unicode TTF for full Unicode support
        if (FONT_DIR / "arial.ttf").exists():
            self.add_font("ArialUni", "", str(FONT_DIR / "arial.ttf"), uni=True)
            self.add_font("ArialUni", "B", str(FONT_DIR / "arialbd.ttf"), uni=True)
            self.add_font("ArialUni", "I", str(FONT_DIR / "ariali.ttf"), uni=True)
            self.add_font("ArialUni", "BI", str(FONT_DIR / "arialbi.ttf"), uni=True)
            self._ufont = "ArialUni"
        else:
            self._ufont = "Helvetica"

    def ufont(self, style="", size=10):
        """Set the Unicode font."""
        self.set_font(self._ufont, style, size)

    def header(self):
        if self.page_no() > 1:
            self.ufont("I", 8)
            self.set_text_color(120, 120, 120)
            half = (self.w - 22) / 2
            self.cell(half, 8, self.title, align="L")
            self.cell(half, 8, f"Page {self.page_no()}", align="R")
            self.ln(5)
            self.set_draw_color(0, 200, 100)
            self.set_line_width(0.3)
            self.line(10, self.get_y(), self.w - 10, self.get_y())
            self.ln(5)

    def footer(self):
        self.set_y(-20)
        self.ufont("I", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, "CONFIDENTIAL", align="C")

    def add_cover_page(self, title: str, subtitle: str = ""):
        self.add_page()
        self.ln(60)

        # Green accent bar
        self.set_fill_color(0, 200, 100)
        self.rect(10, 50, self.w - 20, 3, "F")

        # Title
        self.ufont("B", 26)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 13, title, align="C")
        self.ln(8)

        # Subtitle
        if subtitle:
            self.ufont("", 13)
            self.set_text_color(80, 80, 80)
            self.multi_cell(0, 8, subtitle, align="C")
            self.ln(6)

        # Divider
        self.set_draw_color(0, 200, 100)
        self.set_line_width(0.5)
        y = self.get_y() + 5
        self.line(60, y, self.w - 60, y)
        self.ln(20)

        # Meta fields
        self.ufont("", 11)
        self.set_text_color(60, 60, 60)
        for field in [
            "Prepared By: [YOUR COMPANY NAME]",
            "Date: [DATE]",
            "Client: [CLIENT COMPANY NAME]",
            "Classification: CONFIDENTIAL",
        ]:
            self.cell(0, 10, field, align="C")
            self.ln(8)

        # Bottom accent bar
        self.set_fill_color(0, 200, 100)
        self.rect(10, self.h - 30, self.w - 20, 3, "F")


def clean(text: str) -> str:
    """Strip markdown formatting markers from text."""
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)
    text = re.sub(r'`(.+?)`', r'\1', text)
    return text


def render_table(pdf: TemplatePDF, rows: list):
    """Render a markdown table to PDF."""
    if not rows:
        return

    # Filter out separator rows (---|----|---)
    data_rows = [r for r in rows if not all(c.strip().replace("-", "").replace(":", "") == "" for c in r)]
    if not data_rows:
        return

    num_cols = max(len(r) for r in data_rows)
    if num_cols == 0:
        return

    # Calculate column widths based on content
    usable = pdf.w - 22
    col_widths = []
    for col_idx in range(num_cols):
        max_len = 0
        for row in data_rows:
            if col_idx < len(row):
                max_len = max(max_len, len(row[col_idx].strip()))
        col_widths.append(max(max_len, 3))

    total = sum(col_widths)
    if total > 0:
        col_widths = [(w / total) * usable for w in col_widths]
    else:
        col_widths = [usable / num_cols] * num_cols

    # Ensure minimum column width
    min_width = 12
    for i in range(len(col_widths)):
        if col_widths[i] < min_width:
            col_widths[i] = min_width

    for i, row in enumerate(data_rows):
        is_header = i == 0
        if is_header:
            pdf.set_fill_color(0, 170, 85)
            pdf.set_text_color(255, 255, 255)
            pdf.ufont("B", 8)
        else:
            pdf.set_fill_color(248, 248, 248) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(40, 40, 40)
            pdf.ufont("", 8)

        for j in range(num_cols):
            w = col_widths[j] if j < len(col_widths) else col_widths[-1]
            cell_text = clean(row[j].strip()) if j < len(row) else ""
            # Truncate if too long for cell
            max_chars = int(w / 1.8)
            if len(cell_text) > max_chars:
                cell_text = cell_text[:max_chars - 2] + ".."
            pdf.cell(w, 6, cell_text, border=1, fill=True)

        pdf.ln(6)

    pdf.ln(3)


def parse_markdown_to_pdf(md_text: str, pdf: TemplatePDF):
    """Parse markdown and render to PDF."""
    lines = md_text.split("\n")
    in_table = False
    table_rows = []

    def flush_table():
        nonlocal in_table, table_rows
        if table_rows:
            render_table(pdf, table_rows)
        in_table = False
        table_rows = []

    for line in lines:
        stripped = line.strip()

        # Empty line
        if not stripped:
            if in_table:
                flush_table()
            pdf.set_x(pdf.l_margin)
            pdf.ln(2)
            continue

        # Table row
        if "|" in stripped and stripped.startswith("|"):
            cells = [c for c in stripped.split("|")[1:-1]]
            if not in_table:
                in_table = True
                table_rows = []
            table_rows.append(cells)
            continue
        elif in_table:
            flush_table()

        # Reset x before every element
        pdf.set_x(pdf.l_margin)

        try:
            # H1
            if stripped.startswith("# ") and not stripped.startswith("## "):
                pdf.ln(5)
                pdf.ufont("B", 22)
                pdf.set_text_color(20, 20, 20)
                pdf.multi_cell(0, 11, clean(stripped[2:]))
                pdf.set_draw_color(0, 200, 100)
                pdf.set_line_width(0.8)
                pdf.line(10, pdf.get_y() + 1, pdf.w - 10, pdf.get_y() + 1)
                pdf.ln(5)

            # H2
            elif stripped.startswith("## ") and not stripped.startswith("### "):
                pdf.ln(4)
                pdf.ufont("B", 16)
                pdf.set_text_color(0, 140, 70)
                pdf.multi_cell(0, 9, clean(stripped[3:]))
                pdf.ln(2)

            # H3
            elif stripped.startswith("### ") and not stripped.startswith("#### "):
                pdf.ln(3)
                pdf.ufont("B", 13)
                pdf.set_text_color(40, 40, 40)
                pdf.multi_cell(0, 8, clean(stripped[4:]))
                pdf.ln(2)

            # H4
            elif stripped.startswith("#### "):
                pdf.ln(2)
                pdf.ufont("B", 11)
                pdf.set_text_color(60, 60, 60)
                pdf.multi_cell(0, 7, clean(stripped[5:]))
                pdf.ln(1)

            # Horizontal rule
            elif stripped in ("---", "***", "___"):
                pdf.ln(3)
                pdf.set_draw_color(200, 200, 200)
                pdf.set_line_width(0.3)
                pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
                pdf.ln(4)

            # Checkbox
            elif stripped.startswith("- [ ] ") or stripped.startswith("- [x] "):
                checked = stripped.startswith("- [x] ")
                text = clean(stripped[6:])
                pdf.ufont("", 10)
                pdf.set_text_color(40, 40, 40)
                box = "[X] " if checked else "[  ] "
                pdf.cell(12, 6, box)
                pdf.multi_cell(0, 6, text)

            # Bullet
            elif stripped.startswith("- ") or stripped.startswith("* "):
                text = clean(stripped[2:])
                pdf.ufont("", 10)
                pdf.set_text_color(40, 40, 40)
                pdf.cell(6, 6, "")
                pdf.cell(4, 6, "-")
                pdf.multi_cell(0, 6, text)

            # Numbered list
            elif re.match(r'^\d+\.', stripped):
                num = re.match(r'^(\d+\.)', stripped).group(1)
                text = clean(re.sub(r'^\d+\.\s*', '', stripped))
                pdf.ufont("", 10)
                pdf.set_text_color(40, 40, 40)
                pdf.cell(6, 6, "")
                pdf.ufont("B", 10)
                pdf.cell(7, 6, num)
                pdf.ufont("", 10)
                pdf.multi_cell(0, 6, text)

            # Block quote
            elif stripped.startswith("> "):
                text = clean(stripped[2:])
                y = pdf.get_y()
                pdf.set_fill_color(0, 200, 100)
                pdf.rect(12, y, 2, 7, "F")
                pdf.ufont("I", 10)
                pdf.set_text_color(60, 100, 70)
                pdf.cell(8, 6, "")
                pdf.multi_cell(0, 6, text)
                pdf.ln(2)

            # Code block fence
            elif stripped.startswith("```"):
                pass

            # Signature lines
            elif "________________________________" in stripped:
                pdf.ln(2)
                pdf.ufont("", 10)
                pdf.set_text_color(40, 40, 40)
                label = stripped.split(":")[0] + ":" if ":" in stripped else ""
                pdf.multi_cell(0, 6, f"{label}  {'_' * 40}")
                pdf.ln(4)

            # Regular text
            else:
                text = clean(stripped)
                pdf.ufont("", 10)
                pdf.set_text_color(40, 40, 40)
                pdf.multi_cell(0, 6, text)
                pdf.ln(1)

        except Exception:
            # Skip problematic lines rather than failing the whole doc
            pdf.set_x(pdf.l_margin)
            pdf.ln(3)

    if in_table:
        flush_table()


def convert_template(md_path: Path, output_dir: Path):
    """Convert a single markdown template to PDF."""
    md_text = md_path.read_text(encoding="utf-8")

    title_match = re.search(r'^#\s+(.+)$', md_text, re.MULTILINE)
    title = clean(title_match.group(1)) if title_match else md_path.stem

    subtitles = {
        "01_proposal": "Cybersecurity Assessment Services",
        "02_rules": "Master Services Agreement",
        "03_statement": "Exhibit A -- Service Details",
        "04_invoice": "Cybersecurity Assessment Services",
        "05_pricing": "Internal Reference Document",
        "06_outreach": "Sales & Marketing Templates",
    }
    subtitle = ""
    for key, val in subtitles.items():
        if key in md_path.stem:
            subtitle = val
            break

    pdf = TemplatePDF()
    pdf.title = title
    pdf.set_margins(11, 10, 11)

    pdf.add_cover_page(title, subtitle)
    pdf.add_page()
    parse_markdown_to_pdf(md_text, pdf)

    output_path = output_dir / (md_path.stem + ".pdf")
    pdf.output(str(output_path))
    return output_path


def main():
    templates_dir = Path(__file__).parent
    output_dir = templates_dir / "pdfs"
    output_dir.mkdir(exist_ok=True)

    md_files = sorted(templates_dir.glob("*.md"))
    if not md_files:
        print("No markdown files found!")
        return

    print("=" * 50)
    print("  Generating PDF Business Templates")
    print("=" * 50)
    print()

    generated = []
    for md_file in md_files:
        try:
            output = convert_template(md_file, output_dir)
            print(f"  [+] {md_file.name}  ->  {output.name}")
            generated.append(output)
        except Exception as e:
            print(f"  [-] {md_file.name} FAILED: {e}")

    print()
    print(f"Generated {len(generated)} PDFs in: {output_dir}")
    print()
    for p in generated:
        print(f"  {p}")


if __name__ == "__main__":
    main()
