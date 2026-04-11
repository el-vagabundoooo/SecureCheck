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
    """
    Uses Jinja2 to render the HTML report template with real data.

    Environment() sets up the Jinja2 template engine:
      loader=FileSystemLoader('templates') tells Jinja2 where to find
      template files — the 'templates' folder relative to where the
      script runs.

    get_template() loads the specific template file.
    render() fills in all the {{ placeholders }} with real values
    and returns the complete HTML as a string.

    We then write that string to a .html file in the output folder.
    """
    os.makedirs(output_dir, exist_ok=True)

    env = Environment(loader=FileSystemLoader("templates"))
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