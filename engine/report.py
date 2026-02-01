import json
from jinja2 import Template

def generate_report():
    # Load findings
    with open("evidence/findings.json") as f:
        findings = json.load(f)

    # Load HTML template
    with open("report/template.html") as f:
        template = Template(f.read())

    # Render
    html = template.render(findings=findings)

    # Write output
    with open("report/scan_report.html", "w") as f:
        f.write(html)

    print("[+] HTML report generated: report/scan_report.html")
