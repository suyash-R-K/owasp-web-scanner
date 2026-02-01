import json
from jinja2 import Template

with open("evidence/findings.json") as f:
    findings = json.load(f)

with open("report/template.html") as f:
    template = Template(f.read())

html = template.render(findings=findings)

with open("report/scan_report.html", "w") as f:
    f.write(html)

print("[+] Report written to report/scan_report.html")
