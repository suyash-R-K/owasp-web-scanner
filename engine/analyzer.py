import json
from collections import defaultdict

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "SQLite",
    "syntax error",
    "ODBC",
    "PostgreSQL"
]

SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

CONFIDENCE_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Very High": 4
}

class Analyzer:
    def __init__(self, responses):
        self.responses = responses
        self.raw_findings = []
        self.merged_findings = []

    def is_sqli(self, text):
        for err in SQL_ERRORS:
            if err.lower() in text.lower():
                return True
        return False

    def count_rows(self, text):
        return text.count("ID:") + text.count("Surname:") + text.count("First name")

    def analyze(self):
        # --- Stage 1: Raw detection (same as before) ---
        for r in self.responses:
            snippet = r["snippet"]

            # Error-based SQLi
            if self.is_sqli(snippet):
                self.raw_findings.append({
                    "url": r["url"],
                    "type": "SQL Injection",
                    "engine": "error",
                    "severity": "High",
                    "confidence": "High",
                    "payload": r["payload"]
                })

            # Content-based SQLi
            rows = self.count_rows(snippet)
            if rows > 1:
                self.raw_findings.append({
                    "url": r["url"],
                    "type": "SQL Injection",
                    "engine": "content",
                    "severity": "Critical",
                    "confidence": "Medium",
                    "payload": r["payload"]
                })

            # Blind SQLi
            diff = abs(r["length"] - r["baseline_length"])
            threshold = r["baseline_length"] * 0.10
            if diff > threshold and diff > 50:
                self.raw_findings.append({
                    "url": r["url"],
                    "type": "SQL Injection",
                    "engine": "blind",
                    "severity": "High",
                    "confidence": "Low",
                    "payload": r["payload"]
                })

            # XSS
            encoded = r["payload"].replace("<", "&lt;").replace(">", "&gt;")
            if ("<" in r["payload"] or ">" in r["payload"]) and (r["payload"] in snippet or encoded in snippet):
                self.raw_findings.append({
                    "url": r["url"],
                    "type": "Cross-Site Scripting (XSS)",
                    "engine": "reflection",
                    "severity": "Medium",
                    "confidence": "High",
                    "payload": r["payload"]
                })

        # --- Stage 2: Merge by (url, type) ---
        grouped = defaultdict(list)
        for f in self.raw_findings:
            grouped[(f["url"], f["type"])].append(f)

        for (url, vtype), items in grouped.items():
            max_sev = "Low"
            engines = set()
            payloads = []

            for i in items:
                engines.add(i["engine"])
                payloads.append(i["payload"])
                if SEVERITY_RANK[i["severity"]] > SEVERITY_RANK[max_sev]:
                    max_sev = i["severity"]

            # Confidence increases when multiple engines agree
            if len(engines) >= 3:
                confidence = "Very High"
            elif len(engines) == 2:
                confidence = "High"
            else:
                confidence = items[0]["confidence"]

            self.merged_findings.append({
                "url": url,
                "type": vtype,
                "severity": max_sev,
                "confidence": confidence,
                "engines": list(engines),
                "example_payload": payloads[0]
            })

        with open("evidence/findings.json", "w") as f:
            json.dump(self.merged_findings, f, indent=2)

        return self.merged_findings

