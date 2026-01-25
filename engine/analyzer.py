import json

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "SQLite",
    "syntax error",
    "ODBC",
    "PostgreSQL"
]

class Analyzer:
    def __init__(self, responses):
        self.responses = responses
        self.findings = []

    def is_sqli(self, text):
        for err in SQL_ERRORS:
            if err.lower() in text.lower():
                return True
        return False

    def analyze(self):
        for r in self.responses:

            # Error-based SQL Injection
            if self.is_sqli(r["snippet"]):
                self.findings.append({
                    "type": "SQL Injection (error-based)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": r["snippet"]
                })

            # Blind SQL Injection via response length diff
            diff = abs(r["length"] - r["baseline_length"])
            if diff > 100:
                self.findings.append({
                    "type": "SQL Injection (blind)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": f"Response length changed by {diff} bytes"
                })

        with open("evidence/findings.json", "w") as f:
            json.dump(self.findings, f, indent=2)

        return self.findings

