import re
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
            if self.is_sqli(r["snippet"]):
                self.findings.append({
                    "type": "SQL Injection",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": r["snippet"]
                })

        with open("evidence/findings.json", "w") as f:
            json.dump(self.findings, f, indent=2)

        return self.findings

