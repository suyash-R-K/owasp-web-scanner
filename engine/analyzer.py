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

    # DVWA-style content detection
    def count_rows(self, text):
        return text.count("ID:") + text.count("Surname:") + text.count("First name")

    def analyze(self):
        for r in self.responses:
            snippet = r["snippet"]

            # 1️⃣ Error-based SQL Injection
            if self.is_sqli(snippet):
                self.findings.append({
                    "type": "SQL Injection (error-based)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": snippet[:200]
                })

            # 2️⃣ Content-based SQL Injection (DVWA, real apps)
            rows = self.count_rows(snippet)
            if rows > 1:
                self.findings.append({
                    "type": "SQL Injection (content-based)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": f"Returned {rows} database rows"
                })

            # 3️⃣ Blind SQL Injection (length diff)
            diff = abs(r["length"] - r["baseline_length"])
            if diff > 120:
                self.findings.append({
                    "type": "SQL Injection (blind)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": f"Response length changed by {diff} bytes"
                })

            # 4️⃣ XSS — reflected or HTML-encoded
            encoded = r["payload"].replace("<", "&lt;").replace(">", "&gt;")
            if r["payload"] in snippet or encoded in snippet:
                self.findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": r["url"],
                    "payload": r["payload"],
                    "evidence": snippet[:200]
                })

        with open("evidence/findings.json", "w") as f:
            json.dump(self.findings, f, indent=2)

        return self.findings

