# OWASP Web Scanner

A session-aware vulnerability scanner that tests for OWASP Top 10 vulnerabilities with full authentication support.

> **For Educational Use Only**: This tool is designed exclusively for testing applications you own or have explicit permission to test, such as DVWA, OWASP Juice Shop, and authorized CTF environments.

---

## Overview

This scanner performs authenticated vulnerability assessments on web applications, with focus on SQL Injection and Cross-Site Scripting (XSS) detection. Built from scratch to demonstrate security testing principles, it handles complex scenarios like CSRF token management and authenticated crawling.

### Supported Test Environments
- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- Custom vulnerable test applications

---

## Features

### Authentication & Session Management
- Full login flow support with session persistence
- Automatic CSRF token detection and handling
- Session-aware request management

### Crawling & Discovery
- Recursive web crawler with depth control
- Automatic parameter discovery (GET/POST)
- Link extraction and mapping

### Vulnerability Detection
- **SQL Injection**
  - Error-based detection
  - Blind injection (time-based)
  - Content-based analysis
- **Cross-Site Scripting (XSS)**
  - Reflected XSS detection
  - Encoded payload handling
  - Context-aware testing

### Reporting
- Evidence-based JSON reports
- Detailed vulnerability documentation
- HTML report generation (coming soon)

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/suyash-R-K/owasp-web-scanner
cd owasp-web-scanner

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python scanner.py --url http://target-app.local
```

### Authenticated Scan
```bash
python scanner.py \
  --url http://dvwa.local \
  --login-url http://dvwa.local/login.php \
  --username admin \
  --password password
```

### Advanced Options
```bash
python scanner.py \
  --url http://target.local \
  --depth 3 \
  --threads 5 \
  --output results.json
```

### Configuration Options
| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Target base URL (required) | - |
| `--login-url` | Login page URL | None |
| `--username` | Login username | None |
| `--password` | Login password | None |
| `--depth` | Crawl depth | 2 |
| `--threads` | Number of threads | 1 |
| `--output` | Output file path | `scan_results.json` |

---

## Example Output
```json
{
  "scan_date": "2024-01-26T10:30:00",
  "target": "http://dvwa.local",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "HIGH",
      "url": "http://dvwa.local/vulnerabilities/sqli/",
      "parameter": "id",
      "payload": "1' OR '1'='1",
      "evidence": "You have an error in your SQL syntax"
    }
  ]
}
```

---

## Architecture
```
owasp-web-scanner/
├── scanner.py           # Main entry point
├── core/
│   ├── crawler.py       # Web crawling logic
│   ├── auth.py          # Authentication handler
│   └── session.py       # Session management
├── modules/
│   ├── sqli.py          # SQL injection tests
│   └── xss.py           # XSS detection
├── utils/
│   ├── payloads.py      # Attack payloads
│   └── reporter.py      # Report generation
└── requirements.txt
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## Roadmap

- [ ] HTML report generation
- [ ] Additional OWASP Top 10 checks (IDOR, SSRF, etc.)
- [ ] Multi-threaded scanning optimization
- [ ] Plugin architecture for custom tests
- [ ] CI/CD integration support

---

## Legal Disclaimer

This tool is provided for **educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing any system you do not own.

The authors assume no liability for misuse or damage caused by this project.

---

## License

[MIT License](LICENSE)

---

## Author

**Suyash R K**
- GitHub: [@suyash-R-K](https://github.com/suyash-R-K)

---

## Acknowledgments

- OWASP Foundation for security testing standards
- DVWA and Juice Shop projects for testing environments
