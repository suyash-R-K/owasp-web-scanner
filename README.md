# OWASP Web Scanner

A session-aware vulnerability scanner that tests for OWASP Top 10 vulnerabilities with full authentication support.

> **For Educational Use Only**: This tool is designed exclusively for testing applications you own or have explicit permission to test, such as DVWA, OWASP Juice Shop, and authorized CTF environments.

---

## Overview

This scanner performs authenticated vulnerability assessments on web applications, focusing on SQL Injection and Cross-Site Scripting (XSS) detection. Built from scratch to demonstrate security testing principles, it handles complex scenarios like CSRF token management and authenticated crawling.

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
- DVWA-specific: Automatic database setup and reset

### Crawling & Discovery
- Recursive web crawler with depth control
- Automatic parameter discovery (GET/POST)
- Link extraction and mapping
- Attack surface analysis

### Vulnerability Detection

**SQL Injection**
- Error-based detection
- Blind injection (time-based)
- Content-based analysis
- Multi-engine confirmation system

**Cross-Site Scripting (XSS)**
- Reflected XSS detection
- Encoded payload handling
- Context-aware testing

### Reporting
- Console output with severity ratings
- Detailed vulnerability classification
- Detection engine attribution
- Example payload documentation

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

### Interactive Mode
```bash
python scanner.py
```
The scanner will prompt for the target URL and handle authentication automatically.

### Scanning Any Web Application
```bash
python scanner.py
Enter target URL: http://target-application.local
```

### DVWA-Specific Features
When scanning DVWA, the scanner automatically:
- Sets up and resets the database
- Authenticates with default credentials
- Handles DVWA-specific session management

---

## Example Output

```
[*] Attempting to setup/reset DVWA database...
[+] DVWA Database setup/reset completed
[+] Logged into DVWA
[*] Crawling: http://127.0.0.1:8080
[*] Crawling: http://127.0.0.1:8080/vulnerabilities/sqli
[*] Crawling: http://127.0.0.1:8080/vulnerabilities/xss_r
[+] Attack surface size: 13

[+] Vulnerabilities Found:

[Critical] SQL Injection (Very High)
  URL: http://127.0.0.1:8080/vulnerabilities/sqli
  Example Payload: ' OR '1'='1
  Detection Engines: error, content, blind

[High] SQL Injection (High)
  URL: http://127.0.0.1:8080/vulnerabilities/brute
  Example Payload: ' OR 1=1--
  Detection Engines: error, blind

[Medium] Cross-Site Scripting (XSS) (High)
  URL: http://127.0.0.1:8080/vulnerabilities/xss_r
  Example Payload: <script>alert(1337)</script>
  Detection Engines: reflection
```

---

## Severity Ratings

The scanner uses a multi-engine detection system to classify vulnerability severity:

| Rating | Description | Detection Engines |
|--------|-------------|-------------------|
| **Critical** | Confirmed by 3+ detection methods | error, content, blind |
| **High** | Confirmed by 2+ detection methods | error, blind |
| **Medium** | Confirmed by single detection method | reflection, error, or blind |

---

## Project Structure

```
owasp-web-scanner/
├── scanner.py           # Main scanner implementation
├── requirements.txt     # Python dependencies
└── results/            # Scan results directory
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

- [ ] JSON/HTML report generation
- [ ] Command-line argument support
- [ ] Additional OWASP Top 10 checks (CSRF, File Upload, XXE)
- [ ] Custom authentication handlers
- [ ] Multi-threaded scanning optimization
- [ ] Modular architecture refactoring
- [ ] Plugin system for custom tests

---

## Legal Disclaimer

This tool is provided for **educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing any system you do not own.

The authors assume no liability for misuse or damage caused by this program.

---

## Author

**Suyash R K**
- GitHub: [@suyash-R-K](https://github.com/suyash-R-K)

---

## Acknowledgments

- OWASP Foundation for vulnerability classification standards
- DVWA and Juice Shop projects for testing environments
