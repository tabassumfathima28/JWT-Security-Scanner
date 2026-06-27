# JWT Security Scanner 🔐
📦 Available on PyPI
```bash
pip install jwt-security-scanner


> A Python-based command-line tool that automatically scans JWT tokens for security vulnerabilities and generates professional security reports.

---

## What is This Tool?

JWT (JSON Web Token) is used by millions of websites to handle user authentication. But poorly configured JWT tokens can be exploited by hackers to bypass login, steal accounts, or gain admin access.

This tool acts like a **security doctor for JWT tokens** — you give it a token, it runs 5 security checks and tells you exactly what's wrong and how to fix it.

---

## Features

- Detects 5 critical JWT vulnerability categories
- Beautiful colored terminal output
- Generates professional HTML security report
- Generates text report for documentation
- Includes security recommendations
-  Works with standard JWTs signed using common algorithms (e.g., HS256, RS256).


---

## Vulnerabilities Detected

| Check | What it detects | Risk Level |
|-------|----------------|------------|
| Algorithm Check | Dangerous 'none' algorithm usage | CRITICAL |
| Weak Secret Key | Guesses secret key from common passwords | CRITICAL |
| Token Expiry | Missing or expired expiry time | HIGH |
| Sensitive Data | Passwords or private data in payload | HIGH |
| Token Claims | Missing issuer, subject, audience | MEDIUM |

---

## Tools and Technologies

- **Python 3** — Core programming language
- **PyJWT** — JWT token decoding and validation
- **Rich** — Beautiful terminal formatting
- **Colorama** — Terminal color support

---
## Installation

Install from PyPI:

```bash
pip install jwt-security-scanner
```

If `pip` is not recognized:

```bash
py -m pip install jwt-security-scanner
```

---

## Usage

Run:

```bash
jwt-scanner
```

### Windows Users

If `jwt-scanner` is not recognized, run:

```bash
py -m jwt_scanner.scanner
```

```markdown
## License

This project is licensed under the MIT License.
## Example Output

```
JWT Security Scanner
Finds vulnerabilities in JWT tokens

SECURITY FINDINGS
CRITICAL   WEAK SECRET KEY FOUND: 'secret'
HIGH       No expiry time found!
HIGH       Sensitive fields found: password

SECURITY SUMMARY
CRITICAL   1
HIGH       2
MEDIUM     0
LOW        5

CRITICAL VULNERABILITIES FOUND! This token is DANGEROUS!
```

---

## Reports Generated

After every scan the tool automatically generates:

### 1. Text Report
Plain text file with all findings — perfect for documentation

### 2. HTML Report
Professional security report with color coded risk levels, summary dashboard, findings table, recommendations and cybersecurity quotes

---

## What I Learned Building This

- JWT token structure — Header, Payload, Signature
- Common JWT vulnerabilities and how attackers exploit them
- Python security tool development
- Automated vulnerability scanning techniques
- Professional security report generation
- The difference between encoding and encryption
- Python package publishing with PyPI

---

## Real World Application

This tool simulates what penetration testers and security engineers do when auditing web applications. JWT vulnerabilities are listed in the **OWASP Top 10** and are responsible for thousands of security breaches every year.

---

## Project Structure

JWT-Security-Scanner/
│
├── jwt_scanner/
│   ├── __init__.py
│   └── scanner.py
├── setup.py
├── pyproject.toml
├── requirements.txt
├── README.md
---
SCREENSHOTS:
<img width="1906" height="947" alt="image" src="https://github.com/user-attachments/assets/2b96c95a-2803-4b80-a813-7fc30ad7096c" />
<img width="1607" height="272" alt="image" src="https://github.com/user-attachments/assets/5fce963c-c35b-4e5b-ab00-cfbf2378a956" />
<img width="1208" height="2228" alt="_C__Users_Dell_jwt-security-scanner_jwt_report_20260627_141033 html" src="https://github.com/user-attachments/assets/4effd147-8312-47d0-9cff-9d1d1a22ccff" />
<img width="735" height="875" alt="image" src="https://github.com/user-attachments/assets/8f902496-4975-4523-bacd-ce7eccf8543c" />



## Also Check Out

My other cybersecurity project:
- [AI-Powered SIEM Home Lab](https://github.com/tabassumfathima28/SIEM-HOME-LAB-PROJECT) — Detects real cyber attacks using Elastic SIEM and Tines automation

---

## Connect With Me

Built as part of my cybersecurity learning journey with a focus on application security and secure authentication.

Connect on https://www.linkedin.com/in/tabassumfathima2812/

---

> "Security is not a product, but a process." — Bruce Schneier
