# JWT Security Scanner 🔐

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
- Works on any JWT token

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

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOURUSERNAME/JWT-Security-Scanner.git
cd JWT-Security-Scanner
```

### Step 2 — Install dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

### Run the scanner
```bash
python jwt_scanner.py
```

### Or pass token directly
```bash
python jwt_scanner.py YOUR_JWT_TOKEN_HERE
```

### Generate a test vulnerable token
```bash
python -c "import jwt; print(jwt.encode({'user': 'admin', 'password': 'secret123'}, 'secret', algorithm='HS256'))"
```

---

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

---

## Real World Application

This tool simulates what penetration testers and security engineers do when auditing web applications. JWT vulnerabilities are listed in the **OWASP Top 10** and are responsible for thousands of security breaches every year.

---

## Project Structure

```
JWT-Security-Scanner/
│
├── jwt_scanner.py       Main scanner with all checks
├── requirements.txt     Python dependencies
└── README.md           Project documentation
```

---

## Also Check Out

My other cybersecurity project:
- [AI-Powered SIEM Home Lab](https://github.com/tabassumfathima28/SIEM-HOME-LAB-PROJECT) — Detects real cyber attacks using Elastic SIEM and Tines automation

---

## Connect With Me

Built by an aspiring SOC Analyst learning cybersecurity through hands-on projects.

Connect on https://www.linkedin.com/in/tabassumfathima2812/

---

> "Security is not a product, but a process." — Bruce Schneier
