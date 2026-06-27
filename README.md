# 🔐 JWT Security Scanner

> Analyze JSON Web Tokens (JWTs) for common security vulnerabilities and generate professional security reports.

---

## 📦 Available on PyPI

Install the tool directly:

```bash
pip install jwt-security-scanner
```

Run the scanner:

```bash
jwt-scanner
```

> **Windows Users:** If `jwt-scanner` is not recognized, run:

```bash
py -m jwt_scanner.scanner
```

---

## 📖 Project Overview

JWT (JSON Web Token) is widely used for authentication in modern web applications. However, insecure JWT implementations can expose applications to authentication bypass, privilege escalation, token forgery, and unauthorized access.

This project is a **Python-based command-line security scanner** that analyzes JWTs for common security misconfigurations and generates detailed security reports with remediation recommendations.

---

## 🚀 Features

- ✅ Detects 5 common JWT security vulnerability categories
- 🎨 Beautiful colored terminal output using Rich
- 📄 Generates professional HTML security reports
- 📝 Generates text reports for documentation
- 🛡 Provides security recommendations
- ⚡ Simple command-line interface
- 📦 Available as a PyPI package

---

## 🔍 Security Checks

| Security Check | Description | Risk |
|---------------|-------------|------|
| 🔐 Algorithm Check | Detects insecure `none` algorithm usage | 🔴 Critical |
| 🔑 Weak Secret Key | Detects commonly used weak HMAC secrets | 🔴 Critical |
| ⏳ Expiry Check | Detects missing or expired tokens | 🟠 High |
| 📄 Sensitive Data | Detects passwords or confidential data in payload | 🟠 High |
| 🛡 Token Claims | Checks missing `iss`, `sub`, `aud`, `iat` claims | 🟡 Medium |

---


---

## ⚙️ Technologies Used

- Python 3
- PyJWT
- Rich
- Colorama
- Requests

---

## 💻 Installation

### Install from PyPI

```bash
pip install jwt-security-scanner
```

If `pip` is unavailable:

```bash
py -m pip install jwt-security-scanner
```

---

## ▶️ Usage

Launch the scanner:

```bash
jwt-scanner
```

Or, if the command is not recognized on Windows:

```bash
py -m jwt_scanner.scanner
```

Follow the prompts to paste a JWT token. The scanner will automatically:

- Decode the token
- Perform security analysis
- Display findings
- Generate HTML and TXT reports

---

## 📊 Example Output

```text
JWT Security Scanner

SECURITY FINDINGS

CRITICAL   Weak Secret Key Found
HIGH       No Expiration Time
HIGH       Sensitive Data Detected

SECURITY SUMMARY

Critical : 1
High     : 2
Medium   : 0
Low      : 5

Verdict:
CRITICAL VULNERABILITIES FOUND
```

---

## 📄 Reports Generated

Every scan automatically generates:

### 📝 Text Report

- Plain text format
- Easy to archive
- Useful for documentation

### 🌐 HTML Report

- Modern responsive design
- Severity dashboard
- Findings table
- Token information
- Security recommendations

---

## 📚 What I Learned

- JWT Architecture (Header • Payload • Signature)
- Digital Signatures
- HMAC & SHA-256
- HS256 vs RS256
- Base64URL Encoding
- JWT Security Best Practices
- Python Security Tool Development
- HTML Report Generation
- Python Package Publishing (PyPI)

---

## 🌍 Real-World Application

JWT security is an important part of modern web application security. During security assessments, penetration testers and application security engineers review JWT implementations to identify weaknesses such as insecure algorithms, weak signing secrets, missing expiration, and improper token validation.

This tool helps automate those checks for learning and testing purposes.

---

## 📂 Project Structure

```text
JWT-Security-Scanner/
│
├── jwt_scanner/
│   ├── __init__.py
│   └── scanner.py
├── setup.py
├── pyproject.toml
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🚀 Running from Source

Clone the repository:

```bash
git clone https://github.com/tabassumfathima28/JWT-Security-Scanner.git
cd JWT-Security-Scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
py jwt_scanner\scanner.py
```

---

## 🔗 Related Project

### 🛡 AI-Powered SIEM Home Lab

A complete SIEM lab built using Elastic SIEM and Tines automation.

https://github.com/tabassumfathima28/SIEM-HOME-LAB-PROJECT

---

## 👩‍💻 Author

**Tabassum Fathima**

Cybersecurity Undergraduate | Aspiring SOC Analyst

- GitHub: https://github.com/tabassumfathima28
- LinkedIn: https://www.linkedin.com/in/tabassumfathima2812/

---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub!

---

> **"Security is not a product, but a process." — Bruce Schneier**
