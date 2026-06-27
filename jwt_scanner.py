import jwt
import json
import base64
import sys
from html import escape
from datetime import datetime
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Initialize colorama
init()
console = Console()
# Common weak secret keys hackers try
WEAK_KEYS = [
    "secret", "password", "123456", "key", "private",
    "mysecret", "jwt_secret", "supersecret", "admin",
    "test", "hello", "qwerty", "abc123", "password123",
    "secretkey", "mykey", "token", "jwt", "auth"
]

# Sensitive fields that should never be in JWT
SENSITIVE_FIELDS = [
    "password", "passwd", "pwd", "credit_card", "ccv",
    "ssn", "social_security", "bank_account", "private_key",
    "secret", "api_key", "access_key", "pin"
]


def print_banner():
    """Print tool banner"""
    console.print(Panel.fit(
        "[bold cyan]JWT Security Scanner[/bold cyan]\n"
        "[white]Finds vulnerabilities in JWT tokens[/white]\n"
        "[dim]Built for cybersecurity portfolio[/dim]",
        border_style="cyan"
    ))


def decode_token_parts(token):
    """Decode JWT token without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, "Invalid JWT format - must have 3 parts"

        # Decode header
        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))

        # Decode payload
        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))

        return header, payload, None
    except Exception as e:
        return None, None, str(e)


def check_algorithm(header):
    """Check 1 - Algorithm Security"""
    results = []
    algorithm = header.get('alg', 'unknown').upper()

    if algorithm == 'NONE':
        results.append({
            "status": "CRITICAL",
            "finding": "Algorithm is set to 'none'!",
            "detail": "Token has NO signature! Anyone can forge this token!",
            "risk": "CRITICAL"
        })
    elif algorithm in ['HS256', 'HS384', 'HS512']:
        results.append({
            "status": "INFO",
            "finding": f"Algorithm: {algorithm}",
            "detail": "Symmetric algorithm — safe if secret key is strong",
            "risk": "LOW"
        })
    elif algorithm in ['RS256', 'RS384', 'RS512']:
        results.append({
            "status": "PASS",
            "finding": f"Algorithm: {algorithm}",
            "detail": "Asymmetric algorithm — good choice!",
            "risk": "LOW"
        })
    else:
        results.append({
            "status": "WARNING",
            "finding": f"Unknown algorithm: {algorithm}",
            "detail": "Unrecognized algorithm detected",
            "risk": "MEDIUM"
        })

    return results


def check_expiry(payload):
    """Check 2 - Token Expiry"""
    results = []

    if 'exp' not in payload:
        results.append({
            "status": "HIGH",
            "finding": "No expiry time found!",
            "detail": "Token never expires! Stolen token works forever!",
            "risk": "HIGH"
        })
    else:
        exp_time = datetime.fromtimestamp(payload['exp'])
        now = datetime.now()

        if now > exp_time:
            results.append({
                "status": "WARNING",
                "finding": "Token is EXPIRED",
                "detail": f"Expired at: {exp_time}",
                "risk": "MEDIUM"
            })
        else:
            diff = exp_time - now
            results.append({
                "status": "PASS",
                "finding": "Token has valid expiry",
                "detail": f"Expires at: {exp_time} ({diff.days} days remaining)",
                "risk": "LOW"
            })

    if 'iat' not in payload:
        results.append({
            "status": "WARNING",
            "finding": "No 'issued at' time found",
            "detail": "Cannot verify when token was created",
            "risk": "LOW"
        })

    return results


def check_weak_secret(token, header):
    """Check 3 - Weak Secret Key"""
    results = []
    algorithm = header.get('alg', '').upper()

    if algorithm.startswith('HS'):
        cracked_key = None
        for key in WEAK_KEYS:
            try:
                jwt.decode(token, key, algorithms=[algorithm])
                cracked_key = key
                break
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

        if cracked_key:
            results.append({
                "status": "CRITICAL",
                "finding": f"WEAK SECRET KEY FOUND: '{cracked_key}'",
                "detail": "Secret key was guessed from common passwords list!",
                "risk": "CRITICAL"
            })
        else:
            results.append({
                "status": "PASS",
                "finding": "Secret key not found in common keys list",
                "detail": "Key appears strong enough to resist basic attacks",
                "risk": "LOW"
            })
    else:
        results.append({
            "status": "INFO",
            "finding": "Asymmetric algorithm — secret key check skipped",
            "detail": "RS/ES algorithms use public/private key pairs",
            "risk": "LOW"
        })

    return results


def check_sensitive_data(payload):
    """Check 4 - Sensitive Data in Payload"""
    results = []
    found_sensitive = []

    for field in payload:
        if field.lower() in SENSITIVE_FIELDS:
            found_sensitive.append(field)

    if found_sensitive:
        results.append({
            "status": "HIGH",
            "finding": f"Sensitive fields found: {', '.join(found_sensitive)}",
            "detail": "JWT payload is base64 encoded NOT encrypted! Anyone can read it!",
            "risk": "HIGH"
        })
    else:
        results.append({
            "status": "PASS",
            "finding": "No sensitive data found in payload",
            "detail": "Payload looks clean",
            "risk": "LOW"
        })

    return results


def check_claims(payload):
    """Check 5 - Important Claims"""
    results = []

    if 'iss' not in payload:
        results.append({
            "status": "WARNING",
            "finding": "No 'issuer' claim found",
            "detail": "Cannot verify who created this token",
            "risk": "LOW"
        })

    if 'sub' not in payload:
        results.append({
            "status": "WARNING",
            "finding": "No 'subject' claim found",
            "detail": "Token does not identify who it belongs to",
            "risk": "LOW"
        })

    if 'aud' not in payload:
        results.append({
            "status": "INFO",
            "finding": "No 'audience' claim found",
            "detail": "Token can be used on any service",
            "risk": "LOW"
        })

    return results


def print_results(all_results, header, payload):
    """Print beautiful security report"""

    # Count findings by risk
    critical = sum(1 for r in all_results if r['risk'] == 'CRITICAL')
    high = sum(1 for r in all_results if r['risk'] == 'HIGH')
    medium = sum(1 for r in all_results if r['risk'] == 'MEDIUM')
    low = sum(1 for r in all_results if r['risk'] == 'LOW')

    # Print token info
    console.print("\n[bold cyan]═══ TOKEN INFORMATION ═══[/bold cyan]")
    info_table = Table(show_header=True, header_style="bold cyan")
    info_table.add_column("Field", style="cyan")
    info_table.add_column("Value", style="white")

    info_table.add_row("Algorithm", header.get('alg', 'unknown'))
    info_table.add_row("Token Type", header.get('typ', 'unknown'))

    for key, value in payload.items():
        if key == 'exp' or key == 'iat':
            value = str(datetime.fromtimestamp(value))
        info_table.add_row(key, str(value))

    console.print(info_table)

    # Print findings
    console.print("\n[bold cyan]═══ SECURITY FINDINGS ═══[/bold cyan]")

    findings_table = Table(show_header=True, header_style="bold cyan")
    findings_table.add_column("Risk", style="bold", width=10)
    findings_table.add_column("Finding", width=35)
    findings_table.add_column("Detail", width=45)

    for result in all_results:
        risk = result['risk']
        if risk == 'CRITICAL':
            risk_style = "[bold red]CRITICAL[/bold red]"
        elif risk == 'HIGH':
            risk_style = "[red]HIGH[/red]"
        elif risk == 'MEDIUM':
            risk_style = "[yellow]MEDIUM[/yellow]"
        else:
            risk_style = "[green]LOW[/green]"

        findings_table.add_row(
            risk_style,
            result['finding'],
            result['detail']
        )

    console.print(findings_table)

    # Print summary
    console.print("\n[bold cyan]═══ SECURITY SUMMARY ═══[/bold cyan]")
    summary_table = Table(show_header=False)
    summary_table.add_column("Level", style="bold")
    summary_table.add_column("Count")

    summary_table.add_row("[bold red]CRITICAL[/bold red]", str(critical))
    summary_table.add_row("[red]HIGH[/red]", str(high))
    summary_table.add_row("[yellow]MEDIUM[/yellow]", str(medium))
    summary_table.add_row("[green]LOW/INFO[/green]", str(low))

    console.print(summary_table)

    # Overall verdict
    if critical > 0:
        console.print(Panel("[bold red]⚠ CRITICAL VULNERABILITIES FOUND! This token is DANGEROUS![/bold red]", border_style="red"))
    elif high > 0:
        console.print(Panel("[red]⚠ HIGH RISK VULNERABILITIES FOUND! Immediate action needed![/red]", border_style="red"))
    elif medium > 0:
        console.print(Panel("[yellow]⚠ MEDIUM RISK FINDINGS. Review and fix recommended.[/yellow]", border_style="yellow"))
    else:
        console.print(Panel("[green]✓ No critical issues found. Token appears reasonably secure.[/green]", border_style="green"))


def scan_token(token):
    """Main scanning function"""
    console.print("\n[cyan]Scanning JWT token...[/cyan]\n")

    # Decode token parts
    header, payload, error = decode_token_parts(token)

    if error:
        console.print(f"[red]Error decoding token: {error}[/red]")
        return

    # Run all checks
    all_results = []

    console.print("[cyan]Running Check 1: Algorithm Security...[/cyan]")
    all_results.extend(check_algorithm(header))

    console.print("[cyan]Running Check 2: Token Expiry...[/cyan]")
    all_results.extend(check_expiry(payload))

    console.print("[cyan]Running Check 3: Weak Secret Key...[/cyan]")
    all_results.extend(check_weak_secret(token, header))

    console.print("[cyan]Running Check 4: Sensitive Data...[/cyan]")
    all_results.extend(check_sensitive_data(payload))

    console.print("[cyan]Running Check 5: Token Claims...[/cyan]")
    all_results.extend(check_claims(payload))

    # Print results
    print_results(all_results, header, payload)
    filename = save_report(token, all_results, header, payload)
    console.print(f"\n[green]Text report saved to: {filename}[/green]")

    html_filename = save_html_report(token, all_results, header, payload)
    console.print(f"[green]HTML report saved to: {html_filename}[/green]")
    console.print(f"\n[cyan]Open the HTML file in your browser to see the full report![/cyan]")


def main():
    print_banner()

    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        console.print("\n[cyan]Enter JWT token to scan:[/cyan]")
        token = input("> ").strip()

    if not token:
        console.print("[red]No token provided![/red]")
        return

    scan_token(token)


def save_report(token, all_results, header, payload):
    """Save scan results to a text report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"jwt_report_{timestamp}.txt"

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("JWT SECURITY SCAN REPORT\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("=" * 60 + "\n\n")

        f.write("TOKEN INFORMATION\n")
        f.write("-" * 40 + "\n")
        f.write(f"Algorithm: {header.get('alg', 'unknown')}\n")
        f.write(f"Token Type: {header.get('typ', 'unknown')}\n")
        for key, value in payload.items():
            if key in ['exp', 'iat']:
                value = str(datetime.fromtimestamp(value))
            f.write(f"{key}: {value}\n")

        f.write("\nSECURITY FINDINGS\n")
        f.write("-" * 40 + "\n")
        for result in all_results:
            f.write(f"[{result['risk']}] {result['finding']}\n")
            f.write(f"  Detail: {result['detail']}\n\n")

        critical = sum(1 for r in all_results if r['risk'] == 'CRITICAL')
        high = sum(1 for r in all_results if r['risk'] == 'HIGH')
        medium = sum(1 for r in all_results if r['risk'] == 'MEDIUM')

        f.write("\nSECURITY SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"CRITICAL: {critical}\n")
        f.write(f"HIGH: {high}\n")
        f.write(f"MEDIUM: {medium}\n")

        if critical > 0:
            f.write("\nVERDICT: CRITICAL VULNERABILITIES FOUND!\n")
        elif high > 0:
            f.write("\nVERDICT: HIGH RISK VULNERABILITIES FOUND!\n")
        else:
            f.write("\nVERDICT: No critical issues found.\n")

    return filename


def save_html_report(token, all_results, header, payload):
    """Save scan results to an HTML report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"jwt_report_{timestamp}.html"

    critical = sum(1 for r in all_results if r['risk'] == 'CRITICAL')
    high = sum(1 for r in all_results if r['risk'] == 'HIGH')
    medium = sum(1 for r in all_results if r['risk'] == 'MEDIUM')
    low = sum(1 for r in all_results if r['risk'] == 'LOW')
    total = len(all_results)

    payload_html = []
    for key, value in payload.items():
        if key in ['exp', 'iat']:
            value = str(datetime.fromtimestamp(value))
        payload_html.append(
            f"<tr><td style='color: #e91e63; font-weight: 700;'>{escape(str(key))}:</td><td>{escape(str(value))}</td></tr>"
        )

    findings_html = []
    for idx, result in enumerate(all_results, 1):
        risk = result['risk']
        if risk == 'CRITICAL':
            dot_color = '#dc2626'
        elif risk == 'HIGH':
            dot_color = '#ea580c'
        elif risk == 'MEDIUM':
            dot_color = '#b45309'
        else:
            dot_color = '#4b5563'

        findings_html.append(
            f"<tr>"
            f"<td>{idx}</td>"
            f"<td><span style='color: {dot_color}; font-weight: 700;'>● {escape(risk)}</span></td>"
            f"<td>{escape(result.get('finding', ''))}</td>"
            f"<td>{escape(result.get('detail', ''))}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>JWT Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: Arial, sans-serif;
            background: #fef5f9;
            color: #333;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #ffc0e3;
            padding-bottom: 30px;
        }}
        
        h1 {{
            color: #e91e63;
            font-size: 32px;
            margin-bottom: 8px;
            font-weight: 700;
            letter-spacing: 1px;
        }}
        
        .subtitle {{
            color: #666;
            font-size: 13px;
            margin-bottom: 4px;
        }}
        
        .date {{
            color: #999;
            font-size: 12px;
            margin-bottom: 20px;
        }}
        
        .heart {{
            color: #e91e63;
            font-size: 20px;
            margin: 15px 0;
        }}
        
        .quote {{
            font-style: italic;
            color: #e91e63;
            text-align: center;
            margin: 20px 0;
            font-size: 15px;
            line-height: 1.8;
        }}
        
        .section-title {{
            color: #e91e63;
            font-size: 16px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-top: 35px;
            margin-bottom: 15px;
            border-bottom: 1px solid #ffc0e3;
            padding-bottom: 10px;
        }}
        
        .overview {{
            background: #fef5f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            line-height: 1.8;
            font-size: 14px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat {{
            text-align: center;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 8px;
            border-left: 3px solid #ffc0e3;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 12px;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        
        .stat-value {{
            font-size: 28px;
            font-weight: 700;
            color: #e91e63;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        
        th {{
            text-align: left;
            padding: 12px 10px;
            background: white;
            border-bottom: 2px solid #ffc0e3;
            color: #e91e63;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
        }}
        
        td {{
            padding: 12px 10px;
            border-bottom: 1px solid #f0f0f0;
            vertical-align: top;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        .token-box {{
            background: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 15px;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            color: #333;
            max-height: 200px;
            overflow-y: auto;
            margin-bottom: 30px;
        }}
        
        ul {{
            margin-left: 20px;
            margin-bottom: 30px;
        }}
        
        li {{
            margin-bottom: 8px;
            color: #333;
        }}
        
        .footer {{
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ffc0e3;
        }}
        
        .footer-icon {{
            color: #e91e63;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>JWT SECURITY ASSESSMENT REPORT</h1>
            <p class="subtitle">Automated Vulnerability Scan | Confidential Security Document</p>
            <p class="date">Report Generated: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}</p>
            <div class="heart">💗</div>
            <p class="quote">"The goal of security is not to eliminate risk,<br>but to bring it to an acceptable level."</p>
        </div>
        
        <h2 class="section-title">Report Overview</h2>
        <div class="overview">
            This report presents the results of an automated security assessment performed on the provided JSON Web Token (JWT). The scanner analyzed the token against multiple security best practices and identified potential vulnerabilities.
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Critical</div>
                <div class="stat-value" style="color: #dc2626;">{critical}</div>
            </div>
            <div class="stat">
                <div class="stat-label">High</div>
                <div class="stat-value" style="color: #ea580c;">{high}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Medium</div>
                <div class="stat-value" style="color: #b45309;">{medium}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Low</div>
                <div class="stat-value" style="color: #4b5563;">{low}</div>
            </div>
        </div>
        
        <h2 class="section-title">Security Findings</h2>
        <table>
            <tr>
                <th style="width: 40px;">#</th>
                <th style="width: 80px;">Severity</th>
                <th style="width: 200px;">Category</th>
                <th>Finding</th>
                <th>Details</th>
            </tr>
            {''.join(findings_html)}
        </table>
        
        <h2 class="section-title">Token Details</h2>
        <table>
            {''.join(payload_html)}
        </table>
        
        <h2 class="section-title">Recommendations</h2>
        <ul>
            <li>Never use 'none' algorithm. Always use a secure algorithm like RS256 or HS256.</li>
            <li>Always set an expiration time (exp) for tokens.</li>
            <li>Avoid including sensitive information in the payload.</li>
            <li>Use strong secret keys (minimum 32 characters for HS256).</li>
            <li>Follow the principle of least privilege when assigning permissions.</li>
        </ul>
        
        <div class="footer">
            Generated by <strong>JWT Security Scanner</strong><br>
            Stay safe, stay pink, stay secure! <span class="footer-icon">🌸</span>
        </div>
    </div>
</body>
</html>"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    return filename


if __name__ == "__main__":
    main()