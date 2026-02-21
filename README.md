# PhishGuard - Phishing Email & URL Analyzer

```
    ░█▀█░█░█░▀█▀░█▀▀░█░█░█▀▀░█░█░█▀█░█▀▄
    ░█▀▀░█▀█░░█░░▀▀█░█▀█░█░█░█░█░█▀█░█▀▄
    ░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀
```

**Detect phishing emails and URLs with confidence.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Type-Security%20Tool-red.svg)](#)

---

## What Is PhishGuard?

PhishGuard is a Python-based security tool that analyzes **emails** and **URLs** to detect phishing attempts. It checks for:

- Suspicious URL patterns (typosquatting, URL shorteners, IP-based URLs)
- Fake email headers (spoofed senders, mismatched domains)
- Known phishing indicators (urgency words, suspicious attachments)
- Reputation of domains (using free threat intelligence feeds)

It gives each email/URL a **risk score** (0-100) and explains exactly **WHY** something is suspicious — like a security analyst would.

---

## Features

- **URL Analysis** — 12 distinct phishing checks on any URL
- **Email Analysis** — 10 phishing checks on .eml email files
- **Threat Intelligence** — Checks against known phishing databases and URLhaus API
- **Risk Scoring** — Transparent 0-100 scoring with clear explanations
- **Professional Reports** — HTML and text reports with detailed findings
- **Bulk Analysis** — Analyze multiple URLs from a file
- **Offline Mode** — Works without internet using local threat database
- **Educational** — Explains each phishing technique it detects
- **Command-Line & Interactive** — Use via menu or CLI arguments

---

## How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Input URL   │────▶│  URL Analyzer    │────▶│  Risk Scoring   │
│  or Email    │     │  (12 checks)     │     │  Engine (0-100) │
└─────────────┘     └──────────────────┘     └────────┬────────┘
                           │                          │
                    ┌──────▼──────────┐     ┌────────▼────────┐
                    │ Threat Intel    │     │ Report Generator │
                    │ (URLhaus, local)│     │ (Text + HTML)    │
                    └─────────────────┘     └─────────────────┘
```

---

## Installation

```bash
# Step 1: Clone the repository
git clone https://github.com/OMALICHAC/PhishGuard-Phishing-Email-URL-Analyzer.git
cd PhishGuard-Phishing-Email-URL-Analyzer

# Step 2: Install dependencies (only 3 packages!)
pip install -r requirements.txt

# Step 3: Run the tool
python phishguard.py
```

---

## Usage

### Interactive Mode (Guided Menu)
```bash
python phishguard.py
```
This launches a friendly menu where you can choose what to analyze.

### Analyze a Single URL
```bash
python phishguard.py --url "https://paypa1-secure.login-verify.com/account"
```

### Analyze an Email File
```bash
python phishguard.py --email sample_emails/phishing_example_1.eml
```

### Bulk Analyze URLs from a File
```bash
python phishguard.py --bulk urls_to_check.txt
```

### Save Report to File
```bash
python phishguard.py --url "https://suspicious.com" --report
```

---

## Understanding the Risk Score

PhishGuard uses a transparent scoring system. Every check that triggers adds points, and the final score determines the risk level:

| Score Range | Risk Level       | Meaning                                    |
|-------------|------------------|--------------------------------------------|
| 0 - 20     | LOW RISK         | Likely legitimate                          |
| 21 - 40    | MODERATE RISK    | Some suspicious elements, proceed with caution |
| 41 - 60    | HIGH RISK        | Multiple phishing indicators detected      |
| 61 - 80    | VERY HIGH        | Strong phishing indicators, likely malicious |
| 81 - 100   | CRITICAL         | Almost certainly a phishing attempt        |

### URL Checks (12 indicators)

| Check                    | What It Detects                           | Points |
|--------------------------|-------------------------------------------|--------|
| IP address as URL        | `http://192.168.1.1/login`                | +25    |
| Excessive subdomains     | `paypal.secure.login.evil.com`            | +15    |
| Typosquatting            | `paypa1.com`, `g00gle.com`                | +20    |
| URL shortener            | `bit.ly`, `tinyurl.com` links             | +10    |
| Suspicious TLD           | `.xyz`, `.top`, `.buzz`, `.click`         | +10    |
| HTTPS missing            | `http://` instead of `https://`           | +10    |
| Long URL                 | Over 75 characters                        | +5     |
| @ symbol in URL          | `http://google.com@evil.com`              | +25    |
| Suspicious keywords      | `/login`, `/verify`, `/secure`            | +10    |
| Suspicious domain pattern| Excessive hyphens, brand impersonation    | +15    |
| Encoded characters       | `%2F`, `%40` obfuscation                  | +10    |
| Known phishing domain    | Matched in threat intelligence database   | +30    |

### Email Checks (10 indicators)

| Check                    | What It Detects                           | Points |
|--------------------------|-------------------------------------------|--------|
| Sender/Reply-To mismatch | Different domains for From and Reply-To   | +25    |
| Display name spoofing    | "PayPal" from random@evil.com             | +20    |
| Urgency language         | "URGENT", "ACT NOW", "SUSPENDED"          | +10    |
| Threat language          | "account closed", "legal action"          | +10    |
| Grammar errors           | Common phishing misspellings              | +5     |
| Suspicious attachments   | .exe, .js, .vbs, .scr files              | +25    |
| Suspicious links         | Phishing URLs in email body               | varies |
| SPF/DKIM failure         | Email authentication failed               | +20    |
| Generic greeting         | "Dear Customer" instead of your name      | +5     |
| Mismatched link text     | Shows paypal.com but links to evil.com    | +25    |

---

## Sample Analysis

### Analyzing a Phishing URL
```
$ python phishguard.py --url "http://paypa1-secure.login-verify.com/account/update"

  ══════════════════════════════════════════════════════════
    ANALYSIS RESULTS
  ══════════════════════════════════════════════════════════

  Target: http://paypa1-secure.login-verify.com/account/update
  Type:   URL Analysis

  ──────────────────────────────────────────────────
  🚨 RISK LEVEL: CRITICAL
  Score: [████████████████████████████░░] 95/100
  Almost certainly a phishing attempt
  Confidence: Very High (95%)
  ──────────────────────────────────────────────────

  Findings (6):
  [1] Domain may be impersonating 'paypal' (paypal.com)
  [2] URL does not use HTTPS (encrypted connection)
  [3] URL path contains suspicious keywords: 'account', 'update'
  [4] Domain contains brand name 'paypal' but is not the official site
  [5] Domain/URL flagged as KNOWN MALICIOUS
  [6] Domain uses suspicious domain pattern
```

---

## Project Structure

```
PhishGuard/
├── README.md                  # This file
├── requirements.txt           # Python dependencies (only 3!)
├── LICENSE                    # MIT License
├── phishguard.py             # Main entry point (run this)
├── url_analyzer.py           # URL analysis engine (12 checks)
├── email_analyzer.py         # Email analysis engine (10 checks)
├── threat_intel.py           # Threat intelligence checker
├── scoring.py                # Risk scoring engine
├── report_generator.py       # Report creator (text + HTML)
├── sample_emails/            # Example emails for testing
│   ├── phishing_example_1.eml
│   ├── phishing_example_2.eml
│   └── legitimate_example.eml
├── sample_reports/           # Example output reports
└── data/                     # Threat intelligence data
    ├── suspicious_keywords.txt
    ├── trusted_domains.txt
    └── known_phishing_domains.txt
```

---

## Technologies Used

| Technology    | Purpose                        |
|---------------|--------------------------------|
| Python 3.8+   | Core language                  |
| `email` (stdlib) | Parse .eml email files      |
| `urllib` (stdlib) | Parse and analyze URLs      |
| `re` (stdlib)    | Pattern matching             |
| `requests`       | Threat intelligence API calls |
| `colorama`       | Coloured terminal output     |
| `tqdm`           | Progress bars                |

---

## Legal & Ethical Disclaimer

> **This tool is for EDUCATIONAL PURPOSES and authorized security analysis only.**
> Do not use this tool to analyze emails or URLs without proper authorization.
> Always respect privacy laws and organizational policies.
> The authors are not responsible for any misuse of this tool.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Chioma Iroka**

---

*Built with Python. Designed to help people identify phishing attempts and stay safe online.*
