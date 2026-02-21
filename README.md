# 🛡️ PhishGuard — Phishing Email & URL Analyzer

<div align="center">

```
░█▀█░█░█░▀█▀░█▀▀░█░█░█▀▀░█░█░█▀█░█▀▄
░█▀▀░█▀█░░█░░▀▀█░█▀█░█░█░█░█░█▀█░█▀▄
░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀
```

**Detect phishing emails and URLs with confidence.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Type-Security%20Tool-red.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

*A beginner-friendly Python tool that analyzes emails and URLs for phishing indicators, scores them 0-100, and explains exactly WHY something is suspicious.*

</div>

---

## 📋 Table of Contents

- [What Is PhishGuard?](#-what-is-phishguard)
- [Why Phishing Detection Matters](#-why-phishing-detection-matters)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Interactive Mode](#interactive-mode-easiest)
  - [Command-Line Mode](#command-line-mode)
  - [Bulk Analysis](#bulk-analysis)
- [Understanding the Risk Score](#-understanding-the-risk-score)
  - [URL Checks (12 Indicators)](#url-checks-12-indicators)
  - [Email Checks (10 Indicators)](#email-checks-10-indicators)
- [Example Analysis Output](#-example-analysis-output)
- [Project Structure](#-project-structure)
- [How Each Module Works](#-how-each-module-works)
- [Technologies Used](#-technologies-used)
- [Sample Reports](#-sample-reports)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🔍 What Is PhishGuard?

PhishGuard is a **phishing detection tool** built in Python that analyzes emails and URLs for signs of phishing attacks. It performs the same types of checks that security analysts do manually, but automated and explained in plain English.

**What does it do?**

1. **Analyzes URLs** for 12 distinct phishing indicators (typosquatting, IP-based URLs, suspicious TLDs, URL shorteners, and more)
2. **Analyzes email files** (.eml format) for 10 phishing indicators (spoofed senders, urgency language, mismatched links, failed SPF/DKIM, and more)
3. **Checks threat intelligence** databases (URLhaus API + local database) for known malicious domains
4. **Scores each target 0-100** with a transparent breakdown showing exactly which checks triggered and why
5. **Generates professional reports** (HTML and text) suitable for documentation

**Who is this for?**

- Cybersecurity students and professionals learning phishing analysis
- SOC (Security Operations Centre) analysts building their portfolio
- Anyone studying for CompTIA Security+, CEH, or similar certifications
- Security awareness trainers demonstrating phishing techniques
- Anyone who wants to understand how phishing detection works

---

## 🎯 Why Phishing Detection Matters

> **Phishing is the #1 initial attack vector in cybersecurity**, responsible for over 80% of reported security incidents.
> — *Verizon 2024 Data Breach Investigations Report*

Understanding how to detect phishing is one of the most valuable skills for any cybersecurity professional. PhishGuard teaches you the techniques by implementing them:

- **Typosquatting detection** — How attackers create look-alike domains
- **Email header analysis** — How to spot spoofed senders
- **Threat intelligence** — Using reputation databases to identify known threats
- **Social engineering indicators** — Recognizing urgency and fear tactics

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **12 URL Checks** | Comprehensive URL analysis covering IP addresses, typosquatting, suspicious TLDs, URL shorteners, encoded characters, and more |
| **10 Email Checks** | Deep email analysis including header spoofing, SPF/DKIM validation, mismatched links, suspicious attachments, urgency/threat language |
| **Threat Intelligence** | Real-time checks against URLhaus (abuse.ch) + local curated database of known phishing domains |
| **Transparent Scoring** | Every check shows its point contribution — users see exactly WHY something is flagged |
| **Professional Reports** | Styled HTML reports with expandable findings, plus clean text reports |
| **Bulk Analysis** | Analyze multiple URLs from a file with summary table |
| **Offline Mode** | Built-in threat database ensures the tool works without internet |
| **Educational** | Every phishing technique is explained in comments and output |
| **Interactive + CLI** | Guided menu for beginners, command-line flags for advanced users |
| **Sample Data** | Includes example phishing and legitimate emails for immediate testing |
| **Heavily Commented** | Every function and phishing concept is explained in the code |

---

## 🔄 How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│                     PhishGuard Workflow                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   [INPUT] URL or .eml Email File                                 │
│        │                                                         │
│        ├──── URL? ─────▶ URL ANALYZER (12 checks)                │
│        │                    │  IP address detection               │
│        │                    │  Typosquatting detection             │
│        │                    │  URL shortener check                 │
│        │                    │  Suspicious TLD check                │
│        │                    │  ... and 8 more checks               │
│        │                    ▼                                      │
│        │              THREAT INTEL                                │
│        │                    │  Check URLhaus API (abuse.ch)        │
│        │                    │  Check local phishing database       │
│        │                    ▼                                      │
│        ├──── Email? ──▶ EMAIL ANALYZER (10 checks)                │
│        │                    │  Sender/Reply-To mismatch            │
│        │                    │  Display name spoofing               │
│        │                    │  SPF/DKIM authentication             │
│        │                    │  Urgency & threat language            │
│        │                    │  ... and 6 more checks               │
│        │                    ▼                                      │
│        └─────────────▶ RISK SCORING ENGINE                        │
│                            │  Combine all findings                 │
│                            │  Calculate score (0-100)              │
│                            │  Determine risk level                 │
│                            │  Generate recommendations             │
│                            ▼                                      │
│                       REPORT GENERATOR                            │
│                            │  Terminal output (colour-coded)       │
│                            │  HTML report (styled, professional)   │
│                            │  Text report (clean, readable)        │
│                            ▼                                      │
│   [OUTPUT] Risk score + detailed findings + recommendations      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.8 or higher** — [Download Python](https://www.python.org/downloads/)
- **pip** — Python's package manager (comes with Python)

### Step-by-Step Installation

```bash
# Step 1: Clone this repository
git clone https://github.com/OMALICHAC/PhishGuard-Phishing-Email-URL-Analyzer.git

# Step 2: Navigate into the project folder
cd PhishGuard-Phishing-Email-URL-Analyzer

# Step 3: (Optional but recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # On macOS/Linux
# venv\Scripts\activate         # On Windows

# Step 4: Install the required packages
pip install -r requirements.txt
```

**That's it! You're ready to detect phishing.**

### What Gets Installed?

Only **3 small packages** (everything else is built into Python):

| Package | Size | Purpose |
|---------|------|---------|
| `requests` | ~150 KB | Makes HTTP calls to the URLhaus threat intelligence API |
| `colorama` | ~25 KB | Enables coloured text in the terminal |
| `tqdm` | ~75 KB | Shows progress bars during bulk analysis |

---

## 💻 Usage

### Interactive Mode (Easiest)

Just run the tool and follow the prompts:

```bash
python phishguard.py
```

You'll see a menu:

```
╔══════════════════════════════════════╗
║        PhishGuard v1.0.0             ║
║      Phishing Detection Tool         ║
╠══════════════════════════════════════╣
║                                      ║
║  1. Analyze a URL                    ║
║  2. Analyze an email file (.eml)     ║
║  3. Bulk analyze (multiple URLs)     ║
║  4. View help / how to use           ║
║  5. Exit                             ║
║                                      ║
╚══════════════════════════════════════╝
```

### Command-Line Mode

For users who prefer command-line flags:

```bash
# Analyze a single URL
python phishguard.py --url "https://paypa1-secure.login-verify.com/account"

# Analyze an email file
python phishguard.py --email sample_emails/phishing_example_1.eml

# Bulk analyze URLs from a file
python phishguard.py --bulk urls_to_check.txt

# Analyze and save report
python phishguard.py --url "https://suspicious.com" --report

# Show help
python phishguard.py --help
```

### Command-Line Options

| Flag | Short | Description |
|------|-------|-------------|
| `--url` | `-u` | URL to analyze for phishing indicators |
| `--email` | `-e` | Path to .eml email file to analyze |
| `--bulk` | `-b` | Path to file with URLs (one per line) |
| `--report` | `-r` | Save analysis report (text + HTML) |
| `--help` | `-h` | Show help message |

### Bulk Analysis

Create a text file with one URL per line:

```
# urls_to_check.txt
https://paypa1.com/login
https://google.com
http://192.168.1.1/verify-account
https://amaz0n-security.xyz/update
```

Then run:
```bash
python phishguard.py --bulk urls_to_check.txt --report
```

PhishGuard will analyze each URL and show a summary table with all scores.

---

## 📊 Understanding the Risk Score

PhishGuard uses a **transparent scoring system**. Every check that triggers adds risk points, and the total determines the risk level. You can see exactly which checks fired and how many points each contributed.

### Scoring Scale

| Score | Risk Level | Icon | What It Means | What To Do |
|-------|------------|------|---------------|------------|
| 0-20 | **LOW RISK** | ✅ | Likely legitimate | Likely safe, but verify if unexpected |
| 21-40 | **MODERATE RISK** | 🟡 | Some suspicious elements | Proceed with caution, verify the sender |
| 41-60 | **HIGH RISK** | 🟠 | Multiple phishing indicators | Do NOT click links or provide information |
| 61-80 | **VERY HIGH** | 🔴 | Strong phishing indicators | Report to security team immediately |
| 81-100 | **CRITICAL** | 🚨 | Almost certainly phishing | Delete immediately, change passwords if you interacted |

### URL Checks (12 Indicators)

| # | Check | What It Detects | Points | Example |
|---|-------|-----------------|--------|---------|
| 1 | IP Address as URL | Raw IP instead of domain | +25 | `http://192.168.1.1/login` |
| 2 | Excessive Subdomains | Too many subdomain levels | +15 | `paypal.secure.login.evil.com` |
| 3 | Typosquatting | Look-alike brand domains | +20 | `paypa1.com`, `g00gle.com` |
| 4 | URL Shortener | Hidden destinations | +10 | `bit.ly/xyz`, `tinyurl.com/abc` |
| 5 | Suspicious TLD | Frequently abused TLDs | +10 | `.xyz`, `.top`, `.buzz`, `.click` |
| 6 | HTTPS Missing | No encryption | +10 | `http://` instead of `https://` |
| 7 | Long URL | Unusually long (>75 chars) | +5 | URL hiding real domain |
| 8 | @ Symbol in URL | Deceptive URL trick | +25 | `http://google.com@evil.com` |
| 9 | Suspicious Keywords | Login/verify words in path | +10 | `/login`, `/verify`, `/secure` |
| 10 | Suspicious Domain Pattern | Hyphens, brand impersonation | +15 | `paypal-secure-login-verify.com` |
| 11 | Encoded Characters | URL obfuscation | +10 | `%2F`, `%40` in domain |
| 12 | Known Phishing Domain | Flagged in threat databases | +30 | Matched in URLhaus or local DB |

### Email Checks (10 Indicators)

| # | Check | What It Detects | Points | Example |
|---|-------|-----------------|--------|---------|
| 1 | Sender/Reply-To Mismatch | Different From and Reply-To domains | +25 | From: bank@legit.com, Reply-To: hacker@evil.com |
| 2 | Display Name Spoofing | Trusted name with wrong email | +20 | "PayPal Security" <random@evil.com> |
| 3 | Urgency Language | Pressure words | +10 | "URGENT", "ACT NOW", "IMMEDIATELY" |
| 4 | Threat Language | Scare tactics | +10 | "account closed", "legal action" |
| 5 | Grammar Errors | Common phishing misspellings | +5 | "verifiy", "securty", "acount" |
| 6 | Suspicious Attachments | Dangerous file types | +25 | .exe, .js, .vbs, .scr files |
| 7 | Suspicious Links | Phishing URLs in body | varies | Links scoring high on URL analysis |
| 8 | SPF/DKIM Failure | Email authentication failed | +20 | Spoofed sender not authorized |
| 9 | Generic Greeting | Impersonal salutation | +5 | "Dear Customer" instead of your name |
| 10 | Mismatched Link Text | Display text differs from actual URL | +25 | Text shows paypal.com, links to evil.com |

---

## 🖥️ Example Analysis Output

### Analyzing a Phishing Email (Score: 100/100 CRITICAL)

```
$ python phishguard.py --email sample_emails/phishing_example_1.eml

════════════════════════════════════════════════════════════
  ANALYSIS RESULTS
════════════════════════════════════════════════════════════

  Target: phishing_example_1.eml
  Type:   EMAIL Analysis

  ──────────────────────────────────────────────────
  🚨 RISK LEVEL: CRITICAL
  Score: [██████████████████████████████] 100/100
  Almost certainly a phishing attempt
  Confidence: Very High (95%)
  ──────────────────────────────────────────────────

  Findings (8):

  [1] From domain (nationa1-bank.com) differs from Reply-To domain
      (secure-banking-login.com)
      Category: Sender Mismatch | Risk: +25 pts

  [2] Email contains urgency keywords: 'urgent', 'immediately',
      'act now', 'within 24 hours', 'suspended'
      Category: Urgency Language | Risk: +10 pts

  [3] Email contains threatening language: 'unauthorized access',
      'security alert', 'legal action', 'will be suspended'
      Category: Threat Language | Risk: +10 pts

  [4] Email contains suspicious URL (score: 45)
      Category: Suspicious Link | Risk: +15 pts

  [5] SPF authentication FAILED — sender may be spoofed
      Category: Email Authentication | Risk: +20 pts

  [6] DKIM authentication FAILED — email may be tampered
      Category: Email Authentication | Risk: +20 pts

  [7] Email uses generic greeting: 'dear valued customer'
      Category: Generic Greeting | Risk: +5 pts

  [8] Link text shows 'www.nationalbank.com' but actually goes to
      '192.168.45.67'
      Category: Mismatched Link | Risk: +25 pts

  Recommendations:
  * DO NOT interact with this email/URL in any way.
  * Report this immediately to your IT/Security team.
  * If you entered credentials, change ALL passwords immediately.
  * Enable multi-factor authentication on all your accounts.
```

### Analyzing a Legitimate URL (Score: 0/100 LOW)

```
$ python phishguard.py --url "https://www.google.com"

  ──────────────────────────────────────────────────
  ✅ RISK LEVEL: LOW RISK
  Score: [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0/100
  Likely legitimate
  ──────────────────────────────────────────────────

  Findings (1):
  [1] Domain 'www.google.com' is a known legitimate domain
```

---

## 📁 Project Structure

```
PhishGuard/
│
├── phishguard.py             # Main entry point — run this file
│                              # Interactive menu + CLI argument handling
│                              # Colour-coded terminal output
│
├── url_analyzer.py           # URL analysis engine
│                              # 12 distinct phishing checks on URLs
│                              # Typosquatting, IP detection, TLD checks, etc.
│
├── email_analyzer.py         # Email analysis engine
│                              # 10 phishing checks on .eml files
│                              # Header analysis, SPF/DKIM, attachment checks
│
├── threat_intel.py           # Threat intelligence module
│                              # URLhaus API integration (abuse.ch)
│                              # Local known-phishing database
│                              # Trusted domain whitelist
│
├── scoring.py                # Risk scoring engine
│                              # Combines findings into 0-100 score
│                              # Generates risk levels and recommendations
│
├── report_generator.py       # Report generation module
│                              # Professional HTML reports with CSS
│                              # Clean text reports
│                              # Expandable finding details
│
├── requirements.txt          # Python dependencies (only 3 packages!)
├── LICENSE                   # MIT License
├── .gitignore                # Git ignore rules
├── README.md                 # This file
│
├── data/                      # Threat intelligence data files
│   ├── known_phishing_domains.txt    # Curated list of known bad domains
│   ├── trusted_domains.txt           # Known legitimate domains (whitelist)
│   └── suspicious_keywords.txt       # Words common in phishing
│
├── sample_emails/             # Test emails (try these immediately!)
│   ├── phishing_example_1.eml        # Fake bank account suspension
│   ├── phishing_example_2.eml        # Fake package delivery notification
│   └── legitimate_example.eml        # Normal newsletter (should score LOW)
│
└── sample_reports/            # Example HTML reports
    ├── sample_url_report.html
    └── sample_email_report.html
```

---

## 🧠 How Each Module Works

### url_analyzer.py — URL Phishing Detection

**Concept: Breaking down and examining every part of a URL**

A URL like `http://paypa1-secure.login-verify.xyz/account/update` has multiple red flags that PhishGuard detects:

```python
# Each part of a URL tells us something:
#
#   http://paypa1-secure.login-verify.xyz/account/update
#   ^^^^                                ^^^^
#   No HTTPS = unencrypted             Suspicious keywords
#
#          ^^^^^^^
#          Typosquatting "paypal" (1 instead of l)
#
#                                   ^^^^
#                                   Suspicious TLD (.xyz)
```

The URL analyzer parses the URL and runs 12 independent checks, each testing for a different phishing technique.

### email_analyzer.py — Email Phishing Detection

**Concept: Examining email headers and content for manipulation**

Email headers contain metadata that reveals how an email was actually sent, versus how it claims to have been sent:

```
From: "PayPal Security" <security@paypal.com>     ← What you see
Reply-To: verify@evil-hacker-domain.com            ← Where replies go
Authentication-Results: spf=fail; dkim=fail        ← Email is spoofed!
```

PhishGuard reads `.eml` files using Python's built-in `email` library and checks every header, the body text, attachments, and embedded links.

### threat_intel.py — Threat Intelligence Checking

**Concept: Checking domains against known-bad databases**

Just like police check fingerprints against criminal databases, we check domains against threat intelligence feeds:

1. **Local database** — A curated list of known phishing domains (works offline)
2. **URLhaus API** — A free, real-time API from abuse.ch that tracks malicious URLs
3. **Trusted domains whitelist** — Known legitimate domains to reduce false positives

### scoring.py — Risk Assessment Engine

**Concept: Combining multiple weak signals into a strong conclusion**

No single indicator proves phishing on its own. But when multiple indicators appear together, the confidence increases dramatically:

- IP address as URL alone = suspicious
- IP address + no HTTPS + urgency language + spoofed sender = almost certainly phishing

The scoring engine collects all findings, adds up the points (capped at 100), and generates a risk level with actionable recommendations.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3** | Core programming language |
| **email** (built-in) | Parse .eml email files and headers |
| **urllib** (built-in) | Parse and decompose URLs |
| **re** (built-in) | Regular expressions for pattern matching |
| **argparse** (built-in) | Command-line argument parsing |
| **requests** | HTTP requests to URLhaus threat intelligence API |
| **colorama** | Cross-platform coloured terminal output |
| **tqdm** | Progress bars for bulk analysis |
| **URLhaus API** | Free real-time threat intelligence from abuse.ch |

---

## 📄 Sample Reports

PhishGuard generates professional **HTML reports** that you can open in any browser. Each report includes:

- **Risk score** displayed prominently with colour coding
- **Visual score bar** showing the score out of 100
- **Expandable findings** — click each finding to see the full explanation
- **Recommendations** tailored to the risk level
- **Professional disclaimer** for documentation purposes

Sample reports are included in the `sample_reports/` folder — open them in your browser to see the design.

---

## ⚖️ Legal Disclaimer

> **This tool is for EDUCATIONAL PURPOSES and authorized security analysis only.**
>
> - Do not use this tool to analyze emails or URLs without proper authorization
> - Always respect privacy laws and organizational policies
> - Do not use PhishGuard to facilitate or conduct phishing attacks
> - The authors are not responsible for any misuse of this tool
>
> **PhishGuard is a DEFENSIVE tool** — it helps you detect and understand phishing, not create it.
>
> **For practicing email analysis safely:**
> - Use the sample emails included in `sample_emails/`
> - Analyze your own spam/phishing emails (forward suspicious emails to yourself as .eml files)
> - Use test domains and URLs, not real people's private communications

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** this repository
2. **Create** a feature branch (`git checkout -b feature/new-feature`)
3. **Commit** your changes (`git commit -m "Add new feature"`)
4. **Push** to the branch (`git push origin feature/new-feature`)
5. **Open** a Pull Request

### Ideas for Contributions

- Add more typosquatting detection patterns
- Integrate additional threat intelligence feeds (PhishTank, Google Safe Browsing)
- Add support for .msg email format (Outlook)
- Create a web-based interface using Flask
- Add machine learning-based classification
- Improve grammar checking with NLP techniques
- Add email forwarding analysis (header chain examination)

---

## 👤 Author

**Chioma Iroka**

- Computer Science graduate with a focus on cybersecurity
- Skilled in network security, vulnerability assessment, and defensive operations
- Experienced with threat detection, Nessus Essentials, and Wireshark

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with Python for the cybersecurity community**

*Phishing is the #1 attack vector — understanding it is your best defence.*

*If you found this useful, please consider giving it a ⭐!*

</div>
