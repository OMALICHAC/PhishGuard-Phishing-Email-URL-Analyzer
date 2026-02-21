# PhishGuard — Phishing Email & URL Analyzer

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

*A Python-based phishing detection tool that analyzes emails and URLs, scores them 0–100, and explains exactly WHY something is suspicious — the way a security analyst would.*

</div>

---

## Table of Contents

- [Why PhishGuard](#why-phishguard)
- [What PhishGuard Actually Does](#what-phishguard-actually-does)
- [Features at a Glance](#features-at-a-glance)
- [Architecture and Workflow](#architecture-and-workflow)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
  - [Interactive Mode](#1-interactive-mode-best-for-beginners)
  - [Command-Line Mode](#2-command-line-mode-for-scripting-and-advanced-use)
  - [Bulk Analysis](#3-bulk-analysis-scanning-many-urls-at-once)
  - [Generating Reports](#4-generating-reports)
- [Understanding the Risk Score](#understanding-the-risk-score)
- [Full Walkthrough: Analyzing a Phishing URL](#full-walkthrough-analyzing-a-phishing-url)
- [Full Walkthrough: Analyzing a Phishing Email](#full-walkthrough-analyzing-a-phishing-email)
- [Full Walkthrough: Analyzing a Legitimate Email](#full-walkthrough-analyzing-a-legitimate-email)
- [Walkthrough: Fake Package Delivery Scam](#walkthrough-fake-package-delivery-scam)
- [The Detection Engine Explained](#the-detection-engine-explained)
  - [URL Checks — 12 Indicators](#url-checks--12-indicators)
  - [Email Checks — 10 Indicators](#email-checks--10-indicators)
- [How Each Module Works](#how-each-module-works)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Skills Demonstrated](#skills-demonstrated)
- [Legal and Ethical Disclaimer](#legal-and-ethical-disclaimer)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Why PhishGuard

Phishing is still the #1 way attackers get in. I built PhishGuard to automate the analysis a security analyst would do manually — checking headers, decomposing URLs, looking up domains — and score the result 0-100 with plain-English explanations.

---

## What PhishGuard Actually Does

Give it a URL or an `.eml` file and it checks:

**For URLs**, it breaks the URL apart and examines each piece:
- Is the domain an IP address instead of a real domain name?
- Does the domain look like a typosquat of a well-known brand?
- Is it using a URL shortener to hide the real destination?
- Is the top-level domain one that's frequently abused (`.xyz`, `.buzz`, `.click`)?
- Does the URL path contain credential-harvesting keywords like `/login` or `/verify`?
- Is this domain already flagged in threat intelligence databases?

**For emails**, it parses the `.eml` file and inspects everything:
- Does the "From" address match the "Reply-To" address? (A mismatch is a classic spoofing sign.)
- Is the display name impersonating a known brand while the actual email address is from a random domain?
- Does the email use urgency or threat language to pressure the reader?
- Are there executable file attachments (`.exe`, `.js`, `.vbs`)?
- Did SPF and DKIM authentication pass or fail?
- Do the clickable links in the email body actually go where they claim to?

Every check that triggers adds points to a risk score (0–100). The tool then explains each finding in detail, assigns a risk level, and provides actionable recommendations.

---

## Features at a Glance

| Feature | Description |
|---------|-------------|
| **12 URL Checks** | IP detection, typosquatting, shorteners, suspicious TLDs, encoded characters, @ symbol tricks, and more |
| **10 Email Checks** | Header spoofing, SPF/DKIM validation, mismatched links, dangerous attachments, urgency/threat language |
| **Threat Intelligence** | Real-time lookups against URLhaus (abuse.ch) + a curated local database of known phishing domains |
| **Transparent Scoring** | Every check shows its point contribution — you see exactly WHY something was flagged |
| **Professional Reports** | Styled HTML reports with expandable findings sections, plus clean text reports |
| **Bulk Analysis** | Feed it a file of URLs and get a scored summary table for all of them |
| **Offline Mode** | The built-in threat database means it works without internet — useful for demos and air-gapped environments |
| **Educational** | Every phishing technique is explained in the code comments and in the output |
| **Interactive + CLI** | Guided menu for learning, command-line flags for scripting and automation |
| **Sample Data Included** | Two phishing emails and one legitimate email ship with the tool so you can test it immediately |

---

## Architecture and Workflow

Here is how data flows through PhishGuard from input to final report:

```
                        ┌─────────────────────┐
                        │    USER INPUT        │
                        │  URL or .eml file    │
                        └──────────┬──────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
             ┌──────▼──────┐              ┌──────▼──────┐
             │  URL         │              │  EMAIL       │
             │  ANALYZER    │              │  ANALYZER    │
             │  (12 checks) │              │  (10 checks) │
             └──────┬──────┘              └──────┬──────┘
                    │                             │
                    │    ┌─────────────────┐      │
                    ├───►│ THREAT INTEL    │◄─────┤
                    │    │ URLhaus API +   │      │
                    │    │ Local Database  │      │
                    │    └─────────────────┘      │
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  SCORING ENGINE     │
                        │  Combines findings  │
                        │  Calculates 0-100   │
                        │  Assigns risk level │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  REPORT GENERATOR   │
                        │  Terminal (colour)   │
                        │  HTML (styled)       │
                        │  Text (plain)        │
                        └─────────────────────┘
```

---

## Installation

### Prerequisites

- **Python 3.8 or higher** — [Download Python](https://www.python.org/downloads/)
- **pip** — Python's package manager (ships with Python)

### Setup

```bash
# Clone this repository
git clone https://github.com/OMALICHAC/PhishGuard-Phishing-Email-URL-Analyzer.git

# Move into the project folder
cd PhishGuard-Phishing-Email-URL-Analyzer

# (Optional but recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows

# Install the dependencies
pip install -r requirements.txt
```

That's it. Three packages get installed:

| Package | Why It's Needed |
|---------|-----------------|
| `requests` | Makes HTTP calls to the URLhaus threat intelligence API |
| `colorama` | Enables coloured text in the terminal (cross-platform) |
| `tqdm` | Shows progress bars when running bulk analysis |

Everything else — URL parsing, email parsing, regex, argument handling — is built into Python's standard library.

---

## Usage Guide

PhishGuard offers two interfaces: an **interactive menu** (great for learning and demos) and **command-line flags** (great for scripting and automation).

### 1. Interactive Mode (Best for Beginners)

```bash
python phishguard.py
```

This launches a guided menu:

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

Pick an option, paste in a URL or file path, and PhishGuard walks you through the results.

### 2. Command-Line Mode (For Scripting and Advanced Use)

```bash
# Analyze a single URL
python phishguard.py --url "http://paypa1.com/login/verify-account"

# Analyze an email file
python phishguard.py --email sample_emails/phishing_example_1.eml

# Analyze and save a report
python phishguard.py --url "http://suspicious-site.com" --report
```

| Flag | Short | What It Does |
|------|-------|--------------|
| `--url` | `-u` | Analyze a URL for phishing indicators |
| `--email` | `-e` | Analyze an .eml email file |
| `--bulk` | `-b` | Analyze multiple URLs from a text file (one per line) |
| `--report` | `-r` | Save the results as both an HTML and text report |
| `--help` | `-h` | Show the help message |

### 3. Bulk Analysis (Scanning Many URLs at Once)

Create a text file with one URL per line:

```
# urls_to_check.txt
https://paypa1.com/login
https://google.com
http://192.168.1.1/verify-account
https://amaz0n-security.xyz/update
```

Run it:

```bash
python phishguard.py --bulk urls_to_check.txt --report
```

PhishGuard analyzes each URL, displays a summary table with all scores, and saves individual HTML reports if `--report` is used.

### 4. Generating Reports

When you add the `--report` flag, PhishGuard saves two files:
- A **text report** (clean, readable, good for logs and documentation)
- An **HTML report** (styled, colour-coded, good for presentations and sharing)

The HTML report has expandable sections — click on any finding to read the full explanation of the phishing technique and why it was flagged.

---

## Understanding the Risk Score

PhishGuard's scoring system is designed to be **transparent**. You never have to wonder "why did it flag this?" — every check that contributes to the score is listed with its point value and a plain-English explanation.

### How Scoring Works

Each check that triggers adds a specific number of risk points. The points are summed (capped at 100), and the total determines the risk level:

```
  SCORE        RISK LEVEL        WHAT IT MEANS
 ─────────────────────────────────────────────────────────────
  0  - 20      ✅ LOW RISK        Likely legitimate. No significant
                                  phishing indicators found.

  21 - 40      🟡 MODERATE        Some suspicious elements. Could be
                                  legitimate but worth a closer look.
                                  Don't enter credentials.

  41 - 60      🟠 HIGH RISK       Multiple phishing indicators detected.
                                  Do NOT click links or provide any
                                  personal information.

  61 - 80      🔴 VERY HIGH       Strong phishing indicators across
                                  multiple categories. Report this to
                                  your security team immediately.

  81 - 100     🚨 CRITICAL        Almost certainly a phishing attempt.
                                  Delete it. If you already interacted,
                                  change your passwords now.
 ─────────────────────────────────────────────────────────────
```

---

## Full Walkthrough: Analyzing a Phishing URL

Let's walk through a real analysis so you can see exactly what PhishGuard does and what each result means.

We're going to analyze this URL: `http://paypa1.com/login/verify-account`

At first glance, it might look like a PayPal login page. But look closer — that's `paypa1` with a **number one**, not `paypal` with a lowercase **L**. A classic **typosquatting** attack.

```bash
$ python phishguard.py --url "http://paypa1.com/login/verify-account"
```

Here is the actual output:

```
════════════════════════════════════════════════════════════
  ANALYSIS RESULTS
════════════════════════════════════════════════════════════

  Target: http://paypa1.com/login/verify-account
  Type:   URL Analysis

  ──────────────────────────────────────────────────
  🔴  RISK LEVEL: VERY HIGH
  Score: [█████████████████████░░░░░░░░░] 70/100
  Strong phishing indicators, likely malicious
  Confidence: High (80%)
  ──────────────────────────────────────────────────
```

**What this tells us:** PhishGuard scored this URL 70 out of 100, which falls in the "VERY HIGH" risk range. Four separate checks triggered. The confidence is "High" because multiple independent indicators all point in the same direction. Let's look at each finding.

### Finding 1: Typosquatting Detected (+20 points)

```
  [1] Domain may be impersonating 'paypal' (paypal.com)
      Category: Typosquatting | Risk: +20 pts
```

**What this means:** PhishGuard detected that the domain `paypa1.com` is suspiciously similar to `paypal.com`. The attacker replaced the lowercase letter `l` with the number `1` — a swap that's almost invisible in many fonts. Attackers register these look-alike domains and set up fake login pages to harvest credentials.

### Finding 2: No HTTPS (+10 points)

```
  [2] URL does not use HTTPS (encrypted connection)
      Category: Missing HTTPS | Risk: +10 pts
```

**What this means:** The URL uses plain `http://` instead of `https://`. HTTPS encrypts the data between your browser and the server, which means without it, anything you type (including passwords) is sent in cleartext. Any legitimate login page — especially one claiming to be PayPal — would use HTTPS.

### Finding 3: Suspicious Keywords in URL Path (+10 points)

```
  [3] URL path contains suspicious keywords: 'login', 'verify', 'account'
      Category: Suspicious Keywords | Risk: +10 pts
```

**What this means:** The URL path (`/login/verify-account`) contains words strongly associated with credential harvesting. Phishing URLs are designed to look like login or verification pages because that's where victims are expected to type their usernames and passwords.

### Finding 4: Known Malicious Domain (+30 points)

```
  [4] Domain/URL flagged as KNOWN MALICIOUS
      Category: Threat Intelligence | Risk: +30 pts
```

**What this means:** PhishGuard checked `paypa1.com` against its threat intelligence databases and found it listed as a **known phishing domain**. This is the strongest possible signal — this domain has already been reported, investigated, and confirmed as malicious.

### The Verdict

Four findings, 70/100, VERY HIGH risk. Typosquatting + no encryption + credential-harvesting keywords + a known malicious domain. PhishGuard's recommendations:

```
  Recommendations:
  * DO NOT interact with this email/URL in any way.
  * Report this immediately to your IT/Security team.
  * If you entered credentials, change ALL passwords immediately.
  * Enable multi-factor authentication on all your accounts.
```

---

## Full Walkthrough: Analyzing a Phishing Email

Now let's analyze an email. The sample file `phishing_example_1.eml` simulates a classic bank account suspension scam.

```bash
$ python phishguard.py --email sample_emails/phishing_example_1.eml
```

```
  ──────────────────────────────────────────────────
  🚨  RISK LEVEL: CRITICAL
  Score: [██████████████████████████████] 100/100
  Almost certainly a phishing attempt
  Confidence: Very High (95%)
  ──────────────────────────────────────────────────

  Findings (8):
```

**Eight separate phishing indicators.** 100/100. Let's break them down.

### Finding 1: Sender Mismatch (+25 points)

```
  [1] From domain (nationa1-bank.com) differs from
      Reply-To domain (secure-banking-login.com)
      Category: Sender Mismatch | Risk: +25 pts
```

**What happened here:** The "From" header says `security-alert@nationa1-bank.com`, but the "Reply-To" points to `verify-account@secure-banking-login.com`. The attacker fakes the sender to look like a bank but routes replies to their own domain.

### Finding 2: Urgency Language (+10 points)

```
  [2] Email contains urgency keywords: 'urgent', 'immediately',
      'act now', 'within 24 hours', 'suspended'
      Category: Urgency Language | Risk: +10 pts
```

**What happened here:** Five urgency keywords in one email. Phishing relies on panic — if the victim fears their account is about to be closed, they skip the step of verifying the email is real.

### Finding 3: Threat Language (+10 points)

```
  [3] Email contains threatening language: 'unauthorized access',
      'security alert', 'legal action', 'will be suspended'
      Category: Threat Language | Risk: +10 pts
```

**What happened here:** Beyond urgency, the email uses explicit threats to frighten the recipient into acting. Legitimate organizations don't threaten customers with legal action via automated emails.

### Finding 4: Suspicious Embedded Link (+15 points)

```
  [4] Email contains suspicious URL (score: 45):
      http://192.168.45.67/login/verify-account
      Category: Suspicious Link | Risk: +15 pts
```

**What happened here:** The embedded link scored 45/100 on its own — a raw IP address with credential-harvesting keywords. Legitimate banks don't send you links that go to IP addresses.

### Finding 5: SPF Authentication Failed (+20 points)

```
  [5] SPF authentication FAILED — sender may be spoofed
      Category: Email Authentication | Risk: +20 pts
```

**What happened here:** SPF checks whether a mail server is authorized to send on behalf of a domain. `spf=fail` means whoever sent this email was pretending to be someone else.

### Finding 6: DKIM Authentication Failed (+20 points)

```
  [6] DKIM authentication FAILED — email may be tampered
      Category: Email Authentication | Risk: +20 pts
```

**What happened here:** DKIM uses digital signatures to prove an email hasn't been altered. A failure means the email was modified in transit or the sender is forging the domain.

### Finding 7: Generic Greeting (+5 points)

```
  [7] Email uses generic greeting: 'dear valued customer'
      Category: Generic Greeting | Risk: +5 pts
```

**What happened here:** "Dear Valued Customer" instead of an actual name. Phishing emails are sent in bulk — the attacker doesn't know the victim's name.

### Finding 8: Mismatched Link Text (+25 points)

```
  [8] Link text shows 'www.nationalbank.com' but actually
      goes to '192.168.45.67'
      Category: Mismatched Link | Risk: +25 pts
```

**What happened here:** The link displays as `https://www.nationalbank.com/secure/verify` but actually points to `http://192.168.45.67/login/verify-account`. The email lies about where the link goes. PhishGuard catches this automatically.

### The Verdict

Eight findings, 100/100, CRITICAL. Spoofed sender, failed authentication, urgency, threats, a generic greeting, a disguised malicious link, and link text that lies about its destination. Textbook phishing, identified with 95% confidence.

---

## Full Walkthrough: Analyzing a Legitimate Email

Just as important — PhishGuard doesn't flag legitimate emails. Here's a normal GitHub notification:

```bash
$ python phishguard.py --email sample_emails/legitimate_example.eml
```

```
  ──────────────────────────────────────────────────
  ✅  RISK LEVEL: LOW RISK
  Score: [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0/100
  Likely legitimate
  ──────────────────────────────────────────────────

  No suspicious indicators detected.

  Recommendations:
  * This appears to be legitimate, but always exercise caution.
  * Verify the sender if the email was unexpected.
```

**Score: 0/100. Zero false positives.** SPF/DKIM passed, sender domain matches `github.com`, no urgency or threat keywords, no suspicious attachments, no mismatched links. PhishGuard correctly identifies this as clean.

---

## Walkthrough: Fake Package Delivery Scam

The second sample email simulates a fake DHL package delivery notification.

```bash
$ python phishguard.py --email sample_emails/phishing_example_2.eml
```

```
  🚨  RISK LEVEL: CRITICAL
  Score: [██████████████████████████████] 100/100
  Almost certainly a phishing attempt
  Confidence: Very High (95%)

  Findings (7):

  [1] Display name claims 'DHL Express Delivery' but email is from 'dh1-delivery.com'
      Category: Display Name Spoofing | Risk: +20 pts

  [2] Email contains urgency keywords: 'within 48 hours'
      Category: Urgency Language | Risk: +10 pts

  [3] Possible spelling errors detected: 'informations'
      Category: Grammar Errors | Risk: +5 pts

  [4] Dangerous attachment(s) detected: 'DHL_Shipping_Label.exe'
      Category: Suspicious Attachment | Risk: +25 pts

  [5] Email contains suspicious URL (score: 30):
      https://dh1-delivery.com/track/reschedule?id=8847291056
      Category: Suspicious Link | Risk: +15 pts

  [6] SPF authentication FAILED — sender may be spoofed
      Category: Email Authentication | Risk: +20 pts

  [7] Email uses generic greeting: 'dear customer'
      Category: Generic Greeting | Risk: +5 pts
```

**Key things PhishGuard caught:**

- **Display name spoofing:** Says "DHL Express Delivery" but the address is `dh1-delivery.com` — number `1` instead of letter `l`.
- **Dangerous `.exe` attachment:** `DHL_Shipping_Label.exe` is an executable, not a shipping label — opening it would likely install malware.
- **Grammar errors:** "informations" instead of "information," common in bulk-generated phishing.
- **Failed SPF:** The sending server wasn't authorized for the claimed domain.

---

## The Detection Engine Explained

### URL Checks — 12 Indicators

Every URL is decomposed and tested against these 12 checks:

| # | Check | What It Catches | Points | Real-World Example |
|---|-------|-----------------|--------|--------------------|
| 1 | **IP Address as URL** | URLs using raw IPs instead of domain names | +25 | `http://192.168.1.1/login` — Legitimate sites use domain names; IPs are used to dodge domain-based blocking |
| 2 | **Excessive Subdomains** | Domains with more than 4 levels | +15 | `paypal.secure.login.evil.com` — The real domain is `evil.com`; the subdomains are window dressing |
| 3 | **Typosquatting** | Domains that look like known brands but aren't | +20 | `paypa1.com` (1 vs l), `g00gle.com` (0 vs o) — Nearly invisible character swaps |
| 4 | **URL Shortener** | Shortened links that hide the real destination | +10 | `bit.ly/xyz` — Could lead anywhere; commonly used to bypass email filters |
| 5 | **Suspicious TLD** | Top-level domains frequently abused for phishing | +10 | `.xyz`, `.top`, `.buzz`, `.click` — Cheap to register, minimal verification |
| 6 | **HTTPS Missing** | No encryption on the connection | +10 | `http://` — Any legitimate login page uses HTTPS |
| 7 | **Long URL** | URLs over 75 characters | +5 | Used to push the real domain out of the browser's visible address bar |
| 8 | **@ Symbol in URL** | The @ trick that changes the actual destination | +25 | `http://google.com@evil.com` — The browser goes to `evil.com`, not Google |
| 9 | **Suspicious Keywords** | Credential-harvesting words in the URL path | +10 | `/login`, `/verify`, `/secure`, `/update`, `/account` |
| 10 | **Suspicious Domain Pattern** | Excessive hyphens or brand names in non-official domains | +15 | `paypal-secure-login-verify.com` — The real PayPal doesn't need four hyphens |
| 11 | **Encoded Characters** | URL encoding used to obfuscate the domain | +10 | `%2F`, `%40` in the domain portion — Hiding the real destination |
| 12 | **Known Phishing Domain** | Domain flagged in threat intelligence databases | +30 | Matched against URLhaus (abuse.ch) or the local curated database |

### Email Checks — 10 Indicators

Every email is parsed and tested against these 10 checks:

| # | Check | What It Catches | Points | Real-World Example |
|---|-------|-----------------|--------|--------------------|
| 1 | **Sender/Reply-To Mismatch** | "From" and "Reply-To" go to different domains | +25 | From: bank@legit.com → Reply-To: hacker@evil.com |
| 2 | **Display Name Spoofing** | Trusted brand name with a random email address | +20 | "PayPal Security" <x9kj2@random-domain.com> |
| 3 | **Urgency Language** | Words designed to create panic | +10 | "URGENT", "ACT NOW", "Your account will be closed" |
| 4 | **Threat Language** | Words designed to frighten | +10 | "legal action", "unauthorized access", "permanently disabled" |
| 5 | **Grammar Errors** | Misspellings common in phishing | +5 | "verifiy", "informations", "securty", "acount" |
| 6 | **Suspicious Attachments** | Executable file types that can install malware | +25 | `.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.ps1` |
| 7 | **Suspicious Links** | URLs in the email body that score high on URL analysis | varies | Each link is run through the full URL analyzer |
| 8 | **SPF/DKIM Failure** | Email authentication mechanisms report failure | +20 | `spf=fail` or `dkim=fail` in Authentication-Results header |
| 9 | **Generic Greeting** | Impersonal salutation suggesting bulk sending | +5 | "Dear Customer", "Dear Valued Member", "Dear User" |
| 10 | **Mismatched Link Text** | Displayed link text differs from the actual URL | +25 | Text shows `paypal.com` but the link goes to `evil.com` |

---

## How Each Module Works

### `url_analyzer.py` — URL Phishing Detection

Takes any URL and decomposes it into its constituent parts — scheme, domain, subdomains, path, parameters. Then runs each of the 12 checks independently.

Here is how the tool sees a phishing URL:

```
  http://paypa1-secure.login-verify.xyz/account/update
  ^^^^                                ^^^^
  │                                   └── Suspicious keywords in path (+10)
  └── No HTTPS — connection is unencrypted (+10)

         ^^^^^^^
         └── Typosquatting: "paypa1" looks like "paypal" (+20)

                                   ^^^^
                                   └── Suspicious TLD: .xyz (+10)
```

Each finding is independent. They feed into the scoring engine, which adds them up and determines the overall risk.

### `email_analyzer.py` — Email Phishing Detection

Uses Python's built-in `email` library to parse `.eml` files. Extracts and examines headers (From, Reply-To, Authentication-Results, Date, Subject), body content (text and HTML, plus embedded URLs), and attachments (filenames and extensions). Every embedded URL gets run through the full URL analyzer automatically.

### `threat_intel.py` — Threat Intelligence

Checks domains against two sources: a local database (`data/known_phishing_domains.txt`) with 87+ known phishing domains that works offline, and the URLhaus API (abuse.ch) for real-time lookups when internet is available. A trusted domain whitelist (`data/trusted_domains.txt`) with 65+ legitimate domains prevents false positives on sites like Google, PayPal, or Amazon.

### `scoring.py` — Risk Scoring Engine

Collects findings from all analyzers, sums the risk points (capped at 100), and determines the risk level. Also calculates a confidence rating based on the number of findings and generates tailored recommendations based on severity.

### `report_generator.py` — Report Generator

Creates text reports (clean, structured, good for logs) and HTML reports (styled with CSS, colour-coded risk scores, visual progress bar, expandable finding sections). HTML reports open in any browser and can be shared directly.

---

## Project Structure

```
PhishGuard/
│
├── phishguard.py              # Main entry point — run this file
│                               # Handles the interactive menu, CLI arguments,
│                               # and colour-coded terminal output
│
├── url_analyzer.py            # URL analysis engine
│                               # 12 independent phishing checks on URLs
│                               # Typosquatting, IP detection, TLD analysis, etc.
│
├── email_analyzer.py          # Email analysis engine
│                               # 10 phishing checks on .eml files
│                               # Header parsing, SPF/DKIM, attachment inspection
│
├── threat_intel.py            # Threat intelligence module
│                               # URLhaus API integration (abuse.ch)
│                               # Local known-phishing database
│                               # Trusted domain whitelist
│
├── scoring.py                 # Risk scoring engine
│                               # Combines findings into a 0-100 score
│                               # Generates risk levels and recommendations
│
├── report_generator.py        # Report generation module
│                               # Professional HTML reports with CSS
│                               # Clean text reports for documentation
│
├── requirements.txt           # Python dependencies (3 packages)
├── LICENSE                    # MIT License
├── .gitignore                 # Git ignore rules
├── README.md                  # This file
│
├── data/                       # Threat intelligence data files
│   ├── known_phishing_domains.txt     # 87+ known phishing domains
│   ├── trusted_domains.txt            # 65+ known legitimate domains
│   └── suspicious_keywords.txt        # 78 phishing-related keywords
│
├── sample_emails/              # Test emails — try these immediately
│   ├── phishing_example_1.eml         # Fake bank account suspension scam
│   ├── phishing_example_2.eml         # Fake package delivery notification
│   └── legitimate_example.eml         # Real GitHub newsletter (should score 0)
│
└── sample_reports/             # Pre-generated HTML reports
    ├── sample_url_report.html         # URL analysis report example
    └── sample_email_report.html       # Email analysis report example
```

---

## Technologies Used

| Technology | What It Does in This Project |
|------------|------------------------------|
| **Python 3** | Core language for all modules |
| **email** (stdlib) | Parses `.eml` email files — extracts headers, body, and attachments |
| **urllib** (stdlib) | Decomposes URLs into scheme, domain, path, and parameters |
| **re** (stdlib) | Regular expressions for pattern matching (IP detection, URL extraction, etc.) |
| **argparse** (stdlib) | Handles `--url`, `--email`, `--bulk`, `--report` command-line flags |
| **requests** | HTTP client for querying the URLhaus threat intelligence API |
| **colorama** | Cross-platform coloured terminal output (risk levels are colour-coded) |
| **tqdm** | Progress bars for bulk URL analysis |
| **URLhaus API** | Free real-time threat intelligence feed from abuse.ch |

---

## Skills Demonstrated

Covers phishing detection (22 checks), threat intelligence integration, email authentication (SPF/DKIM), Python CLI design, and HTML report generation.

---

## Legal and Ethical Disclaimer

> **This tool is for EDUCATIONAL PURPOSES and authorized security analysis only.**
>
> - Do not analyze emails or URLs without proper authorization
> - Always respect privacy laws and organizational policies
> - Do not use PhishGuard to facilitate or conduct phishing attacks
> - The authors are not responsible for any misuse of this tool
>
> **PhishGuard is a DEFENSIVE tool** — it helps you detect and understand phishing, not create it.

---

## Contributing

Contributions are welcome. Here's how:

1. **Fork** this repository
2. **Create** a feature branch (`git checkout -b feature/new-feature`)
3. **Commit** your changes (`git commit -m "Add new feature"`)
4. **Push** to the branch (`git push origin feature/new-feature`)
5. **Open** a Pull Request

### Ideas for Contributions

- Integrate additional threat intelligence feeds (PhishTank, Google Safe Browsing)
- Add support for `.msg` email format (Microsoft Outlook)
- Build a web-based interface using Flask or FastAPI
- Add machine learning-based phishing classification

---

## Author

**Chioma Iroka**
Computer Science Graduate | Cybersecurity Focus

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
