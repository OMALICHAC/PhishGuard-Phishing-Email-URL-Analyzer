"""
PhishGuard - Email Analysis Engine
====================================
Reads .eml email files and checks for phishing indicators.

Uses Python's built-in `email` library to parse .eml files.

Performs 10 distinct checks, each contributing risk points:
    1.  Sender vs Reply-To mismatch   (+25 points)
    2.  Display name spoofing         (+20 points)
    3.  Urgency language              (+10 points)
    4.  Threat language               (+10 points)
    5.  Grammar/spelling errors       (+5 points)
    6.  Suspicious attachments        (+25 points)
    7.  Links in email body           (varies)
    8.  SPF/DKIM check (basic)        (+20 points)
    9.  Generic greeting              (+5 points)
    10. Mismatched link text          (+25 points)
"""

import email
import email.policy
import os
import re
from email import policy
from email.parser import BytesParser

from scoring import create_risk_score
from url_analyzer import analyze_url

# Path to the data directory
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# === Urgency Keywords ===
# Words/phrases that create a false sense of urgency, commonly used in phishing
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "right away", "expires today",
    "limited time", "time sensitive", "within 24 hours", "within 48 hours",
    "don't delay", "hurry", "last chance", "final warning", "final notice",
    "expire", "expiring", "suspended", "suspension", "asap",
]

# === Threat Keywords ===
# Words that threaten negative consequences, pressuring the victim to act
THREAT_KEYWORDS = [
    "account closed", "account suspended", "account terminated",
    "unauthorized access", "unauthorized transaction", "security alert",
    "security warning", "legal action", "law enforcement", "police report",
    "court order", "penalty", "fine", "locked out", "permanently disabled",
    "will be closed", "will be suspended", "will be terminated",
]

# === Suspicious Attachment Extensions ===
# File types commonly used to deliver malware
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".msi",
    ".com", ".pif", ".hta", ".cpl", ".jar", ".wsf", ".reg",
    ".dll", ".lnk", ".inf", ".rgs", ".sct",
}

# === Generic Greetings ===
# Phishing emails often use generic greetings instead of your real name
GENERIC_GREETINGS = [
    "dear customer", "dear valued customer", "dear user",
    "dear account holder", "dear member", "dear client",
    "dear sir", "dear madam", "dear sir/madam", "dear sir or madam",
    "dear valued member", "dear email user",
    "hello customer", "hello user",
    "attention customer", "attention user",
]

# === Common Misspellings Found in Phishing ===
COMMON_PHISHING_MISSPELLINGS = [
    "recieve", "verifiy", "informations", "securty", "acount",
    "suspeneded", "immediattely", "verfy", "pasword", "updatte",
    "accont", "activite", "regestration", "notifcation", "temporarly",
]


def analyze_email(filepath):
    """
    Perform a comprehensive phishing analysis on an email file (.eml).

    This is the main function called by phishguard.py. It parses the
    email file and runs all 10 checks.

    Args:
        filepath: Path to the .eml email file

    Returns:
        RiskScore object with all findings, score, and recommendations
    """
    risk = create_risk_score(os.path.basename(filepath), "email")

    # Parse the email file
    try:
        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        risk.add_finding(
            0, "Error",
            f"Email file not found: {filepath}",
            "The specified email file could not be found. Please check the path."
        )
        return risk
    except Exception as e:
        risk.add_finding(
            0, "Error",
            f"Failed to parse email file: {str(e)}",
            "The email file could not be parsed. It may be corrupted or not a valid .eml file."
        )
        return risk

    # Extract email components
    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    body = _get_email_body(msg)
    headers = dict(msg.items())

    # Run all 10 checks
    _check_sender_reply_to_mismatch(risk, sender, reply_to)
    _check_display_name_spoofing(risk, sender)
    _check_urgency_language(risk, subject, body)
    _check_threat_language(risk, subject, body)
    _check_grammar_errors(risk, body)
    _check_suspicious_attachments(risk, msg)
    _check_links_in_body(risk, body)
    _check_spf_dkim(risk, headers)
    _check_generic_greeting(risk, body)
    _check_mismatched_links(risk, body)

    return risk


def _get_email_body(msg):
    """
    Extract the body text from an email message.

    Handles both plain text and HTML emails, preferring plain text.

    Args:
        msg: email.message.EmailMessage object

    Returns:
        String containing the email body text
    """
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_content()
                    break
                except Exception:
                    pass
            elif content_type == "text/html" and not body:
                try:
                    body = part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload(decode=True) or "")

    return body if isinstance(body, str) else str(body)


def _extract_email_address(header_value):
    """
    Extract the actual email address from a header value.

    Handles formats like:
        - "John Doe <john@example.com>"
        - "john@example.com"
        - "<john@example.com>"

    Args:
        header_value: The raw header value string

    Returns:
        The email address string, or empty string if not found
    """
    if not header_value:
        return ""

    # Try to extract from angle brackets
    match = re.search(r"<([^>]+)>", str(header_value))
    if match:
        return match.group(1).lower()

    # Try to extract a plain email address
    match = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", str(header_value))
    if match:
        return match.group(0).lower()

    return str(header_value).strip().lower()


def _extract_domain(email_address):
    """Extract the domain part from an email address."""
    if "@" in email_address:
        return email_address.split("@")[1].lower()
    return ""


# ============================================================
# Individual Check Functions
# ============================================================

def _check_sender_reply_to_mismatch(risk, sender, reply_to):
    """
    CHECK 1: Sender vs Reply-To Mismatch (+25 points)

    In phishing emails, the "From" address and "Reply-To" address
    often differ. The "From" is spoofed to look legitimate, but
    replies go to the attacker's real address.

    Example:
        From: security@paypal.com
        Reply-To: hacker123@evil-domain.com
    """
    if not reply_to:
        return

    sender_addr = _extract_email_address(sender)
    reply_addr = _extract_email_address(reply_to)

    if not sender_addr or not reply_addr:
        return

    sender_domain = _extract_domain(sender_addr)
    reply_domain = _extract_domain(reply_addr)

    if sender_domain and reply_domain and sender_domain != reply_domain:
        risk.add_finding(
            25, "Sender Mismatch",
            f"From domain ({sender_domain}) differs from Reply-To domain ({reply_domain})",
            f"SENDER MISMATCH: The email claims to be from '{sender_addr}' "
            f"but replies would go to '{reply_addr}' — a completely different "
            "domain! In phishing attacks, the 'From' address is spoofed to "
            "look legitimate, while the 'Reply-To' address is the attacker's "
            "real email. This is a strong phishing indicator."
        )


def _check_display_name_spoofing(risk, sender):
    """
    CHECK 2: Display Name Spoofing (+20 points)

    Attackers set a trusted display name (like "PayPal Security")
    but use a completely unrelated email address.

    Example: "PayPal Security" <random123@evil-domain.com>

    Most email clients show only the display name, hiding the actual address.
    """
    if not sender:
        return

    sender_str = str(sender)

    # Check if there's a display name with angle brackets
    display_match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>', sender_str)
    if not display_match:
        return

    display_name = display_match.group(1).strip().lower()
    email_addr = display_match.group(2).strip().lower()
    email_domain = _extract_domain(email_addr)

    # Check if the display name contains a well-known brand
    # but the email domain doesn't match
    from url_analyzer import BRAND_DOMAINS

    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in display_name and email_domain != legit_domain:
            # Also check if email domain is a subdomain of the legit domain
            if not email_domain.endswith("." + legit_domain):
                risk.add_finding(
                    20, "Display Name Spoofing",
                    f"Display name claims '{display_match.group(1).strip()}' but email is from '{email_domain}'",
                    f"DISPLAY NAME SPOOFING: The sender's display name contains "
                    f"'{brand}' (suggesting {legit_domain}), but the actual "
                    f"email address is from '{email_domain}'. Attackers set "
                    "trusted display names to trick users — most email clients "
                    "show only the display name, hiding the real email address. "
                    "Always check the actual email address, not just the name."
                )
                break


def _check_urgency_language(risk, subject, body):
    """
    CHECK 3: Urgency Language (+10 points)

    Phishing emails create a false sense of urgency to pressure
    victims into acting quickly without thinking. They use words
    like "URGENT", "ACT NOW", "IMMEDIATELY", etc.
    """
    text = f"{subject} {body}".lower()
    found = [kw for kw in URGENCY_KEYWORDS if kw in text]

    if found:
        keywords_str = ", ".join(f"'{k}'" for k in found[:5])
        risk.add_finding(
            10, "Urgency Language",
            f"Email contains urgency keywords: {keywords_str}",
            "Phishing emails use urgency language to pressure you into "
            "acting quickly without thinking critically. Words like "
            f"{keywords_str} are designed to create panic and bypass your "
            "natural skepticism. Legitimate organizations rarely demand "
            "immediate action via email."
        )


def _check_threat_language(risk, subject, body):
    """
    CHECK 4: Threat Language (+10 points)

    Phishing emails threaten negative consequences (like closing your
    account or legal action) to scare victims into complying.
    """
    text = f"{subject} {body}".lower()
    found = [kw for kw in THREAT_KEYWORDS if kw in text]

    if found:
        keywords_str = ", ".join(f"'{k}'" for k in found[:5])
        risk.add_finding(
            10, "Threat Language",
            f"Email contains threatening language: {keywords_str}",
            "This email uses threatening language to pressure you: "
            f"{keywords_str}. Phishing emails commonly threaten account "
            "closure, legal action, or other negative consequences to scare "
            "victims into clicking links or providing information. Legitimate "
            "organizations typically don't threaten customers via email."
        )


def _check_grammar_errors(risk, body):
    """
    CHECK 5: Grammar/Spelling Errors (+5 points)

    Phishing emails often contain grammar and spelling errors because
    they are frequently written by non-native speakers or auto-generated.
    While not conclusive, it's an additional indicator.
    """
    if not body:
        return

    body_lower = body.lower()
    found = [word for word in COMMON_PHISHING_MISSPELLINGS if word in body_lower]

    if found:
        words_str = ", ".join(f"'{w}'" for w in found[:5])
        risk.add_finding(
            5, "Grammar Errors",
            f"Possible spelling errors detected: {words_str}",
            "This email contains possible spelling errors commonly found in "
            f"phishing emails: {words_str}. While occasional typos are normal, "
            "phishing emails frequently contain grammar and spelling errors "
            "because they are often auto-generated or written by non-native "
            "speakers. Combined with other indicators, this raises concern."
        )


def _check_suspicious_attachments(risk, msg):
    """
    CHECK 6: Suspicious Attachments (+25 points)

    Phishing emails often include malicious attachments that install
    malware when opened. Dangerous file types include:
    .exe, .js, .vbs, .scr (executable code)

    NEVER open attachments from unknown or suspicious senders.
    """
    if not msg.is_multipart():
        return

    suspicious_found = []

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            _, ext = os.path.splitext(filename.lower())
            if ext in SUSPICIOUS_EXTENSIONS:
                suspicious_found.append(filename)

    if suspicious_found:
        files_str = ", ".join(f"'{f}'" for f in suspicious_found)
        risk.add_finding(
            25, "Suspicious Attachment",
            f"Dangerous attachment(s) detected: {files_str}",
            f"DANGEROUS ATTACHMENT(S): {files_str}. These file types can "
            "execute code on your computer and are commonly used to deliver "
            "malware (viruses, ransomware, keyloggers). NEVER open "
            "attachments from unknown or suspicious senders. Even if the "
            "sender appears familiar, verify with them before opening."
        )


def _check_links_in_body(risk, body):
    """
    CHECK 7: Links in Email Body (varies)

    Extracts all URLs from the email body and analyzes each one
    using the URL analyzer. This catches phishing links embedded
    in the email text.
    """
    if not body:
        return

    # Extract URLs from the email body
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(body)

    if not urls:
        return

    # Analyze each URL (limit to first 5 to avoid excessive processing)
    suspicious_urls = []
    for url in urls[:5]:
        url_risk = analyze_url(url)
        if url_risk.total_score > 20:
            suspicious_urls.append((url, url_risk.total_score))

    if suspicious_urls:
        for url, score in suspicious_urls:
            risk.add_finding(
                min(score // 2, 15),  # Half the URL score, max 15 per link
                "Suspicious Link",
                f"Email contains suspicious URL (score: {score}): {url[:60]}...",
                f"A link in this email was analyzed and scored {score}/100 "
                f"for phishing risk: {url} — This URL has multiple phishing "
                "indicators. Do NOT click links in suspicious emails. "
                "Instead, navigate to the website directly by typing the URL."
            )


def _check_spf_dkim(risk, headers):
    """
    CHECK 8: SPF/DKIM Authentication Check (+20 points)

    SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail)
    are email authentication mechanisms that verify the sender is
    authorized to send from that domain. A "fail" result means the
    email is likely spoofed.

    We check the Authentication-Results header for SPF/DKIM status.
    """
    auth_results = headers.get("Authentication-Results", "")
    if not auth_results:
        # Also check for Received-SPF header
        spf_header = headers.get("Received-SPF", "")
        if spf_header:
            auth_results = spf_header

    if not auth_results:
        return  # Can't check without auth headers

    auth_lower = str(auth_results).lower()

    # Check for SPF fail
    if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
        risk.add_finding(
            20, "Email Authentication",
            "SPF authentication FAILED — sender may be spoofed",
            "SPF (Sender Policy Framework) authentication FAILED for this email. "
            "SPF verifies that the sending server is authorized to send email "
            "on behalf of the claimed domain. A FAIL result means the email "
            "was likely sent from an unauthorized server — a strong indicator "
            "of email spoofing (faking the sender address)."
        )

    # Check for DKIM fail
    if "dkim=fail" in auth_lower:
        risk.add_finding(
            20, "Email Authentication",
            "DKIM authentication FAILED — email may be tampered",
            "DKIM (DomainKeys Identified Mail) authentication FAILED. "
            "DKIM uses digital signatures to verify the email hasn't been "
            "altered in transit and really comes from the claimed domain. "
            "A FAIL result means the email's signature is invalid — it may "
            "have been modified or the sender is forging the domain."
        )


def _check_generic_greeting(risk, body):
    """
    CHECK 9: Generic Greeting (+5 points)

    Phishing emails often use generic greetings like "Dear Customer"
    or "Dear Valued Member" because they are sent to thousands of
    people. Legitimate organizations that have your account usually
    address you by name.
    """
    if not body:
        return

    body_lower = body.lower()

    for greeting in GENERIC_GREETINGS:
        if greeting in body_lower:
            risk.add_finding(
                5, "Generic Greeting",
                f"Email uses generic greeting: '{greeting}'",
                f"This email uses the generic greeting '{greeting}' instead "
                "of addressing you by name. Phishing emails are sent to "
                "thousands of people, so they use generic greetings. "
                "Legitimate organizations that have your account typically "
                "address you by your real name."
            )
            break


def _check_mismatched_links(risk, body):
    """
    CHECK 10: Mismatched Link Text (+25 points)

    In HTML emails, the displayed text of a link can differ from the
    actual URL. For example, the text might say "paypal.com" but
    clicking it takes you to "evil-site.com". This is a common
    and very effective phishing technique.

    Example: <a href="http://evil.com">www.paypal.com</a>
    """
    if not body:
        return

    # Find HTML links where display text looks like a URL
    # Pattern: <a href="ACTUAL_URL">DISPLAYED_TEXT</a>
    link_pattern = re.compile(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )

    matches = link_pattern.findall(body)

    for href, display_text in matches:
        display_clean = re.sub(r"<[^>]+>", "", display_text).strip()

        # Check if display text looks like a URL/domain
        if re.match(r"(https?://|www\.)\S+", display_clean):
            # Extract domains from both
            href_domain = _extract_domain_from_url(href)
            display_domain = _extract_domain_from_url(display_clean)

            if href_domain and display_domain and href_domain != display_domain:
                risk.add_finding(
                    25, "Mismatched Link",
                    f"Link text shows '{display_domain}' but actually goes to '{href_domain}'",
                    f"LINK MISMATCH: The email displays the link as going to "
                    f"'{display_domain}', but clicking it would actually take "
                    f"you to '{href_domain}'. This is one of the most common "
                    "and effective phishing techniques — the displayed text "
                    "is designed to make you think you're clicking a safe link "
                    "while the real destination is malicious."
                )


def _extract_domain_from_url(url):
    """Extract domain from a URL string."""
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""
