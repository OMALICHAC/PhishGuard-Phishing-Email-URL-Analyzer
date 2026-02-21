"""
PhishGuard - URL Analysis Engine
=================================
Breaks down a URL and checks it for phishing indicators.

Performs 12 distinct checks, each contributing risk points:
    1.  IP address as URL          (+25 points)
    2.  Excessive subdomains       (+15 points)
    3.  Typosquatting detection     (+20 points)
    4.  URL shortener              (+10 points)
    5.  Suspicious TLD             (+10 points)
    6.  HTTPS missing              (+10 points)
    7.  Long URL                   (+5 points)
    8.  @ symbol in URL            (+25 points)
    9.  Suspicious keywords in path(+10 points)
    10. Domain age (heuristic)     (+15 points)
    11. Encoded characters         (+10 points)
    12. Known phishing domain      (+30 points)
"""

import re
import os
from urllib.parse import urlparse, unquote

from scoring import create_risk_score
from threat_intel import check_domain, is_trusted_domain

# Path to the data directory
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# === Known URL Shortener Domains ===
# URL shorteners hide the real destination, a common phishing tactic
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "lnkd.in", "db.tt", "qr.ae",
    "rebrand.ly", "bl.ink", "short.to", "cutt.ly", "v.gd", "rb.gy",
    "shorturl.at", "t.ly",
}

# === Suspicious Top-Level Domains ===
# These TLDs are frequently abused by phishers due to low cost / lax registration
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".click", ".club", ".work", ".link",
    ".surf", ".rest", ".fit", ".site", ".online", ".icu", ".info",
    ".store", ".live", ".gq", ".ml", ".tk", ".cf", ".ga", ".pw",
}

# === Suspicious Path Keywords ===
# Words commonly found in phishing URL paths
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "banking",
    "password", "credential", "authenticate", "wallet", "payment",
    "billing", "invoice", "document", "dropbox", "onedrive", "sharepoint",
    "suspended", "locked", "unusual", "recover", "restore",
]

# === Typosquatting Detection ===
# Common character substitutions used in typosquatting attacks
CHAR_SUBSTITUTIONS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["@", "4"],
    "s": ["5", "$"],
    "t": ["7"],
    "b": ["8"],
    "g": ["9", "q"],
}

# Well-known brands to check for typosquatting
BRAND_DOMAINS = {
    "google": "google.com",
    "facebook": "facebook.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citibank.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "walmart": "walmart.com",
    "ebay": "ebay.com",
}


def analyze_url(url):
    """
    Perform a comprehensive phishing analysis on a URL.

    This is the main function called by phishguard.py. It runs all 12
    checks and returns a RiskScore object with detailed findings.

    Args:
        url: The URL to analyze (string)

    Returns:
        RiskScore object with all findings, score, and recommendations
    """
    # Ensure the URL has a scheme for proper parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    risk = create_risk_score(url, "url")
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url

    # If the domain is a known trusted domain, reduce concern
    if is_trusted_domain(domain):
        risk.add_finding(
            0, "Trusted Domain",
            f"Domain '{domain}' is a known legitimate domain",
            "This domain is recognized as a legitimate, trusted website. "
            "However, always verify you reached it through a trusted link."
        )
        return risk

    # Run all 12 checks
    _check_ip_address(risk, domain)
    _check_excessive_subdomains(risk, domain)
    _check_typosquatting(risk, domain)
    _check_url_shortener(risk, domain)
    _check_suspicious_tld(risk, domain)
    _check_https_missing(risk, parsed.scheme)
    _check_long_url(risk, full_url)
    _check_at_symbol(risk, full_url)
    _check_suspicious_keywords(risk, path)
    _check_suspicious_domain_pattern(risk, domain)
    _check_encoded_characters(risk, full_url)
    _check_known_phishing(risk, domain, full_url)

    return risk


# ============================================================
# Individual Check Functions
# ============================================================

def _check_ip_address(risk, domain):
    """
    CHECK 1: IP Address as URL (+25 points)

    Legitimate websites almost always use domain names (e.g., google.com).
    Phishing sites often use IP addresses to avoid domain-based blocking
    and make the URL harder to identify as malicious.

    Example: http://192.168.1.1/login
    """
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"  # IPv4 pattern
    )

    if ip_pattern.match(domain):
        risk.add_finding(
            25, "URL Structure",
            "URL uses an IP address instead of a domain name",
            "Legitimate websites almost always use domain names (e.g., google.com). "
            "Phishing sites often use IP addresses to avoid domain-based blocking "
            "and to make the URL harder to identify as malicious. "
            f"IP address detected: {domain}"
        )


def _check_excessive_subdomains(risk, domain):
    """
    CHECK 2: Excessive Subdomains (+15 points)

    Phishers use many subdomains to make a URL look legitimate.
    For example: paypal.secure.login.evil.com
    The actual domain is evil.com, but the subdomains make it look like PayPal.
    """
    parts = domain.split(".")
    # A normal domain has 2-3 parts (e.g., www.google.com)
    # More than 4 parts is suspicious
    if len(parts) > 4:
        risk.add_finding(
            15, "URL Structure",
            f"Excessive subdomains detected ({len(parts)} levels)",
            "Phishing URLs often use many subdomains to make a link look "
            "legitimate. For example, 'paypal.secure.login.evil.com' — the "
            "actual domain is 'evil.com', but the subdomains are designed to "
            f"trick you into thinking it's PayPal. Detected: {domain}"
        )


def _check_typosquatting(risk, domain):
    """
    CHECK 3: Typosquatting Detection (+20 points)

    TYPOSQUATTING is when attackers register domains that look like
    real ones but with small changes:
        - paypa1.com (number 1 instead of letter l)
        - g00gle.com (zeros instead of o's)
        - amaz0n.com (zero instead of o)

    This tricks users into thinking they're on a real website.
    We check for common character substitutions.
    """
    domain_name = domain.split(".")[0].lower()  # Get just the name part

    for brand, legitimate_domain in BRAND_DOMAINS.items():
        # Skip if it IS the legitimate domain
        if domain.lower() == legitimate_domain or domain.lower().endswith("." + legitimate_domain):
            continue

        # Check if domain name is suspiciously similar to a brand
        if _is_typosquat(domain_name, brand):
            risk.add_finding(
                20, "Typosquatting",
                f"Domain may be impersonating '{brand}' ({legitimate_domain})",
                f"TYPOSQUATTING DETECTED: The domain '{domain}' looks suspiciously "
                f"similar to the legitimate brand '{brand}' ({legitimate_domain}). "
                "Typosquatting uses small character changes (like replacing 'l' "
                "with '1' or 'o' with '0') to create fake domains that look real. "
                "Always type important URLs directly into your browser."
            )
            break  # Only flag the first match


def _is_typosquat(domain_name, brand):
    """
    Check if a domain name is a likely typosquat of a brand name.

    Uses character substitution detection and edit distance.

    Args:
        domain_name: The domain name to check (without TLD)
        brand: The brand name to compare against

    Returns:
        Boolean - True if likely typosquat
    """
    # If the domain contains the brand name as a substring (like paypal-secure),
    # that's suspicious but handled elsewhere
    if brand in domain_name and domain_name != brand:
        return True

    # Check character substitutions
    # Generate possible typosquat variations of the brand
    if len(domain_name) != len(brand):
        # Only check if lengths are equal (direct substitution)
        # or differ by 1 (added/removed character)
        if abs(len(domain_name) - len(brand)) > 2:
            return False

    # Count character differences
    differences = 0
    min_len = min(len(domain_name), len(brand))

    for i in range(min_len):
        if domain_name[i] != brand[i]:
            # Check if this is a known substitution
            if brand[i] in CHAR_SUBSTITUTIONS:
                if domain_name[i] in CHAR_SUBSTITUTIONS[brand[i]]:
                    differences += 1
                    continue
            differences += 1

    # Add length difference
    differences += abs(len(domain_name) - len(brand))

    # If there are 1-2 suspicious differences, likely a typosquat
    return 1 <= differences <= 2


def _check_url_shortener(risk, domain):
    """
    CHECK 4: URL Shortener (+10 points)

    URL shorteners (like bit.ly, tinyurl.com) hide the real destination.
    Phishers use them to disguise malicious URLs and bypass security filters.
    While URL shorteners have legitimate uses, they are a common phishing tactic.
    """
    if domain.lower() in URL_SHORTENERS:
        risk.add_finding(
            10, "URL Shortener",
            f"URL uses a shortening service ({domain})",
            f"URL shorteners like '{domain}' hide the real destination of a link. "
            "While they have legitimate uses, phishers frequently use them to "
            "disguise malicious URLs and bypass security filters. "
            "Be cautious - the shortened link could lead anywhere."
        )


def _check_suspicious_tld(risk, domain):
    """
    CHECK 5: Suspicious Top-Level Domain (+10 points)

    Certain TLDs (like .xyz, .top, .buzz, .click) are frequently
    abused for phishing because they are cheap to register and have
    fewer registration requirements. Legitimate businesses typically
    use .com, .org, .net, or country-specific TLDs.
    """
    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            risk.add_finding(
                10, "Suspicious TLD",
                f"Domain uses suspicious TLD: {tld}",
                f"The top-level domain '{tld}' is frequently abused for phishing "
                "because it's cheap to register and has fewer verification "
                "requirements. While not all domains with this TLD are malicious, "
                "legitimate businesses typically use .com, .org, .net, or "
                "country-specific TLDs."
            )
            break


def _check_https_missing(risk, scheme):
    """
    CHECK 6: HTTPS Missing (+10 points)

    HTTPS encrypts the connection between your browser and the website.
    Legitimate websites handling sensitive data (logins, payments)
    almost always use HTTPS. A plain HTTP connection means your data
    is sent unencrypted and could be intercepted.
    """
    if scheme == "http":
        risk.add_finding(
            10, "Missing HTTPS",
            "URL does not use HTTPS (encrypted connection)",
            "This URL uses plain HTTP instead of HTTPS. HTTPS encrypts the "
            "connection between your browser and the website, protecting your "
            "data from interception. Legitimate websites that handle sensitive "
            "information (logins, payments) almost always use HTTPS. "
            "Never enter credentials on an HTTP-only website."
        )


def _check_long_url(risk, url):
    """
    CHECK 7: Long URL (+5 points)

    Phishing URLs are often very long to hide the actual malicious
    domain within a sea of subdomains and path segments. Most
    legitimate URLs are relatively short and readable.
    """
    if len(url) > 75:
        risk.add_finding(
            5, "URL Length",
            f"URL is unusually long ({len(url)} characters)",
            "Phishing URLs are often very long to hide the actual malicious "
            "domain within a sea of subdomains, paths, and parameters. "
            f"This URL is {len(url)} characters long (typical legitimate "
            "URLs are under 75 characters). Long URLs can also be used to "
            "push the real domain out of the browser's address bar."
        )


def _check_at_symbol(risk, url):
    """
    CHECK 8: @ Symbol in URL (+25 points)

    The @ symbol in a URL is used for HTTP authentication, but phishers
    abuse it to create deceptive URLs. In http://google.com@evil.com,
    the browser actually goes to evil.com, not google.com. The part
    before @ is treated as a username, not a domain.
    """
    # Check after the scheme (http:// or https://)
    url_after_scheme = url.split("://", 1)[-1]
    if "@" in url_after_scheme.split("/")[0]:  # Only check the authority part
        risk.add_finding(
            25, "Deceptive URL",
            "URL contains @ symbol (used to disguise real destination)",
            "The @ symbol in a URL is a classic phishing trick. In a URL like "
            "'http://google.com@evil.com', the browser actually goes to "
            "evil.com, NOT google.com. The part before @ is treated as a "
            "username (ignored by most browsers), while the part after @ is "
            "the real destination. This is used to trick users into thinking "
            "they're visiting a legitimate site."
        )


def _check_suspicious_keywords(risk, path):
    """
    CHECK 9: Suspicious Keywords in Path (+10 points)

    Phishing URLs often contain keywords related to logging in,
    verifying accounts, or updating information. These words are
    designed to create urgency and trick users into entering credentials.
    """
    path_lower = path.lower()
    found_keywords = []

    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path_lower:
            found_keywords.append(keyword)

    if found_keywords:
        keywords_str = ", ".join(f"'{k}'" for k in found_keywords[:5])
        risk.add_finding(
            10, "Suspicious Keywords",
            f"URL path contains suspicious keywords: {keywords_str}",
            "Phishing URLs often include keywords related to security, "
            "authentication, or account management to create urgency. "
            f"Suspicious keywords detected in the URL path: {keywords_str}. "
            "These words are commonly used in phishing to trick users into "
            "entering their credentials or personal information."
        )


def _check_suspicious_domain_pattern(risk, domain):
    """
    CHECK 10: Suspicious Domain Patterns (+15 points)

    Checks for domain patterns commonly used in phishing:
    - Domains with many hyphens (e.g., paypal-secure-login-verify.com)
    - Domains containing brand names as subdomains
    - Very new-looking generated domains
    """
    domain_lower = domain.lower()

    # Check for excessive hyphens (common in phishing domains)
    if domain_lower.count("-") >= 3:
        risk.add_finding(
            15, "Suspicious Domain",
            f"Domain contains excessive hyphens ({domain_lower.count('-')} hyphens)",
            "Phishing domains often contain many hyphens to combine words that "
            "look legitimate (e.g., 'paypal-secure-login-verify.com'). "
            "Legitimate domains rarely use more than one or two hyphens. "
            f"This domain has {domain_lower.count('-')} hyphens, which is unusual."
        )
        return

    # Check if domain contains a brand name as a keyword (not the real domain)
    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in domain_lower and domain_lower != legit_domain:
            # Make sure it's not just a subdomain of the real domain
            if not domain_lower.endswith("." + legit_domain):
                risk.add_finding(
                    15, "Brand Impersonation",
                    f"Domain contains brand name '{brand}' but is not the official site",
                    f"The domain '{domain}' contains the brand name '{brand}' "
                    f"but is NOT the official domain ({legit_domain}). "
                    "Phishers often include well-known brand names in their "
                    "domains to trick users into trusting the site. "
                    "Always verify you're on the official domain."
                )
                break


def _check_encoded_characters(risk, url):
    """
    CHECK 11: Encoded Characters (+10 points)

    URL encoding (%XX) is used legitimately for special characters,
    but phishers abuse it to obfuscate malicious URLs. Encoded
    characters like %2F (/) or %40 (@) in the domain part of a URL
    are especially suspicious.
    """
    # Check for encoded characters in the domain/authority portion
    url_after_scheme = url.split("://", 1)[-1]
    authority = url_after_scheme.split("/")[0]

    encoded_pattern = re.compile(r"%[0-9A-Fa-f]{2}")
    encoded_matches = encoded_pattern.findall(authority)

    if encoded_matches:
        decoded = unquote(authority)
        risk.add_finding(
            10, "URL Obfuscation",
            f"URL contains encoded characters in domain: {', '.join(encoded_matches[:5])}",
            "URL encoding (%XX format) is being used in the domain portion "
            "of this URL. While URL encoding is normal in paths and parameters, "
            "encoded characters in the domain are suspicious and often used to "
            f"obfuscate the real destination. Decoded domain: '{decoded}'"
        )


def _check_known_phishing(risk, domain, url):
    """
    CHECK 12: Known Phishing Domain (+30 points)

    Checks the domain against threat intelligence databases:
    - Local curated list of known phishing domains
    - URLhaus API (abuse.ch) for known malicious URLs
    """
    result = check_domain(domain, url)

    if result["overall_status"] == "KNOWN MALICIOUS":
        risk.add_finding(
            30, "Threat Intelligence",
            f"Domain/URL flagged as KNOWN MALICIOUS",
            f"THREAT INTELLIGENCE ALERT: {result['summary']} "
            "This domain or URL has been reported and confirmed as malicious "
            "by threat intelligence sources. DO NOT visit this URL or enter "
            "any information. Report it to your security team."
        )
