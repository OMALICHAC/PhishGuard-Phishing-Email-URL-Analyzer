"""
PhishGuard - Threat Intelligence Checker
=========================================
Checks domains and URLs against known threat data sources.

Data Sources (all free, no API keys required):
    1. Local database - Curated list of known phishing domains
    2. URLhaus API   - Free API from abuse.ch for known malicious URLs
    3. Offline fallback if no internet is available

This module always works, even without internet connectivity,
by falling back to the local database.
"""

import os
import requests

# Path to the data directory (relative to this script)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def load_known_phishing_domains():
    """
    Load the local database of known phishing domains.

    Reads from data/known_phishing_domains.txt, ignoring comments and blanks.

    Returns:
        Set of known phishing domain strings (lowercase)
    """
    domains = set()
    filepath = os.path.join(DATA_DIR, "known_phishing_domains.txt")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        # If the file doesn't exist, return empty set
        pass

    return domains


def load_trusted_domains():
    """
    Load the list of known trusted/legitimate domains.

    Returns:
        Set of trusted domain strings (lowercase)
    """
    domains = set()
    filepath = os.path.join(DATA_DIR, "trusted_domains.txt")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        pass

    return domains


def check_local_database(domain):
    """
    Check a domain against the local known phishing domains database.

    Args:
        domain: The domain to check (e.g., "paypa1.com")

    Returns:
        Dictionary with:
            - found (bool): Whether the domain was found in the database
            - source (str): "local_database"
            - status (str): "KNOWN MALICIOUS" or "NOT FOUND"
    """
    known_domains = load_known_phishing_domains()
    domain_lower = domain.lower()

    # Check exact match
    if domain_lower in known_domains:
        return {
            "found": True,
            "source": "local_database",
            "status": "KNOWN MALICIOUS",
            "detail": f"Domain '{domain}' is listed in the local phishing database.",
        }

    # Check if it's a subdomain of a known bad domain
    for known in known_domains:
        if domain_lower.endswith("." + known):
            return {
                "found": True,
                "source": "local_database",
                "status": "KNOWN MALICIOUS",
                "detail": (
                    f"Domain '{domain}' is a subdomain of known phishing domain "
                    f"'{known}'."
                ),
            }

    return {
        "found": False,
        "source": "local_database",
        "status": "NOT FOUND",
        "detail": "Domain not found in local phishing database.",
    }


def check_urlhaus(url):
    """
    Check a URL against the URLhaus API (abuse.ch).

    URLhaus is a free threat intelligence feed that tracks malicious URLs
    used for malware distribution. No API key is required.

    API Documentation: https://urlhaus-api.abuse.ch/v1/

    Args:
        url: The full URL to check

    Returns:
        Dictionary with:
            - found (bool): Whether the URL was found
            - source (str): "urlhaus"
            - status (str): Threat status
            - detail (str): Description of findings
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    try:
        response = requests.post(
            api_url,
            data={"url": url},
            timeout=10,
            headers={"User-Agent": "PhishGuard/1.0"},
        )

        if response.status_code == 200:
            data = response.json()

            if data.get("query_status") == "no_results":
                return {
                    "found": False,
                    "source": "urlhaus",
                    "status": "CLEAN",
                    "detail": "URL not found in URLhaus threat database.",
                }

            if data.get("query_status") == "ok":
                threat_type = data.get("threat", "unknown")
                tags = ", ".join(data.get("tags", [])) or "none"
                url_status = data.get("url_status", "unknown")

                return {
                    "found": True,
                    "source": "urlhaus",
                    "status": "KNOWN MALICIOUS",
                    "detail": (
                        f"URL found in URLhaus database! "
                        f"Threat: {threat_type}, Tags: {tags}, "
                        f"Status: {url_status}"
                    ),
                    "threat_type": threat_type,
                    "tags": data.get("tags", []),
                }

        return {
            "found": False,
            "source": "urlhaus",
            "status": "UNKNOWN",
            "detail": f"URLhaus returned unexpected status: {response.status_code}",
        }

    except requests.exceptions.Timeout:
        return {
            "found": False,
            "source": "urlhaus",
            "status": "TIMEOUT",
            "detail": "URLhaus API request timed out. Using local database only.",
        }
    except requests.exceptions.ConnectionError:
        return {
            "found": False,
            "source": "urlhaus",
            "status": "OFFLINE",
            "detail": "No internet connection. Using local database only.",
        }
    except requests.exceptions.RequestException as e:
        return {
            "found": False,
            "source": "urlhaus",
            "status": "ERROR",
            "detail": f"URLhaus API error: {str(e)}",
        }


def check_urlhaus_domain(domain):
    """
    Check a domain (host) against the URLhaus API.

    Args:
        domain: The domain to check

    Returns:
        Dictionary with threat intelligence results
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/host/"

    try:
        response = requests.post(
            api_url,
            data={"host": domain},
            timeout=10,
            headers={"User-Agent": "PhishGuard/1.0"},
        )

        if response.status_code == 200:
            data = response.json()

            if data.get("query_status") == "no_results":
                return {
                    "found": False,
                    "source": "urlhaus_host",
                    "status": "CLEAN",
                    "detail": "Domain not found in URLhaus host database.",
                }

            if data.get("query_status") == "ok":
                url_count = data.get("url_count", 0)
                return {
                    "found": True,
                    "source": "urlhaus_host",
                    "status": "KNOWN MALICIOUS",
                    "detail": (
                        f"Domain found in URLhaus database with "
                        f"{url_count} known malicious URL(s)."
                    ),
                    "url_count": url_count,
                }

        return {
            "found": False,
            "source": "urlhaus_host",
            "status": "UNKNOWN",
            "detail": "Unexpected response from URLhaus host API.",
        }

    except (requests.exceptions.RequestException,):
        return {
            "found": False,
            "source": "urlhaus_host",
            "status": "OFFLINE",
            "detail": "Could not reach URLhaus host API.",
        }


def is_trusted_domain(domain):
    """
    Check if a domain is in the trusted domains list.

    Args:
        domain: The domain to check

    Returns:
        Boolean - True if the domain is trusted
    """
    trusted = load_trusted_domains()
    domain_lower = domain.lower()

    # Direct match
    if domain_lower in trusted:
        return True

    # Check if it's a subdomain of a trusted domain
    for t in trusted:
        if domain_lower.endswith("." + t):
            return True

    return False


def check_domain(domain, url=None):
    """
    Perform a comprehensive threat intelligence check on a domain.

    This is the main function other modules should call. It checks:
    1. Whether the domain is trusted (known legitimate)
    2. Local phishing database
    3. URLhaus API (if internet is available)

    Args:
        domain: The domain to check
        url: Optional full URL for more detailed URLhaus lookup

    Returns:
        Dictionary with:
            - overall_status (str): "CLEAN", "SUSPICIOUS", or "KNOWN MALICIOUS"
            - is_trusted (bool): Whether it's a known legitimate domain
            - checks (list): Results from each intelligence source
            - summary (str): Human-readable summary
    """
    results = {
        "domain": domain,
        "overall_status": "CLEAN",
        "is_trusted": False,
        "checks": [],
        "summary": "",
    }

    # Step 1: Check if it's a trusted domain
    if is_trusted_domain(domain):
        results["is_trusted"] = True
        results["summary"] = (
            f"Domain '{domain}' is a known trusted domain."
        )
        return results

    # Step 2: Check local phishing database
    local_result = check_local_database(domain)
    results["checks"].append(local_result)

    if local_result["found"]:
        results["overall_status"] = "KNOWN MALICIOUS"
        results["summary"] = local_result["detail"]
        return results

    # Step 3: Check URLhaus API (online check)
    if url:
        urlhaus_result = check_urlhaus(url)
        results["checks"].append(urlhaus_result)

        if urlhaus_result["found"]:
            results["overall_status"] = "KNOWN MALICIOUS"
            results["summary"] = urlhaus_result["detail"]
            return results

    # Step 4: Check domain against URLhaus host database
    host_result = check_urlhaus_domain(domain)
    results["checks"].append(host_result)

    if host_result["found"]:
        results["overall_status"] = "KNOWN MALICIOUS"
        results["summary"] = host_result["detail"]
        return results

    # If nothing was found, it's clean (as far as we know)
    results["summary"] = (
        f"Domain '{domain}' was not found in any threat intelligence databases. "
        f"This does not guarantee it is safe."
    )
    return results
