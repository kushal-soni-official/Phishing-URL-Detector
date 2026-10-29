"""
phishing_detector_advanced.py
------------------------------
Phishing URL Detector — Advanced Version

An enhanced command-line phishing URL analyser that runs ten real-world
checks against every URL, computes a weighted risk score, and returns one
of five verdict levels from "Likely Safe" to "Phishing Detected".

Unlike the simplified EWB checker (phishing_checker.py), this version:
  - Runs 10 checks instead of 6
  - Assigns HIGH / MEDIUM / LOW severity to each indicator
  - Computes a cumulative risk score and maps it to a verdict
  - Maintains a whitelist of trusted domains to eliminate false positives
  - Includes a DNS resolution check (requires network access)
  - Uses colour-coded terminal output for quick visual scanning

Note: This file makes one optional network call via socket.gethostbyname()
for the DNS check. All other checks are purely text-based.

Author  : Kushal Soni
GitHub  : https://github.com/kushal-soni-official/Phishing-URL-Detector
Run     : python phishing_detector_advanced.py
Requires: Python 3.8+  |  pip install requests  (optional — for HTTP checks)
"""

# ── Standard Library Imports ───────────────────────────────────────────────
import re               # Regular expression pattern matching
import socket           # DNS hostname resolution (network call)
import urllib.parse     # URL component parsing
from datetime import datetime

# ── Optional Third-Party Import ───────────────────────────────────────────
# The requests library is used only for HTTP header checks.
# If not installed, those checks are skipped gracefully.
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("  [INFO] 'requests' not installed. HTTP header checks will be skipped.")
    print("         Run: pip install requests\n")


# ── ANSI Colour Codes ──────────────────────────────────────────────────────
# Used to colour-code terminal output by risk level.
# These work on most modern terminals (Windows Terminal, PowerShell, macOS, Linux).
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


# ── Phishing Indicator Databases ──────────────────────────────────────────

# TLDs heavily associated with phishing campaigns.
# Source: Anti-Phishing Working Group (APWG) quarterly reports.
SUSPICIOUS_TLDS: list[str] = [
    ".xyz", ".top", ".club", ".online", ".site", ".tk",
    ".ml", ".ga", ".cf", ".gq",     # Free domain registrars — very common in phishing
    ".buzz", ".icu", ".cyou", ".monster", ".rest",
    ".zip", ".mov",                 # Newer TLDs exploited for phishing links
]

# Brand names frequently impersonated in phishing attacks.
BRAND_KEYWORDS: list[str] = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "bank", "secure", "account", "verify", "login", "signin",
    "update", "confirm", "wallet", "crypto", "ebay", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "coinbase",
]

# Known URL shortener domains that hide the true destination.
URL_SHORTENERS: list[str] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "tiny.cc",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
]

# Trusted domains. URLs whose base domain appears here bypass all checks.
# This prevents false positives on well-known legitimate sites.
WHITELIST: list[str] = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "github.com", "wikipedia.org",
    "paypal.com", "ebay.com", "reddit.com",
]

# Risk score thresholds that map a cumulative score to a verdict label.
# Each HIGH indicator = 3 pts, MEDIUM = 2 pts, LOW = 1 pt.
SCORE_THRESHOLDS: dict[str, tuple[int, int]] = {
    "LIKELY SAFE"      : (0, 0),
    "LOW RISK"         : (1, 2),
    "SUSPICIOUS"       : (3, 5),
    "HIGH RISK"        : (6, 8),
    "PHISHING DETECTED": (9, 9999),
}

RISK_WEIGHTS: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── URL Parser ────────────────────────────────────────────────────────────

def parse_url(url: str) -> dict:
    """
    Break a URL into its components and return them as a dictionary.

    Automatically prepends 'https://' if the user omitted the scheme.
    Strips the port number from the host (e.g. 'example.com:8080' → 'example.com').
    Extracts the base domain as the last two dot-separated labels.

    Args:
        url: Raw URL string entered by the user.

    Returns:
        Dictionary with keys: original, scheme, netloc, host, base_domain,
        path, query, parts, full_url.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed     = urllib.parse.urlparse(url)
    netloc     = parsed.netloc.lower()
    host       = netloc.split(":")[0]           # drop port number if present
    parts      = host.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    return {
        "original"   : url,
        "scheme"     : parsed.scheme,
        "netloc"     : netloc,
        "host"       : host,
        "base_domain": base_domain,
        "path"       : parsed.path,
        "query"      : parsed.query,
        "parts"      : parts,
        "full_url"   : url,
    }


# ── Individual Checks ─────────────────────────────────────────────────────
# Each function receives the parsed URL dictionary and returns a tuple:
#   (is_suspicious: bool, reason: str, risk_level: str)
# risk_level is one of "HIGH", "MEDIUM", or "LOW".

def check_ip_based_url(info: dict) -> tuple:
    """
    Check 1: Raw IP address as hostname.
    Legitimate services almost never expose bare IPs in public URLs.
    Example: http://192.168.1.1/login
    """
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(info["host"]):
        return (
            True,
            f"URL uses raw IP address ({info['host']}) instead of a domain name",
            "HIGH",
        )
    return False, "", ""


def check_suspicious_tld(info: dict) -> tuple:
    """
    Check 2: Suspicious top-level domain.
    Free and newly-created TLDs are heavily abused by phishing campaigns.
    Example: evil-login.xyz
    """
    for tld in SUSPICIOUS_TLDS:
        if info["host"].endswith(tld):
            return (
                True,
                f"Domain uses suspicious TLD: '{tld}' (commonly abused in phishing)",
                "HIGH",
            )
    return False, "", ""


def check_brand_in_subdomain(info: dict) -> tuple:
    """
    Check 3: Brand name appearing in a subdomain rather than the real domain.
    Classic trick: 'paypal.secure-login.xyz' — 'paypal' is the subdomain,
    but the real domain is 'secure-login.xyz'.
    """
    subdomains    = info["parts"][:-2] if len(info["parts"]) > 2 else []
    subdomain_str = ".".join(subdomains).lower()

    for brand in BRAND_KEYWORDS:
        if brand in subdomain_str:
            return (
                True,
                f"Brand '{brand}' found in subdomain — real domain is '{info['base_domain']}'",
                "HIGH",
            )
    return False, "", ""


def check_brand_in_path(info: dict) -> tuple:
    """
    Check 4: Brand name appearing in the URL path.
    Example: evil.com/paypal/login — the path mimics a legitimate service.
    """
    path_lower = info["path"].lower()
    for brand in BRAND_KEYWORDS:
        if brand in path_lower:
            return (
                True,
                f"Brand '{brand}' found in URL path (possible spoofing attempt)",
                "MEDIUM",
            )
    return False, "", ""


def check_excessive_subdomains(info: dict) -> tuple:
    """
    Check 5: Excessive number of subdomains.
    Legitimate sites rarely use more than three subdomains.
    Phishers stack subdomains to visually bury the real domain.
    Example: paypal.com.account.secure.verify.evil.com
    """
    subdomain_count = len(info["parts"]) - 2
    if subdomain_count >= 4:
        return (
            True,
            f"Excessive subdomains ({subdomain_count}) — often used to obscure the real domain",
            "HIGH",
        )
    if subdomain_count == 3:
        return (
            True,
            f"Multiple subdomains ({subdomain_count}) — worth verifying carefully",
            "MEDIUM",
        )
    return False, "", ""


def check_url_shortener(info: dict) -> tuple:
    """
    Check 6: Known URL shortener service.
    Shorteners hide the true destination behind a redirect.
    Example: bit.ly/xyz3ab
    """
    for shortener in URL_SHORTENERS:
        if info["base_domain"] == shortener or info["host"] == shortener:
            return (
                True,
                f"URL shortener detected ({shortener}) — real destination is hidden",
                "MEDIUM",
            )
    return False, "", ""


def check_https(info: dict) -> tuple:
    """
    Check 7: HTTP instead of HTTPS.
    Login and financial pages always use HTTPS.
    Note: HTTPS alone does not confirm a site is safe — phishing sites use it too.
    """
    if info["scheme"] == "http":
        return True, "URL uses HTTP (not HTTPS) — connection is unencrypted", "MEDIUM"
    return False, "", ""


def check_url_length(info: dict) -> tuple:
    """
    Check 8: Unusually long URL.
    Phishing URLs are often padded with junk parameters to hide the real domain.
    Thresholds: 75+ characters = slightly suspicious, 100+ = very suspicious.
    """
    length = len(info["original"])
    if length > 100:
        return (
            True,
            f"URL is very long ({length} chars) — often used to obscure the true destination",
            "MEDIUM",
        )
    if length > 75:
        return (
            True,
            f"URL is moderately long ({length} chars) — slightly suspicious",
            "LOW",
        )
    return False, "", ""


def check_special_chars(info: dict) -> tuple:
    """
    Check 9: Suspicious characters in the URL.
    @ symbol: 'http://google.com@evil.com' → browser visits evil.com, not google.com.
    Excessive dashes in the domain are a hallmark of typosquatting and lookalike domains.
    """
    url        = info["original"]
    host       = info["host"]
    dash_count = host.count("-")

    if "@" in url:
        return (
            True,
            "URL contains '@' — can redirect browsers to a completely different host",
            "HIGH",
        )
    if dash_count >= 3:
        return (
            True,
            f"Domain has {dash_count} hyphens — common in lookalike and typosquat domains",
            "MEDIUM",
        )
    return False, "", ""


def check_dns_resolvable(info: dict) -> tuple:
    """
    Check 10: DNS resolution (network call).
    A domain that does not resolve may be a recently registered or abandoned
    phishing domain. NOTE: this check makes a network request to a DNS server.
    """
    try:
        socket.gethostbyname(info["host"])
        return False, "", ""    # Resolves correctly — not flagged
    except socket.gaierror:
        return (
            True,
            f"Domain '{info['host']}' does not resolve in DNS",
            "MEDIUM",
        )


def check_whitelist(info: dict) -> bool:
    """Return True if the base domain is in the trusted whitelist."""
    return info["base_domain"] in WHITELIST


# ── Analysis Engine ───────────────────────────────────────────────────────

def analyse_url(url: str) -> dict:
    """
    Run all ten checks against a URL and compute the overall risk verdict.

    Scoring:
      HIGH   indicator = 3 risk points
      MEDIUM indicator = 2 risk points
      LOW    indicator = 1 risk point

    Verdict thresholds:
      0 pts   → Likely Safe
      1-2 pts → Low Risk
      3-5 pts → Suspicious
      6-8 pts → High Risk
      9+ pts  → Phishing Detected

    Args:
        url: Raw URL string entered by the user.

    Returns:
        Dictionary with url, info, whitelisted flag, findings list,
        cumulative score, and risk_level string.
    """
    info     = parse_url(url)
    findings = []

    # Whitelisted domains skip all checks immediately
    if check_whitelist(info):
        return {
            "url"        : url,
            "info"       : info,
            "whitelisted": True,
            "findings"   : [],
            "score"      : 0,
            "risk_level" : "SAFE",
        }

    # Run all ten checks in sequence
    checks = [
        check_ip_based_url(info),
        check_suspicious_tld(info),
        check_brand_in_subdomain(info),
        check_brand_in_path(info),
        check_excessive_subdomains(info),
        check_url_shortener(info),
        check_https(info),
        check_url_length(info),
        check_special_chars(info),
        check_dns_resolvable(info),
    ]

    # Accumulate findings and score
    score = 0
    for is_suspicious, reason, risk in checks:
        if is_suspicious:
            findings.append((reason, risk))
            score += RISK_WEIGHTS.get(risk, 1)

    # Map cumulative score to a verdict label
    risk_level = "LIKELY SAFE"
    for label, (low, high) in SCORE_THRESHOLDS.items():
        if low <= score <= high:
            risk_level = label
            break

    return {
        "url"        : url,
        "info"       : info,
        "whitelisted": False,
        "findings"   : findings,
        "score"      : score,
        "risk_level" : risk_level,
    }


# ── Display ───────────────────────────────────────────────────────────────

RISK_COLOURS: dict[str, str] = {
    "LIKELY SAFE"      : GREEN,
    "LOW RISK"         : YELLOW,
    "SUSPICIOUS"       : YELLOW,
    "HIGH RISK"        : RED,
    "PHISHING DETECTED": RED,
    "SAFE"             : GREEN,
}

RISK_ICONS: dict[str, str] = {
    "LIKELY SAFE"      : "[OK]    ",
    "LOW RISK"         : "[LOW]   ",
    "SUSPICIOUS"       : "[WARN]  ",
    "HIGH RISK"        : "[HIGH]  ",
    "PHISHING DETECTED": "[PHISH] ",
    "SAFE"             : "[SAFE]  ",
}


def display_result(result: dict) -> None:
    """
    Print a formatted URL analysis report for one URL.
    Colour-codes the verdict, lists each indicator with its severity,
    and provides actionable advice based on the risk level.
    """
    info       = result["info"]
    risk_level = result["risk_level"]
    colour     = RISK_COLOURS.get(risk_level, YELLOW)
    icon       = RISK_ICONS.get(risk_level, "[WARN]  ")

    divider = "=" * 62
    thin    = "-" * 62

    print(f"\n  {divider}")
    print(f"  {BOLD}URL ANALYSIS REPORT{RESET}")
    print(f"  {divider}")
    print(f"  URL        : {info['original']}")
    print(f"  Domain     : {info['host']}")
    print(f"  Base Domain: {info['base_domain']}")
    print(f"  Scheme     : {info['scheme'].upper()}")

    # Whitelisted domains get a short trusted message and exit early
    if result["whitelisted"]:
        print(f"\n  {GREEN}{BOLD}[TRUSTED] Whitelisted domain — no further checks needed.{RESET}")
        print(f"  {divider}\n")
        return

    print(f"  Score      : {result['score']} risk point(s)")
    print(f"\n  Verdict    : {BOLD}{colour}{icon} {risk_level}{RESET}")
    print(f"  {divider}")

    if not result["findings"]:
        print(f"\n  {GREEN}No phishing indicators detected.{RESET}")
    else:
        print(f"\n  {BOLD}Indicators Found ({len(result['findings'])}):{RESET}\n")
        for reason, risk in result["findings"]:
            risk_colour = RED if risk == "HIGH" else (YELLOW if risk == "MEDIUM" else CYAN)
            print(f"  {risk_colour}[{risk:6}]{RESET}  {reason}")

    # Actionable advice
    print(f"\n  {thin}")
    if risk_level in ("HIGH RISK", "PHISHING DETECTED"):
        print(f"  {RED}{BOLD}Do NOT visit this URL or enter any credentials.{RESET}")
        print(f"  {YELLOW}  Report phishing: https://safebrowsing.google.com/safebrowsing/report_phish/{RESET}")
    elif risk_level == "SUSPICIOUS":
        print(f"  {YELLOW}Proceed with caution. Verify the URL carefully before visiting.{RESET}")
    else:
        print(f"  {GREEN}URL appears relatively safe, but always verify before clicking.{RESET}")

    print(f"  {divider}\n")


def print_banner() -> None:
    """Print the startup banner with example URLs."""
    print(f"\n{BOLD}{CYAN}  Phishing URL Detector — Advanced Version")
    print(f"  10 checks | Risk scoring | Colour output{RESET}\n")
    print(f"  {YELLOW}Example URLs to try:{RESET}")
    print(f"  [SAFE ] https://www.google.com")
    print(f"  {RED}[PHISH] http://paypal.secure-login.verify.xyz/account{RESET}")
    print(f"  {YELLOW}[WARN ] http://192.168.1.1/login{RESET}")
    print(f"\n  Type 'quit' to exit.\n")


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Entry point. Displays the banner and runs an interactive analysis loop.
    The user types a URL, receives a full report, and the loop continues
    until they type 'quit'.
    """
    print_banner()

    while True:
        url = input("  Enter URL to analyse: ").strip()

        if url.lower() in ("quit", "exit", "q"):
            print(f"\n  {CYAN}Stay safe online.{RESET}\n")
            break

        if not url:
            print(f"  {YELLOW}Please enter a URL.{RESET}\n")
            continue

        result = analyse_url(url)
        display_result(result)


if __name__ == "__main__":
    main()
