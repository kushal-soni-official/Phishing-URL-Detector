# ============================================================
#   PHISHING URL DETECTOR
#   Author  : Your Name
#   GitHub  : github.com/yourusername
#   Purpose : Analyses a URL for phishing indicators such as
#             lookalike domains, suspicious TLDs, URL shorteners,
#             excessive subdomains, IP-based URLs, and more.
#
#   Dependencies:
#     pip install requests
# ============================================================

import re           # Pattern matching (regex)
import socket       # DNS resolution
import urllib.parse # URL parsing tools built into Python
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("  ⚠  'requests' not installed. HTTP checks will be skipped.")
    print("     Run: pip install requests\n")

# ── ANSI colour codes ──
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


# ══════════════════════════════════════════════
#  PHISHING INDICATOR DATABASES
# ══════════════════════════════════════════════

# TLDs (Top-Level Domains) heavily abused by phishers
# Source: Anti-Phishing Working Group (APWG) reports
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".tk",
    ".ml", ".ga", ".cf", ".gq",   # Free domains — favourite of phishers
    ".buzz", ".icu", ".cyou", ".monster", ".rest",
    ".zip", ".mov",                # New TLDs abused for phishing links
]

# Well-known brands that phishers frequently impersonate
BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "bank", "secure", "account", "verify", "login", "signin",
    "update", "confirm", "wallet", "crypto", "ebay", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "coinbase",
]

# URL shortener services — hide the real destination
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "tiny.cc",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
]

# Legitimate domains — reduce false positives for these
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "github.com", "wikipedia.org",
    "paypal.com", "ebay.com", "reddit.com",
]


# ══════════════════════════════════════════════
#  URL PARSER HELPER
#  Breaks a URL into its parts for analysis
# ══════════════════════════════════════════════

def parse_url(url: str) -> dict:
    """
    Parses a URL into components using urllib.
    Adds 'https://' prefix if user forgot it.

    Example:
      Input : "http://secure-paypal.login.xyz/account"
      Output: {scheme: 'http', netloc: 'secure-paypal.login.xyz',
               path: '/account', domain: 'login.xyz', ...}
    """
    # Add scheme if missing so urllib can parse it
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()

    # Remove port if present (e.g. "example.com:8080" → "example.com")
    host = netloc.split(":")[0]

    # Extract base domain (last 2 parts: "sub.example.com" → "example.com")
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


# ══════════════════════════════════════════════
#  INDIVIDUAL CHECKS
#  Each function returns: (is_suspicious, reason, risk_level)
# ══════════════════════════════════════════════

def check_ip_based_url(info: dict) -> tuple:
    """
    Checks if the URL uses a raw IP address instead of a domain.
    Legitimate sites almost never use raw IPs in URLs.
    Example: http://192.168.1.1/login  →  very suspicious
    """
    ip_pattern = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    if ip_pattern.match(info["host"]):
        return True, f"URL uses raw IP address ({info['host']}) instead of a domain name", "HIGH"
    return False, "", ""


def check_suspicious_tld(info: dict) -> tuple:
    """
    Checks if the domain uses a TLD commonly associated with phishing.
    Free TLDs like .tk, .ml, .ga are favourite tools of phishers.
    """
    for tld in SUSPICIOUS_TLDS:
        if info["host"].endswith(tld):
            return True, f"Domain uses suspicious TLD: '{tld}' (common in phishing)", "HIGH"
    return False, "", ""


def check_brand_in_subdomain(info: dict) -> tuple:
    """
    Checks if a brand name appears in a subdomain rather than the real domain.
    Trick: 'paypal.secure-login.xyz'  ← paypal is NOT the real domain here!
    The real domain is 'secure-login.xyz'
    """
    # Subdomains = everything except the last 2 parts
    subdomains = info["parts"][:-2] if len(info["parts"]) > 2 else []
    subdomain_str = ".".join(subdomains).lower()

    for brand in BRAND_KEYWORDS:
        if brand in subdomain_str:
            return (
                True,
                f"Brand name '{brand}' found in subdomain — classic phishing trick! "
                f"Real domain is '{info['base_domain']}'",
                "HIGH"
            )
    return False, "", ""


def check_brand_in_path(info: dict) -> tuple:
    """
    Checks if a brand name appears in the URL path.
    Example: evil.com/paypal/login  ← path contains 'paypal'
    """
    path_lower = info["path"].lower()
    for brand in BRAND_KEYWORDS:
        if brand in path_lower:
            return True, f"Brand name '{brand}' found in URL path (possible spoofing)", "MEDIUM"
    return False, "", ""


def check_excessive_subdomains(info: dict) -> tuple:
    """
    Counts subdomains. Legitimate sites rarely have 4+ subdomains.
    Phishers use long subdomains to confuse victims:
    'paypal.com.account.secure.verify.evil.com'
    """
    subdomain_count = len(info["parts"]) - 2
    if subdomain_count >= 4:
        return True, f"Excessive subdomains ({subdomain_count}) — used to hide real domain", "HIGH"
    elif subdomain_count == 3:
        return True, f"Multiple subdomains ({subdomain_count}) — worth verifying", "MEDIUM"
    return False, "", ""


def check_url_shortener(info: dict) -> tuple:
    """
    Checks if the URL is from a known URL shortener.
    Shorteners hide the real destination — a common phishing technique.
    """
    for shortener in URL_SHORTENERS:
        if info["base_domain"] == shortener or info["host"] == shortener:
            return True, f"URL shortener detected ({shortener}) — real destination is hidden", "MEDIUM"
    return False, "", ""


def check_https(info: dict) -> tuple:
    """
    Checks if the URL uses HTTP instead of HTTPS.
    Legitimate login/banking pages ALWAYS use HTTPS.
    Note: HTTPS alone doesn't mean safe — phishing sites can also use HTTPS.
    """
    if info["scheme"] == "http":
        return True, "URL uses HTTP (not HTTPS) — data sent unencrypted", "MEDIUM"
    return False, "", ""


def check_url_length(info: dict) -> tuple:
    """
    Checks if the URL is unusually long.
    Phishing URLs often embed lots of parameters to confuse victims.
    Threshold: 75+ characters is suspicious, 100+ is very suspicious.
    """
    length = len(info["original"])
    if length > 100:
        return True, f"URL is very long ({length} chars) — often used to hide true destination", "MEDIUM"
    elif length > 75:
        return True, f"URL is moderately long ({length} chars) — slightly suspicious", "LOW"
    return False, "", ""


def check_special_chars(info: dict) -> tuple:
    """
    Checks for suspicious characters in the URL:
    - '@' symbol can redirect browsers: 'http://google.com@evil.com' → goes to evil.com
    - Double slashes '//' in path are unusual
    - Multiple dashes in domain often signal lookalike domains
    """
    url = info["original"]
    host = info["host"]

    if "@" in url:
        return True, "URL contains '@' — can be used to redirect to a different host", "HIGH"

    dash_count = host.count("-")
    if dash_count >= 3:
        return True, f"Domain has {dash_count} dashes — common in lookalike/typosquat domains", "MEDIUM"

    return False, "", ""


def check_dns_resolvable(info: dict) -> tuple:
    """
    Checks if the domain actually resolves in DNS.
    Some phishing URLs are sent before the site is live —
    non-resolving domains are suspicious if recently registered.
    """
    try:
        socket.gethostbyname(info["host"])
        return False, "", ""  # Resolves fine — not suspicious
    except socket.gaierror:
        return True, f"Domain '{info['host']}' does not resolve in DNS", "MEDIUM"


def check_whitelist(info: dict) -> bool:
    """Returns True if the base domain is in our trusted whitelist."""
    return info["base_domain"] in WHITELIST


# ══════════════════════════════════════════════
#  MAIN ANALYSIS ENGINE
#  Runs all checks and computes a risk score
# ══════════════════════════════════════════════

def analyse_url(url: str) -> dict:
    """
    Runs all phishing checks on a URL.
    Returns a full results dict with score, risk level, and findings.
    """
    info     = parse_url(url)
    findings = []   # List of (suspicious, reason, risk_level)

    # ── Whitelist bypass ──
    if check_whitelist(info):
        return {
            "url"       : url,
            "info"      : info,
            "whitelisted": True,
            "findings"  : [],
            "score"     : 0,
            "risk_level": "SAFE",
        }

    # ── Run all checks ──
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

    # ── Score calculation ──
    # HIGH risk indicator  = 3 points
    # MEDIUM risk indicator = 2 points
    # LOW risk indicator    = 1 point
    score = 0
    risk_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for is_suspicious, reason, risk in checks:
        if is_suspicious:
            findings.append((reason, risk))
            score += risk_weights.get(risk, 1)

    # ── Overall risk level ──
    if score == 0:
        risk_level = "LIKELY SAFE"
    elif score <= 2:
        risk_level = "LOW RISK"
    elif score <= 5:
        risk_level = "SUSPICIOUS"
    elif score <= 8:
        risk_level = "HIGH RISK"
    else:
        risk_level = "PHISHING DETECTED"

    return {
        "url"        : url,
        "info"       : info,
        "whitelisted": False,
        "findings"   : findings,
        "score"      : score,
        "risk_level" : risk_level,
    }


# ══════════════════════════════════════════════
#  DISPLAY RESULT
# ══════════════════════════════════════════════

RISK_COLOURS = {
    "LIKELY SAFE"      : GREEN,
    "LOW RISK"         : YELLOW,
    "SUSPICIOUS"       : YELLOW,
    "HIGH RISK"        : RED,
    "PHISHING DETECTED": RED,
    "SAFE"             : GREEN,
}

RISK_ICONS = {
    "LIKELY SAFE"      : "✅",
    "LOW RISK"         : "🟡",
    "SUSPICIOUS"       : "⚠️ ",
    "HIGH RISK"        : "🔴",
    "PHISHING DETECTED": "🚨",
    "SAFE"             : "✅",
}

def display_result(result: dict) -> None:
    """Prints a formatted analysis report for one URL."""

    info       = result["info"]
    risk_level = result["risk_level"]
    colour     = RISK_COLOURS.get(risk_level, YELLOW)
    icon       = RISK_ICONS.get(risk_level, "⚠️")

    print(f"\n  {'═' * 62}")
    print(f"  {BOLD}URL ANALYSIS REPORT{RESET}")
    print(f"  {'═' * 62}")
    print(f"  URL        : {info['original']}")
    print(f"  Domain     : {info['host']}")
    print(f"  Base Domain: {info['base_domain']}")
    print(f"  Scheme     : {info['scheme'].upper()}")

    if result["whitelisted"]:
        print(f"\n  {GREEN}{BOLD}✅ WHITELISTED — Trusted domain. No further checks needed.{RESET}")
        print(f"  {'═' * 62}\n")
        return

    print(f"  Score      : {result['score']} risk points")
    print(f"\n  Verdict    : {BOLD}{colour}{icon}  {risk_level}{RESET}")
    print(f"  {'═' * 62}")

    if not result["findings"]:
        print(f"\n  {GREEN}No phishing indicators detected.{RESET}")
    else:
        print(f"\n  {BOLD}Indicators Found ({len(result['findings'])}):{RESET}\n")
        for reason, risk in result["findings"]:
            risk_colour = RED if risk == "HIGH" else (YELLOW if risk == "MEDIUM" else CYAN)
            print(f"  {risk_colour}[{risk}]{RESET} {reason}")

    # ── Safety advice ──
    print(f"\n  {'─' * 62}")
    if risk_level in ("HIGH RISK", "PHISHING DETECTED"):
        print(f"  {RED}{BOLD}⛔ DO NOT visit this URL or enter any credentials!{RESET}")
        print(f"  {YELLOW}  → Report it: https://safebrowsing.google.com/safebrowsing/report_phish/{RESET}")
    elif risk_level == "SUSPICIOUS":
        print(f"  {YELLOW}⚠  Proceed with caution. Verify the URL carefully before visiting.{RESET}")
    else:
        print(f"  {GREEN}✅ URL appears relatively safe, but always stay alert.{RESET}")

    print(f"  {'═' * 62}\n")


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════

def print_banner():
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗")
    print(f"║     📧 PHISHING URL DETECTOR            ║")
    print(f"║     Stay Safe — Verify Before You Click ║")
    print(f"╚══════════════════════════════════════════╝{RESET}\n")


def main():
    print_banner()

    print(f"  {YELLOW}Try these example URLs to see the detector in action:{RESET}")
    print(f"  ✅ Safe    : https://www.google.com")
    print(f"  🚨 Phish   : http://paypal.secure-login.verify.xyz/account")
    print(f"  ⚠  Suspect : http://192.168.1.1/login\n")
    print(f"  Type 'quit' to exit.\n")

    while True:
        url = input("  Enter URL to analyse: ").strip()

        if url.lower() == "quit":
            print(f"\n  {CYAN}Stay safe online! 🔐{RESET}\n")
            break

        if not url:
            print(f"  {YELLOW}Please enter a URL.{RESET}\n")
            continue

        result = analyse_url(url)
        display_result(result)


if __name__ == "__main__":
    main()
