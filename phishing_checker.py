"""
phishing_checker.py
--------------------
EWB Cybersecurity Internship — Final Project Submission
Phishing URL Awareness Checker

A text-only, command-line tool that inspects a URL string for six phishing
warning signs as specified in the EWB Cybersecurity Mini Project Workbook.

Key rule: this program NEVER opens a URL, sends a network request, or
connects to the internet. It reads URL text only.

Author  : Kushal Soni
GitHub  : https://github.com/kushal-soni-official/Phishing-URL-Detector
Run     : python phishing_checker.py
"""

# ── Standard Library Imports ───────────────────────────────────────────────
# re        : built-in module for regular expressions (text pattern matching)
# urlparse  : built-in function that splits a URL into its components
#             (scheme, hostname, path, query, etc.)
import re
from urllib.parse import urlparse


# ── Constants ──────────────────────────────────────────────────────────────
# Named constants keep numbers meaningful and easy to change in one place.

URL_LENGTH_THRESHOLD: int = 100
# PDF specification: flag any URL longer than 100 characters (Check 2)

MIN_HOSTNAME_PARTS: int = 5
# PDF specification: flag hostnames with 5 or more dot-separated labels (Check 4)

SEPARATOR: str = "-" * 55
# Visual divider line used throughout the terminal output


# ── Improvement D: Warning Explanations Dictionary ─────────────────────────
# Maps a keyword found in each warning message to a plain-English reason.
# Printed under the warning so the user understands why it is suspicious.
# (PDF Section 10, Improvement D)

REASONS: dict[str, str] = {
    "@ symbol":
        "Browsers ignore text before @. "
        "'paypal.com@evil.com' actually takes you to evil.com, not paypal.com.",

    "long URL":
        "Very long links push the real destination far to the right "
        "where it is easy to miss at a glance.",

    "IP address":
        "Legitimate websites use readable domain names. "
        "A raw number address hides who actually owns the server.",

    "hostname segments":
        "Stacking many dot-separated labels such as a.b.c.d.e.example.com "
        "is a common trick to make a fake domain look official.",

    "punycode":
        "Punycode (xn--) encodes non-English characters as plain ASCII. "
        "Attackers use it to register domains that look identical to real ones "
        "but use look-alike foreign letters.",

    "HTTP":
        "HTTP is unencrypted — data you send can be read by anyone on the network. "
        "Note: HTTPS alone does not prove a site is trustworthy either.",
}


# ── Improvement B: Informational Prefix Detector ──────────────────────────
# Messages that start with one of these strings are informational only —
# they are NOT real phishing warnings. Used by has_warnings() below.
# (PDF Section 10, Improvement B — INFO_MESSAGES concept)

INFO_PREFIXES: tuple[str, ...] = (
    "No URL entered",       # user pressed Enter without typing anything
    "Could not identify",   # hostname could not be extracted
    "No listed warning",    # no warnings found — clean result
    "Could not parse",      # malformed URL caught by Improvement C
)


# ── Core Function: inspect_url ─────────────────────────────────────────────
# This is the primary detection function required by the EWB PDF (Section 07).
# It applies the six checks and returns a list of warning strings.

def inspect_url(raw_url: str) -> list[str]:
    """
    Inspect a URL string for the six phishing warning signs defined in the
    EWB Cybersecurity Mini Project Workbook (Section 01 and Section 06).

    This function performs text analysis only. It never opens the URL,
    resolves DNS, sends network requests, or accesses external services.

    Args:
        raw_url: The URL string typed by the user.

    Returns:
        A list of finding strings. Each string is either a warning message
        (one per triggered check) or a single informational message when
        no warnings are found.
    """
    url: str = raw_url.strip()
    # strip() removes any accidental leading or trailing whitespace

    findings: list[str] = []
    # Starts empty. A warning string is appended for each check that triggers.

    # ── Guard: empty input ─────────────────────────────────────────────────
    if not url:
        return ["No URL entered."]
        # PDF exact wording. Returned early — no further checks needed.

    # ── Scheme normalisation ───────────────────────────────────────────────
    # urlparse requires a scheme (http:// or https://) to correctly identify
    # the hostname. If the user typed "www.example.com" without a scheme,
    # prepend "http://" so parsing works. This also means a bare hostname
    # without a scheme is treated as HTTP — which may trigger Check 6.
    candidate: str = url if "://" in url else "http://" + url

    # ── Improvement C: crash-safe URL parsing ─────────────────────────────
    # Typing a malformed IPv6 bracket such as "http://[bad" causes urlparse
    # to raise a ValueError, crashing the original PDF starter code.
    # Wrapping it in try/except returns a friendly message instead.
    # (PDF Section 10, Improvement C)
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ["Could not parse this URL format. Please check and try again."]

    # Extract the hostname in lowercase for case-insensitive comparisons.
    host: str = (parsed.hostname or "").lower()

    if not host:
        return ["Could not identify a hostname."]
        # PDF exact wording. Returned early — hostname is required for checks 3-5.

    # ── Check 1: @ symbol ──────────────────────────────────────────────────
    # A browser ignores everything before @ in a URL.
    # "victim.com@evil.com" → the browser visits evil.com, not victim.com.
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # ── Check 2: URL length ────────────────────────────────────────────────
    # Phishing URLs are often padded to push the real domain far to the right.
    if len(url) > URL_LENGTH_THRESHOLD:
        findings.append("Unusually long URL (over 100 characters).")

    # ── Check 3: IP address as hostname ───────────────────────────────────
    # Pattern: four groups of 1-3 digits each, separated by literal dots.
    # re.fullmatch requires the entire hostname to match — not just a part.
    # Example match: 192.0.2.10
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # ── Check 4: Many hostname segments (subdomains) ───────────────────────
    # Split the hostname at every dot and count the resulting labels.
    # "a.b.c.d.e.example.invalid" produces 7 labels — above the threshold of 5.
    labels: list[str] = [label for label in host.split(".") if label]
    if len(labels) >= MIN_HOSTNAME_PARTS:
        findings.append("Contains many hostname segments/subdomains.")

    # ── Check 5: Punycode marker ───────────────────────────────────────────
    # Punycode-encoded hostname labels begin with "xn--".
    # Attackers register xn-- domains to mimic real domains using
    # visually identical characters from other scripts (homograph attacks).
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # ── Check 6: HTTP scheme ──────────────────────────────────────────────
    # HTTP transmits data in plain text — no encryption.
    # HTTPS encrypts traffic but does NOT guarantee a site is legitimate.
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    # ── No warnings found ─────────────────────────────────────────────────
    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")
        # Absence of these six clues does not make a URL safe.

    return findings


# ── Helper: has_warnings ───────────────────────────────────────────────────
# Distinguishes real warnings from informational messages.
# Used by print_result() to decide whether to print the REVIEW CAREFULLY line.
# (PDF Section 10, Improvement B)

def has_warnings(findings: list[str]) -> bool:
    """
    Return True if findings contain at least one real phishing warning.
    Return False if findings contain only an informational message
    (empty input, unparseable URL, or no warnings detected).
    """
    return bool(findings) and not findings[0].startswith(INFO_PREFIXES)


# ── Helper: explain_finding ───────────────────────────────────────────────
# Looks up the plain-English reason for a warning in the REASONS dictionary.
# (PDF Section 10, Improvement D)

def explain_finding(finding: str) -> str | None:
    """
    Return the plain-English explanation for a warning string,
    or None if no explanation is mapped for this finding.
    Matching is done by searching for a keyword inside the finding text.
    """
    for keyword, reason in REASONS.items():
        if keyword.lower() in finding.lower():
            return reason
    return None


# ── Output: print_result ───────────────────────────────────────────────────
# Formats and prints all findings for one URL.
# Implements Improvements D (explanations) and E (formatted output).

def print_result(findings: list[str]) -> None:
    """
    Print the list of findings in a clean, numbered format.

    Each finding is numbered and followed by its plain-English explanation
    if one is available. A summary line is printed at the end indicating
    whether warnings were found.
    """
    print(f"\n{SEPARATOR}")
    print("Result:")
    print(SEPARATOR)

    # Improvement E: number each finding for clarity
    for index, finding in enumerate(findings, start=1):
        print(f"  {index}. {finding}")

        # Improvement D: look up and print the explanation if one exists
        reason = explain_finding(finding)
        if reason:
            print(f"     Why: {reason}")

    # Improvement B: verdict summary line
    if has_warnings(findings):
        warning_count = len(findings)
        print(f"\nREVIEW CAREFULLY: {warning_count} warning sign(s) found.")
    else:
        print("\n[OK] No listed warning signs detected.")

    print(SEPARATOR)
    print("Never enter passwords from unexpected links.")
    print(SEPARATOR + "\n")


# ── Main: interactive loop ─────────────────────────────────────────────────
# Runs until the user types q, quit, or exit.
# (PDF Section 10, Improvement A)

def main() -> None:
    """
    Entry point. Runs an interactive loop that accepts one URL at a time,
    passes it to inspect_url(), and prints the result via print_result().
    The loop continues until the user types q to quit.
    """
    print(SEPARATOR)
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    print(SEPARATOR)
    print("Type a sample URL and press Enter to inspect it.")
    print("Type q to quit.")
    print(SEPARATOR + "\n")

    while True:
        # Improvement A: loop so the user can check multiple URLs in one session
        raw_url = input("\nEnter a sample URL (or type q to quit): ").strip()

        if raw_url.lower() in ("q", "quit", "exit"):
            print("Goodbye! Stay alert online.")
            break

        findings = inspect_url(raw_url)
        print_result(findings)


# ── Entry guard ────────────────────────────────────────────────────────────
# main() runs only when this file is executed directly.
# If another module imports this file, main() will NOT run automatically.
if __name__ == "__main__":
    main()
