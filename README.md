# 📧 Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Category](https://img.shields.io/badge/Category-Phishing%20Detection-red)

A command-line phishing URL analyser that checks URLs against 10 real-world phishing
indicators used by security professionals — no API keys or external databases needed.

---

## 📸 Preview

```
╔══════════════════════════════════════════╗
║     📧 PHISHING URL DETECTOR            ║
║     Stay Safe — Verify Before You Click ║
╚══════════════════════════════════════════╝

  Enter URL to analyse: http://paypal.secure-login.verify.xyz/account

  ══════════════════════════════════════════════════════════════
  URL ANALYSIS REPORT
  ══════════════════════════════════════════════════════════════
  URL        : http://paypal.secure-login.verify.xyz/account
  Domain     : paypal.secure-login.verify.xyz
  Base Domain: verify.xyz
  Scheme     : HTTP
  Score      : 11 risk points

  Verdict    : 🚨  PHISHING DETECTED
  ══════════════════════════════════════════════════════════════

  Indicators Found (4):

  [HIGH]   Domain uses suspicious TLD: '.xyz' (common in phishing)
  [HIGH]   Brand name 'paypal' found in subdomain — classic phishing trick!
  [HIGH]   Excessive subdomains (3) — used to hide real domain
  [MEDIUM] URL uses HTTP (not HTTPS) — data sent unencrypted

  ──────────────────────────────────────────────────────────────
  ⛔ DO NOT visit this URL or enter any credentials!
```

---

## 🚀 Features

- ✅ **10 phishing checks** — all run automatically on every URL
- ✅ Risk scoring system — points weighted by severity (HIGH/MEDIUM/LOW)
- ✅ 5 verdict levels — from **Likely Safe** to **Phishing Detected**
- ✅ Trusted domain whitelist — no false positives for Google, Apple, etc.
- ✅ DNS resolution check — detects non-existent domains
- ✅ Colour-coded terminal output with actionable advice
- ✅ Scan multiple URLs in one session

---

## 🔍 The 10 Checks Explained

| # | Check | What It Catches |
|---|-------|----------------|
| 1 | IP-based URL | `http://192.168.1.1/login` — raw IPs hide real sites |
| 2 | Suspicious TLD | `.xyz`, `.tk`, `.ml` — free TLDs loved by phishers |
| 3 | Brand in subdomain | `paypal.evil.com` — brand name NOT the real domain |
| 4 | Brand in path | `evil.com/paypal/login` — spoofed path |
| 5 | Excessive subdomains | 4+ subdomains obscure the real domain |
| 6 | URL shortener | `bit.ly/xyz` — real destination is hidden |
| 7 | No HTTPS | Login pages must use HTTPS |
| 8 | Long URL | 75+ chars — often stuffed with fake parameters |
| 9 | Special characters | `@` in URL redirects to a different host |
| 10 | DNS resolution | Domain doesn't exist at all |

---

## 🧪 Example URLs to Test

```bash
# Safe (whitelisted)
https://www.google.com
https://github.com

# Phishing examples
http://paypal.secure-login.verify.xyz/account
http://192.168.1.1/signin
https://apple-id.account-verify.tk/update
http://bit.ly/free-iphone-2024
```

---

## ⚙️ Installation & Usage

### Requirements
- Python 3.8+
- `requests` library (optional — for HTTP header checks)

```bash
pip install requests
```

### Run it

```bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
python phishing_url_detector.py
```

---

## 📁 Project Structure

```
phishing-url-detector/
│
├── phishing_url_detector.py   # Main script
└── README.md                  # This file
```

---

## 🧠 What I Learned

- How phishers craft convincing fake URLs using subdomains and lookalike TLDs
- URL structure: scheme, netloc, subdomain, base domain, path, query
- Python's `urllib.parse` module for URL decomposition
- Regex patterns for IP address detection
- How weighted scoring systems are used in threat detection
- The difference between heuristic and signature-based detection

---

## ⚠️ Disclaimer

This tool uses **heuristic analysis** — it is not a guarantee.
Always verify URLs through multiple means before trusting them.
For real-time phishing detection, also use:
- [Google Safe Browsing](https://safebrowsing.google.com/)
- [VirusTotal URL Scanner](https://www.virustotal.com/)

---

## 📄 License

MIT — free to use, modify, and distribute.
