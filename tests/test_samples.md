# Test Results

**File:** `phishing_checker.py` &nbsp;|&nbsp; **Python:** 3.14.3 &nbsp;|&nbsp; **OS:** Windows 10 &nbsp;|&nbsp; **Date:** 2026-10-28

| # | Input | Expected Result | Actual Result | Pass / Fail |
|---|-------|-----------------|---------------|-------------|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP warnings | Uses an IP address instead of a familiar domain. Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP warnings | Contains an @ symbol; inspect carefully. Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes

- **Test 1** — No warnings produced on a well-formed HTTPS URL. The tool correctly avoids
  false positives; absence of warnings is not a safety guarantee.
- **Test 2** — Two checks triggered simultaneously: raw IP address (hides the true site owner)
  and HTTP scheme (connection is unencrypted).
- **Test 3** — The @ trick: browsers ignore everything before @, so the real destination is
  `sample.invalid`, not `example.com`. The HTTP warning triggered as well.
- **Test 4** — The hostname contains 7 dot-separated labels (a, b, c, d, e, example, invalid),
  exceeding the threshold of 5. Subdomain stacking is used to make fake domains look official.
- **Test 5** — Punycode label `xn--` detected. Attackers use punycode to register domains
  that are visually identical to real ones but contain look-alike foreign-script characters.

**Bonus edge cases tested:**
- Empty input (just Enter pressed) → `No URL entered.` — no crash.
- Malformed input `http://[bad` → `Could not parse this URL format.` — no crash (Improvement C).
