# 👻 PhantomRecon

**Website reconnaissance & security fingerprinting CLI — part of the Phantom security toolkit.**

![Python](https://img.shields.io/badge/python-3.8%2B-00F5FF)
![Dependencies](https://img.shields.io/badge/dependencies-none-00FF88)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Status](https://img.shields.io/badge/status-active-00F5FF)

PhantomRecon points at any website and comes back with a full passive recon report — tech stack, security headers, SSL/TLS health, real CVE matches, attack surface, cookies, third-party services, and a weighted security score. Single Python file, zero pip installs, terminal-first, color-coded — same DNA as `PhantomSniff` and `PhantomShield AI`.

```
  ███████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██║ ██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝ ███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔══╝   ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║      ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
                    R E C O N
```

---

## ⚠️ Use Responsibly

This tool is for **authorized security testing, bug bounty programs, and learning**. Only scan domains/IPs you own or have explicit written permission to test. Scanning systems without authorization may be illegal in your jurisdiction.

---
## ⚠️ Legal & Ethical Use

PhantomRecon only performs checks you could already make by visiting a site
in a browser, inspecting its TLS handshake, resolving DNS, or making a TCP
connection — it does **not** exploit, brute-force, or attack anything.

**Only run this against systems you own or are explicitly authorized to
test.** Unauthorized scanning of third-party systems may be illegal in your
jurisdiction (e.g. India's IT Act, 2000 — Section 43).

## Features

| # | Module | What it does |
|---|--------|---------------|
| 1 | **Technology Detection** | Fingerprints frontend framework, backend tech, language, web server, CMS, and hosting/cloud provider from live headers + HTML |
| 2 | **Database Fingerprinting** | Heuristic confidence score (e.g. `MySQL — 70%`) inferred from detected stack signals |
| 3 | **Security Header Analysis** | Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, with risk rating per gap |
| 4 | **SSL/TLS Scanner** | TLS version, cipher suite, certificate issuer & expiry, weak-cipher detection |
| 5 | **Vulnerability Intelligence** | Matches detected software + version against live **NVD** CVE data and flags anything in the **CISA KEV** (actively exploited) catalog |
| 6 | **Attack Surface Discovery** | Common open ports, subdomains (via certificate transparency / crt.sh), exposed admin/login/API paths |
| 7 | **Cookie Analysis** | Secure / HttpOnly / SameSite flags per cookie |
| 8 | **Third-Party Services** | Google Analytics, Firebase, Stripe, Razorpay, reCAPTCHA, CDN providers |
| 9 | **Performance Analysis** | Real load time, page size, JS size, CSS size |
| 10 | **Security Score** | Weighted 0–100 score across Technology, Headers, SSL, and Configuration |

Every result is computed from real responses — no fabricated numbers. CVE data only lists publicly known vulnerabilities for the version actually detected; no exploit code is generated.

---

## Requirements

- Python **3.8+**
- No third-party packages. Everything runs on the standard library (`urllib`, `socket`, `ssl`, `concurrent.futures`).

## Installation

```bash
# just grab the one file
python3 phantom_recon.py
```

That's it. Nothing to `pip install`.

## Usage

```bash
python3 phantom_recon.py
```

You'll land on the menu:

```
phantom-recon> 0          # set your target first
Website URL or Domain: example.com
IP Address (optional, Enter to auto-resolve):

phantom-recon> 1          # run the full scan
```

| Choice | Action |
|--------|--------|
| `0` | Set / change target (URL, domain, optional IP) |
| `1` | Full Recon Scan — runs all 10 modules and prints the score |
| `2`–`10` | Run a single module on its own |
| `11` | Export the last full report to JSON |
| `12` | Exit |

## Optional Free API Keys

PhantomRecon works fully without any keys. Set these as environment variables to unlock more data:

| Variable | Unlocks | Get it |
|----------|---------|--------|
| `NVD_API_KEY` | Higher CVE lookup rate limit (5/30s → 50/30s) | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) (free) |
| `SHODAN_API_KEY` | Enriches Attack Surface with Shodan's pre-scanned host data (org, OS, known ports/vulns) | [shodan.io](https://shodan.io) (free dev key) |

```bash
export NVD_API_KEY="your-key-here"
export SHODAN_API_KEY="your-key-here"
python3 phantom_recon.py
```

## Sample Output

```
┌─[ 3. SECURITY HEADER ANALYSIS ]─────────────────────────
  ✘ CSP: Missing  [Risk: High]
  ✔ HSTS: Present
  ✘ X-Frame-Options: Missing  [Risk: Medium]

┌─[ 5. VULNERABILITY INTELLIGENCE (NVD + CISA KEV) ]──────
  WordPress 6.2
    CVE-2023-XXXXX  Severity: HIGH  CVSS: 8.1
    Unauthenticated stored XSS in block editor...

┌─[ 10. SECURITY SCORE ]───────────────────────────────────
  Overall Score: 78/100
    Technology Security   85/100
    Headers                60/100
    SSL                    95/100
    Configuration          75/100
```

## How It Works (Methodology)

- **Tech/CMS/server detection** — pattern matching on response headers + HTML, same approach as Wappalyzer
- **DB fingerprinting** — passive heuristic only; PhantomRecon never sends probing payloads to trigger DB errors
- **Vuln intel** — live keyword query against NVD's public CVE API + cross-reference against CISA's published Known Exploited Vulnerabilities feed
- **Attack surface** — short-timeout connect scan on ~19 common ports, certificate-transparency subdomain lookup via crt.sh, and a small built-in wordlist for common admin/login/API paths
- **Performance** — actual measured load time and fetched JS/CSS payload sizes, not estimates

## Project Structure

```
phantom_recon.py   # everything — banner, menu, all 10 modules, scoring, JSON export
```

One file, by design — same pattern as the rest of the Phantom toolkit.

## Roadmap

- [ ] **v2**: full web app — React/Next.js + Tailwind frontend, FastAPI backend, PostgreSQL for scan history
- [ ] Nuclei template integration for active vuln confirmation (with explicit opt-in)
- [ ] Scheduled/recurring scans with diffing between runs
- [ ] PDF report export

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---

Built as part of the **Phantom** security toolkit · `PhantomSniff` · `PhantomShield AI` · `PhantomCTF` · **PhantomRecon**
