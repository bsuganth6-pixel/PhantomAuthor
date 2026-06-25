# PhantomAuthor

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      P H A N T O M A U T H O R  -  Web Recon & Intel Tool        ║
║      Attack Surface Intelligence  |  Phantom Series              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

**PhantomAuthor** is a single-file, terminal-first Python CLI tool that performs
passive/low-impact web reconnaissance and attack-surface intelligence gathering
against a target website, domain, or IP. Part of the **Phantom** security
tooling series.

---

## ⚠️ Legal & Ethical Use

PhantomAuthor only performs checks you could already make by visiting a site
in a browser, inspecting its TLS handshake, resolving DNS, or making a TCP
connection — it does **not** exploit, brute-force, or attack anything.

**Only run this against systems you own or are explicitly authorized to
test.** Unauthorized scanning of third-party systems may be illegal in your
jurisdiction (e.g. India's IT Act, 2000 — Section 43).

---

## Features

| # | Module | What it does |
|---|--------|---------------|
| 1 | **Technology Detection** | Frontend framework, backend tech, language, web server, CMS, hosting/cloud — via header & HTML signature matching |
| 2 | **Database Fingerprinting** | Confidence-scored *estimate* of likely backing database, based on stack conventions and any leaked DB error strings |
| 3 | **Security Header Analysis** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy — flags missing headers with risk level |
| 4 | **SSL/TLS Scanner** | Real TLS handshake: protocol version, cipher suite, weak-cipher detection, certificate issuer & expiry |
| 5 | **Vulnerability Intelligence** | Queries the **real public NVD API** for known CVEs matching detected software — only ever shows real, published CVE IDs/severity/CVSS, never fabricated data |
| 6 | **Attack Surface Discovery** | Common open ports (TCP connect), admin/login panel probing, exposed API path probing, passive subdomain DNS guesses |
| 7 | **Cookie Analysis** | Secure flag, HttpOnly, SameSite attribute per cookie |
| 8 | **Third-Party Services** | Google Analytics, Firebase, Stripe, Razorpay, reCAPTCHA, CDN providers |
| 9 | **Performance Analysis** | Load time, HTML page size, sampled JS/CSS size |
| 10 | **Security Score** | Composite 0–100 score with sub-scores for Technology Security, Headers, SSL, and Configuration |

At the end of a scan, you can save the full report as a structured JSON file.

---

## Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
```

No `nmap`, `Shodan`, or paid APIs required. Everything works out of the box.

---

## Usage

```bash
python3 phantom_author.py
```

You'll get an interactive menu:

```
[1] Run Full Scan
[2] About PhantomAuthor
[0] Exit
```

Choose **[1]**, then provide:
- **Website URL or Domain Name** (required) — e.g. `example.com` or `https://example.com`
- **IP Address** (optional) — shown in the report header if provided

The tool will fetch the target, run all 10 modules in sequence, print colored
results to the terminal, and offer to save a full JSON report at the end.

---

## Optional Environment Variable

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Raises your rate limit against the NVD CVE API. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |

```bash
export NVD_API_KEY="your-key-here"
python3 phantom_author.py
```

Without a key, the tool still works — it just respects the NVD's stricter
public rate limit and adds small delays between lookups.

---

## Example Output (abridged)

```
◆ 1. TECHNOLOGY DETECTION
------------------------------------------------------------------------
   CMS Detection:              WordPress
   Web Server:                 Nginx
   Hosting/Cloud:               Cloudflare

◆ 10. SECURITY SCORE
------------------------------------------------------------------------
   Overall Score: 78/100

   Technology Security:   80/100
   Headers:               60/100
   SSL:                   95/100
   Configuration:         75/100
```

---

## Design Notes

- **Single Python file** — no web framework, no build step.
- **Menu-driven, color-coded** — ANSI 256-color palette (cyan / violet / green
  on near-black), consistent with the rest of the Phantom CLI tool series
  (PhantomSniff, PhantomShield AI, PhantomCTF).
- **Honesty-first reporting** — anything that can't be verified (e.g. database
  type, exact CVE-to-version match) is explicitly labeled as an *estimate* or
  skipped entirely rather than guessed and presented as fact.
- **No active exploitation** — port checks are plain TCP connects, path probes
  are plain GET requests, subdomain discovery is plain DNS resolution.

---

## Roadmap Ideas

- Optional Shodan API integration for richer port/service data (with explicit
  user opt-in and API key)
- Export to PDF/HTML report alongside JSON
- Integration hook for the PhantomCTF dashboard

---

*Part of the Phantom security tooling series — built for hands-on
cybersecurity learning and authorized recon practice.*
