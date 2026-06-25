#!/usr/bin/env python3
"""
PHANTOM RECON
Website reconnaissance & security fingerprinting tool.
Part of the Phantom security toolkit.

Stack: pure Python 3 standard library. No pip installs required.
Optional free API keys (set as environment variables to unlock more data):
    NVD_API_KEY     -> higher rate limit on NVD CVE lookups (free, https://nvd.nist.gov/developers/request-an-api-key)
    SHODAN_API_KEY  -> enriches Attack Surface with Shodan's pre-scanned host data (free dev key, https://shodan.io)

For authorized security testing, bug bounty, and educational use only.
Only scan systems you own or have explicit permission to test.
"""

import os
import re
import sys
import json
import time
import socket
import ssl
import datetime
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ───────────────────────────── COLORS (Phantom brand) ─────────────────────────────
class C:
    CYAN = "\033[96m"
    VIOLET = "\033[95m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (PhantomRecon/1.0; +educational-authorized-security-scan)"
}


# ANSI-Shadow figlet-style banner (Phantom toolkit house style)
_PHANTOM_ART = r"""██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"""

_RECON_ART = r"""██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"""


def banner():
    print()
    for line in _PHANTOM_ART.splitlines():
        print(f"  {C.CYAN}{C.BOLD}{line}{C.END}")
    print()
    for line in _RECON_ART.splitlines():
        print(f"  {C.VIOLET}{C.BOLD}{line}{C.END}")
    print()
    print(f"  {C.GREEN}// website fingerprinting & attack surface scanner{C.END}")
    print(f"  {C.GRAY}For authorized security testing & education only. Scan only what you own.{C.END}")


def header(title):
    line = "─" * max(2, 50 - len(title))
    print(f"\n{C.VIOLET}{C.BOLD}┌─[ {title} ]{line}{C.END}")


def kv(key, value, color=C.CYAN):
    print(f"  {C.GRAY}{key:<24}{C.END}{color}{value}{C.END}")


def good(msg): print(f"  {C.GREEN}✔ {msg}{C.END}")
def warn(msg): print(f"  {C.YELLOW}⚠ {msg}{C.END}")
def bad(msg): print(f"  {C.RED}✘ {msg}{C.END}")


# ───────────────────────────── CORE FETCH ─────────────────────────────
def normalize_url(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


def get_domain(url):
    return urllib.parse.urlparse(url).hostname


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def fetch(url, timeout=8, method="GET"):
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS, method=method)
    try:
        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout)
        elapsed = time.time() - start
        body = resp.read()
        set_cookies = resp.headers.get_all("Set-Cookie") or []
        return {
            "status": resp.status, "headers": dict(resp.headers.items()),
            "set_cookies": set_cookies, "body": body, "elapsed": elapsed,
            "final_url": resp.url,
        }
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        set_cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        return {
            "status": e.code, "headers": dict(e.headers.items()) if e.headers else {},
            "set_cookies": set_cookies or [], "body": body, "elapsed": 0,
            "final_url": url, "error": str(e),
        }
    except Exception as e:
        return {"error": str(e), "status": None, "headers": {}, "set_cookies": [],
                "body": b"", "elapsed": 0, "final_url": url}


def fetch_size(url, timeout=5):
    try:
        r = fetch(url, timeout=timeout)
        return len(r.get("body", b""))
    except Exception:
        return 0


# ───────────────────────────── 1. TECHNOLOGY DETECTION ─────────────────────────────
TECH_SIGNATURES = {
    "frontend": {
        "Next.js": [r"__NEXT_DATA__", r"/_next/static/"],
        "React": [r"react-dom", r"data-reactroot", r"_reactlistening"],
        "Angular": [r"ng-version", r"ng-app"],
        "Vue.js": [r"data-v-app", r"__vue__", r"vue\.runtime"],
        "Svelte": [r"svelte-", r"__svelte"],
    },
    "backend": {
        "Express/Node.js": [r"x-powered-by:\s*express"],
        "Django": [r"csrftoken", r"\bdjango\b"],
        "Flask": [r"werkzeug", r"x-powered-by:\s*flask"],
        "Laravel": [r"laravel_session"],
        "Spring Boot": [r"jsessionid", r"x-application-context"],
        "ASP.NET": [r"asp\.net", r"x-aspnet-version", r"__viewstate"],
    },
    "cms": {
        "WordPress": [r"wp-content", r"wp-includes", r'generator"\s+content="wordpress'],
        "Drupal": [r"drupal\.settings", r"/sites/default/"],
        "Joomla": [r"joomla!", r"/templates/system/"],
        "Shopify": [r"cdn\.shopify\.com", r"shopify\.theme"],
    },
    "server": {
        "Nginx": [r"\bnginx\b"], "Apache": [r"\bapache\b"],
        "IIS": [r"\biis\b"], "LiteSpeed": [r"litespeed"],
    },
    "hosting": {
        "Cloudflare": [r"cloudflare", r"cf-ray"],
        "AWS": [r"amazonaws", r"x-amz-"],
        "Google Cloud": [r"googleusercontent", r"\bgws\b"],
        "Azure": [r"azurewebsites", r"x-azure-ref"],
    },
}


def detect_technology(resp):
    headers_str = " ".join(f"{k}: {v}" for k, v in resp.get("headers", {}).items()).lower()
    body_str = resp.get("body", b"").decode("utf-8", errors="ignore").lower()
    haystack = headers_str + " " + body_str[:300000]

    found = {}
    for category, items in TECH_SIGNATURES.items():
        matches = []
        for name, patterns in items.items():
            if any(re.search(p, haystack, re.IGNORECASE) for p in patterns):
                matches.append(name)
        found[category] = sorted(set(matches))

    langs = set()
    if re.search(r"x-powered-by:\s*php|\.php\b", haystack): langs.add("PHP")
    for b in found["backend"]:
        if "express" in b.lower() or "node" in b.lower(): langs.add("JavaScript/Node.js")
        if "django" in b.lower() or "flask" in b.lower(): langs.add("Python")
        if "laravel" in b.lower(): langs.add("PHP")
        if "spring" in b.lower(): langs.add("Java")
        if "asp.net" in b.lower(): langs.add("C#")
    if found["frontend"]:
        langs.add("JavaScript")
        if re.search(r"\.tsx?\b|typescript", haystack): langs.add("TypeScript")
    found["languages"] = sorted(langs)
    found["_body_str"] = body_str  # internal use for other modules
    return found


def print_technology(tech):
    header("1. TECHNOLOGY DETECTION")
    labels = [
        ("Frontend Framework", "frontend"), ("Backend Technology", "backend"),
        ("Programming Languages", "languages"), ("Web Server", "server"),
        ("CMS Detection", "cms"), ("Hosting / Cloud", "hosting"),
    ]
    for label, key in labels:
        vals = tech.get(key, [])
        kv(label, ", ".join(vals) if vals else "Not detected", C.CYAN if vals else C.GRAY)


# ───────────────────────────── 2. DATABASE FINGERPRINTING (heuristic) ─────────────────────────────
DB_HEURISTICS = {
    "MySQL": [("WordPress", 70), ("Laravel", 55), ("PHP", 35)],
    "MariaDB": [("WordPress", 25), ("PHP", 15)],
    "PostgreSQL": [("Django", 55), ("Spring Boot", 35), ("Express/Node.js", 15)],
    "MongoDB": [("Express/Node.js", 45)],
    "SQLite": [("Flask", 30), ("Django", 15)],
    "Redis": [("Laravel", 15), ("Express/Node.js", 15)],
}


def guess_database(tech):
    signals = tech.get("backend", []) + tech.get("cms", []) + tech.get("languages", [])
    scores = {}
    for db, rules in DB_HEURISTICS.items():
        for sig, weight in rules:
            if sig in signals:
                scores[db] = min(scores.get(db, 0) + weight, 90)
    return sorted(scores.items(), key=lambda x: -x[1])


def print_database(ranked):
    header("2. DATABASE FINGERPRINTING (heuristic estimate)")
    if not ranked:
        warn("No strong database signal from passive fingerprinting.")
    for db, score in ranked[:4]:
        kv(db, f"{score}%", C.GREEN if score >= 60 else C.YELLOW)
    print(f"  {C.GRAY}Note: inferred from stack patterns, not a direct DB probe. Treat as a hint, not fact.{C.END}")


# ───────────────────────────── 3. SECURITY HEADER ANALYSIS ─────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": ("CSP", "High"),
    "Strict-Transport-Security": ("HSTS", "High"),
    "X-Frame-Options": ("X-Frame-Options", "Medium"),
    "X-Content-Type-Options": ("X-Content-Type-Options", "Medium"),
    "Referrer-Policy": ("Referrer-Policy", "Low"),
}


def check_security_headers(headers):
    hl = {k.lower(): v for k, v in headers.items()}
    results = []
    for hkey, (label, risk) in SECURITY_HEADERS.items():
        present = hkey.lower() in hl
        results.append({"header": label, "present": present,
                         "value": hl.get(hkey.lower()), "risk": "None" if present else risk})
    return results


def print_headers(results):
    header("3. SECURITY HEADER ANALYSIS")
    for r in results:
        if r["present"]:
            good(f"{r['header']}: Present")
        else:
            risk_color = C.RED if r["risk"] == "High" else C.YELLOW if r["risk"] == "Medium" else C.GRAY
            print(f"  {C.RED}✘ {r['header']}: Missing{C.END}  {risk_color}[Risk: {r['risk']}]{C.END}")


# ───────────────────────────── 4. SSL/TLS SCANNER ─────────────────────────────
WEAK_CIPHERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]


def ssl_scan(hostname, port=443, timeout=6):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                issuer = dict(x[0] for x in cert.get("issuer", []))
                weak = any(w in (cipher[0] if cipher else "") for w in WEAK_CIPHERS)
                return {
                    "tls_version": version, "cipher": cipher[0] if cipher else "Unknown",
                    "expiry": expiry.strftime("%Y-%m-%d") if expiry else "Unknown",
                    "days_left": (expiry - datetime.datetime.utcnow()).days if expiry else None,
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                    "weak_cipher": weak,
                }
    except Exception as e:
        return {"error": str(e)}


def print_ssl(result):
    header("4. SSL/TLS SCANNER")
    if "error" in result:
        bad(f"Could not establish TLS connection: {result['error']}")
        return
    kv("TLS Version", result["tls_version"], C.GREEN if result["tls_version"] in ("TLSv1.3", "TLSv1.2") else C.RED)
    kv("Cipher Suite", result["cipher"])
    kv("Certificate Issuer", result["issuer"])
    days = result["days_left"]
    exp_color = C.GREEN if (days is None or days > 30) else C.YELLOW if days > 7 else C.RED
    kv("Certificate Expiry", f"{result['expiry']} ({days} days left)" if days is not None else result["expiry"], exp_color)
    if result["weak_cipher"]:
        bad("Weak cipher detected in negotiated suite")
    else:
        good("No weak ciphers detected")


# ───────────────────────────── 5. VULNERABILITY INTELLIGENCE ─────────────────────────────
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def extract_versions(body_str):
    versions = {}
    patterns = {
        "WordPress": r'generator"\s+content="wordpress\s+([\d.]+)',
        "Joomla": r'generator"\s+content="joomla!\s*-?\s*([\d.]+)',
        "Drupal": r'drupal\s+([\d.]+)',
    }
    for name, pat in patterns.items():
        m = re.search(pat, body_str, re.IGNORECASE)
        if m:
            versions[name] = m.group(1)
    return versions


def extract_server_version(headers):
    server = headers.get("Server") or headers.get("server", "")
    m = re.search(r"([A-Za-z\-]+)/([\d.]+)", server)
    return (m.group(1), m.group(2)) if m else (server or None, None)


def fetch_cves(product, version=None, max_results=5):
    query = f"{product} {version}" if version else product
    api_key = os.environ.get("NVD_API_KEY")
    params = {"keywordSearch": query, "resultsPerPage": str(max_results)}
    url = NVD_API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        cves = []
        for item in data.get("vulnerabilities", []):
            c = item.get("cve", {})
            desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            metrics = c.get("metrics", {})
            cvss, severity = None, "Unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]["cvssData"]
                    cvss = m.get("baseScore")
                    severity = metrics[key][0].get("baseSeverity", m.get("baseSeverity", "Unknown"))
                    break
            cves.append({"id": c.get("id"), "cvss": cvss, "severity": severity, "summary": desc[:150]})
        return cves
    except Exception as e:
        return {"error": str(e)}


def fetch_kev_catalog():
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers=DEFAULT_HEADERS)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception:
        return set()


def vulnerability_intel(tech, headers):
    components = dict(extract_versions(tech.get("_body_str", "")))
    sname, sver = extract_server_version(headers)
    if sname and sver:
        components[sname] = sver

    if not components:
        return {}

    kev = fetch_kev_catalog()
    report = {}
    for name, version in components.items():
        result = fetch_cves(name, version)
        if isinstance(result, dict) and "error" in result:
            report[name] = {"version": version, "error": result["error"]}
            continue
        for c in result:
            c["kev"] = c["id"] in kev if c["id"] else False
        report[name] = {"version": version, "cves": result}
    return report


def print_vulnerabilities(report):
    header("5. VULNERABILITY INTELLIGENCE (NVD + CISA KEV)")
    if not report:
        warn("No versioned software detected to match against CVE Database. Try Technology Detection first.")
        return
    for name, info in report.items():
        print(f"\n  {C.BOLD}{C.VIOLET}{name} {info.get('version','')}{C.END}")
        if "error" in info:
            bad(f"  Lookup failed: {info['error']}")
            continue
        cves = info.get("cves", [])
        if not cves:
            good("  No publicly known CVEs matched.")
        for c in cves:
            sev_color = C.RED if c["severity"] in ("CRITICAL", "HIGH") else C.YELLOW if c["severity"] == "MEDIUM" else C.GRAY
            kev_tag = f" {C.RED}{C.BOLD}[CISA KEV - Actively Exploited]{C.END}" if c.get("kev") else ""
            print(f"    {sev_color}{c['id']}{C.END}  Severity: {sev_color}{c['severity']}{C.END}  CVSS: {c['cvss']}{kev_tag}")
            print(f"    {C.GRAY}{c['summary']}{C.END}")
    print(f"\n  {C.GRAY}Only publicly known CVEs for the detected version are listed. No exploit code is provided.{C.END}")


# ───────────────────────────── 6. ATTACK SURFACE DISCOVERY ─────────────────────────────
COMMON_PORTS = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-TLS", 993: "IMAPS",
                995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"}

COMMON_PATHS = ["/admin", "/administrator", "/wp-admin", "/wp-login.php", "/login",
                "/user/login", "/cpanel", "/.env", "/api", "/api/v1", "/graphql",
                "/swagger", "/swagger-ui", "/phpmyadmin", "/.git/config"]


def scan_port(ip, port, timeout=1.2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port, s.connect_ex((ip, port)) == 0
    except Exception:
        return port, False


def scan_ports(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(scan_port, ip, p) for p in COMMON_PORTS]
        for f in as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports.append((port, COMMON_PORTS.get(port, "Unknown")))
    return sorted(open_ports)


def find_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n.endswith(domain) and "*" not in n:
                    subs.add(n)
        return sorted(subs)
    except Exception:
        return []


def probe_paths(base_url):
    found = []
    for path in COMMON_PATHS:
        r = fetch(base_url.rstrip("/") + path, timeout=5)
        if r.get("status") and r["status"] < 400:
            found.append((path, r["status"]))
    return found


def shodan_lookup(ip):
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key or not ip:
        return None
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode())
        return {"org": data.get("org"), "os": data.get("os"), "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else [],
                "hostnames": data.get("hostnames", [])}
    except Exception as e:
        return {"error": str(e)}


def attack_surface(domain, ip, base_url):
    result = {"open_ports": [], "subdomains": [], "exposed_paths": [], "shodan": None}
    if ip:
        result["open_ports"] = scan_ports(ip)
        result["shodan"] = shodan_lookup(ip)
    result["subdomains"] = find_subdomains(domain) if domain else []
    result["exposed_paths"] = probe_paths(base_url)
    return result


def print_attack_surface(result):
    header("6. ATTACK SURFACE DISCOVERY")
    risky = {21, 23, 3306, 3389, 5432, 6379, 27017}
    if result["open_ports"]:
        for port, name in result["open_ports"]:
            (bad if port in risky else good)(f"Port {port} open ({name})")
    else:
        good("No common ports found open (or scan blocked by firewall).")

    print(f"\n  {C.BOLD}Subdomains{C.END} ({len(result['subdomains'])} found via certificate transparency):")
    for s in result["subdomains"][:15]:
        kv("", s, C.CYAN)
    if len(result["subdomains"]) > 15:
        print(f"  {C.GRAY}... and {len(result['subdomains'])-15} more{C.END}")

    print(f"\n  {C.BOLD}Exposed / Login Paths{C.END}:")
    if result["exposed_paths"]:
        for path, status in result["exposed_paths"]:
            warn(f"{path}  -> HTTP {status}")
    else:
        good("No common admin/login/API paths responded.")

    if result["shodan"]:
        sh = result["shodan"]
        print(f"\n  {C.BOLD}Shodan Enrichment{C.END}:")
        if "error" in sh:
            warn(f"Shodan lookup failed: {sh['error']}")
        else:
            kv("Organization", sh.get("org") or "Unknown")
            kv("OS", sh.get("os") or "Unknown")
            kv("Known Open Ports", ", ".join(map(str, sh.get("ports", []))) or "None")
            if sh.get("vulns"):
                bad(f"Shodan-flagged CVEs: {', '.join(sh['vulns'][:10])}")


# ───────────────────────────── 7. COOKIE ANALYSIS ─────────────────────────────
def analyze_cookies(set_cookies):
    results = []
    for raw in set_cookies:
        name = raw.split("=")[0].strip()
        lower = raw.lower()
        if "samesite=lax" in lower: samesite = "Lax"
        elif "samesite=strict" in lower: samesite = "Strict"
        elif "samesite=none" in lower: samesite = "None"
        else: samesite = "Not set"
        results.append({"name": name, "secure": "secure" in lower,
                         "httponly": "httponly" in lower, "samesite": samesite})
    return results


def print_cookies(cookies):
    header("7. COOKIE ANALYSIS")
    if not cookies:
        warn("No cookies set on initial response.")
        return
    for c in cookies:
        flags = []
        flags.append(f"{C.GREEN}Secure{C.END}" if c["secure"] else f"{C.RED}No Secure{C.END}")
        flags.append(f"{C.GREEN}HttpOnly{C.END}" if c["httponly"] else f"{C.RED}No HttpOnly{C.END}")
        flags.append(f"SameSite={c['samesite']}")
        print(f"  {C.CYAN}{c['name']}{C.END}: {'  '.join(flags)}")


# ───────────────────────────── 8. THIRD-PARTY SERVICES ─────────────────────────────
THIRD_PARTY_SIGNATURES = {
    "Google Analytics": [r"google-analytics\.com", r"gtag\("],
    "Firebase": [r"firebaseapp\.com", r"firebase-analytics"],
    "Stripe": [r"js\.stripe\.com"],
    "Razorpay": [r"checkout\.razorpay\.com"],
    "reCAPTCHA": [r"recaptcha"],
    "Cloudflare CDN": [r"cdnjs\.cloudflare\.com"],
    "jsDelivr CDN": [r"cdn\.jsdelivr\.net"],
    "unpkg CDN": [r"unpkg\.com"],
}


def detect_third_party(body_str):
    found = []
    for name, patterns in THIRD_PARTY_SIGNATURES.items():
        if any(re.search(p, body_str, re.IGNORECASE) for p in patterns):
            found.append(name)
    return sorted(set(found))


def print_third_party(found):
    header("8. THIRD-PARTY SERVICES")
    if not found:
        warn("No common third-party services detected.")
        return
    for f in found:
        good(f)


# ───────────────────────────── 9. PERFORMANCE ANALYSIS ─────────────────────────────
def performance_analysis(resp, body_str, base_url):
    size_bytes = len(resp.get("body", b""))
    js_links = re.findall(r'<script[^>]+src="([^"]+)"', body_str, re.IGNORECASE)[:10]
    css_links = re.findall(r'<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"', body_str, re.IGNORECASE)[:10]
    js_links = [urllib.parse.urljoin(base_url, l) for l in js_links]
    css_links = [urllib.parse.urljoin(base_url, l) for l in css_links]

    with ThreadPoolExecutor(max_workers=10) as ex:
        js_size = sum(ex.map(fetch_size, js_links)) if js_links else 0
        css_size = sum(ex.map(fetch_size, css_links)) if css_links else 0

    return {"load_time_sec": round(resp.get("elapsed", 0), 2),
            "page_size_kb": round(size_bytes / 1024, 1),
            "js_size_kb": round(js_size / 1024, 1), "css_size_kb": round(css_size / 1024, 1),
            "js_files": len(js_links), "css_files": len(css_links)}


def print_performance(p):
    header("9. PERFORMANCE ANALYSIS")
    kv("Load Time", f"{p['load_time_sec']} sec")
    kv("Page Size", f"{p['page_size_kb']} KB")
    kv("JS Size", f"{p['js_size_kb']} KB ({p['js_files']} files)")
    kv("CSS Size", f"{p['css_size_kb']} KB ({p['css_files']} files)")


# ───────────────────────────── 10. SECURITY SCORE ─────────────────────────────
def compute_score(headers_result, ssl_result, cookies, surface):
    total = len(headers_result)
    present = sum(1 for h in headers_result if h["present"])
    headers_score = round((present / total) * 100) if total else 0

    if "error" in ssl_result:
        ssl_score = 0
    else:
        ssl_score = 100
        if ssl_result.get("weak_cipher"): ssl_score -= 40
        if ssl_result.get("days_left") is not None and ssl_result["days_left"] < 14: ssl_score -= 20
        if ssl_result.get("tls_version") in ("TLSv1", "TLSv1.1"): ssl_score -= 30
        ssl_score = max(ssl_score, 0)

    risky_ports = {21, 23, 3306, 3389, 5432, 6379, 27017}
    open_risky = [p for p, _ in surface.get("open_ports", []) if p in risky_ports]
    tech_score = max(100 - min(len(open_risky) * 15, 60) - min(len(surface.get("exposed_paths", [])) * 10, 40), 0)

    if cookies:
        secure_count = sum(1 for c in cookies if c["secure"] and c["httponly"])
        config_score = round((secure_count / len(cookies)) * 100)
    else:
        config_score = 100

    overall = round(headers_score * 0.3 + ssl_score * 0.3 + tech_score * 0.25 + config_score * 0.15)
    return {"overall": overall, "technology_security": tech_score,
            "headers": headers_score, "ssl": ssl_score, "configuration": config_score}


def print_score(score):
    header("10. SECURITY SCORE")
    color = C.GREEN if score["overall"] >= 80 else C.YELLOW if score["overall"] >= 50 else C.RED
    print(f"  {C.BOLD}Overall Score: {color}{score['overall']}/100{C.END}")
    kv("  Technology Security", f"{score['technology_security']}/100")
    kv("  Headers", f"{score['headers']}/100")
    kv("  SSL", f"{score['ssl']}/100")
    kv("  Configuration", f"{score['configuration']}/100")


# ───────────────────────────── ORCHESTRATION ─────────────────────────────
def run_full_scan(target):
    url, domain, ip = target["url"], target["domain"], target["ip"]
    print(f"\n{C.GRAY}Scanning {url} ...{C.END}")
    resp = fetch(url)
    target["resp"] = resp
    if resp.get("error") and not resp.get("body"):
        bad(f"Could not reach target: {resp['error']}")
        return None

    body_str = resp.get("body", b"").decode("utf-8", errors="ignore")
    tech = detect_technology(resp)
    print_technology(tech)

    db_ranked = guess_database(tech)
    print_database(db_ranked)

    headers_result = check_security_headers(resp["headers"])
    print_headers(headers_result)

    ssl_result = ssl_scan(domain) if domain else {"error": "no domain"}
    print_ssl(ssl_result)

    vulns = vulnerability_intel(tech, resp["headers"])
    print_vulnerabilities(vulns)

    surface = attack_surface(domain, ip, url)
    print_attack_surface(surface)

    cookies = analyze_cookies(resp["set_cookies"])
    print_cookies(cookies)

    third_party = detect_third_party(body_str)
    print_third_party(third_party)

    perf = performance_analysis(resp, body_str, url)
    print_performance(perf)

    score = compute_score(headers_result, ssl_result, cookies, surface)
    print_score(score)

    report = {
        "target": url, "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "technology": {k: v for k, v in tech.items() if k != "_body_str"},
        "database_guess": db_ranked, "security_headers": headers_result,
        "ssl": ssl_result, "vulnerabilities": vulns, "attack_surface": surface,
        "cookies": cookies, "third_party": third_party, "performance": perf, "score": score,
    }
    return report


def prompt_target():
    header("TARGET")
    raw = input(f"  {C.CYAN}Website URL or Domain:{C.END} ").strip()
    if not raw:
        return None
    url = normalize_url(raw)
    domain = get_domain(url)
    ip_input = input(f"  {C.CYAN}IP Address (optional, Enter to auto-resolve):{C.END} ").strip()
    if ip_input:
        ip = ip_input
        good(f"Using provided IP {ip}")
    else:
        ip = resolve_ip(domain)
        if ip:
            good(f"Resolved {domain} -> {ip}")
        else:
            warn("Could not resolve IP. Port scan / Shodan lookup will be skipped.")
    return {"url": url, "domain": domain, "ip": ip, "resp": None}


def export_report(report):
    if not report:
        warn("No report to export yet. Run a scan first.")
        return
    fname = f"phantom_recon_report_{int(time.time())}.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=2, default=str)
    good(f"Report saved to {fname}")


def main_menu():
    target = None
    last_report = None
    options = [
        "Set / Change Target", "Full Recon Scan", "Technology Detection",
        "Database Fingerprinting", "Security Header Analysis", "SSL/TLS Scanner",
        "Vulnerability Intelligence (NVD/KEV)", "Attack Surface Discovery",
        "Cookie Analysis", "Third-Party Services", "Performance Analysis",
        "Export Last Report (JSON)", "Exit",
    ]
    while True:
        print(f"\n{C.VIOLET}{C.BOLD}╔══════════════════════════════════════════╗")
        print(f"║         P H A N T O M  M E N U           ║")
        print(f"╚══════════════════════════════════════════╝{C.END}")
        if target:
            print(f"  {C.GRAY}Current target: {C.GREEN}{target['url']}{C.END}")
        for i, opt in enumerate(options):
            print(f"  {C.CYAN}[{i}]{C.END} {opt}")
        choice = input(f"\n  {C.VIOLET}{C.BOLD}phantom-recon>{C.END} ").strip()

        if choice == "0":
            new_target = prompt_target()
            if new_target:
                target = new_target
        elif choice in [str(i) for i in range(1, 12)] and not target:
            warn("Set a target first (option 0).")
            continue
        elif choice == "1":
            last_report = run_full_scan(target)
        elif choice == "2":
            target["resp"] = target["resp"] or fetch(target["url"])
            print_technology(detect_technology(target["resp"]))
        elif choice == "3":
            target["resp"] = target["resp"] or fetch(target["url"])
            print_database(guess_database(detect_technology(target["resp"])))
        elif choice == "4":
            target["resp"] = target["resp"] or fetch(target["url"])
            print_headers(check_security_headers(target["resp"]["headers"]))
        elif choice == "5":
            print_ssl(ssl_scan(target["domain"]))
        elif choice == "6":
            target["resp"] = target["resp"] or fetch(target["url"])
            tech = detect_technology(target["resp"])
            print_vulnerabilities(vulnerability_intel(tech, target["resp"]["headers"]))
        elif choice == "7":
            print_attack_surface(attack_surface(target["domain"], target["ip"], target["url"]))
        elif choice == "8":
            target["resp"] = target["resp"] or fetch(target["url"])
            print_cookies(analyze_cookies(target["resp"]["set_cookies"]))
        elif choice == "9":
            target["resp"] = target["resp"] or fetch(target["url"])
            body_str = target["resp"]["body"].decode("utf-8", errors="ignore")
            print_third_party(detect_third_party(body_str))
        elif choice == "10":
            target["resp"] = target["resp"] or fetch(target["url"])
            body_str = target["resp"]["body"].decode("utf-8", errors="ignore")
            print_performance(performance_analysis(target["resp"], body_str, target["url"]))
        elif choice == "11":
            export_report(last_report)
        elif choice == "12":
            print(f"\n{C.VIOLET}Stay phantom. 👻{C.END}")
            break
        else:
            bad("Invalid choice.")


if __name__ == "__main__":
    try:
        banner()
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{C.VIOLET}Interrupted. Stay phantom. 👻{C.END}")
        sys.exit(0)

# PhantomShield
# Copyright 2026 Suganth B
#
# Licensed under the Apache License, Version 2.0
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.