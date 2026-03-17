#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║        Full Recon Suite  —  based on cgomezsec methodology   ║
║  From 0 to Hero v2: The Startup Reconnaissance on Large Scopes
║                                                              ║
║  Phases:                                                     ║
║    1. Auto-install all required tools                        ║
║    2. ASN Enumeration  (amass + bgp.he.net + bgpview.io)     ║
║    3. IP Range Extraction  (mapcidr)                         ║
║    4. Domain Discovery  (crt.sh + whoisxmlapi CT logs)       ║
║    5. Reverse DNS  (dnsx PTR)                                ║
║    6. Subdomain Enumeration  (subfinder + amass)             ║
║    7. GitHub Subdomain  (github-subdomains)                  ║
║    8. DNS Resolution Filtering  (dnsx)                       ║
║    9. HTTP Probing  (httpx multi-port, tech, title, ss)      ║
║   10. JS Endpoint Extraction  (regex, no bs4)                ║
║                                                              ║
║  Usage:                                                      ║
║    python3 recon_suite.py -o "Apple Inc" -d apple.com        ║
║    python3 recon_suite.py -d target.com --skip-asn           ║
║    python3 recon_suite.py -d target.com --whoisxml-key KEY   ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, re, sys, json, time, random, shutil, argparse, subprocess
from urllib.parse import urljoin, urlparse, quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from pathlib import Path
from datetime import datetime

# ── dependency check ──────────────────────────────────────────────────────────
try:
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("\033[91m[!] pip install requests\033[0m"); sys.exit(1)

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    R="\033[0m"; B="\033[1m"
    RED="\033[91m"; GRN="\033[92m"; YLW="\033[93m"
    BLU="\033[94m"; MGT="\033[95m"; CYN="\033[96m"
    WHT="\033[97m"; GRY="\033[90m"; ORG="\033[38;5;208m"
    DIM="\033[2m"

_lock = Lock()

def log(color, tag, msg=""):
    with _lock:
        ts = time.strftime("%H:%M:%S")
        print(f"{C.GRY}{ts}{C.R} {color}{C.B}{tag}{C.R}{color} {msg}{C.R}")

def section(n, title):
    w = 62
    print(f"\n{C.CYN}{C.B}{'═'*w}")
    print(f"  [{n}] {title}")
    print(f"{'═'*w}{C.R}\n")

def progress(done, total, label=""):
    pct = int((done/total)*46) if total else 46
    bar = "█"*pct + "░"*(46-pct)
    with _lock:
        print(f"\r{C.CYN}  [{bar}] {done}/{total} {label}{C.R}   ", end="", flush=True)

def banner(args):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    org  = args.org  if args.org  else "—"
    domain = args.domain if args.domain else "—"
    print(f"""
{C.CYN}{C.B}╔══════════════════════════════════════════════════════════════╗
║          Full Recon Suite  v3.0  —  0xh3l1x methodology      ║
║  ASN → IP Ranges → Domains → Subdomains → Probe → Endpoints  ║
╚══════════════════════════════════════════════════════════════╝{C.R}
{C.YLW}  Org      : {C.WHT}{org}
{C.YLW}  Domain   : {C.WHT}{domain}
{C.YLW}  Threads  : {C.WHT}{args.threads}
{C.YLW}  Timeout  : {C.WHT}{args.timeout}s
{C.YLW}  Output   : {C.WHT}{args.outdir}
{C.YLW}  Started  : {C.WHT}{ts}{C.R}
""")

# ── random UA pool ────────────────────────────────────────────────────────────
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0.0.0 Mobile",
    "curl/8.4.0", "Wget/1.21.4", "Go-http-client/2.0",
]

def rh():
    return {"User-Agent": random.choice(UAS),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7"}

def http_get(url, timeout=12):
    try:
        return requests.get(url, headers=rh(), timeout=timeout, verify=False)
    except Exception:
        return None

def http_text(url, timeout=12):
    r = http_get(url, timeout)
    return r.text if r else None

# ── output helpers ────────────────────────────────────────────────────────────
def outfile(outdir, name):
    return str(Path(outdir) / name)

def write_lines(path, lines, header=""):
    with open(path, "w") as f:
        if header:
            f.write(f"# {header}\n# Generated: {datetime.now()}\n\n")
        for l in sorted(set(lines)):
            if l:
                f.write(l.strip() + "\n")
    return path

def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def run(cmd, timeout=300, capture=True):
    """Run shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str),
                           capture_output=capture, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)

def cmd_exists(name):
    return shutil.which(name) is not None

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — Auto-install tools
# ══════════════════════════════════════════════════════════════════════════════

GO_TOOLS = {
    "amass":              "github.com/owasp-amass/amass/v4/...@latest",
    "subfinder":          "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx":               "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx":              "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "mapcidr":            "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "massdns":            None,   # apt
    "github-subdomains":  "github.com/gwen001/github-subdomains@latest",
}

APT_TOOLS = {
    "massdns": "massdns",
    "git":     "git",
    "curl":    "curl",
    "jq":      "jq",
}

PY_PKGS = ["requests"]

def install_python_deps():
    log(C.YLW, "[INSTALL]", "Checking Python packages...")
    for pkg in PY_PKGS:
        try:
            __import__(pkg)
        except ImportError:
            log(C.ORG, "[PIP]", f"Installing {pkg}")
            run(f"{sys.executable} -m pip install {pkg} -q")

def install_apt(pkg, apt_name):
    if cmd_exists(pkg):
        log(C.GRN, "[OK]", f"{pkg} already installed")
        return
    log(C.ORG, "[APT]", f"Installing {apt_name} ...")
    rc, _, err = run(f"sudo apt-get install -y {apt_name} -qq", timeout=120)
    if rc == 0:
        log(C.GRN, "[OK]", f"{apt_name} installed")
    else:
        log(C.RED, "[ERR]", f"apt install {apt_name} failed: {err[:80]}")

def install_go_tool(name, pkg):
    if cmd_exists(name):
        log(C.GRN, "[OK]", f"{name} already installed")
        return
    if not cmd_exists("go"):
        log(C.RED, "[ERR]", "Go not found — install golang-go first")
        log(C.YLW, "[CMD]", "sudo apt-get install -y golang-go")
        return
    log(C.ORG, "[GO]", f"Installing {name} ...")
    rc, _, err = run(f"go install {pkg}", timeout=180)
    if rc == 0:
        log(C.GRN, "[OK]", f"{name} installed via go install")
    else:
        log(C.RED, "[ERR]", f"go install {name} failed: {err[:120]}")

def phase0_install(skip=False):
    section(0, "Auto-install Required Tools")
    if skip:
        log(C.GRY, "[SKIP]", "Tool install skipped (--no-install)")
        return

    install_python_deps()

    for pkg, apt_name in APT_TOOLS.items():
        install_apt(pkg, apt_name)

    # ensure ~/go/bin is in PATH for this process
    go_bin = os.path.expanduser("~/go/bin")
    if go_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = go_bin + ":" + os.environ.get("PATH", "")

    for name, go_pkg in GO_TOOLS.items():
        if go_pkg:
            install_go_tool(name, go_pkg)
        else:
            install_apt(name, name)

    log(C.MGT, "\n[✓]", "Tool check complete\n")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — ASN Enumeration
# ══════════════════════════════════════════════════════════════════════════════

def bgpview_asns(org):
    """Query bgpview.io for ASNs by org name."""
    asns = set()
    try:
        q = quote_plus(org)
        r = http_get(f"https://api.bgpview.io/search?query_term={q}", timeout=15)
        if r and r.status_code == 200:
            data = r.json().get("data", {})
            for entry in data.get("asns", []):
                asns.add(f"AS{entry['asn']}")
    except Exception:
        pass
    return asns

def bgphe_asns(org):
    """Scrape bgp.he.net for ASNs."""
    asns = set()
    try:
        q = quote_plus(org)
        r = http_get(f"https://bgp.he.net/search?search[search]={q}&commit=Search", timeout=15)
        if r:
            found = re.findall(r'href="/AS(\d+)"', r.text)
            asns = {f"AS{n}" for n in found}
    except Exception:
        pass
    return asns

def amass_asns(org):
    """Use amass intel to find ASNs."""
    asns = set()
    if not cmd_exists("amass"):
        return asns
    log(C.BLU, "[AMASS]", f"amass intel -org \"{org}\" ...")
    rc, out, _ = run(f'amass intel -org "{org}"', timeout=120)
    for line in out.splitlines():
        m = re.search(r'AS(\d+)', line)
        if m:
            asns.add(f"AS{m.group(1)}")
    return asns

def phase1_asn(org, outdir):
    section(1, "ASN Enumeration")
    if not org:
        log(C.YLW, "[SKIP]", "No org name provided (--org), skipping ASN phase")
        return []

    all_asns = set()

    log(C.BLU, "[BGPView]", "Querying bgpview.io ...")
    r1 = bgpview_asns(org)
    all_asns.update(r1)
    log(C.GRN if r1 else C.GRY, "[BGPView]", f"{len(r1)} ASNs")

    log(C.BLU, "[BGP.HE]", "Querying bgp.he.net ...")
    r2 = bgphe_asns(org)
    all_asns.update(r2)
    log(C.GRN if r2 else C.GRY, "[BGP.HE]", f"{len(r2)} ASNs")

    r3 = amass_asns(org)
    all_asns.update(r3)
    log(C.GRN if r3 else C.GRY, "[AMASS]", f"{len(r3)} ASNs")

    asns = sorted(all_asns)
    path = outfile(outdir, "asns.txt")
    write_lines(path, asns, f"ASNs for {org}")
    log(C.MGT, "\n[✓]", f"{len(asns)} unique ASNs → {path}")
    for a in asns:
        log(C.CYN, "  ASN", a)
    return asns


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — IP Range Extraction
# ══════════════════════════════════════════════════════════════════════════════

def bgpview_ranges(asn):
    """Get IP prefixes for an ASN from bgpview.io."""
    ranges = []
    asn_num = asn.replace("AS", "").replace("as", "")
    try:
        r = http_get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=15)
        if r and r.status_code == 200:
            data = r.json().get("data", {})
            for p in data.get("ipv4_prefixes", []):
                ranges.append(p["prefix"])
    except Exception:
        pass
    return ranges

def phase2_ip_ranges(asns, outdir, threads):
    section(2, "IP Range Extraction")
    if not asns:
        log(C.YLW, "[SKIP]", "No ASNs — skipping IP range extraction")
        return []

    all_ranges = []
    done = 0
    total = len(asns)

    with ThreadPoolExecutor(max_workers=min(threads, total)) as ex:
        futures = {ex.submit(bgpview_ranges, asn): asn for asn in asns}
        for f in as_completed(futures):
            asn = futures[f]
            ranges = f.result()
            all_ranges.extend(ranges)
            done += 1
            progress(done, total, f"[{asn}] {len(ranges)} ranges")

    print()
    path = outfile(outdir, "ip_ranges.txt")
    write_lines(path, all_ranges, "IP ranges extracted from ASNs")

    # run mapcidr to expand CIDRs if available
    if cmd_exists("mapcidr") and all_ranges:
        expanded = outfile(outdir, "ip_list.txt")
        log(C.BLU, "[MAPCIDR]", "Expanding CIDRs ...")
        run(f"mapcidr -cl {path} -silent -o {expanded}", timeout=300)
        count = len(read_lines(expanded))
        log(C.GRN, "[MAPCIDR]", f"{count:,} IPs → {expanded}")

    log(C.MGT, "\n[✓]", f"{len(all_ranges)} IP ranges → {path}")
    return all_ranges


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Domain Discovery
# ══════════════════════════════════════════════════════════════════════════════

def crtsh_by_org(org):
    domains = set()
    try:
        q = quote_plus(org)
        r = http_get(f"https://crt.sh/?o={q}&output=json", timeout=20)
        if r and r.status_code == 200:
            for e in r.json():
                name = e.get("common_name","").lstrip("*.")
                if name:
                    domains.add(name.lower())
    except Exception:
        pass
    return domains

def crtsh_by_domain(domain):
    domains = set()
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r and r.status_code == 200:
            for e in r.json():
                for n in e.get("name_value","").splitlines():
                    n = n.strip().lstrip("*.")
                    if domain in n:
                        domains.add(n.lower())
    except Exception:
        pass
    return domains

def whoisxml_domains(org, api_key, outdir):
    if not api_key:
        log(C.GRY, "[WHOIS]", "No --whoisxml-key, skipping reverse WHOIS")
        return set()
    log(C.BLU, "[WHOIS]", "Reverse WHOIS via WhoisXMLAPI ...")
    domains = set()
    try:
        payload = {
            "apiKey": api_key,
            "searchType": "current",
            "mode": "purchase",
            "punycode": True,
            "responseFormat": "json",
            "includeAuditDates": True,
            "basicSearchTerms": {"include": [org]}
        }
        r = requests.post("https://reverse-whois.whoisxmlapi.com/api/v2",
                          json=payload, headers=rh(), timeout=30, verify=False)
        data = r.json()
        for d in data.get("domainsList", []):
            name = d.get("domainName","").strip().lower()
            if name:
                domains.add(name)
        raw = outfile(outdir, "whoisxml_raw.json")
        with open(raw, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(C.RED, "[WHOIS]", f"Error: {e}")
    log(C.GRN if domains else C.GRY, "[WHOIS]", f"{len(domains)} domains")
    return domains

def phase3_domains(org, domain, api_key, outdir):
    section(3, "Domain Discovery")
    all_domains = set()

    if domain:
        log(C.BLU, "[CRT.SH]", f"CT log search for *.{domain} ...")
        r1 = crtsh_by_domain(domain)
        all_domains.update(r1)
        log(C.GRN if r1 else C.GRY, "[CRT.SH]", f"{len(r1)} entries")

    if org:
        log(C.BLU, "[CRT.SH]", f"Org-based CT log search for \"{org}\" ...")
        r2 = crtsh_by_org(org)
        all_domains.update(r2)
        log(C.GRN if r2 else C.GRY, "[CRT.SH-ORG]", f"{len(r2)} entries")

        all_domains.update(whoisxml_domains(org, api_key, outdir))

    path = outfile(outdir, "domains_raw.txt")
    write_lines(path, all_domains, f"Domains discovered for {org or domain}")
    log(C.MGT, "\n[✓]", f"{len(all_domains)} domains → {path}")
    return sorted(all_domains)


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Reverse DNS
# ══════════════════════════════════════════════════════════════════════════════

def phase4_reverse_dns(outdir, threads):
    section(4, "Reverse DNS Enumeration")
    ip_list = outfile(outdir, "ip_list.txt")
    out = outfile(outdir, "reverse_dns.txt")

    if not os.path.exists(ip_list):
        log(C.YLW, "[SKIP]", "No ip_list.txt found — skipping reverse DNS")
        return []

    total = len(read_lines(ip_list))
    log(C.BLU, "[*]", f"Running PTR lookups on {total:,} IPs ...")

    if cmd_exists("dnsx"):
        log(C.BLU, "[DNSX]", f"dnsx PTR → {out}")
        rc, _, _ = run(
            f"cat {ip_list} | dnsx -ptr -resp-only -silent -t {threads} -o {out}",
            timeout=600)
        results = read_lines(out)
        log(C.GRN if results else C.GRY, "[DNSX]", f"{len(results)} hostnames via PTR")
        return results

    elif cmd_exists("massdns"):
        log(C.BLU, "[MASSDNS]", f"massdns PTR → {out}")
        resolvers = outfile(outdir, "resolvers.txt")
        if not os.path.exists(resolvers):
            # use public resolvers
            pub = ["8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9"]
            write_lines(resolvers, pub)
        rc, _, _ = run(
            f"massdns -r {resolvers} -t PTR -o S -w {out} {ip_list}",
            timeout=600)
        results = read_lines(out)
        log(C.GRN if results else C.GRY, "[MASSDNS]", f"{len(results)} lines")
        return results

    else:
        log(C.YLW, "[SKIP]", "Neither dnsx nor massdns found")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — Subdomain Enumeration
# ══════════════════════════════════════════════════════════════════════════════

def _clean_subs(lines, domain):
    out = set()
    for s in lines:
        s = s.strip().lower().lstrip("*.")
        if s and domain in s and " " not in s and len(s) > 3:
            out.add(s)
    return out

def api_crtsh_subs(domain):
    subs = set()
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r:
            for e in r.json():
                for n in e.get("name_value","").splitlines():
                    subs.add(n)
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_hackertarget(domain):
    subs = set()
    try:
        text = http_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if text and "error" not in text[:50].lower():
            for line in text.splitlines():
                subs.add(line.split(",")[0])
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_alienvault(domain):
    subs = set()
    try:
        for page in range(1, 6):
            r = http_get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?page={page}",
                timeout=15)
            if not r: break
            data = r.json()
            for e in data.get("passive_dns", []):
                subs.add(e.get("hostname",""))
            if not data.get("has_next"): break
            time.sleep(0.3)
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_rapiddns(domain):
    subs = set()
    try:
        r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=15)
        if r:
            subs = set(re.findall(
                r'<td>([\w.\-]+\.' + re.escape(domain) + r')</td>', r.text, re.I))
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_urlscan(domain):
    subs = set()
    try:
        r = http_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200", timeout=15)
        if r:
            for res in r.json().get("results",[]):
                subs.add(res.get("page",{}).get("domain",""))
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_bufferover(domain):
    subs = set()
    try:
        r = http_get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15)
        if r:
            data = r.json()
            for rec in data.get("FDNS_A",[]) + data.get("RDNS",[]):
                parts = rec.split(",")
                if len(parts) >= 2:
                    subs.add(parts[1].strip().rstrip("."))
    except Exception:
        pass
    return _clean_subs(subs, domain)

def api_certspotter(domain):
    subs = set()
    try:
        r = http_get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            f"&include_subdomains=true&expand=dns_names", timeout=20)
        if r:
            for e in r.json():
                for n in e.get("dns_names",[]):
                    subs.add(n)
    except Exception:
        pass
    return _clean_subs(subs, domain)

PASSIVE_SOURCES = [
    ("crt.sh",       api_crtsh_subs),
    ("hackertarget", api_hackertarget),
    ("alienvault",   api_alienvault),
    ("rapiddns",     api_rapiddns),
    ("urlscan",      api_urlscan),
    ("bufferover",   api_bufferover),
    ("certspotter",  api_certspotter),
]

def tool_subfinder(domain, outdir, threads):
    out = outfile(outdir, "subfinder_out.txt")
    if not cmd_exists("subfinder"):
        return set()
    log(C.BLU, "[SUBFINDER]", f"subfinder -d {domain} ...")
    rc, stdout, _ = run(
        f"subfinder -d {domain} -all -silent -t {threads} -o {out}", timeout=300)
    subs = _clean_subs(read_lines(out), domain)
    log(C.GRN if subs else C.GRY, "[SUBFINDER]", f"{len(subs)} subdomains")
    return subs

def tool_amass(domain, outdir):
    out = outfile(outdir, "amass_out.txt")
    if not cmd_exists("amass"):
        return set()
    log(C.BLU, "[AMASS]", f"amass enum -d {domain} ...")
    rc, _, _ = run(f"amass enum -d {domain} -o {out} -silent", timeout=600)
    subs = _clean_subs(read_lines(out), domain)
    log(C.GRN if subs else C.GRY, "[AMASS]", f"{len(subs)} subdomains")
    return subs

def tool_github_subdomains(domain, outdir, github_token):
    if not cmd_exists("github-subdomains"):
        return set()
    if not github_token:
        log(C.GRY, "[GITHUB]", "No --github-token, skipping github-subdomains")
        return set()
    out = outfile(outdir, f"github_subs_{domain}.txt")
    log(C.BLU, "[GITHUB]", f"github-subdomains -d {domain} ...")
    env = os.environ.copy()
    env["GITHUB_TOKEN"] = github_token
    rc, stdout, _ = run(
        f"github-subdomains -d {domain} -o {out}", timeout=300)
    subs = _clean_subs(read_lines(out), domain)
    log(C.GRN if subs else C.GRY, "[GITHUB]", f"{len(subs)} subdomains")
    return subs

def phase5_subdomains(domain, outdir, threads, github_token):
    section(5, "Subdomain Enumeration")
    if not domain:
        log(C.YLW, "[SKIP]", "No domain — skipping subdomain enum")
        return []

    all_subs = {domain}

    # passive API sources — concurrent
    log(C.YLW, "[*]", "Running passive API sources concurrently ...")
    with ThreadPoolExecutor(max_workers=len(PASSIVE_SOURCES)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in PASSIVE_SOURCES}
        for f in as_completed(futures):
            name = futures[f]
            try:
                result = f.result()
                all_subs.update(result)
                col = C.GRN if result else C.GRY
                log(col, f"  [{name}]", f"{len(result)} subdomains")
            except Exception as e:
                log(C.RED, f"  [{name}]", f"error: {e}")

    # CLI tools — sequential (they do their own threading)
    all_subs.update(tool_subfinder(domain, outdir, threads))
    all_subs.update(tool_amass(domain, outdir))
    all_subs.update(tool_github_subdomains(domain, outdir, github_token))

    # also pull in reverse DNS results
    rev = read_lines(outfile(outdir, "reverse_dns.txt"))
    all_subs.update(_clean_subs(rev, domain))

    all_subs = sorted(all_subs)
    path = outfile(outdir, "subdomains_all.txt")
    write_lines(path, all_subs, f"All subdomains for {domain}")
    log(C.MGT, "\n[✓]", f"{len(all_subs)} unique subdomains → {path}")
    return all_subs


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — DNS Resolution Filtering
# ══════════════════════════════════════════════════════════════════════════════

def phase6_dns_filter(subdomains, outdir, threads):
    section(6, "DNS Resolution Filtering")
    if not subdomains:
        log(C.YLW, "[SKIP]", "No subdomains to resolve")
        return subdomains

    inp = outfile(outdir, "subdomains_all.txt")
    out = outfile(outdir, "subdomains_resolved.txt")

    if cmd_exists("dnsx"):
        log(C.BLU, "[DNSX]", f"Resolving {len(subdomains)} subdomains ...")
        rc, _, _ = run(
            f"dnsx -l {inp} -silent -a -t {threads} -o {out}", timeout=600)
        resolved = read_lines(out)
        log(C.GRN, "[DNSX]", f"{len(resolved)} resolve OK → {out}")
        return resolved
    else:
        log(C.YLW, "[SKIP]", "dnsx not found — skipping resolution filter")
        return subdomains


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — HTTP Probing
# ══════════════════════════════════════════════════════════════════════════════

PORTS = "80,443,1337,2375,2376,3000,3001,3002,3003,3306,4000,4001,4002,4200,4443,5000,5173,5432,5601,6379,8000,8080,8081,8082,8083,8443,8888,9000,9001,9090,9200,10250,27017,50000"

INTERESTING_CODES = {200,201,204,301,302,303,307,308,401,403}
STATUS_COL = {
    200:C.GRN, 201:C.GRN, 204:C.GRN,
    301:C.YLW, 302:C.YLW, 303:C.YLW, 307:C.YLW, 308:C.YLW,
    401:C.ORG, 403:C.ORG,
}

def probe_host(sub, timeout):
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, headers=rh(), timeout=timeout,
                             verify=False, allow_redirects=True)
            if r.status_code in INTERESTING_CODES:
                return url, r.status_code, str(r.url)
        except Exception:
            continue
    return None

def phase7_http_probe(subdomains, outdir, threads, timeout):
    section(7, "HTTP Probing")
    if not subdomains:
        log(C.YLW, "[SKIP]", "No subdomains to probe")
        return [], []

    # prefer httpx if available (multi-port, tech-detect, title, screenshots)
    inp = outfile(outdir, "subdomains_resolved.txt")
    if not os.path.exists(inp):
        inp = outfile(outdir, "subdomains_all.txt")

    if cmd_exists("httpx"):
        log(C.BLU, "[HTTPX]", f"Multi-port probing ({PORTS}) with tech-detect + title + screenshots ...")
        raw_out  = outfile(outdir, "httpx_raw.txt")
        ss_dir   = outfile(outdir, "screenshots")
        Path(ss_dir).mkdir(exist_ok=True)
        rc, _, _ = run(
            f"httpx -l {inp} -probe -silent -status-code -tech-detect -title -fr "
            f"-ss -screenshot-path {ss_dir} "
            f"-ports \"{PORTS}\" -threads {threads} -timeout {timeout} "
            f"| tee {raw_out}",
            timeout=1800, capture=False)

        # parse results
        live, live_200 = [], []
        for line in read_lines(raw_out):
            m = re.match(r'(https?://\S+)', line)
            code_m = re.search(r'\[(\d{3})\]', line)
            if m and code_m:
                url = m.group(1)
                code = int(code_m.group(1))
                col = STATUS_COL.get(code, C.GRY)
                log(col, f"  [{code}]", url)
                live.append((url, code, url))
                if code == 200:
                    live_200.append(url)
    else:
        log(C.YLW, "[FALLBACK]", f"httpx not found — using Python probe ({threads} threads) ...")
        live, live_200 = [], []
        total = len(subdomains)
        done = 0

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(probe_host, s, timeout): s for s in subdomains}
            for f in as_completed(futures):
                done += 1
                res = f.result()
                if res:
                    url, code, final = res
                    col = STATUS_COL.get(code, C.GRY)
                    log(col, f"  [{code}]", f"{url}  {C.GRY}→ {final[:60]}{C.R}")
                    live.append((url, code, final))
                    if code == 200:
                        live_200.append(url)
                progress(done, total)
        print()

    # save
    sub_path = outfile(outdir, "subdomains.txt")
    sub_200  = outfile(outdir, "subdomains_200.txt")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(sub_path, "w") as f:
        f.write(f"# Live hosts — {ts}\n\n")
        for url, code, final in sorted(live, key=lambda x: x[1]):
            f.write(f"[{code}]  {url:<55}  ->  {final}\n")

    with open(sub_200, "w") as f:
        f.write(f"# HTTP-200 hosts — {ts}\n\n")
        for url in sorted(live_200):
            f.write(url + "\n")

    log(C.MGT, "\n[✓]", f"Live: {len(live)} | 200-only: {len(live_200)}")
    log(C.GRN, "[✓]", f"→ {sub_path}")
    log(C.GRN, "[✓]", f"→ {sub_200}")
    return live, live_200


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 8 — JS Endpoint Extraction
# ══════════════════════════════════════════════════════════════════════════════

RE_SCRIPT = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
RE_JS_STR = re.compile(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')

EP_PATS = [
    re.compile(
        r'["\`](\/(?:api|v\d+|rest|graphql|gql|auth|oauth|rpc|service|services|'
        r'data|query|mutation|admin|public|private|internal|mobile|gateway|proxy|'
        r'backend|user|users|account|order|product|payment|invoice|report|'
        r'analytics|upload|download|file|media|config|health|status|ping|token|'
        r'refresh|login|logout|register|signup|profile|dashboard|notification|'
        r'message|email|sms|webhook|event|log|search|batch|export|import|sync|'
        r'stream|subscribe)[\/\w\-\.:\{\}?=&%#]*)["\`]', re.I),
    re.compile(
        r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*'
        r'["\`]([^"\`\s]{4,})["\`]', re.I),
    re.compile(
        r'(?:baseURL|baseUrl|BASE_URL|API_URL|apiUrl|apiEndpoint|endpoint)\s*'
        r'[=:]\s*["\`]([^"\`\s]{5,})["\`]', re.I),
    re.compile(
        r'["\`](https?://[^\s"\`\'<>]{10,}'
        r'(?:api|v\d+|rest|graphql|auth|service|gateway)[^\s"\`\'<>]*)["\`]', re.I),
    re.compile(r'["\`](\/[\w\-]{2,}\/[\w\-\/\.\{\}:?=&%]{2,})["\`]'),
]

NOISE = re.compile(
    r'\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|html?|txt|md)(\?.*)?$'
    r'|^\/\/|node_modules|\/\*', re.I)

INTERESTING_RE = re.compile(
    r'["\`]((?:https?:\/\/[^\s"\`\'<>]+|\/[\w\-\/\.]+)'
    r'(?:admin|panel|dashboard|login|signup|api|swagger|graphql|debug|test|'
    r'staging|internal|config|\.env|\.git|backup|dump|secret|password)'
    r'[^\s"\`\'<>]*)["\`]', re.I)

def find_js(base_url, html):
    js = set()
    netloc = urlparse(base_url).netloc
    for pat in (RE_SCRIPT, RE_JS_STR):
        for m in pat.finditer(html):
            src = m.group(1)
            full = urljoin(base_url, src) if not src.startswith("http") else src
            pu = urlparse(full)
            if not pu.netloc or pu.netloc == netloc:
                js.add(full)
    return js

def extract_eps(content):
    eps, interesting = set(), set()
    for pat in EP_PATS:
        for m in pat.finditer(content):
            ep = m.group(1).strip()
            if ep and not NOISE.search(ep) and len(ep) > 3:
                eps.add(ep)
    for m in INTERESTING_RE.finditer(content):
        lnk = m.group(1).strip()
        if lnk: interesting.add(lnk)
    return eps, interesting

def scan_js(js_url, delay, idx, total, timeout):
    time.sleep(delay + random.uniform(0, delay * 0.4))
    short = js_url.split("/")[-1][:50]
    text = http_text(js_url, timeout=timeout)
    if not text:
        return js_url, set(), set()
    eps, interesting = extract_eps(text)
    col = C.GRN if eps else C.GRY
    log(col, f"  [{idx:>3}/{total}]",
        f"{short}  {C.B}{len(eps)}{C.R}{col} ep  {C.ORG}{len(interesting)}{C.R} interesting")
    return js_url, eps, interesting

def phase8_endpoints(live_200_urls, outdir, threads, delay, timeout, domain):
    section(8, "JS Endpoint Extraction")
    if not live_200_urls:
        log(C.YLW, "[SKIP]", "No 200 hosts — skipping JS scan")
        return

    all_js = set()
    log(C.BLU, "[*]", f"Discovering JS files from {len(live_200_urls)} hosts ...")
    for url in live_200_urls:
        html = http_text(url, timeout=timeout)
        if html:
            found = find_js(url, html)
            if found:
                log(C.CYN, "  [JS]", f"{url} → {len(found)} files")
            all_js.update(found)

    log(C.MGT, "\n[JS]", f"{len(all_js)} total JS files\n")
    if not all_js:
        return

    js_list = sorted(all_js)
    total = len(js_list)
    all_eps, all_interesting = set(), set()

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(scan_js, url, delay, i+1, total, timeout): url
            for i, url in enumerate(js_list)
        }
        for f in as_completed(futures):
            _, eps, interesting = f.result()
            all_eps.update(eps)
            all_interesting.update(interesting)

    # print
    if all_eps:
        log(C.GRN, "\n[ENDPOINTS]", f"{C.B}{len(all_eps)}{C.R}{C.GRN} unique endpoints:\n")
        for ep in sorted(all_eps):
            if ep.startswith("http"): col = C.MGT
            elif re.search(r'auth|login|token|oauth', ep, re.I): col = C.RED
            elif re.search(r'api|v\d|rest|graphql', ep, re.I): col = C.GRN
            else: col = C.CYN
            log(col, "  >", ep)

    if all_interesting:
        log(C.ORG, "\n[INTERESTING]", f"{C.B}{len(all_interesting)}{C.R}{C.ORG} links:\n")
        for lnk in sorted(all_interesting):
            log(C.ORG, "  >", lnk)

    # save
    tag = re.sub(r'^https?://', '', domain or "target").split("/")[0]
    fname = outfile(outdir, f"{tag}_api-endpoints.txt")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(fname, "w") as f:
        f.write(f"# API Endpoints — {tag}  ({ts})\n")
        f.write(f"# endpoints: {len(all_eps)}  interesting: {len(all_interesting)}\n")
        f.write("="*60 + "\n\n## API ENDPOINTS\n")
        for ep in sorted(all_eps):
            f.write(f"  {ep}\n")
        f.write("\n## INTERESTING LINKS\n")
        for lnk in sorted(all_interesting):
            f.write(f"  {lnk}\n")

    log(C.GRN, "\n[✓]", f"Saved → {fname}")
    return all_eps, all_interesting


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(outdir, domain, asns, ip_ranges, domains,
                  subdomains, live, live_200, eps, interesting):
    ep_count = len(eps) if eps else 0
    int_count = len(interesting) if interesting else 0
    print(f"""
{C.CYN}{C.B}╔══════════════════════════════════════════════════════════════╗
║                     FINAL SUMMARY                            ║
╠══════════════════════════════════════════════════════════════╣{C.R}
{C.WHT}  ASNs discovered       : {C.B}{len(asns)}{C.R}
{C.WHT}  IP ranges extracted   : {C.B}{len(ip_ranges)}{C.R}
{C.WHT}  Domains found         : {C.B}{len(domains)}{C.R}
{C.WHT}  Subdomains enumerated : {C.B}{len(subdomains)}{C.R}
{C.WHT}  Live hosts            : {C.B}{len(live)}{C.R}
{C.WHT}  HTTP 200 hosts        : {C.B}{len(live_200)}{C.R}
{C.WHT}  API endpoints         : {C.B}{ep_count}{C.R}
{C.WHT}  Interesting links     : {C.B}{int_count}{C.R}
{C.GRY}  Output directory      : {outdir}{C.R}
{C.CYN}{C.B}╚══════════════════════════════════════════════════════════════╝{C.R}

{C.YLW}Output files:{C.R}
{C.GRY}  {outdir}/asns.txt
  {outdir}/ip_ranges.txt
  {outdir}/ip_list.txt
  {outdir}/domains_raw.txt
  {outdir}/subdomains_all.txt
  {outdir}/subdomains_resolved.txt
  {outdir}/subdomains.txt
  {outdir}/subdomains_200.txt
  {outdir}/<domain>_api-endpoints.txt
  {outdir}/screenshots/  (if httpx + -ss ran){C.R}
""")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Full Recon Suite — 0xh3l1x / cgomezsec methodology",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python3 recon_suite.py -o "Apple Inc" -d apple.com
  python3 recon_suite.py -d target.com --skip-asn --threads 20
  python3 recon_suite.py -o "Acme Corp" -d acme.com \\
      --whoisxml-key YOUR_KEY --github-token ghp_xxx"""
    )
    ap.add_argument("-d",  "--domain",        help="Root domain  e.g. apple.com")
    ap.add_argument("-o",  "--org",           help="Organization name  e.g. \"Apple Inc\"")
    ap.add_argument("-t",  "--threads",       type=int,   default=10,  metavar="N",
                   help="Threads (default: 10)")
    ap.add_argument("-T",  "--timeout",       type=int,   default=8,   metavar="S",
                   help="HTTP timeout s (default: 8)")
    ap.add_argument("--delay",                type=float, default=0.3, metavar="F",
                   help="JS scan base delay (default: 0.3)")
    ap.add_argument("--outdir",               default="recon_output",
                   help="Output directory (default: recon_output)")
    ap.add_argument("--whoisxml-key",         metavar="KEY",
                   help="WhoisXMLAPI key for reverse WHOIS")
    ap.add_argument("--github-token",         metavar="TOKEN",
                   help="GitHub token for github-subdomains tool")
    ap.add_argument("--skip-asn",            action="store_true",
                   help="Skip ASN + IP range phases")
    ap.add_argument("--skip-probe",          action="store_true",
                   help="Skip HTTP probing phase")
    ap.add_argument("--skip-js",             action="store_true",
                   help="Skip JS endpoint extraction")
    ap.add_argument("--no-install",          action="store_true",
                   help="Skip auto-install of tools")
    args = ap.parse_args()

    if not args.domain and not args.org:
        ap.print_help()
        print(f"\n{C.RED}[!] Provide at least -d <domain> or -o <org>{C.R}\n")
        sys.exit(1)

    # normalize domain
    if args.domain:
        args.domain = re.sub(r'^https?://', '', args.domain).split("/")[0].strip().lower()

    # prepare output dir
    outdir = args.outdir
    Path(outdir).mkdir(parents=True, exist_ok=True)

    banner(args)

    # Phase 0 — install
    phase0_install(skip=args.no_install)

    # Phase 1 — ASN
    asns = []
    ip_ranges = []
    if not args.skip_asn and args.org:
        asns = phase1_asn(args.org, outdir)
        ip_ranges = phase2_ip_ranges(asns, outdir, args.threads)
    elif args.skip_asn:
        log(C.GRY, "[SKIP]", "ASN + IP range phases skipped (--skip-asn)")

    # Phase 3 — domains
    domains = phase3_domains(args.org, args.domain, args.whoisxml_key, outdir)

    # Phase 4 — reverse DNS
    phase4_reverse_dns(outdir, args.threads)

    # Phase 5 — subdomains
    subdomains = phase5_subdomains(args.domain, outdir, args.threads, args.github_token)

    # Phase 6 — DNS filter
    resolved = phase6_dns_filter(subdomains, outdir, args.threads)

    # Phase 7 — HTTP probe
    live, live_200 = [], []
    if not args.skip_probe:
        live, live_200 = phase7_http_probe(resolved or subdomains, outdir,
                                           args.threads, args.timeout)
    else:
        log(C.GRY, "[SKIP]", "HTTP probing skipped (--skip-probe)")

    # Phase 8 — JS endpoints
    eps, interesting = set(), set()
    if not args.skip_js:
        live_200_urls = [u for u, c, _ in live if c == 200] if live else live_200
        result = phase8_endpoints(live_200_urls, outdir, args.threads,
                                  args.delay, args.timeout, args.domain or "target")
        if result:
            eps, interesting = result
    else:
        log(C.GRY, "[SKIP]", "JS endpoint extraction skipped (--skip-js)")

    print_summary(outdir, args.domain, asns, ip_ranges, domains,
                  subdomains, live, live_200, eps, interesting)


if __name__ == "__main__":
    main()
