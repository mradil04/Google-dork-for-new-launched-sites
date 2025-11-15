#!/usr/bin/env python3
"""
find_disclosure.py
Passive discovery of security disclosure / bug-bounty pages for domains.
- Checks common paths and searches page content
- Queries crt.sh for certs (simple GET)
- Produces Google/DuckDuckGo/Bing dork URLs (opens in browser if asked)
- Outputs CSV report

Usage:
  python3 find_disclosure.py -d example.com
  python3 find_disclosure.py -f domains.txt -o results.csv --open-dorks
"""

import argparse
import requests
import csv
import sys
import time
import re
import urllib.parse
import webbrowser
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

USER_AGENT = "Mozilla/5.0 (compatible; disclosure-finder/1.0; +https://github.com/you/repo)"
TIMEOUT = 10
COMMON_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/security",
    "/bug-bounty",
    "/bug-bounty-policy",
    "/.well-known/bug-bounty",
    "/responsible-disclosure",
    "/.well-known/responsible-disclosure",
    "/.well-known/security",
    "/.well-known/vulnerability-disclosure",
    "/vulnerability-disclosure",
    "/security-policy",
    "/.well-known/security-policy",
    "/.well-known/hackerone",  # sometimes used
]

KEYWORDS = [
    "security.txt", "bug bounty", "responsible disclosure",
    "vulnerability disclosure", "security policy", "security@",
    "hackerone", "bugcrowd", "security contact", "disclosure policy"
]

HEADERS = {"User-Agent": USER_AGENT}


def fetch_url(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text, r.headers
    except requests.RequestException as e:
        return None, None, None


def head_url(url):
    try:
        r = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.headers
    except requests.RequestException:
        return None, None


def check_domain(domain):
    domain = domain.strip()
    if not domain:
        return None
    if not re.match(r"https?://", domain):
        base = f"https://{domain}"
    else:
        base = domain.rstrip("/")

    findings = {
        "domain": domain,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "found_paths": [],
        "keyword_hits": [],
        "crt_sh": "",
        "notes": ""
    }

    # 1) check common paths (HEAD first then GET if promising)
    for p in COMMON_PATHS:
        url = urllib.parse.urljoin(base, p.lstrip("/"))
        status, headers = head_url(url)
        if status and status < 400:
            # do GET to fetch content snippet
            s, text, h = fetch_url(url)
            snippet = (text or "")[:200].replace("\n", " ")
            findings["found_paths"].append(f"{url} (HTTP {status})")
            # look for keywords in the content
            hits = [k for k in KEYWORDS if k.lower() in (text or "").lower()]
            if hits:
                findings["keyword_hits"].append({"url": url, "hits": hits})
        time.sleep(0.15)

    # 2) check homepage & /contact for keywords (GET)
    for p in ["/", "/index.html", "/contact", "/about", "/legal"]:
        url = urllib.parse.urljoin(base, p.lstrip("/"))
        status, text, headers = fetch_url(url)
        if status and text:
            lower = text.lower()
            hits = [k for k in KEYWORDS if k.lower() in lower]
            if hits:
                findings["keyword_hits"].append({"url": url, "hits": hits})
        time.sleep(0.15)

    # 3) query crt.sh for cert entries (very simple, public UI scrape)
    try:
        q = urllib.parse.quote_plus("%." + domain if not domain.startswith("http") else "%." + urllib.parse.urlparse(domain).hostname)
        crt_url = f"https://crt.sh/?q={q}&output=json"
        r = requests.get(crt_url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            findings['crt_sh'] = 'found' if r.text and len(r.text) > 5 else ''
        else:
            findings['crt_sh'] = ''
    except Exception:
        findings['crt_sh'] = ''

    # 4) build dork URLs (browser-friendly, don't scrape Google)
    hostname = urllib.parse.urlparse(base).hostname or domain
    dorks = {
        "google_security_txt": f"https://www.google.com/search?q=site:{hostname}+%22security.txt%22",
        "google_bug_bounty": f"https://www.google.com/search?q=site:{hostname}+%22bug+bounty%22",
        "bing_security_txt": f"https://www.bing.com/search?q=site:{hostname}+%22security.txt%22",
        "ddg_bug_bounty": f"https://duckduckgo.com/?q=site:{hostname}+%22bug+bounty%22",
    }
    findings["dorks"] = dorks

    return findings


def main():
    parser = argparse.ArgumentParser(description="Passive discovery of security disclosure pages.")
    parser.add_argument("-d", "--domain", help="Single domain (example.com)")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("-o", "--output", default="disclosure_results.csv", help="CSV output file")
    parser.add_argument("--open-dorks", action="store_true", help="Open dork URLs in browser for manual review (no scraping).")
    parser.add_argument("--threads", type=int, default=6, help="Concurrency threads")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.file:
        p = Path(args.file)
        if not p.exists():
            print("File not found:", args.file, file=sys.stderr)
            sys.exit(1)
        domains.extend([l.strip() for l in p.read_text().splitlines() if l.strip()])

    if not domains:
        parser.print_help()
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_domain, d): d for d in domains}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    # write CSV
    csv_path = args.output
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["domain", "checked_at", "found_paths", "keyword_hits", "crt_sh", "dorks", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "domain": r["domain"],
                "checked_at": r["checked_at"],
                "found_paths": " | ".join(r["found_paths"]),
                "keyword_hits": " | ".join([f"{h['url']}:{','.join(h['hits'])}" for h in r["keyword_hits"]]),
                "crt_sh": r["crt_sh"],
                "dorks": " | ".join([f"{k}:{v}" for k, v in r["dorks"].items()]),
                "notes": r.get("notes", "")
            })

    print(f"Wrote results to {csv_path}. Domains checked: {len(results)}")

    if args.open_dorks:
        # open dork tabs but be conservative
        for r in results:
            for name, url in r["dorks"].items():
                print(f"Opening {name} for {r['domain']}: {url}")
                webbrowser.open_new_tab(url)
                time.sleep(0.25)


if __name__ == "__main__":
    main()
