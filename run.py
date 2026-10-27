import re
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

ENDPOINT_REGEX = r"""(?:"|')(?:\/|api|v1|v2|v3|v4|v5|admin|auth|user|config|setting|dev|internal|wp-json|graphql)[a-zA-Z0-9_\-\/\.\?=\&\#%]*?(?:"|')"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*"
}

def scan_js_url(js_url):
    print(f"[*] Scanning: {js_url}")
    try:
        response = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
        if response.status_code == 200:
            matches = re.findall(ENDPOINT_REGEX, response.text, re.IGNORECASE)
            endpoints = set()
            for match in matches:
                cleaned = match.strip("\"'")
                if len(cleaned) > 2:
                    endpoints.add(cleaned)
            return list(endpoints)
    except Exception as e:
        print(f"[-] Error scanning {js_url}: {str(e)}")
    return []

def main():
    parser = argparse.ArgumentParser(description="BountyExtractor - Hidden Endpoint Scanner for Web Bug Bounty")
    parser.add_argument("-u", "--url", help="Target URL of a JavaScript file")
    parser.add_argument("-l", "--list", help="Path to a file containing a list of JS URLs to scan")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (Default: 5)")
    
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    urls_to_scan = []
    if args.url:
        urls_to_scan.append(args.url)
    if args.list:
        with open(args.list, "r") as f:
            urls_to_scan = [line.strip() for line in f if line.strip()]

    print(f"[+] Total URLs to scan: {len(urls_to_scan)}")
    print("[+] Extracting endpoints... Please wait.")
    
    all_discovered_endpoints = set()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(scan_js_url, urls_to_scan)
        for result in results:
            for endpoint in result:
                all_discovered_endpoints.add(endpoint)

    print("\n" + "="*40)
    print(f"[+] DISCOVERED ENDPOINTS ({len(all_discovered_endpoints)} unique found):")
    print("="*40)
    
    for ep in sorted(all_discovered_endpoints):
        print(ep)

if __name__ == "__main__":
    main()
