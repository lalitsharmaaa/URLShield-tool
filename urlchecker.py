"""Welcome to URLShield by Lalit Sharma, a small tool which helps you predict vulnerabilities and tactics in a URL"""

import re
import sys
from urllib.parse import urlparse


SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".click")

KNOWN_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd")

WATCHED_BRANDS = ("paypal", "google", "microsoft", "apple", "amazon",
                   "facebook", "instagram", "netflix", "bank", "irs")


def normalize_url(raw_url):
    """Make sure the URL has a scheme so urlparse can read it properly."""
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url
    return raw_url


def get_host(url):
    """Pull out just the domain/host part of the URL, lowercased."""
    return urlparse(url).hostname or ""

def is_ip_address(url, host):
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))


def has_at_symbol(url, host):
    return "@" in url


def has_too_many_subdomains(url, host):
    return host.count(".") > 3


def has_many_hyphens(url, host):
    return host.count("-") >= 2


def is_missing_https(url, host):
    return not url.lower().startswith("https://")


def has_suspicious_tld(url, host):
    return host.endswith(SUSPICIOUS_TLDS)


def impersonates_a_brand(url, host):
    clean_host = host[4:] if host.startswith("www.") else host
    for brand in WATCHED_BRANDS:
        if brand in clean_host and not clean_host.startswith(brand + "."):
            return True
    return False


def is_known_shortener(url, host):
    return host in KNOWN_SHORTENERS


def has_nonstandard_port(url, host):
    return bool(re.search(r":\d{2,5}(/|$)", url.split("://")[-1]))


def is_unusually_long(url, host):
    return len(url) > 75


RULES = [
    (is_ip_address, 30, "The address uses a raw IP instead of a domain name — a common way to dodge domain checks."),
    (has_at_symbol, 25, "Contains an '@' symbol, which browsers ignore everything before — used to hide the real destination."),
    (impersonates_a_brand, 25, "A known brand name appears in the domain, but the domain isn't actually that brand's."),
    (has_too_many_subdomains, 15, "Unusually deep subdomain chain — often used to bury the real domain."),
    (has_suspicious_tld, 15, "Uses a top-level domain that's disproportionately common in phishing campaigns."),
    (has_many_hyphens, 10, "Multiple hyphens in the domain — often used to mimic a real brand name."),
    (is_missing_https, 10, "No HTTPS — not definitive alone, but most legitimate sites use it today."),
    (has_nonstandard_port, 12, "Uses a non-standard port number, uncommon for normal consumer-facing sites."),
    (is_unusually_long, 8, "URL is unusually long, which can indicate stuffed tracking or redirect parameters."),
    (is_known_shortener, 15, "This is a known URL shortener, which hides the real destination from the user."),
]


def scan_url(raw_url):
    """Run every rule against the URL and return a result dictionary."""
    url = normalize_url(raw_url)
    host = get_host(url)

    fired_rules = []
    for check_function, points, reason in RULES:
        if check_function(url, host):
            fired_rules.append((check_function.__name__, points, reason))

    score = min(100, sum(points for _, points, _ in fired_rules))

    if score >= 50:
        verdict = "HIGH RISK"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "url": raw_url,
        "host": host,
        "score": score,
        "verdict": verdict,
        "fired_rules": fired_rules,
    }


def print_report(result):
    print()
    print("=" * 50)
    print(f"URL checked : {result['url']}")
    print(f"Host        : {result['host']}")
    print(f"Risk score  : {result['score']}/100")
    print(f"Verdict     : {result['verdict']}")
    print("=" * 50)

    if result["fired_rules"]:
        print("\nFlags raised:\n")
        for name, points, reason in result["fired_rules"]:
            print(f"  [+{points}] {reason}")
    else:
        print("\nNo flags raised. That's a good sign, but always check page")
        print("content and the sender/context too — this tool only checks")
        print("the URL string itself.")
    print()


def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        result = scan_url(target_url)
        print_report(result)
    else:
        print("Phishing / suspicious URL checker. Type 'quit' to exit.\n")
        while True:
            target_url = input("Enter a URL to scan: ").strip()
            if target_url.lower() in ("quit", "exit", "q"):
                break
            if not target_url:
                continue
            result = scan_url(target_url)
            print_report(result)


if __name__ == "__main__":
    main()
