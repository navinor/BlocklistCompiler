"""
BlocklistCompiler - compile.py

Downloads ABP-style blocklists from sources.txt and extracts
Pi-hole compatible domain entries into blocklist.txt.

Extraction rules:
  1. ABP domain rules:	||domain.tld^  (with optional $options)
  2. Hosts-file lines:	0.0.0.0 domain.tld	/  127.0.0.1 domain.tld
  3. Plain domain lines: domain.tld

Everything else (element hiding, path-specific rules, exceptions,
comments, etc.) is skipped.
"""

import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# ABP domain-only rule:	 ||example.com^	  or   ||example.com^$third-party
# We require the rule to end with ^ optionally followed by $ and modifier text,
# and NO path component (no "/" after the domain).
RE_ABP_DOMAIN = re.compile(
    r"^\|\|([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\^(\$.*)?$"
)

# Hosts-file line:	0.0.0.0 example.com	  or   127.0.0.1 example.com
RE_HOSTS = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\s*$"
)

# Bare domain on its own line
RE_PLAIN_DOMAIN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})$"
)

# Lines we should skip outright (before trying domain extraction)
RE_SKIP = re.compile(
    r"^(?:"
    r"!|"  # ABP comment
    r"\[|"  # ABP header  e.g. [Adblock Plus …]
    r"#|"  # Hosts-file comment
    r"@@"  # Exception / whitelist rule
    r")"
)

# Element hiding / CSS rules  (skip)
RE_ELEMENT_HIDING = re.compile(r"##|#\?#|#@#|#!#")

SOURCES_FILE = Path(__file__).parent / "sources.txt"
OUTPUT_FILE = Path(__file__).parent / "blocklist.txt"

# Domains that should never be blocked (safety net)
DOMAIN_WHITELIST = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}

# ABP options that act as context/type scopes that Pi-hole cannot enforce.
# If an ABP rule contains any of these, it is not a blanket domain block.
# Some lists use ~resource to exclude things, but even positive resource 
# matches mean "only block if it's an image". Pi-hole can't do that.
# See: https://help.eyeo.com/adblockplus/how-to-write-filters
UNSUPPORTED_ABP_OPTIONS = (
    "domain=",
    "third-party", 
    "~third-party",
    "script", "~script",
    "image", "~image",
    "stylesheet", "~stylesheet",
    "object", "~object",
    "xmlhttprequest", "~xmlhttprequest",
    "subdocument", "~subdocument",
    "ping", "~ping",
    "websocket", "~websocket",
    "webrtc", "~webrtc",
    "document", "~document",
    "elemhide", "~elemhide",
    "genericblock", "~genericblock",
    "generichide", "~generichide",
    "other", "~other",
    "font", "~font",
    "media", "~media",
    "match-case", "~match-case",
    "collapse", "~collapse",
    "donottrack",
    "csp=",
    "rewrite=",
    "header=",
)


def extract_domain(line: str) -> str | None:
    """Try to extract a blockable domain from a single line.

	Returns the domain string (lowercased) or None if the line
	does not represent a domain-level block.
	"""
    line = line.strip()
    if not line:
        return None

    # Skip comments, headers, exceptions
    if RE_SKIP.match(line):
        return None

    # Skip element-hiding / CSS rules
    if RE_ELEMENT_HIDING.search(line):
        return None

    # 1. ABP domain-only rule  ||domain.tld^
    m = RE_ABP_DOMAIN.match(line)
    if m:
        options = m.group(5)  # e.g. "$third-party,~script" or None
        if options:
            option_list = options.lstrip("$").split(",")
            # If any option acts as a restrictive modifier, Pi-hole can't enforce it globally.
            for opt in option_list:
                if any(opt.startswith(unsupported) for unsupported in UNSUPPORTED_ABP_OPTIONS):
                    return None
        return m.group(1).lower()

    # 2. Hosts-file format
    m = RE_HOSTS.match(line)
    if m:
        return m.group(1).lower()

    # 3. Plain domain
    m = RE_PLAIN_DOMAIN.match(line)
    if m:
        return m.group(1).lower()

    return None


def download_list(url: str) -> list[str]:
    """Download a blocklist and return its lines."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "BlocklistCompiler/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace").splitlines()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"  ✗ Failed to download: {exc}")
        return []


def main() -> None:
    if not SOURCES_FILE.exists():
        print(f"Error: {SOURCES_FILE} not found.")
        sys.exit(1)

    urls = [
        line.strip()
        for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        print("No URLs found in sources.txt.")
        sys.exit(1)

    domains: set[str] = set()
    stats: dict[str, int] = {}

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Downloading {url} ...")
        lines = download_list(url)
        count = 0
        for raw_line in lines:
            domain = extract_domain(raw_line)
            if domain and domain not in DOMAIN_WHITELIST:
                domains.add(domain)
                count += 1
        stats[url] = count
        print(f"  ✓ Extracted {count} domains from {len(lines)} lines")

    # Write output
    sorted_domains = sorted(domains)
    OUTPUT_FILE.write_text(
        "\n".join(sorted_domains) + "\n",
        encoding="utf-8",
    )

    # Summary
    print()
    print("=" * 60)
    print(f"Total unique domains: {len(sorted_domains)}")
    print(f"Output written to:	  {OUTPUT_FILE}")
    print("=" * 60)
    print()
    print("Per-source breakdown:")
    for url, count in stats.items():
        name = url.rsplit("/", 1)[-1]
        print(f"  {name:<40s} {count:>6,} domains")


if __name__ == "__main__":
    main()
