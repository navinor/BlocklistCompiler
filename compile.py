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

sources.txt format:
  - Plain URL lines are treated as blocklists.
  - Lines prefixed with "WHITELIST " are treated as whitelists;
    all extracted domains are added to whitelist.txt instead.

  Example:
    https://example.com/ads.txt
    WHITELIST https://raw.githubusercontent.com/cedwards4038/pihole-whitelist/main/whitelist.txt
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

# ABP whitelist rule: @@||example.com^
RE_ABP_WHITELIST = re.compile(
    r"^@@\|\|([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\^(\$.*)?$"
)

# Hosts-file line:	0.0.0.0 example.com	  or   127.0.0.1 example.com
RE_HOSTS = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\s*(?:#.*)?$"
)

# Bare domain on its own line
RE_PLAIN_DOMAIN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\s*(?:#.*)?$"
)

# Lines we should skip outright (before trying domain extraction)
RE_SKIP = re.compile(
    r"^(?:"
    r"!|"  # ABP comment
    r"\[|"  # ABP header  e.g. [Adblock Plus …]
    r"#"   # Hosts-file comment
    r")"
)

# Element hiding / CSS rules  (skip)
RE_ELEMENT_HIDING = re.compile(r"##|#\?#|#@#|#!#")

SOURCES_FILE = Path(__file__).parent / "sources.txt"
OUTPUT_FILE = Path(__file__).parent / "blocklist.txt"
WHITELIST_FILE = Path(__file__).parent / "whitelist.txt"

# ABP options that are 100% safe to ignore because they don't restrict
# the scope of the rule. If a rule has ANY option not in this list, 
# we reject it to be completely safe for Pi-hole.
ALLOWED_ABP_OPTIONS = {
    "important",
    "empty",
}

def extract_domain(line: str) -> tuple[str, str, str] | None:
    """Try to extract a blockable domain from a single line.

	Returns a tuple of (action, format_string, base_domain) or None.
    Actions are 'block' or 'white'.
	"""
    line = line.strip()
    if not line:
        return None

    # Skip comments, headers
    if RE_SKIP.match(line):
        return None

    # Skip element-hiding / CSS rules
    if RE_ELEMENT_HIDING.search(line):
        return None

    # 1. ABP whitelist rule @@||domain.tld^
    m = RE_ABP_WHITELIST.match(line)
    if m:
        options = m.group(5)
        if options:
            option_string = options.lstrip("$")
            if option_string:
                option_list = option_string.split(",")
                for opt in option_list:
                    if not opt or opt.lower() not in ALLOWED_ABP_OPTIONS:
                        return None
        return "white", "{}", m.group(1).lower()

    # 2. ABP domain-only rule  ||domain.tld^
    m = RE_ABP_DOMAIN.match(line)
    if m:
        options = m.group(5)  # e.g. "$third-party,~script" or None
        if options:
            option_string = options.lstrip("$")
            if option_string:
                option_list = option_string.split(",")
                # Strict whitelist approach: if it has any option not explicitly allowed, reject it.
                for opt in option_list:
                    if not opt or opt.lower() not in ALLOWED_ABP_OPTIONS:
                        return None
        return "block", "||{}^", m.group(1).lower()

    # 3. Hosts-file format
    m = RE_HOSTS.match(line)
    if m:
        return "block", "{}", m.group(1).lower()

    # 4. Plain domain
    m = RE_PLAIN_DOMAIN.match(line)
    if m:
        return "block", "{}", m.group(1).lower()

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

    sources: list[tuple[str, bool]] = []  # (url, is_whitelist)
    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("WHITELIST "):
            sources.append((line[len("WHITELIST "):].strip(), True))
        else:
            sources.append((line, False))

    if not sources:
        print("No URLs found in sources.txt.")
        sys.exit(1)

    block_records: dict[str, str] = {}
    white_domains: set[str] = set()
    stats: dict[str, int] = {}

    for i, (url, force_whitelist) in enumerate(sources, 1):
        label = "WHITELIST" if force_whitelist else "blocklist"
        print(f"[{i}/{len(sources)}] Downloading {url} ({label}) ...")
        lines = download_list(url)

        # Track domains unique to this specific source file to avoid
        # overcounting if a source file duplicates a domain internally.
        source_extracted_count = 0
        seen_in_source: set[str] = set()

        for raw_line in lines:
            result = extract_domain(raw_line)
            if not result:
                continue

            action, format_string, domain = result
            
            if domain not in seen_in_source:
                seen_in_source.add(domain)
                source_extracted_count += 1

            if force_whitelist or action == "white":
                white_domains.add(domain)
            elif action == "block":
                # Prefer ABP format (||domain^) over plain format if already recorded
                existing = block_records.get(domain)
                if existing is None or (format_string == "||{}^" and not existing.startswith("||")):
                    block_records[domain] = format_string.format(domain)

        stats[url] = source_extracted_count
        print(f"  [OK] Extracted {source_extracted_count} domains from {len(lines)} lines")

    # Scrub whitelist from block records
    for w in white_domains:
        block_records.pop(w, None)

    # Write blocklist output
    sorted_blocks = [block_records[d] for d in sorted(block_records)]
    OUTPUT_FILE.write_text(
        "\n".join(sorted_blocks) + ("\n" if sorted_blocks else ""),
        encoding="utf-8",
    )

    # Write whitelist output
    sorted_whites = sorted(white_domains)
    WHITELIST_FILE.write_text(
        "\n".join(sorted_whites) + ("\n" if sorted_whites else ""),
        encoding="utf-8",
    )

    # Summary
    print()
    print("=" * 60)
    print(f"Total unique block domains: {len(sorted_blocks)}")
    print(f"Total unique white domains: {len(sorted_whites)}")
    print(f"Output written to:	  {OUTPUT_FILE}")
    print(f"Output written to:	  {WHITELIST_FILE}")
    print("=" * 60)
    print()
    print("Per-source breakdown (pre-whitelist scrub):")
    for url, count in stats.items():
        name = url.rsplit("/", 1)[-1]
        print(f"  {name:<40s} {count:>6,} domains")


if __name__ == "__main__":
    main()
    