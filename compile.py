"""
BlocklistCompiler - compile.py

Downloads block/allow lists from sources.txt and extracts Pi-hole
compatible rules into blocklist.txt and whitelist.txt.

Rule semantics
--------------
A rule has an *action* (block or allow), a *domain*, and a *scope*:

  exact block   bare domain            e.g.  example.com
  suffix block  ABP domain anchor      e.g.  ||example.com^
  exact allow   bare domain            e.g.  example.com
  suffix allow  ABP exception anchor   e.g.  @@||example.com^

Extraction rules:
  1. ABP domain rules, with NO options and NO path:
       ||domain.tld^      -> suffix block
       @@||domain.tld^    -> suffix allow
     Every option-bearing form ($important, $empty, $, $$, $third-party,
     ...) is rejected, as are paths and wildcards.
  2. Hosts-file lines:
       0.0.0.0 domain.tld
       127.0.0.1 domain.tld
       ::1 domain.tld
       0.0.0.0 a.tld b.tld c.tld      (multiple aliases)
     A valid IP prefix is required before more than one hostname is
     accepted; plain prose is never tokenised into hostname fragments.
  3. Plain domain lines: domain.tld
     Exact block.

sources.txt format:
  - Plain URL lines are treated as blocklists.
  - Lines prefixed with "WHITELIST " are treated as allow lists; every
    extracted rule becomes an allow rule (bare -> exact allow,
    ||domain^ and @@||domain^ -> @@||domain^).

Outputs are intentionally NOT cross-scrubbed: blocklist.txt may contain a
rule whose domain also appears in whitelist.txt. Pi-hole resolves the
priority between block and allow rules itself.

Failure behaviour
-----------------
A download either succeeds (returning its lines, possibly empty) or
raises DownloadError. An empty source is a successful download and only
warns. If ANY source fails, compilation aborts with exit code 1 *before*
either output is touched, so the previously published files are retained
byte-for-byte. An empty final block list is also fatal. Both outputs are
staged in sibling temp files and swapped in with os.replace per file.
This is deliberately not a two-file transaction: a replacement failure
can leave blocklist.txt updated while whitelist.txt is not, but the
process exits non-zero so the CI publish step never runs.
"""

import http.client
import ipaddress
import os
import re
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Record model
# ---------------------------------------------------------------------------


class Record(NamedTuple):
    """A single extracted rule before rendering.

    action: "block" or "allow"
    domain: normalised lowercase domain
    suffix: True for a suffix rule (||domain^ / @@||domain^),
            False for an exact bare domain.
    """

    action: str
    domain: str
    suffix: bool


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

# A single DNS label: alphanumeric/underscore at the edges, hyphen allowed
# internally. Underscore labels such as _dmarc are accepted.
RE_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# TLD: alphabetic (>=2 chars) or ASCII punycode (xn--...). Numeric-only
# TLDs and mixed alphanumeric TLDs are rejected.
RE_TLD = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$")

# Element hiding / cosmetic markers: '#' immediately followed by one of
# # $ @ ? % !. Checked BEFORE inline comment stripping.
RE_COSMETIC_MARKER = re.compile(r"#[#\$@\?%!]")

# Domain characters that are never valid and that would otherwise be left
# over from rejected ABP syntax (paths, options, wildcards, anchors).
RE_INVALID_DOMAIN_CHARS = re.compile(r"[/:*|^$\s]")

# Maximum length of the normalised presentation name. Pi-hole's parser
# tolerates 255; we deliberately enforce the safer DNS limit of 253.
MAX_DOMAIN_LENGTH = 253

SOURCES_FILE = Path(__file__).parent / "sources.txt"
OUTPUT_FILE = Path(__file__).parent / "blocklist.txt"
WHITELIST_FILE = Path(__file__).parent / "whitelist.txt"

# Network and I/O policy.
DOWNLOAD_TIMEOUT_SECONDS = 30
# Explicit ceiling on a single response body (100 MiB) so a hostile or
# broken server cannot exhaust memory. Reads request MAX_RESPONSE_BYTES + 1
# so that a body exactly at the limit is accepted and one byte over is not.
MAX_RESPONSE_BYTES = 100 * 1024 * 1024
USER_AGENT = "BlocklistCompiler/1.0"


class DownloadError(Exception):
    """A source could not be downloaded; the pipeline must not publish."""


def normalize_domain(candidate: str) -> str | None:
    """Validate and normalise a candidate domain.

    Returns the lowercase domain, or None if it is not an acceptable
    exact/suffix target. A single trailing dot is normalised away;
    repeated trailing dots are rejected.
    """
    if not candidate:
        return None

    domain = candidate.lower()

    if domain.endswith("."):
        domain = domain[:-1]
        if domain.endswith("."):
            return None

    if not domain or domain.startswith("."):
        return None

    if RE_INVALID_DOMAIN_CHARS.search(domain):
        return None

    # No raw IP targets.
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return None

    labels = domain.split(".")
    # Require a dotted, multi-label name; never block a whole single-label
    # TLD such as "com".
    if len(labels) < 2:
        return None

    for label in labels:
        if not RE_LABEL.match(label):
            return None

    if not RE_TLD.match(labels[-1]):
        return None

    if len(domain) > MAX_DOMAIN_LENGTH:
        return None

    return domain


def _is_ip(token: str) -> bool:
    """True if token is a valid IPv4/IPv6 address (brackets optional)."""
    try:
        ipaddress.ip_address(token.strip("[]"))
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_domains(line: str) -> list[Record]:
    """Extract zero or more Records from one source line."""
    if line.startswith("\ufeff"):
        line = line[1:]

    stripped = line.strip()
    if not stripped:
        return []

    # ABP comments / hosts comments / bracketed ABP headers.
    if stripped[0] == "!":
        return []
    if stripped.startswith("[") and stripped.endswith("]"):
        return []

    # Cosmetic markers must be rejected before inline-comment stripping.
    if RE_COSMETIC_MARKER.search(stripped):
        return []

    # Strip an inline '#' comment only after the cosmetic check.
    content = stripped.split("#", 1)[0].strip()
    if not content:
        return []

    if content.startswith("@@") or content.startswith("||"):
        return _extract_abp(content)

    return _extract_hosts_or_plain(content)


def _extract_abp(content: str) -> list[Record]:
    """Parse an ABP domain-anchored rule, rejecting all options/paths."""
    if content.startswith("@@"):
        body = content[2:]
        action = "allow"
    else:
        body = content
        action = "block"

    if not body.startswith("||"):
        return []

    host = body[2:]

    # The domain must be terminated by '^' with nothing after it. Any
    # trailing text means options ($important, $, $$, ...) or a path.
    if "^" not in host:
        return []

    domain_part, _, trailing = host.partition("^")
    if trailing:
        return []

    domain = normalize_domain(domain_part)
    if domain is None:
        return []

    return [Record(action, domain, suffix=True)]


def _extract_hosts_or_plain(content: str) -> list[Record]:
    """Parse a hosts-file line or a single plain domain line."""
    tokens = content.split()
    if not tokens:
        return []

    if _is_ip(tokens[0]):
        # Hosts line: IP prefix followed by one or more aliases.
        records: list[Record] = []
        for token in tokens[1:]:
            if _is_ip(token):
                continue  # never emit a raw IP as a target
            domain = normalize_domain(token)
            if domain is None:
                continue
            records.append(Record("block", domain, suffix=False))
        return records

    # Not a hosts line: only a single bare domain is accepted. Anything
    # with multiple tokens is prose/browser-rule text, not a target list.
    if len(tokens) != 1:
        return []

    domain = normalize_domain(tokens[0])
    if domain is None:
        return []

    return [Record("block", domain, suffix=False)]


def render_rule(action: str, domain: str, suffix: bool) -> str:
    """Render a (action, domain, suffix) triple as an output line."""
    if action == "allow":
        return f"@@||{domain}^" if suffix else domain
    return f"||{domain}^" if suffix else domain


# ---------------------------------------------------------------------------
# Pure compilation
# ---------------------------------------------------------------------------


class RuleAggregator:
    """Accumulate extracted rules into block/allow collections.

    A source's lines are parsed exactly once by :meth:`add`. The same
    helper backs both :func:`compile_lines` (pure, offline test API) and
    the network pipeline in :func:`run`, so extraction never happens
    twice over a downloaded body.
    """

    def __init__(self) -> None:
        self._blocks: dict[str, bool] = {}
        self._allows: dict[str, bool] = {}

    def add(self, lines: list[str], force_whitelist: bool) -> int:
        """Extract one source's lines; return the unique-domain count."""
        seen: set[str] = set()
        for line in lines:
            for item in extract_domains(line):
                seen.add(item.domain)
                action = "allow" if force_whitelist else item.action
                target = self._allows if action == "allow" else self._blocks
                previous = target.get(item.domain)
                # Keep suffix scope if either occurrence is a suffix.
                if previous is None or (item.suffix and not previous):
                    target[item.domain] = item.suffix
        return len(seen)

    def outputs(self) -> tuple[list[str], list[str]]:
        block_out = [render_rule("block", d, self._blocks[d]) for d in sorted(self._blocks)]
        allow_out = [render_rule("allow", d, self._allows[d]) for d in sorted(self._allows)]
        return block_out, allow_out


def compile_lines(
    sources: list[tuple[list[str], bool]],
) -> tuple[list[str], list[str]]:
    """Compile raw source lines into (blocklist, whitelist) output lines.

    Pure and offline. ``sources`` is a list of ``(lines, force_whitelist)``.
    Duplicate rules are removed; within a single action a suffix rule
    subsumes an exact rule for the same domain. Block and allow rules are
    kept in separate collections and never scrub each other.
    """
    aggregator = RuleAggregator()
    for lines, force_whitelist in sources:
        aggregator.add(lines, force_whitelist)
    return aggregator.outputs()


# ---------------------------------------------------------------------------
# I/O and pipeline
# ---------------------------------------------------------------------------


def parse_sources_text(text: str) -> list[tuple[str, bool]]:
    """Parse sources.txt content into (url, force_whitelist) entries."""
    sources: list[tuple[str, bool]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("WHITELIST "):
            sources.append((line[len("WHITELIST "):].strip(), True))
        else:
            sources.append((line, False))
    return sources


def _declared_length(headers, max_bytes: int, url: str, log) -> int | None:
    """Return a trustworthy Content-Length, or None.

    An advertised size above ``max_bytes`` is rejected before any body is
    read. Invalid or negative values are ignored with a warning; the
    actual-body cap still applies to whatever is read.
    """
    advertised = headers.get("Content-Length")
    if advertised is None:
        return None
    try:
        declared = int(advertised)
    except (TypeError, ValueError):
        log(f"  [WARN] Invalid Content-Length {advertised!r}; ignoring")
        return None
    if declared < 0:
        log(f"  [WARN] Negative Content-Length {declared}; ignoring")
        return None
    if declared > max_bytes:
        raise DownloadError(
            f"advertised size {declared} bytes exceeds {max_bytes} bytes ({url})"
        )
    return declared


def download_list(
    url: str,
    *,
    timeout: int = DOWNLOAD_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    log=print,
) -> list[str]:
    """Download a list and return its lines.

    Raises :class:`DownloadError` on any handled failure (URL/HTTP error,
    timeout, truncated response, malformed URL, or an advertised body over
    the limit). A successful response with an empty body returns ``[]`` and
    is NOT a failure.

    TLS certificate verification is left at urllib's default (enabled); no
    custom SSL context is passed. At most ``max_bytes`` are accepted and the
    body is read with an explicit bound so it is never read unbounded. A
    bounded ``HTTPResponse.read(n)`` can silently return fewer bytes than an
    advertised Content-Length, so the header is validated before reading and
    the received length is checked against it afterwards.
    """
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Chunked transfer-encoding makes Content-Length advisory and
            # http.client ignores it; applying it could flag false truncation.
            if getattr(response, "chunked", False):
                declared = None
            else:
                declared = _declared_length(response.headers, max_bytes, url, log)

            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise DownloadError(
                    f"response exceeds {max_bytes} bytes ({url})"
                )
            # Bounded read(n) silently under-returns on a short body, unlike
            # unbounded read() which raises IncompleteRead; check explicitly.
            if declared is not None and len(data) < declared:
                raise DownloadError(
                    f"truncated response: got {len(data)} of {declared} bytes ({url})"
                )

            charset = response.headers.get_content_charset() or "utf-8"
            try:
                text = data.decode(charset, errors="replace")
            except LookupError:
                log(f"  [WARN] Unknown charset {charset!r}; falling back to UTF-8")
                text = data.decode("utf-8", errors="replace")
            return text.splitlines()
    except DownloadError:
        raise
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        ValueError,
        LookupError,
        OSError,
    ) as exc:
        raise DownloadError(f"{url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Atomic-ish output writing
# ---------------------------------------------------------------------------


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _stage_file(target: Path, text: str) -> Path:
    """Write ``text`` to a closed sibling temp file and return its path.

    The temp file lives in the target's directory so os.replace() is a
    same-filesystem rename. The descriptor ownership is transferred to the
    file handle on success; if os.fdopen() itself fails the descriptor is
    closed explicitly. On any failure the temp file is removed.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=target.name + ".",
        suffix=".tmp",
    )
    tmp = Path(tmp_name)
    try:
        try:
            handle = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(fd)
            raise
        # Ownership of fd now belongs to handle; the with-block closes it.
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        _remove(tmp)
        raise

    # Best-effort permission preservation; not required for correctness.
    try:
        os.chmod(tmp, target.stat().st_mode)
    except OSError:
        pass
    return tmp


def write_outputs(
    output_file: Path,
    whitelist_file: Path,
    block_text: str,
    allow_text: str,
) -> None:
    """Stage both outputs, then swap them in with one os.replace each.

    Both temp files are staged (written, closed, fsynced) before any
    replacement. The ``finally`` removes either temp path for ANY exception
    (not just OSError), so staging/replacement failures leave no litter and
    neither original is touched while staging. If a replacement fails, the
    process must exit non-zero so the GitHub publish step does not run; the
    first os.replace may already have committed, so this is not a two-file
    transaction.
    """
    block_tmp: Path | None = None
    whitelist_tmp: Path | None = None
    try:
        block_tmp = _stage_file(output_file, block_text)
        whitelist_tmp = _stage_file(whitelist_file, allow_text)
        os.replace(block_tmp, output_file)
        block_tmp = None
        os.replace(whitelist_tmp, whitelist_file)
        whitelist_tmp = None
    finally:
        for tmp in (block_tmp, whitelist_tmp):
            if tmp is not None:
                _remove(tmp)


def run(
    sources_file: Path = SOURCES_FILE,
    output_file: Path = OUTPUT_FILE,
    whitelist_file: Path = WHITELIST_FILE,
    *,
    download=download_list,
    log=print,
) -> tuple[list[str], list[str]]:
    """Download, compile, and write both outputs.

    Exits with code 1 (via SystemExit) on any fatal error: a missing or
    empty sources file, any failed download, an empty final block list, or
    an output write failure. In every fatal case the existing outputs are
    left untouched (except a documented partial os.replace failure).
    """
    if not sources_file.exists():
        log(f"Error: {sources_file} not found.")
        sys.exit(1)

    try:
        sources_text = sources_file.read_text(encoding="utf-8")
    except OSError as exc:
        log(f"Error: could not read {sources_file}: {exc}")
        sys.exit(1)

    sources = parse_sources_text(sources_text)
    if not sources:
        log("Error: No URLs found in sources.txt.")
        sys.exit(1)

    aggregator = RuleAggregator()
    stats: dict[str, tuple[int, int]] = {}
    failures: list[tuple[str, str]] = []

    for i, (url, force_whitelist) in enumerate(sources, 1):
        label = "WHITELIST" if force_whitelist else "blocklist"
        log(f"[{i}/{len(sources)}] Downloading {url} ({label}) ...")
        try:
            lines = download(url)
        except DownloadError as exc:
            failures.append((url, str(exc)))
            log(f"  [FAIL] {exc}")
            continue

        # Single extraction pass: count unique domains and aggregate rules.
        count = aggregator.add(lines, force_whitelist)
        stats[url] = (count, len(lines))
        if not lines:
            log("  [WARN] Source is empty (0 lines); continuing")
        elif count == 0:
            # A real, non-empty source whose content is entirely unsupported
            # is not a download failure; warn so it is not confused with an
            # empty/failed fetch.
            log(f"  [WARN] No supported rules found in {len(lines)} lines; continuing")
        else:
            log(f"  [OK] Extracted {count} domains from {len(lines)} lines")

    if failures:
        log("")
        log(f"Error: {len(failures)} source(s) failed to download:")
        for url, message in failures:
            log(f"  - {message}")
        log("Aborting before writing outputs; existing files were NOT replaced.")
        sys.exit(1)

    block_out, allow_out = aggregator.outputs()

    if not block_out:
        log("Error: compilation produced no block rules; refusing to publish an empty blocklist.")
        sys.exit(1)

    block_text = "\n".join(block_out) + "\n"
    allow_text = "\n".join(allow_out) + ("\n" if allow_out else "")

    try:
        write_outputs(output_file, whitelist_file, block_text, allow_text)
    except OSError as exc:
        log(f"Error: failed to write output files: {exc}")
        log("Existing output files may have been left unchanged or partially updated.")
        sys.exit(1)

    log("")
    log("=" * 60)
    log(f"Total unique block rules: {len(block_out)}")
    log(f"Total unique allow rules: {len(allow_out)}")
    log(f"Output written to:        {output_file}")
    log(f"Output written to:        {whitelist_file}")
    log("=" * 60)
    log("")
    log("Per-source breakdown (unique domains extracted):")
    for url, (count, line_count) in stats.items():
        name = url.rsplit("/", 1)[-1]
        log(f"  {name:<40s} {count:>6,} domains ({line_count} lines)")

    return block_out, allow_out


def main() -> None:
    run()


if __name__ == "__main__":
    main()
