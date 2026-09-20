# BlocklistCompiler

Downloads the lists referenced in [`sources.txt`](sources.txt), extracts
Pi-hole compatible domain rules, and writes two deterministic outputs:

- [`blocklist.txt`](blocklist.txt) - domains/rules to **block**
- [`whitelist.txt`](whitelist.txt) - domains/rules to **allow**

The compiler is a single stdlib-only Python script (`compile.py`) and runs
on Python 3.12+.

## Pi-hole setup: subscribe to BOTH files

Add **both** output files as lists in Pi-hole:

| File             | Pi-hole list type | Purpose                        |
| ---------------- | ----------------- | ------------------------------ |
| `blocklist.txt`  | block / adlist    | rules to block                 |
| `whitelist.txt`  | **allow** (whitelist) | rules to allow, overriding blocks |

> Subscribe to `whitelist.txt` with the **allow** type. If the allow list
> is added with the wrong type it will block domains instead of permitting
> them.

Point each subscription at the raw file URL, for example:

```
https://raw.githubusercontent.com/<owner>/<repo>/main/blocklist.txt
https://raw.githubusercontent.com/<owner>/<repo>/main/whitelist.txt
```

## Rule semantics

A rule has three parts: an **action**, a **domain**, and a **scope**.

| Output form      | Action | Scope  | Meaning                                              |
| ---------------- | ------ | ------ | ---------------------------------------------------- |
| `example.com`    | block  | exact  | block exactly `example.com`                          |
| `\|\|example.com^` | block | suffix | block `example.com` and all of its subdomains        |
| `example.com`    | allow  | exact  | allow exactly `example.com` (same spelling as block) |
| `@@\|\|example.com^` | allow | suffix | allow `example.com` and all of its subdomains    |

The action of an output line depends on which file it is written to. A bare
domain in `whitelist.txt` is an exact allow; in `blocklist.txt` it is an
exact block.

### No cross-scrubbing

Block and allow rules are kept in **separate collections**. The compiler
does **not** remove a block rule just because the same domain appears in
the allow list, and vice versa. `blocklist.txt` and `whitelist.txt` may
therefore contain overlapping domains. Pi-hole resolves the priority
between block and allow rules at query time. The compiler preserves the
scope of supported rules; unsupported browser-filter rules are dropped.

### Deduplication

Within a single action, duplicate rules are removed and a suffix rule
subsumes an exact rule for the same domain:

- block `example.com` + block `||example.com^` -> `||example.com^`
- allow `example.com` + allow `@@||example.com^` -> `@@||example.com^`

An allow rule never subsumes a block rule (or vice versa); the subsumption
is **per action only**.

## `sources.txt` format

```
https://example.com/ads.txt
WHITELIST https://example.com/allow.txt
```

- A plain URL is a **blocklist** source.
- A line prefixed with `WHITELIST ` is an **allow-list** source. Every
  rule extracted from it becomes an allow rule:
  - bare `example.com` -> exact allow `example.com`
  - `||example.com^` and `@@||example.com^` -> suffix allow `@@||example.com^`
- Blank lines and lines starting with `#` are ignored.

## Supported input forms

1. **ABP domain rules** (no options, no path):
   - `||example.com^` -> suffix block
   - `@@||example.com^` -> suffix allow
2. **Hosts-file lines** with a valid IPv4 or IPv6 prefix:
   - `0.0.0.0 example.com`
   - `127.0.0.1 example.com`
   - `::1 example.com`
   - `0.0.0.0 a.example.com b.example.net c.example.org` (multiple aliases)
3. **Plain domain lines**: `example.com` -> exact block.
4. **Inline `#` comments**: `0.0.0.0 example.com # ad server`.
5. A leading UTF-8 BOM on the first line is ignored.

## Rejected input forms

- **Every option-bearing ABP rule**: `$important`, `$empty`, `$`, `$$`,
  `$third-party`, `$domain=...`, `$csp=...`, etc. Options can narrow a
  rule's scope, which Pi-hole cannot represent, so the whole rule is
  dropped.
- **Paths and wildcards**: `||example.com/ads/*`, `||example.com/*`,
  `||example.com^/path`.
- **ABP rules without a `^` terminator**: `||example.com`.
- **Exception/other rules with options**: `@@||example.com^$important`.
- **Cosmetic / element-hiding rules**: any `#` immediately followed by
  `#`, `$`, `@`, `?`, `%`, or `!` (checked before comment stripping), e.g.
  `example.com##.ad`, `example.com#@#.ad`, `example.com#?#.ad`.
- **ABP comments and headers**: `! comment`, `[Adblock Plus 2.0]`.
- **Raw IP targets**: `0.0.0.0 1.2.3.4`, or a bare `1.2.3.4`.
- **Prose / multi-token lines without an IP prefix**: only a genuine
  hosts line (valid IP prefix) may carry more than one hostname. A line
  like `example.com foo.com` is not tokenised into two targets.

## Validation and normalisation

The compiler applies narrow, conservative validation so that only entries
Pi-hole can faithfully represent are emitted:

- Domains are lowercased; `www.` and `m.` prefixes are **preserved**
  (no subdomain stripping).
- One trailing dot is normalised away (`example.com.` -> `example.com`);
  repeated trailing dots are rejected.
- A dotted, multi-label name is required. Single-label names such as
  `com` or `localhost` are rejected, so a whole TLD is never blocked.
- Each label must be 1-63 characters, alphanumeric/underscore at the
  edges with internal hyphens allowed. Underscore labels (`_dmarc`) are
  accepted.
- The TLD must be alphabetic (`com`, `info`, ...) or ASCII punycode
  (`xn--p1ai`). **Numeric-only TLDs (`example.123`) are rejected.**
- The normalised presentation name must be at most **253 characters**.
  Pi-hole's parser tolerates 255 characters; the stricter 253 limit is a
  deliberate safety margin.

The numeric-TLD rejection and the 253-character limit are intentional and
stricter than Pi-hole's parser in order to stay within safe DNS limits.

## Reliability, failure behaviour and exit codes

Downloads are explicit about success: a source either returns its lines
(possibly an empty list) or raises a download error.

- **An empty source is not a failure.** If a server returns an empty body,
  the compiler logs `[WARN] Source is empty (0 lines); continuing` and
  keeps going. Only a genuine fetch error is a failure.
- **A non-empty source with no supported rules warns, but is not fatal.**
  If a source has lines but none of them yield a supported rule (for
  example a source that is entirely comments or option-bearing ABP rules),
  the compiler logs `[WARN] No supported rules found in N lines; continuing`
  and does not report `[OK]` for it. This distinguishes an all-unsupported
  source from an empty or failed fetch. The run is only fatal if the final
  block list is empty.
- **Any failed source is fatal.** If any block *or* `WHITELIST` source
  fails (URL/HTTP error, timeout, truncated response, malformed URL), the
  compiler reports every failure, aborts with exit code 1, and **does not
  touch either output file**. The previously published `blocklist.txt` and
  `whitelist.txt` are retained byte-for-byte. The same applies to a missing
  or unparseable `sources.txt` with no URLs.
- **An empty final block list is fatal.** If compilation yields zero block
  rules, the compiler aborts with exit code 1 rather than publishing an
  empty blocklist.
- **Writes are staged, not a two-file transaction.** Both output strings
  are prepared and written to sibling `*.tmp` files (flushed and fsynced)
  before any replacement. If staging fails, the temp files are removed and
  neither original is touched. Each output is then swapped in with a single
  `os.replace`. A replacement failure exits non-zero so the CI publish step
  never runs, but because the two files swap independently a failure
  between them can leave `blocklist.txt` updated while `whitelist.txt` is
  not. This is deliberate; no cross-file backup/rollback is attempted.
- **Exit codes:** `0` on success; `1` on a missing/empty `sources.txt`, any
  failed download, an empty final block list, or an output write failure.
- **Network policy:** a 30 second timeout per source, no retries, no
  caching. HTTPS certificate verification uses Python's default verifying
  context and is never disabled.
- **Response size limit:** each response body is capped at **100 MiB**
  (`MAX_RESPONSE_BYTES`). An advertised `Content-Length` larger than the
  limit is rejected **before** any body is read. The body is then read with
  an explicit bound (`limit + 1` bytes), so a response at the limit is
  accepted and one byte over is rejected; bodies are never read unbounded.
  The cap applies regardless of the header.
- **Truncation is detected.** A bounded `HTTPResponse.read(n)` can silently
  return fewer bytes than an advertised `Content-Length` (unlike an
  unbounded read, which raises `IncompleteRead`), so the received length is
  checked against the header and a short body raises a download error. A
  truncated chunked response is caught via stdlib `IncompleteRead`. For
  chunked responses `Content-Length` is ignored (as `http.client` does), so
  a stale value cannot be mistaken for truncation. An invalid or negative
  `Content-Length` is ignored with a warning rather than trusted.
- **Charset detection is best-effort.** The `Content-Type` charset is used
  when present; undecodable bytes are replaced. An unknown/invalid charset
  logs a warning and falls back to UTF-8.

## Known limitations

- **Some lists are inherently lossy for Pi-hole.** Rules with options,
  paths, or wildcards cannot be expressed as Pi-hole domains and are
  dropped rather than approximated.
- **No cross-scrubbing** means `blocklist.txt` and `whitelist.txt` may
  contain the same domain. This is intentional; see above.
- **Output is regenerated wholesale.** On success the compiler replaces
  both output files; see the staging note above for the one
  non-transactional edge case.

## Development

Run the offline test suite (no network access; all downloads are mocked and
temporary paths are used). CI runs this before compiling:

```
python -B -m unittest -v test_compile
```

The tests cover extraction, validation, scope-preserving deduplication,
the "allow does not delete block" guarantees, download success/failure and
response limits (including real `http.client.HTTPResponse` fixtures proving
Content-Length truncation, pre-read oversize rejection, and chunked
`IncompleteRead` are handled), charset fallback, TLS verification not being
overridden, fatal-abort/preserve-existing-output behaviour, the
zero-supported-rules warning, and output staging/`os.replace` cleanup
(including descriptor closure and cleanup on any exception).
