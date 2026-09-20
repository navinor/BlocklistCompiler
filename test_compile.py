"""Regression tests for compile.py.

Run with:
    python -B -m unittest -v test_compile.py

All tests are offline: network calls are mocked and the integration tests
inject a fake ``download`` callable and use temporary paths.
"""

import http.client
import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from compile import (
    MAX_RESPONSE_BYTES,
    DownloadError,
    Record,
    compile_lines,
    download_list,
    extract_domains,
    run,
    write_outputs,
)


def rec(action: str, domain: str, suffix: bool) -> Record:
    return Record(action, domain, suffix)


class TestExtractDomains(unittest.TestCase):
    # -- plain / exact block ------------------------------------------------
    def test_plain_domain_is_exact_block(self):
        self.assertEqual(extract_domains("example.com"), [rec("block", "example.com", False)])
        self.assertEqual(
            extract_domains("sub.example.com"),
            [rec("block", "sub.example.com", False)],
        )

    def test_plain_domain_requires_a_dot(self):
        self.assertEqual(extract_domains("com"), [])
        self.assertEqual(extract_domains("localhost"), [])

    def test_www_and_m_are_preserved(self):
        self.assertEqual(
            extract_domains("www.example.com"),
            [rec("block", "www.example.com", False)],
        )
        self.assertEqual(
            extract_domains("m.example.com"),
            [rec("block", "m.example.com", False)],
        )

    def test_case_normalization_lowercases(self):
        self.assertEqual(
            extract_domains("WWW.Example.COM"),
            [rec("block", "www.example.com", False)],
        )

    # -- hosts files --------------------------------------------------------
    def test_hosts_format_ipv4(self):
        self.assertEqual(
            extract_domains("0.0.0.0 example.com"),
            [rec("block", "example.com", False)],
        )
        self.assertEqual(
            extract_domains("127.0.0.1 sub.example.com"),
            [rec("block", "sub.example.com", False)],
        )

    def test_hosts_format_ipv6(self):
        self.assertEqual(
            extract_domains("::1 example.com"),
            [rec("block", "example.com", False)],
        )
        self.assertEqual(
            extract_domains("fe80::1 sub.example.com"),
            [rec("block", "sub.example.com", False)],
        )
        self.assertEqual(
            extract_domains("[::1] example.com"),
            [rec("block", "example.com", False)],
        )

    def test_hosts_multiple_aliases(self):
        self.assertEqual(
            extract_domains("0.0.0.0 example.com foo.com bar.example.net"),
            [
                rec("block", "example.com", False),
                rec("block", "foo.com", False),
                rec("block", "bar.example.net", False),
            ],
        )

    def test_hosts_raw_ip_target_rejected(self):
        self.assertEqual(extract_domains("0.0.0.0 1.2.3.4"), [])
        self.assertEqual(extract_domains("1.2.3.4"), [])
        self.assertEqual(extract_domains("0.0.0.0 1.2.3.4 good.com"), [rec("block", "good.com", False)])

    def test_multi_token_prose_is_not_tokenized(self):
        # Only hosts lines (valid IP prefix) may carry more than one token.
        self.assertEqual(extract_domains("example.com foo.com"), [])
        self.assertEqual(extract_domains("some prose here.com"), [])

    # -- ABP ---------------------------------------------------------------
    def test_abp_block_suffix_scope(self):
        self.assertEqual(extract_domains("||example.com^"), [rec("block", "example.com", True)])
        self.assertEqual(
            extract_domains("||sub.example.com^"),
            [rec("block", "sub.example.com", True)],
        )
        self.assertEqual(
            extract_domains("||EXAMPLE.COM^"),
            [rec("block", "example.com", True)],
        )

    def test_abp_allow_suffix_scope(self):
        self.assertEqual(extract_domains("@@||example.com^"), [rec("allow", "example.com", True)])
        self.assertEqual(
            extract_domains("@@||sub.example.com^"),
            [rec("allow", "sub.example.com", True)],
        )

    def test_abp_option_bearing_rules_rejected(self):
        for line in [
            "||example.com^$important",
            "||example.com^$empty",
            "||example.com^$",
            "||example.com^$$",
            "||example.com^$third-party",
            "||example.com^$domain=nontonx.com",
            "||example.com^$domain=~foo.com",
            "||example.com^$script,important",
            "||example.com^$~script",
            "||example.com^$csp=...",
            "||example.com^$match-case",
            "@@||example.com^$important",
            "@@||example.com^$empty",
            "@@||example.com^$empty,domain=foo.com",
            "@@||example.com^$",
        ]:
            with self.subTest(line=line):
                self.assertEqual(extract_domains(line), [])

    def test_abp_paths_and_wildcards_rejected(self):
        for line in [
            "||example.com/ads/*",
            "||example.com/banner.gif",
            "||example.com/*",
            "||example.com^/path",
            "||*.example.com^",
            "||example.com/bookracy/static/main/ads/$domain=bookracy.ru",
        ]:
            with self.subTest(line=line):
                self.assertEqual(extract_domains(line), [])

    def test_abp_requires_terminator(self):
        self.assertEqual(extract_domains("||example.com"), [])
        self.assertEqual(extract_domains("||example.com^extra"), [])

    # -- cosmetic / comments ------------------------------------------------
    def test_cosmetic_markers_rejected(self):
        for line in [
            "example.com##.ad",
            "example.com#@#.ad",
            "example.com#?#.ad",
            "example.com#$#.ad",
            "example.com#@$#.ad",
            "example.com#@%#scriptlet",
            "example.com#%#.ad",
            "example.com#!#.ad",
        ]:
            with self.subTest(line=line):
                self.assertEqual(extract_domains(line), [])

    def test_inline_hash_comments_preserved(self):
        self.assertEqual(
            extract_domains("0.0.0.0 example.com # ad server"),
            [rec("block", "example.com", False)],
        )
        self.assertEqual(
            extract_domains("127.0.0.1 example.com # blocked"),
            [rec("block", "example.com", False)],
        )
        self.assertEqual(
            extract_domains("example.com # tracker"),
            [rec("block", "example.com", False)],
        )

    def test_comment_lines_skipped(self):
        self.assertEqual(extract_domains("! comment"), [])
        self.assertEqual(extract_domains("# comment"), [])
        self.assertEqual(extract_domains("[Adblock Plus 2.0]"), [])

    def test_leading_utf8_bom(self):
        self.assertEqual(
            extract_domains("\ufeff0.0.0.0 bom.example.com"),
            [rec("block", "bom.example.com", False)],
        )

    # -- domain validation --------------------------------------------------
    def test_trailing_dot_normalized_once(self):
        self.assertEqual(
            extract_domains("example.com."),
            [rec("block", "example.com", False)],
        )
        self.assertEqual(extract_domains("example.com.."), [])

    def test_underscores_allowed(self):
        self.assertEqual(
            extract_domains("_dmarc.example.com"),
            [rec("block", "_dmarc.example.com", False)],
        )

    def test_punycode_tld_allowed(self):
        self.assertEqual(
            extract_domains("example.xn--p1ai"),
            [rec("block", "example.xn--p1ai", False)],
        )

    def test_numeric_only_tld_rejected(self):
        self.assertEqual(extract_domains("example.123"), [])
        self.assertEqual(extract_domains("||example.123^"), [])

    def test_label_length_limit(self):
        self.assertEqual(extract_domains(("a" * 64) + ".com"), [])
        self.assertEqual(
            extract_domains(("a" * 63) + ".com"),
            [rec("block", ("a" * 63) + ".com", False)],
        )

    def test_presentation_name_length_limit(self):
        # Build a name of 253 chars using 63-char labels.
        label = "a" * 63
        domain_253 = ".".join([label, label, label, "b" * 57, "com"])
        self.assertEqual(len(domain_253), 253)
        self.assertEqual(extract_domains(domain_253), [rec("block", domain_253, False)])

        domain_254 = ".".join([label, label, label, "b" * 58, "com"])
        self.assertEqual(len(domain_254), 254)
        self.assertEqual(extract_domains(domain_254), [])

    def test_hyphen_placement(self):
        self.assertEqual(extract_domains("a-b.example.com"), [rec("block", "a-b.example.com", False)])
        self.assertEqual(extract_domains("-ab.example.com"), [])
        self.assertEqual(extract_domains("ab-.example.com"), [])


class TestCompileLines(unittest.TestCase):
    def test_child_suffix_exception_survives_parent_block(self):
        blocks, allows = compile_lines(
            [(["||example.com^", "@@||safe.example.com^"], False)]
        )
        self.assertEqual(blocks, ["||example.com^"])
        self.assertEqual(allows, ["@@||safe.example.com^"])

    def test_suffix_subsumes_exact_within_block(self):
        blocks, allows = compile_lines([(["||example.com^"], False), (["example.com"], False)])
        self.assertEqual(blocks, ["||example.com^"])
        self.assertEqual(allows, [])

    def test_suffix_subsumes_exact_within_allow(self):
        blocks, allows = compile_lines([(["@@||example.com^"], False), (["example.com"], True)])
        self.assertEqual(allows, ["@@||example.com^"])
        self.assertEqual(blocks, [])

    def test_exact_allow_does_not_delete_suffix_block(self):
        # The core regression: no compile-time whitelist scrubbing.
        blocks, allows = compile_lines([(["||ads.example.com^"], False), (["ads.example.com"], True)])
        self.assertEqual(blocks, ["||ads.example.com^"])
        self.assertEqual(allows, ["ads.example.com"])

    def test_suffix_whitelist_does_not_narrow_block(self):
        blocks, allows = compile_lines([(["||ads.example.com^"], False), (["||ads.example.com^"], True)])
        self.assertEqual(blocks, ["||ads.example.com^"])
        self.assertEqual(allows, ["@@||ads.example.com^"])

    def test_forced_whitelist_bare_is_exact_allow(self):
        blocks, allows = compile_lines([(["example.com"], True)])
        self.assertEqual(blocks, [])
        self.assertEqual(allows, ["example.com"])

    def test_forced_whitelist_suffixes_become_allow_suffix(self):
        blocks, allows = compile_lines(
            [(["example.com", "||sub.example.com^", "@@||x.example.com^"], True)]
        )
        self.assertEqual(blocks, [])
        self.assertEqual(
            allows,
            ["example.com", "@@||sub.example.com^", "@@||x.example.com^"],
        )

    def test_output_is_deterministic_and_sorted(self):
        blocks, allows = compile_lines(
            [(["z.com", "a.com", "||m.com^"], False), (["b.com"], True)]
        )
        self.assertEqual(blocks, ["a.com", "||m.com^", "z.com"])
        self.assertEqual(allows, ["b.com"])

    def test_duplicate_lines_dedup(self):
        blocks, allows = compile_lines([(["example.com", "example.com"], False)])
        self.assertEqual(blocks, ["example.com"])
        self.assertEqual(allows, [])


class _FakeHeaders:
    """Minimal stand-in for http.client.HTTPMessage."""

    def __init__(self, charset=None, content_length=None):
        self._charset = charset
        self._headers = {}
        if content_length is not None:
            self._headers["content-length"] = str(content_length)

    def get(self, name, default=None):
        return self._headers.get(name.lower(), default)

    def get_content_charset(self):
        return self._charset


class _FakeResponse:
    """Context-manager HTTP response that records how ``read`` was called."""

    def __init__(self, body=b"", charset=None, content_length=None):
        self._body = body
        self.headers = _FakeHeaders(charset, content_length)
        self.read_calls = []

    def read(self, amt=None):
        self.read_calls.append(amt)
        if amt is None:
            return self._body
        return self._body[:amt]

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _RecordingBytesIO(io.BytesIO):
    """BytesIO that remembers any read() of the body."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_calls = []

    def read(self, *args, **kwargs):
        self.read_calls.append(args)
        return super().read(*args, **kwargs)


class _FakeSocket:
    """Socket stub whose makefile() returns a BytesIO over fixed bytes."""

    def __init__(self, data: bytes):
        self._data = data
        self.fp = None

    def makefile(self, *args, **kwargs):
        self.fp = _RecordingBytesIO(self._data)
        return self.fp

    def close(self):
        pass


def _raw_response(headers=(), body=b"", status=b"HTTP/1.1 200 OK") -> bytes:
    """Assemble a raw HTTP/1.1 response byte string."""
    head = status + b"\r\n"
    for name, value in headers:
        head += name + b": " + value + b"\r\n"
    head += b"\r\n"
    return head + body


def _real_response(raw: bytes):
    """Build a REAL http.client.HTTPResponse over a fake socket.

    Returns ``(response, socket)`` so tests can inspect how much of the
    body was consumed (``socket.fp.tell()``). This exercises stdlib parsing
    and read semantics rather than a hand-rolled mock.
    """
    sock = _FakeSocket(raw)
    response = http.client.HTTPResponse(sock)
    response.begin()
    return response, sock


class TestDownloadList(unittest.TestCase):
    def test_max_response_bytes_is_100_mib(self):
        self.assertEqual(MAX_RESPONSE_BYTES, 100 * 1024 * 1024)

    def test_success_returns_lines_and_keeps_tls_verification(self):
        body = b"alpha.com\nbeta.com"
        resp = _FakeResponse(body=body)
        with mock.patch("compile.urllib.request.urlopen", return_value=resp) as urlopen:
            lines = download_list("https://example.test/list")
        self.assertEqual(lines, ["alpha.com", "beta.com"])
        _args, kwargs = urlopen.call_args
        # No custom SSL context => the default, verifying context is used.
        self.assertNotIn("context", kwargs)
        self.assertEqual(kwargs.get("timeout"), 30)

    def test_successful_empty_body_is_not_a_failure(self):
        resp = _FakeResponse(body=b"")
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            self.assertEqual(download_list("https://example.test/list"), [])

    def test_read_is_bounded_not_unbounded(self):
        resp = _FakeResponse(body=b"abcdefghij")  # exactly 10 bytes
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            lines = download_list("https://example.test/list", max_bytes=10)
        self.assertEqual(lines, ["abcdefghij"])
        # Must ask for limit+1 so an oversized body can be detected.
        self.assertEqual(resp.read_calls, [11])
        self.assertNotIn(None, resp.read_calls)

    def test_body_at_limit_is_accepted(self):
        resp = _FakeResponse(body=b"x" * 8)
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            self.assertEqual(download_list("https://example.test/list", max_bytes=8), ["x" * 8])

    def test_oversized_body_is_rejected(self):
        resp = _FakeResponse(body=b"x" * 9)
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list", max_bytes=8)

    def test_url_error_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=urllib.error.URLError("name resolution failed"),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_http_error_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://example.test/list", 500, "Server Error", {}, None
            ),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_timeout_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=TimeoutError("timed out"),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_truncated_response_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=http.client.IncompleteRead(b"partial"),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_http_exception_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=http.client.BadStatusLine("garbage"),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_oversized_headers_raise_download_error(self):
        # http.client raises LineTooLong (an HTTPException) while parsing a
        # header block that exceeds its line limit.
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=http.client.LineTooLong("header line too long"),
        ):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_malformed_url_value_error_raises_download_error(self):
        with mock.patch(
            "compile.urllib.request.urlopen",
            side_effect=ValueError("unknown url type: 'htp'"),
        ):
            with self.assertRaises(DownloadError):
                download_list("htp://example.test/list")

    def test_invalid_charset_falls_back_to_utf8_with_warning(self):
        resp = _FakeResponse(body="caf\u00e9.com".encode("utf-8"), charset="no-such-codec")
        warnings = []
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            lines = download_list("https://example.test/list", log=warnings.append)
        self.assertEqual(lines, ["caf\u00e9.com"])
        self.assertTrue(any("charset" in w.lower() for w in warnings), warnings)

    def test_valid_charset_is_honoured(self):
        resp = _FakeResponse(body="caf\u00e9.com".encode("latin-1"), charset="latin-1")
        with mock.patch("compile.urllib.request.urlopen", return_value=resp):
            self.assertEqual(download_list("https://example.test/list"), ["caf\u00e9.com"])

    # -- real http.client.HTTPResponse-backed responses --------------------
    # Bounded response.read(n) can silently under-return relative to the
    # advertised Content-Length; these use a real HTTPResponse so the check
    # is exercised against stdlib behaviour, not a mock that raises.
    def test_real_response_full_content_length_is_accepted(self):
        raw = _raw_response(headers=[(b"Content-Length", b"10")], body=b"0123456789")
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            self.assertEqual(download_list("https://example.test/list"), ["0123456789"])

    def test_real_response_declared_length_longer_than_body_is_rejected(self):
        raw = _raw_response(headers=[(b"Content-Length", b"100")], body=b"x" * 40)
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_real_response_absent_length_is_accepted(self):
        raw = _raw_response(body=b"alpha.com\nbeta.com")
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            self.assertEqual(
                download_list("https://example.test/list"),
                ["alpha.com", "beta.com"],
            )

    def test_real_response_absent_length_actual_body_cap_applies(self):
        raw = _raw_response(body=b"x" * 20)
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list", max_bytes=8)

    def test_real_response_oversize_header_rejected_before_read(self):
        advertised = MAX_RESPONSE_BYTES + 1
        raw = _raw_response(
            headers=[(b"Content-Length", str(advertised).encode())],
            body=b"tiny",
        )
        response, sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")
        # The body must not have been read: the advertised size is rejected
        # from the header alone.
        self.assertEqual(sock.fp.read_calls, [])

    def test_real_response_invalid_content_length_ignored_with_warning(self):
        raw = _raw_response(headers=[(b"Content-Length", b"not-a-number")], body=b"alpha.com")
        response, _sock = _real_response(raw)
        warnings = []
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            self.assertEqual(
                download_list("https://example.test/list", log=warnings.append),
                ["alpha.com"],
            )
        self.assertTrue(any("content-length" in w.lower() for w in warnings), warnings)

    def test_real_response_negative_content_length_ignored_with_warning(self):
        raw = _raw_response(headers=[(b"Content-Length", b"-5")], body=b"alpha.com")
        response, _sock = _real_response(raw)
        warnings = []
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            self.assertEqual(
                download_list("https://example.test/list", log=warnings.append),
                ["alpha.com"],
            )
        self.assertTrue(any("content-length" in w.lower() for w in warnings), warnings)

    def test_real_chunked_truncated_body_raises_download_error(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"a\r\n"
            b"0123456789\r\n"
            b"5\r\n"
            b"01"
        )
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            with self.assertRaises(DownloadError):
                download_list("https://example.test/list")

    def test_real_chunked_bogus_content_length_is_not_false_truncation(self):
        # With chunked transfer-encoding, Content-Length is ignored by
        # http.client; a stale/bogus value must not be read as truncation.
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 1000\r\n"
            b"\r\n"
            b"a\r\n"
            b"0123456789\r\n"
            b"0\r\n"
            b"\r\n"
        )
        response, _sock = _real_response(raw)
        with mock.patch("compile.urllib.request.urlopen", return_value=response):
            self.assertEqual(download_list("https://example.test/list"), ["0123456789"])


class TestRunIntegration(unittest.TestCase):
    def _run(self, sources_text, outcomes, *, block_initial=None, allow_initial=None):
        """Run the pipeline offline against a temporary directory.

        ``outcomes`` maps URL to either a list of lines (success) or an
        Exception instance (raised by the fake downloader). Returns
        ``(root, block_path, allow_path, exit_code, logs)``.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        sources = root / "sources.txt"
        block_out = root / "blocklist.txt"
        allow_out = root / "whitelist.txt"
        sources.write_text(sources_text, encoding="utf-8")
        if block_initial is not None:
            block_out.write_bytes(block_initial)
        if allow_initial is not None:
            allow_out.write_bytes(allow_initial)

        logs = []

        def fake_download(url):
            outcome = outcomes[url]
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        code = 0
        try:
            run(
                sources_file=sources,
                output_file=block_out,
                whitelist_file=allow_out,
                download=fake_download,
                log=logs.append,
            )
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        return root, block_out, allow_out, code, logs

    def _run_with(self, sources_text, downloads):
        root, block_out, allow_out, code, logs = self._run(sources_text, downloads)
        self.assertEqual(code, 0, f"unexpected exit {code}: {logs}")
        return (
            block_out.read_text(encoding="utf-8").splitlines(),
            allow_out.read_text(encoding="utf-8").splitlines(),
        )

    def test_end_to_end_outputs(self):
        blocks, allows = self._run_with(
            "http://block.test/list\nWHITELIST http://allow.test/list\n",
            {
                "http://block.test/list": [
                    "||ads.example.com^",
                    "example.org # keep",
                    "! comment",
                ],
                "http://allow.test/list": ["ads.example.com", "||track.example.net^"],
            },
        )
        # Exact allow must not delete the suffix block, and vice versa.
        self.assertEqual(blocks, ["||ads.example.com^", "example.org"])
        self.assertEqual(allows, ["ads.example.com", "@@||track.example.net^"])

    def test_success_creates_missing_targets(self):
        root, block, allow, code, _logs = self._run(
            "http://block.test/list\n",
            {"http://block.test/list": ["example.com"]},
        )
        self.assertEqual(code, 0)
        self.assertTrue(block.exists())
        self.assertTrue(allow.exists())
        self.assertEqual(block.read_text(encoding="utf-8"), "example.com\n")
        self.assertEqual(allow.read_text(encoding="utf-8"), "")

    def test_bom_first_line(self):
        blocks, allows = self._run_with(
            "http://bom.test/list\n",
            {"http://bom.test/list": ["\ufeff0.0.0.0 bom.example.com"]},
        )
        self.assertEqual(blocks, ["bom.example.com"])
        self.assertEqual(allows, [])

    def test_successful_empty_source_warns_but_does_not_fail(self):
        # An empty response is a successful download; other sources still work.
        root, block, allow, code, logs = self._run(
            "http://empty.test/list\nhttp://block.test/list\n",
            {"http://empty.test/list": [], "http://block.test/list": ["example.com"]},
        )
        joined = "\n".join(logs)
        self.assertEqual(code, 0, joined)
        self.assertIn("[WARN]", joined)
        self.assertNotIn("failed to download", joined.lower())
        self.assertEqual(block.read_text(encoding="utf-8"), "example.com\n")

    def test_nonempty_source_with_zero_supported_rules_warns_not_fatal(self):
        # A source full of unsupported content is not a download failure and
        # is not fatal, as long as another source yields block rules.
        root, block, allow, code, logs = self._run(
            "http://junk.test/list\nhttp://block.test/list\n",
            {
                "http://junk.test/list": [
                    "! comment",
                    "[Adblock Plus 2.0]",
                    "||ads.example.com^$important",
                    "example.com##.banner",
                ],
                "http://block.test/list": ["real.example.com"],
            },
        )
        joined = "\n".join(logs)
        self.assertEqual(code, 0, joined)
        self.assertIn("[WARN]", joined)
        self.assertIn("no supported rules", joined.lower())
        # The zero-rule source must not be reported as OK.
        self.assertNotIn("Extracted 0 domains", joined)
        self.assertEqual(block.read_text(encoding="utf-8"), "real.example.com\n")

    def test_successful_empty_source_with_no_blocks_aborts(self):
        # Empty is not a download failure, but an empty final blocklist is fatal.
        root, block, allow, code, logs = self._run(
            "http://empty.test/list\n",
            {"http://empty.test/list": []},
        )
        joined = "\n".join(logs)
        self.assertNotEqual(code, 0)
        self.assertIn("[WARN]", joined)
        self.assertNotIn("failed to download", joined.lower())
        self.assertIn("no block rules", joined.lower())
        self.assertFalse(block.exists())
        self.assertFalse(allow.exists())

    def test_download_failure_preserves_existing_outputs(self):
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        root, block, allow, code, logs = self._run(
            "http://down.test/list\n",
            {"http://down.test/list": DownloadError("connection refused")},
            block_initial=old_block,
            allow_initial=old_allow,
        )
        joined = "\n".join(logs)
        self.assertNotEqual(code, 0)
        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertIn("failed to download", joined.lower())
        self.assertNotIn("[OK]", joined)

    def test_partial_failure_preserves_both_outputs(self):
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        root, block, allow, code, logs = self._run(
            "http://ok.test/list\nhttp://down.test/list\n",
            {
                "http://ok.test/list": ["new.example.com"],
                "http://down.test/list": DownloadError("boom"),
            },
            block_initial=old_block,
            allow_initial=old_allow,
        )
        self.assertNotEqual(code, 0)
        # The successful source must NOT overwrite anything.
        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)

    def test_whitelist_source_failure_aborts(self):
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        root, block, allow, code, _logs = self._run(
            "http://block.test/list\nWHITELIST http://allow.test/list\n",
            {
                "http://block.test/list": ["example.com"],
                "http://allow.test/list": DownloadError("tls failure"),
            },
            block_initial=old_block,
            allow_initial=old_allow,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)

    def test_all_sources_fail_leaves_no_preexisting_targets_untouched(self):
        root, block, allow, code, _logs = self._run(
            "http://a.test/list\nhttp://b.test/list\n",
            {
                "http://a.test/list": DownloadError("a down"),
                "http://b.test/list": DownloadError("b down"),
            },
        )
        self.assertNotEqual(code, 0)
        self.assertFalse(block.exists())
        self.assertFalse(allow.exists())

    def test_missing_sources_file_exits_nonzero(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        logs = []
        with self.assertRaises(SystemExit) as ctx:
            run(
                sources_file=root / "missing.txt",
                output_file=root / "blocklist.txt",
                whitelist_file=root / "whitelist.txt",
                download=lambda url: [],
                log=logs.append,
            )
        self.assertEqual(ctx.exception.code, 1)

    def test_no_urls_in_sources_exits_nonzero(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "sources.txt").write_text("# only comments\n\n", encoding="utf-8")
        logs = []
        with self.assertRaises(SystemExit) as ctx:
            run(
                sources_file=root / "sources.txt",
                output_file=root / "blocklist.txt",
                whitelist_file=root / "whitelist.txt",
                download=lambda url: [],
                log=logs.append,
            )
        self.assertEqual(ctx.exception.code, 1)

    def test_write_failure_exits_nonzero_and_preserves_outputs(self):
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        sources = root / "sources.txt"
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        sources.write_text("http://ok.test/list\n", encoding="utf-8")
        block.write_bytes(old_block)
        allow.write_bytes(old_allow)
        logs = []
        with mock.patch("compile.os.replace", side_effect=OSError("no space left")):
            with self.assertRaises(SystemExit) as ctx:
                run(
                    sources_file=sources,
                    output_file=block,
                    whitelist_file=allow,
                    download=lambda url: ["example.com"],
                    log=logs.append,
                )
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])


class TestWriteOutputs(unittest.TestCase):
    def _tmpdir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def test_writes_both_files(self):
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        write_outputs(block, allow, "a.example\n", "b.example\n")
        self.assertEqual(block.read_text(encoding="utf-8"), "a.example\n")
        self.assertEqual(allow.read_text(encoding="utf-8"), "b.example\n")
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])

    def test_creates_files_when_targets_absent(self):
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        self.assertFalse(block.exists())
        self.assertFalse(allow.exists())
        write_outputs(block, allow, "a.example\n", "")
        self.assertTrue(block.exists())
        self.assertTrue(allow.exists())
        self.assertEqual(allow.read_text(encoding="utf-8"), "")

    def test_staging_failure_cleans_temp_and_preserves_originals(self):
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        block.write_bytes(old_block)
        allow.write_bytes(old_allow)

        with mock.patch("compile.os.fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write_outputs(block, allow, "new-block\n", "new-allow\n")

        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])

    def test_replace_failure_cleans_temp_and_preserves_originals(self):
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        block.write_bytes(old_block)
        allow.write_bytes(old_allow)

        with mock.patch("compile.os.replace", side_effect=OSError("nope")):
            with self.assertRaises(OSError):
                write_outputs(block, allow, "new-block\n", "new-allow\n")

        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])

    def test_second_replace_failure_is_partial_and_cleans_temp(self):
        # Documents the non-transactional guarantee: the first os.replace may
        # have committed, the second may not, but temps are cleaned up.
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        old_allow = b"old-allow.example\n"
        allow.write_bytes(old_allow)

        real_replace = os.replace
        calls = {"n": 0}

        def flaky_replace(src, dst):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_replace(src, dst)
            raise OSError("second replace failed")

        with mock.patch("compile.os.replace", side_effect=flaky_replace):
            with self.assertRaises(OSError):
                write_outputs(block, allow, "new-block\n", "new-allow\n")

        self.assertEqual(block.read_text(encoding="utf-8"), "new-block\n")
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])

    def test_unexpected_exception_still_cleans_temps(self):
        # Cleanup must happen on ANY exception, not only OSError.
        root = self._tmpdir()
        block = root / "blocklist.txt"
        allow = root / "whitelist.txt"
        old_block = b"||old-block.example^\n"
        old_allow = b"old-allow.example\n"
        block.write_bytes(old_block)
        allow.write_bytes(old_allow)

        with mock.patch("compile.os.replace", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                write_outputs(block, allow, "new-block\n", "new-allow\n")

        self.assertEqual(block.read_bytes(), old_block)
        self.assertEqual(allow.read_bytes(), old_allow)
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])

    def test_fd_is_closed_when_fdopen_fails(self):
        root = self._tmpdir()
        target = root / "blocklist.txt"
        captured = {}
        real_mkstemp = tempfile.mkstemp

        def fake_mkstemp(**kwargs):
            fd, name = real_mkstemp(**kwargs)
            captured["fd"] = fd
            return fd, name

        with mock.patch("compile.tempfile.mkstemp", side_effect=fake_mkstemp):
            with mock.patch("compile.os.fdopen", side_effect=OSError("fdopen boom")):
                with self.assertRaises(OSError):
                    write_outputs(target, root / "whitelist.txt", "a\n", "b\n")

        fd = captured["fd"]
        with self.assertRaises(OSError):
            os.fstat(fd)  # a closed fd raises EBADF
        self.assertEqual(sorted(p.name for p in root.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
