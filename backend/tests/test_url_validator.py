import pytest

from app.url_validator import InvalidURLError, validate_and_normalize_url


def test_valid_https_url():
    assert validate_and_normalize_url("https://example.com/path?q=1") == "https://example.com/path?q=1"


def test_valid_http_url():
    assert validate_and_normalize_url("http://example.com") == "http://example.com"


def test_scheme_lowercased():
    assert validate_and_normalize_url("HTTPS://Example.COM") == "https://Example.COM"


def test_whitespace_stripped():
    assert validate_and_normalize_url("  https://example.com  ") == "https://example.com"


def test_rejects_empty():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("")


def test_rejects_whitespace_only():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("   ")


def test_rejects_missing_scheme():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("example.com")


def test_rejects_disallowed_scheme():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("ftp://example.com")


def test_rejects_javascript_scheme():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("javascript:alert(1)")


def test_rejects_file_scheme():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("file:///etc/passwd")


def test_rejects_newline_injection():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("https://example.com/\r\nHost: evil")


def test_rejects_control_chars():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("https://exa\x00mple.com")


def test_rejects_too_long():
    long_url = "https://example.com/" + "a" * 3000
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url(long_url)


def test_rejects_no_host():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("https://")
