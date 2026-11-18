from security.csp_builder import (
    build_csp,
    validate_source,
    nonce,
    is_unsafe,
    merge_policy
)


def test_default():
    assert "default-src 'none'" in build_csp({})

def test_nonce():
    assert 'nonce-' in build_csp({'script-src': ['nonce']})

def test_unsafe_inline():
    assert validate_source("'unsafe-inline'") is False

def test_unsafe_eval():
    assert validate_source("'unsafe-eval'") is False

def test_wildcard():
    assert validate_source('*') is False

def test_data():
    assert validate_source('data:') is False

def test_self():
    assert validate_source("'self'") is True

def test_https():
    assert validate_source('https://cdn.example') is True

def test_frame():
    assert "frame-ancestors 'none'" in build_csp({})

def test_report():
    assert 'report-uri' in build_csp({'report-uri': '/csp'})

def test_empty():
    assert validate_source('') is False

def test_merge():
    assert merge_policy({'script-src': ['self']}, {'script-src': ['none']})['script-src'] == ['none']

def test_nonce_len():
    assert len(nonce()) >= 16

def test_bad():
    assert validate_source('http://evil') is False

def test_duplicate():
    assert build_csp({'script-src': ['self', 'self']}).count('self') == 1
