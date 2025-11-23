"""Tests for the functional interface of RFC 3230 Digest headers."""

import os

import pytest

from rfc3230_digest_headers.functional import create_digest, verify_digest
from rfc3230_digest_headers.rfc3230 import (
    DigestHeaderAlgorithm,
    UnsatisfiableDigestError,
)


def test_create_digest_auto():
    data = b"hello world"
    header = create_digest(data)
    assert header.header_name == "Digest"
    assert header.header_value.startswith("sha-256=")


def test_create_digest_multiple():
    data = b"abc"
    header = create_digest(
        data, algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
    )
    assert "sha-256=" in header.header_value
    assert "md5=" in header.header_value


def test_create_digest_with_want_digest():
    data = b"xyz"
    want_digest_header = "sha-256;q=1.0,md5;q=0.5,unknownalg;q=0.1"
    header = create_digest(data, want_digest_header)
    assert header.header_name == "Digest"
    assert "sha-256=" in header.header_value
    assert (
        "md5=" not in header.header_value
    ), 'because of "auto" mode, only the best algorithm is chosen'
    assert "unknownalg=" not in header.header_value, "unknown algorithms are ignored"


def test_verify_digest_valid_with_fuzzing():
    for size in range(0, 1024, 128):
        data = os.urandom(size)
        header = create_digest(data)
        headers = {"Digest": header.header_value}
        valid, want_digest = verify_digest(headers, data)
        assert valid is True
        assert want_digest is None


def test_verify_digest_invalid():
    for size in range(0, 1024, 128):
        data = os.urandom(size)
        headers = {"Digest": "sha-256=invaliddigest"}
        valid, want_digest = verify_digest(headers, data)
        assert valid is False
        assert want_digest is not None
        assert want_digest.header_name == "Want-Digest"


def test_verify_digest_unacceptable_algorithm():
    data = b"abc"
    headers = {"Digest": "md5=invalid"}
    qvalues = {DigestHeaderAlgorithm.MD5: 0.0, DigestHeaderAlgorithm.SHA256: None}
    valid, want_digest = verify_digest(headers, data, qvalues)
    assert valid is False
    assert want_digest is not None
    assert want_digest.header_name == "Want-Digest"
    assert (
        want_digest.error_description == "Algorithm md5 not acceptable. qvalue is 0.0."
    )


def test_verify_digest_malformed_header():
    data = b"abc"
    headers = {"Digest": "sha-256"}  # Missing '='
    valid, want_digest = verify_digest(headers, data)
    assert not valid
    assert want_digest is not None
    assert want_digest.error_description == "Malformed Digest header"


def test_create_digest_unsatisfiable():
    data = b"abc"
    want_digest_header = "unknownalg;q=1.0"
    with pytest.raises(UnsatisfiableDigestError):
        create_digest(data, want_digest_header)


def test_verify_digest_validation_type_all():
    for size in range(0, 1024, 128):
        data = os.urandom(size)
        header = create_digest(
            data, algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
        )
        headers = {"Digest": header.header_value}

        # Should be valid when both digests match
        valid, want_digest = verify_digest(
            headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: None,
                DigestHeaderAlgorithm.MD5: None,
            },
            verify_type="all",
        )
        assert valid is True
        assert want_digest is None

        # Now tamper with one digest value
        tampered_header_value = header.header_value.replace(
            "md5=" + DigestHeaderAlgorithm.MD5.compute(data), "md5=invalid"
        )
        headers = {"Digest": tampered_header_value}
        # Should be invalid when not all digests match
        valid, want_digest = verify_digest(
            headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: None,
                DigestHeaderAlgorithm.MD5: None,
            },
            verify_type="all",
        )
        assert valid is False
        assert want_digest is not None
        assert want_digest.header_name == "Want-Digest"


def test_verify_digest_validation_type_any():
    for size in range(0, 1024, 128):
        data = os.urandom(size)
        header = create_digest(
            data, algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
        )
        headers = {"Digest": header.header_value}

        # Should be valid when any digest matches
        valid, want_digest = verify_digest(
            headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: None,
                DigestHeaderAlgorithm.MD5: None,
            },
            verify_type="any",
        )
        assert valid is True
        assert want_digest is None

        # Tamper with both digests
        tampered_header_value = header.header_value.replace(
            "sha-256=" + DigestHeaderAlgorithm.SHA256.compute(data), "sha-256=invalid"
        ).replace(
            "md5=" + DigestHeaderAlgorithm.MD5.compute(data), "md5=anotherinvalid"
        )
        headers = {"Digest": tampered_header_value}
        # Should be invalid when none match
        valid, want_digest = verify_digest(
            headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: None,
                DigestHeaderAlgorithm.MD5: None,
            },
            verify_type="any",
        )
        assert valid is False
        assert want_digest is not None
        assert want_digest.header_name == "Want-Digest"
