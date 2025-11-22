import os
import shutil
import subprocess

import pytest

from rfc3230_digest_headers.exceptions import (
    MalformedHeaderError,
    UnacceptableAlgorithmError,
    UnsatisfiableDigestError,
)
from rfc3230_digest_headers.rfc3230 import (
    DigestHeaderAlgorithm,
    HeaderShouldBeAdded,
    _bsdcksum,
    _bsdsum,
    _make_wants_digest_header,
    _parse_digest_header,
    _parse_want_digest_header,
)


def test_bsdsum_hello_world():
    if shutil.which("sum") is not None:
        proc = subprocess.run(
            ["sum"],
            input=b"Hello, World!",
            capture_output=True,
            check=True,
        )
        output = proc.stdout.decode().strip()
        checksum, _ = output.split()
        assert checksum == _bsdsum(b"Hello, World!")
    assert _bsdsum(b"Hello, World!") == "37287"


def test_cksum_hello_world():
    if shutil.which("cksum") is not None:
        proc = subprocess.run(
            ["cksum", "--tag"],
            input=b"Hello, World!",
            capture_output=True,
            check=True,
        )
        output = proc.stdout.decode().strip()
        checksum, _ = output.split()[:2]
        assert checksum == _bsdcksum(b"Hello, World!")
    assert _bsdcksum(b"Hello, World!") == "2609532967"


def test__make_wants_digest_header():
    header = _make_wants_digest_header(
        {
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: None,
        },
    )
    assert header == "sha-256;q=1.0,unixsum,md5;q=0.5"


def test_parse_digest_header():
    header = "sha-256=abc, md5=def , unixsum=ghi"
    parsed = _parse_digest_header(
        header,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: None,
        },
    )
    assert parsed == {
        DigestHeaderAlgorithm.SHA256: "abc",
        DigestHeaderAlgorithm.MD5: "def",
        DigestHeaderAlgorithm.UNIXSUM: "ghi",
    }


def test_parse_digest_header_fails_on_unacceptable_algorithm():
    header = "sha-256=abc, md5=def , unixsum=ghi"
    with pytest.raises(UnacceptableAlgorithmError):
        _parse_digest_header(
            header,
            qvalues={
                DigestHeaderAlgorithm.SHA256: 1.0,
                DigestHeaderAlgorithm.MD5: 0.3,
                DigestHeaderAlgorithm.UNIXSUM: 0.0,  # Not acceptable
            },
        )


def test_parse_digest_header_ignores_unknown_algorithm():
    header = "sha-256=abc, md5=def , unixsum=ghi, unknown=xyz"
    parsed = _parse_digest_header(header, qvalues={DigestHeaderAlgorithm.SHA256: None})
    assert parsed == {
        DigestHeaderAlgorithm.SHA256: "abc",
    }


def test_parse_digest_header_with_empty_part_counts_as_malformed():
    for header in ("sha-256=abc, , md5=def", "sha-256=abc,, md5=def", ""):
        with pytest.raises(MalformedHeaderError):
            _parse_digest_header(header, qvalues={DigestHeaderAlgorithm.SHA256: None})


def test_parse_digest_header_missing_equal_counts_as_malformed():
    header = "sha-256abc, md5=def , unixsum=ghi"
    with pytest.raises(MalformedHeaderError):
        _parse_digest_header(header, qvalues={DigestHeaderAlgorithm.SHA256: None})


def test_spaces_are_stripped_in_digest_header():
    for header in (
        " sha-256 = abc , md5 = def , unixsum = ghi ",
        "sha-256=abc,md5=def,unixsum=ghi",
    ):
        parsed = _parse_digest_header(
            header,
            qvalues={
                DigestHeaderAlgorithm.SHA256: 1.0,
                DigestHeaderAlgorithm.MD5: 0.5,
                DigestHeaderAlgorithm.UNIXSUM: None,
            },
        )
        assert parsed == {
            DigestHeaderAlgorithm.SHA256: "abc",
            DigestHeaderAlgorithm.MD5: "def",
            DigestHeaderAlgorithm.UNIXSUM: "ghi",
        }


def test_parse_each_algorithm_once():
    header = "unixsum=ghi, unixcksum=xyz, md5=def , sha=abc, sha-256=abc, sha-512=ijk, unknown=xyz"
    for alg in DigestHeaderAlgorithm:
        parsed = _parse_digest_header(header, qvalues={alg: None})
        match alg:
            case DigestHeaderAlgorithm.UNIXSUM:
                assert parsed == {DigestHeaderAlgorithm.UNIXSUM: "ghi"}
            case DigestHeaderAlgorithm.UNIXCKSUM:
                assert parsed == {DigestHeaderAlgorithm.UNIXCKSUM: "xyz"}
            case DigestHeaderAlgorithm.MD5:
                assert parsed == {DigestHeaderAlgorithm.MD5: "def"}
            case DigestHeaderAlgorithm.SHA:
                assert parsed == {DigestHeaderAlgorithm.SHA: "abc"}
            case DigestHeaderAlgorithm.SHA256:
                assert parsed == {DigestHeaderAlgorithm.SHA256: "abc"}
            case DigestHeaderAlgorithm.SHA512:
                assert parsed == {DigestHeaderAlgorithm.SHA512: "ijk"}


def test_parse_mixed_case_algorithm_names():
    header = "sHa-256=abc, Md5=def , UnIxSuM=ghi"
    parsed = _parse_digest_header(
        header,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: None,
        },
    )
    assert parsed == {
        DigestHeaderAlgorithm.SHA256: "abc",
        DigestHeaderAlgorithm.MD5: "def",
        DigestHeaderAlgorithm.UNIXSUM: "ghi",
    }


def test_malformed_parse_digest_header_with_empty_algorithm_or_qvaule():
    for header in ("=abc, md5=def", "sha-256=abc, md5="):
        with pytest.raises(MalformedHeaderError):
            _parse_digest_header(header, qvalues={DigestHeaderAlgorithm.SHA256: None})


def test_compute_digests():
    data = b"Hello, World!"

    assert DigestHeaderAlgorithm.UNIXSUM.compute(data) == "37287"
    assert DigestHeaderAlgorithm.UNIXCKSUM.compute(data) == "2609532967"
    assert DigestHeaderAlgorithm.MD5.compute(data) == "ZajifYh5KDgxtmS9i38K1A=="
    assert DigestHeaderAlgorithm.SHA.compute(data) == "CgqfKmdylCVXq1NV12r0Qvj2XgE="
    assert (
        DigestHeaderAlgorithm.SHA256.compute(data)
        == "3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8="
    )
    assert (
        DigestHeaderAlgorithm.SHA512.compute(data)
        == "N015SpXNz9izWZMYX++bo2jxYNja9DLQi6nx7R5avmzGkpHg+i/gAGpSVw7xjBne9OYXwzzlLvCm5fvjGMsDhw=="
    )


def test_parse_want_digest_header():
    header = "sha-256;q=1.0, unixsum, md5;q=0.5"
    parsed = _parse_want_digest_header(header)
    assert parsed == {
        DigestHeaderAlgorithm.SHA256: 1.0,
        DigestHeaderAlgorithm.UNIXSUM: None,
        DigestHeaderAlgorithm.MD5: 0.5,
    }


def test_want_digest_header_missing_semicolon_counts_as_unknown_and_is_ignored():
    header = "sha-256q=1.0, unixsum, md5;q=0.5"
    parsed = _parse_want_digest_header(header)
    assert parsed == {
        DigestHeaderAlgorithm.UNIXSUM: None,
        DigestHeaderAlgorithm.MD5: 0.5,
    }


def test_empty_qvalue_counts_as_malformed_in_want_digest_header():
    header = "sha;q=, unixsum, md5;q=0.5"
    with pytest.raises(MalformedHeaderError):
        _parse_want_digest_header(header)


def test_want_digest_header_without_algorithm_counts_as_malformed():
    for header in (";q=1.0, unixsum, md5;q=0.5", ";q=1.0"):
        with pytest.raises(MalformedHeaderError):
            _parse_want_digest_header(header)


def test_want_digest_header_with_empty_part_counts_as_malformed():
    for header in ("sha-256;q=1.0, , md5;q=0.5", "sha-256;q=1.0,, md5;q=0.5", ""):
        with pytest.raises(MalformedHeaderError):
            _parse_want_digest_header(header)


def test_want_digest_header_with_non_numeric_qvalue_counts_as_malformed():
    for header in ("sha-256;q=abc, unixsum, md5;q=0.5", "sha;q=abc"):
        with pytest.raises(MalformedHeaderError):
            _parse_want_digest_header(header)


def test_whitespace_in_want_digest_header_accepted():
    header = " sha-256 ; q= 1.0 , unixsum , md5 ; q=0.5 "
    parsed = _parse_want_digest_header(header)
    assert parsed == {
        DigestHeaderAlgorithm.SHA256: 1.0,
        DigestHeaderAlgorithm.UNIXSUM: None,
        DigestHeaderAlgorithm.MD5: 0.5,
    }


def test_space_in_want_digest_header_accepted_after_q_is_malformed():
    header = "sha;q =1.0"
    with pytest.raises(MalformedHeaderError):
        _parse_want_digest_header(header)


def test_verify_request():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.SHA256,
            DigestHeaderAlgorithm.MD5,
        ],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header is None


def test_verify_request_fails_on_unacceptable_algorithm():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.SHA256,
            DigestHeaderAlgorithm.MD5,
        ],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" in digest_header.header_value
    with pytest.raises(UnacceptableAlgorithmError):
        DigestHeaderAlgorithm.verify_request(
            request_headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: 1.0,
                DigestHeaderAlgorithm.MD5: 0.0,  # Not acceptable
                DigestHeaderAlgorithm.UNIXSUM: 0,
            },
        )


def test_verify_fails_on_malformed_header():
    data = b"Hello, World!"
    request_headers = {
        "Digest": "sha-256=abc, , md5=def",  # Malformed (empty part)
    }
    with pytest.raises(MalformedHeaderError):
        DigestHeaderAlgorithm.verify_request(
            request_headers,
            data,
            qvalues={
                DigestHeaderAlgorithm.SHA256: 1.0,
                DigestHeaderAlgorithm.MD5: 0.5,
                DigestHeaderAlgorithm.UNIXSUM: 0,
            },
        )


def test_verify_fails_on_missing_header():
    data = b"Hello, World!"
    request_headers = {
        # No Digest header
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)


def test_verify_request_header_negotiation():
    # First send a request with missing header, it responds with a Want-Digest header
    data = b"Hello, World!"
    request_headers = {
        # No Digest header
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)
    assert response_header.header_name == "Want-Digest"
    assert "sha-256" in response_header.header_value
    assert "md5" in response_header.header_value
    assert "unixsum" in response_header.header_value
    # Now send a request with the suggested algorithms
    digest_header = DigestHeaderAlgorithm.handle_want_digest_header(
        instance=data,
        want_digest_header=response_header.header_value,
        algorithms="all",
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" in digest_header.header_value
    assert "unixsum=" not in digest_header.header_value, (
        "unixsum is has qalue 0, so it should not be used"
    )
    valid, response_header2 = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header2 is None

    # Now send request with 'auto'. Should only use sha-256
    digest_header = DigestHeaderAlgorithm.handle_want_digest_header(
        instance=data,
        want_digest_header=response_header.header_value,
        algorithms="auto",
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" not in digest_header.header_value, (
        "md5 has qvalue 0.5, but sha-256 has 1.0, so it should not be used"
    )
    assert "unixsum=" not in digest_header.header_value, (
        "unixsum is has qalue 0, so it should not be used"
    )
    valid, response_header3 = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header3 is None

    # Now send with specifically only md5 as algorithm
    digest_header = DigestHeaderAlgorithm.handle_want_digest_header(
        instance=data,
        want_digest_header=response_header.header_value,
        algorithms=[DigestHeaderAlgorithm.MD5],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "md5=" in digest_header.header_value
    assert "sha-256=" not in digest_header.header_value, (
        "sha-256 has qalue 1.0, but was not requested, so it should not be used"
    )
    assert "unixsum=" not in digest_header.header_value, (
        "unixsum is has qalue 0, so it should not be used"
    )
    valid, response_header4 = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header4 is None


def test_verify_request_negotiation_fails_because_client_does_not_support_requested_algorithm():
    # 1. Client makes request without header
    # 2. Server responds with Want-Digest header
    # 3. Client parses Want-Digest header, but does not support any of the algorithms
    data = b"Hello, World!"
    request_headers = {
        # No Digest header
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0,
        },
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)
    assert response_header.header_name == "Want-Digest"
    assert "sha-256;q=1.0" in response_header.header_value
    assert "md5;q=0.0" in response_header.header_value
    # Now client tries to respond, but does not support any of the suggested algorithms
    with pytest.raises(UnsatisfiableDigestError):
        DigestHeaderAlgorithm.handle_want_digest_header(
            instance=data,
            want_digest_header=response_header.header_value,
            algorithms=[DigestHeaderAlgorithm.SHA],  # Client only supports SHA
        )


def test_default_qvalues_is_sha256():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.SHA256,
            DigestHeaderAlgorithm.MD5,
        ],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues=None,  # Defaults to {SHA256: None}
    )
    assert valid
    assert response_header is None

    digest_header2 = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[DigestHeaderAlgorithm.MD5],
    )
    request_headers2 = {
        "Digest": digest_header2.header_value,
    }
    assert "md5=" in digest_header2.header_value
    valid2, response_header2 = DigestHeaderAlgorithm.verify_request(
        request_headers2,
        data,
        qvalues=None,  # Defaults to {SHA256: None}
    )
    assert not valid2
    assert isinstance(response_header2, HeaderShouldBeAdded)
    assert response_header2.header_name == "Want-Digest"
    assert response_header2.header_value == "sha-256"


def test_verify_request_with_type_all():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.SHA256,
            DigestHeaderAlgorithm.MD5,
        ],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    assert "md5=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
        verify_type="all",
    )
    assert valid
    assert response_header is None


def test_verify_request_type_all_catches_not_all_are_valid():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.MD5,
        ],
    )
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "md5=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
        verify_type="all",
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)
    assert response_header.header_name == "Want-Digest"
    assert "sha-256;q=1.0" in response_header.header_value
    assert "md5;q=0.5" in response_header.header_value
    assert "unixsum;q=0.0" in response_header.header_value


def test_verify_request_with_mixed_case_of_digest_header():
    data = b"Hello, World!"
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=[
            DigestHeaderAlgorithm.SHA256,
        ],
    )

    # Handle uppercase "Digest" case (searched via dictionary get()).
    request_headers = {
        "Digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header is None

    # Handle lowercase "digest" case, searched via dictionary get().
    request_headers = {
        "digest": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header is None

    # Handle mixed case "dIgEsT" case, searched via full scan of headers.
    request_headers = {
        "dIgEsT": digest_header.header_value,
    }
    assert "sha-256=" in digest_header.header_value
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
            DigestHeaderAlgorithm.UNIXSUM: 0,
        },
    )
    assert valid
    assert response_header is None


def test_verify_request_fails_hash_comparison_when_verify_type_is_all():
    data = b"Hello, World!"
    request_headers = {
        "Digest": "sha-256=invalidhash",
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
        },
        verify_type="all",
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)
    assert response_header.header_name == "Want-Digest"
    assert "sha-256;q=1.0" in response_header.header_value


def test_verify_request_fails_if_verify_type_is_any_but_none_match():
    data = b"Hello, World!"
    request_headers = {
        "Digest": "sha-256=invalidhash, md5=anotherinvalidhash",
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues={
            DigestHeaderAlgorithm.SHA256: 1.0,
            DigestHeaderAlgorithm.MD5: 0.5,
        },
        verify_type="any",
    )
    assert not valid
    assert isinstance(response_header, HeaderShouldBeAdded)
    assert response_header.header_name == "Want-Digest"
    assert "sha-256;q=1.0" in response_header.header_value
    assert "md5;q=0.5" in response_header.header_value


def test_make_digest_header_with_want_digest_header_auto():
    """Test that make_digest_header redirects to handle_want_digest_header when want_digest_header is provided with 'auto'."""
    data = b"Hello, World!"
    want_digest_header_value = "sha-256;q=1.0, md5;q=0.5, unixsum;q=0.0"

    # Using make_digest_header with want_digest_header parameter and 'auto'
    header = DigestHeaderAlgorithm.make_digest_header(
        instance=data,
        algorithms="auto",
        want_digest_header=want_digest_header_value,
    )

    assert header.header_name == "Digest"
    assert "sha-256=" in header.header_value
    # With 'auto', only the highest priority algorithm should be used
    assert "md5=" not in header.header_value
    assert "unixsum=" not in header.header_value


def test_make_digest_header_with_want_digest_header_all():
    """Test that make_digest_header redirects to handle_want_digest_header when want_digest_header is provided with 'all'."""
    data = b"Hello, World!"
    want_digest_header_value = "sha-256;q=1.0, md5;q=0.5, unixsum;q=0.0"

    # Using make_digest_header with want_digest_header parameter and 'all'
    header = DigestHeaderAlgorithm.make_digest_header(
        instance=data,
        algorithms="all",
        want_digest_header=want_digest_header_value,
    )

    assert header.header_name == "Digest"
    assert "sha-256=" in header.header_value
    assert "md5=" in header.header_value
    # unixsum has qvalue 0.0, so it should not be used
    assert "unixsum=" not in header.header_value


def test_make_digest_header_with_want_digest_header_explicit_algorithms():
    """Test that make_digest_header redirects to handle_want_digest_header with explicit algorithm list."""
    data = b"Hello, World!"
    want_digest_header_value = "sha-256;q=1.0, md5;q=0.5, sha;q=0.3"

    # Using make_digest_header with want_digest_header parameter and explicit algorithms
    header = DigestHeaderAlgorithm.make_digest_header(
        instance=data,
        algorithms=[DigestHeaderAlgorithm.MD5, DigestHeaderAlgorithm.SHA],
        want_digest_header=want_digest_header_value,
    )

    assert header.header_name == "Digest"
    # Only md5 and sha should be used (from our explicit list that match want_digest)
    assert "md5=" in header.header_value
    assert "sha=" in header.header_value
    # sha-256 is in want_digest but not in our explicit list
    assert "sha-256=" not in header.header_value


def test_make_digest_header_with_want_digest_header_no_acceptable_algorithm():
    """Test that make_digest_header raises UnsatisfiableDigestError when no algorithm matches."""
    data = b"Hello, World!"
    want_digest_header_value = "sha-256;q=1.0, md5;q=0.0"

    # Client only supports SHA (not in the acceptable list from server)
    with pytest.raises(UnsatisfiableDigestError):
        DigestHeaderAlgorithm.make_digest_header(
            instance=data,
            algorithms=[DigestHeaderAlgorithm.SHA],
            want_digest_header=want_digest_header_value,
        )


def test_make_digest_header_raises_error_when_all_without_want_digest():
    """Test that make_digest_header raises ValueError when 'all' is used without want_digest_header."""
    data = b"Hello, World!"

    with pytest.raises(ValueError, match="`all` is not a valid value"):
        DigestHeaderAlgorithm.make_digest_header(
            instance=data,
            algorithms="all",
            want_digest_header=None,
        )


def test_digest_header_from_fuzzed_input():
    """Use all algorithms with an increasing amount of random input data to make sure that no hash can be generated that fails, parsing and validating."""
    for _ in range(3):
        for size in range(0, 1024, 7):
            data = os.urandom(size)
            digest_header = DigestHeaderAlgorithm.make_digest_header(
                data,
                algorithms=list(DigestHeaderAlgorithm),
            )
            request_headers = {
                "Digest": digest_header.header_value,
            }
            valid, response_header = DigestHeaderAlgorithm.verify_request(
                request_headers,
                data,
                qvalues=dict.fromkeys(DigestHeaderAlgorithm),
                verify_type="all",
            )
            assert valid
            assert response_header is None


def test_verify_type_all_fails_if_any_is_invalid_type_any_still_works():
    data = os.urandom(1000)
    digest_header = DigestHeaderAlgorithm.make_digest_header(
        data,
        algorithms=list(DigestHeaderAlgorithm),
    )
    # First lets make sure that the valid case works
    request_headers = {
        "Digest": digest_header.header_value,
    }
    valid, response_header = DigestHeaderAlgorithm.verify_request(
        request_headers,
        data,
        qvalues=dict.fromkeys(DigestHeaderAlgorithm),
        verify_type="all",
    )
    assert valid
    assert response_header is None

    # Now lets pick every algorithm one by one and temper its value to make sure that verify_request fails
    for tempered_alg in DigestHeaderAlgorithm:
        # Prepend something invalid to one of the algorithms
        tempered_header = digest_header.header_value.replace(
            f"{tempered_alg.value.lower()}=", f"{tempered_alg.name.lower()}=a"
        )
        request_headers = {
            "Digest": tempered_header,
        }
        valid, response_header = DigestHeaderAlgorithm.verify_request(
            request_headers,
            data,
            qvalues=dict.fromkeys(DigestHeaderAlgorithm),
            verify_type="all",
        )
        assert not valid
        assert isinstance(response_header, HeaderShouldBeAdded)
        assert response_header.header_name == "Want-Digest"

        # In 'any' mode, it should still be valid as other algorithms are valid
        valid_any, response_header_any = DigestHeaderAlgorithm.verify_request(
            request_headers,
            data,
            qvalues=dict.fromkeys(DigestHeaderAlgorithm),
            verify_type="any",
        )
        assert valid_any
        assert response_header_any is None
