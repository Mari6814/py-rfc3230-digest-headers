"""Functional interface for RFC 3230 Digest headers."""

from collections.abc import Sequence
from typing import Literal

from .rfc3230 import DigestHeaderAlgorithm, HeaderShouldBeAdded


def create_digest(
    instance: bytes,
    want_digest_header: str | None = None,
    algorithms: Sequence[DigestHeaderAlgorithm] | Literal["auto"] = "auto",
) -> HeaderShouldBeAdded:
    """Create a `Digest` header for the given instance bytes, for use in HTTP requests as per RFC 3230.

    This function is used by clients to generate a Digest header for a request. If a Want-Digest header
    is provided (from a previous server response), it will negotiate the digest algorithms accordingly.

    Args:
        instance: The bytes to compute the digest for (e.g., request body or canonicalized request).
        want_digest_header: Optional Want-Digest header value from the server. If provided, this function
            will negotiate the digest algorithms as requested by the server.
        algorithms: A list of algorithms to compute the digest with. If "auto" is provided, only SHA-256
            will be used. If Want-Digest is provided, this is used as an allowlist.

    Returns:
            HeaderShouldBeAdded: An object containing the header name ("Digest") and its value.

    Usage:
        Client: create_digest(instance)
        Client (after Want-Digest): create_digest(instance, want_digest_header)

    Raises:
        MalformedHeaderError: If the Want-Digest header is malformed.
        UnsatisfiableDigestError: If no acceptable digest algorithm is found.
        RuntimeError: If the cksum command is not found or fails for UNIXCKSUM.
        ValueError: If "all" is provided as algorithms without a Want-Digest header.

    """
    if want_digest_header is not None:
        return DigestHeaderAlgorithm.handle_want_digest_header(
            instance, want_digest_header, algorithms
        )
    return DigestHeaderAlgorithm.make_digest_header(instance, algorithms)


def verify_digest(
    request_headers: dict[str, str],
    instance: bytes,
    qvalues: dict[DigestHeaderAlgorithm, float | None] | None = None,
    verify_type: Literal["all", "any"] = "any",
) -> tuple[bool, HeaderShouldBeAdded | None]:
    """Verify the `Digest` header in the request against the given instance bytes, as per RFC 3230.

    This function is used by servers to verify an incoming request's Digest header against the provided instance bytes.
    If the digest does not match, a Want-Digest header is suggested for negotiation.

    Args:
        request_headers: The request headers as a dictionary. Only the Digest header is relevant; case-insensitive.
        instance: The instance bytes to verify the digest against (e.g., request body or canonicalized request).
        qvalues: Optional dictionary of accepted algorithms and their quality values. If None, defaults to SHA-256 only.
        verify_type: If "all", all provided digests must match. If "any", at least one must match. Defaults to "any".

    Returns:
        tuple[bool, HeaderShouldBeAdded | None]:
            - is_valid: True if the Digest header is valid, False otherwise.
            - header: HeaderShouldBeAdded if the server suggests a Want-Digest header for negotiation, else None.

    Usage:
        Server: valid, want_digest = verify_digest(request_headers, instance)

    Raises:
        MalformedHeaderError: If the Digest header is malformed.
        UnacceptableAlgorithmError: If the Digest header contains an algorithm with a qvalue of 0.0.
        RuntimeError: If the cksum command is not found or fails for UNIXCKSUM.

    """
    return DigestHeaderAlgorithm.verify_request(
        request_headers, instance, qvalues, verify_type
    )
