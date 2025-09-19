"""Exceptions for rfc3230_digest_headers module."""


class MalformedHeaderError(ValueError):
    """Exception raised when a Digest header is malformed."""


class UnacceptableAlgorithmError(ValueError):
    """Exception raised when a Digest header contains an unacceptable algorithm."""


class UnsatisfiableDigestError(ValueError):
    """Exception raised when no acceptable digest algorithm is found. This means that the server requested digests that the client can not produce."""
