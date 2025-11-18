"""Implements the `Digest` and `Want-Digest` headers as per RFC 3230."""

import base64
import hashlib
import shutil
import subprocess
from collections.abc import Sequence
from enum import Enum
from typing import Literal, NamedTuple

from .exceptions import (
    MalformedHeaderError,
    UnacceptableAlgorithmError,
    UnsatisfiableDigestError,
)


class DigestHeaderAlgorithm(Enum):
    """Supported digest algorithms for rfc3230. For convenience, we provide more algorithms than the RFC requires.

    - **UNIXSUM** and **UNIXCKSUM:** are provided for legacy reasons. You should not use them anymore.
    - **MD5:** is provided for legacy reasons. You should not use it anymore.
    - **SHA:** is provided for legacy reasons. You should not use it anymore.
    - **SHA256:** is the **recommended** algorithm.
    - **SHA512:** can be used if you want a stronger hash than SHA256.
    """

    UNIXSUM = "unixsum"
    UNIXCKSUM = "unixcksum"
    MD5 = "md5"
    SHA = "sha"
    SHA256 = "sha-256"
    SHA512 = "sha-512"

    @staticmethod
    def verify_request(
        request_headers: dict[str, str],
        instance: bytes,
        qvalues: dict["DigestHeaderAlgorithm", float | None] | None = None,
        verify_type: Literal["all", "any"] = "any",
    ) -> "tuple[bool, HeaderShouldBeAdded | None]":
        """Verify the `Digest` header in the request against the given instance bytes.

        Used by the *server* to verify an incoming request's `Digest` header against the provided instance bytes.

        The `Digest` header is expected to be of the form:
            ```
            digest-algorithm "=" instance-hash-base64 ["," digest-algorithm "=" instance-hash-base64]*
            ```
        where instance-hash-base64 is the base64-encoded hash of the `instance` bytes using the specified `digest-algorithm`. The `digest-algorithm` is one of the supported algorithms in the `Algorithm` enum. The algorithm names are case-insensitive.
        For example:
            ```
            sha-256=abc, md5=def, unixsum=ghi
            ```

        The `Want-Digest` header is returned in the response using the `HeaderShouldBeAdded` class in case of errors:
            ```
            digest-algorithm [";q=" qvalue] ["," digest-algorithm [";q=" qvalue]]*
            ```
        where `qvalue` is a float between 0.0 and 1.0 indicating the preference for that algorithm.
        For example:
            ```
            sha-256;q=1.0,md5;q=0.3;unixsum;q=0.0
            ```
        A qvalue of 0.0 means that the algorithm is not acceptable. An algorithm not listed is ignored.

        Args:
            request_headers: The request headers as a dictionary. Only the `Digest` header is relevant. The reason we accept all headers is because most HTTP frameworks provide the headers as a dictionary and this pattern minimizes the risk, that the dev passes the wrong header. When all headers are passed, this library can handle extracting the right header.
            instance: The instance bytes to verify the digest against. May be fully, partially or not contained at all as part of the request. Usually this is just the method + path + date + body of the request.
            qvalues: An optional dictionary of accepted algorithms and their quality values. If None, defaults to {Algorithm.SHA256: None}. An algorithm not listed here will be ignored. An unkown algorithm will be ignored. An unacceptable algorithm (qvalue of 0.0) will fail the check.
            verify_type: If "all", all provided digests must match. If "any", at least one provided digest must match. Defaults to "all".

        Returns:
            A tuple `(is_valid, header)` where `is_valid` is `True` if the request's Digest header is valid, `False` otherwise.
            `header` is a `HeaderShouldBeAdded` when the server suggests adding a `Want-Digest` header to the response for negotiation,
            otherwise `None`.

        Raises:
            MalformedHeaderError: If the `Digest` header is malformed. E.g. missing `=` or empty algorithm or digest.
            UnacceptableAlgorithmError: If the `Digest` header contains an algorithm with a qvalue of 0.0.
            RuntimeError: If the `cksum` command is not found on the system or if the command fails when using UNIXCKSUM.

        """
        if qvalues is None:
            qvalues = {
                DigestHeaderAlgorithm.SHA256: None,
            }

        digest_header = (
            request_headers.get("Digest")
            or request_headers.get("digest")
            or next(
                (v for k, v in request_headers.items() if k.lower() == "digest"),
                None,
            )  # Allow case-insensitive header names
        )
        if digest_header is None:
            return (
                False,
                HeaderShouldBeAdded("Want-Digest", _make_wants_digest_header(qvalues)),
            )

        provided_digests = _parse_digest_header(digest_header, qvalues)
        if not provided_digests:
            # In the case no known algorithm was provided, we also want to inform the client what we want.
            return (
                False,
                HeaderShouldBeAdded("Want-Digest", _make_wants_digest_header(qvalues)),
            )

        for alg, provided_digest in provided_digests.items():
            computed_digest = alg.compute(instance)
            if verify_type == "any" and provided_digest == computed_digest:
                return (True, None)
            if verify_type == "all" and provided_digest != computed_digest:
                return (
                    False,
                    HeaderShouldBeAdded(
                        "Want-Digest",
                        _make_wants_digest_header(qvalues),
                    ),
                )
        if verify_type == "all":
            # Fail if not all required algorithms have been provided and verified.
            if {alg for alg, qvalue in qvalues.items() if qvalue != 0.0} != set(
                provided_digests.keys(),
            ):
                return (
                    False,
                    HeaderShouldBeAdded(
                        "Want-Digest",
                        _make_wants_digest_header(qvalues),
                    ),
                )
            return (True, None)
        return (
            False,
            HeaderShouldBeAdded("Want-Digest", _make_wants_digest_header(qvalues)),
        )

    @staticmethod
    def make_digest_header(
        instance: bytes,
        algorithms: Sequence["DigestHeaderAlgorithm"] | Literal["all", "auto"] = "auto",
        want_digest_header: str | None = None,
    ) -> "HeaderShouldBeAdded":
        """Generate a `Digest` header for the given instance bytes for each of the specified algorithms.

        Part of the negotiation process between client and server.
        Used by *clients* to create a `Digest` header for the given instance bytes using the specified algorithms.

        Args:
            instance: The instance bytes to compute the digest for. You have to negotiate with the server what exactly is part of this instance.
            algorithms: A list of algorithms to compute the digest with. The server may ignore any and all of them. If "auto" is provided, only `SHA256` will be used. "all" is only valid in the case that a `Want-Digest` header is provided.
            want_digest_header: An optional `Want-Digest` header value from the server. If provided, this method will call `handle_want_digest_header` instead to negotiate the algorithms.

        Returns:
            A `HeaderShouldBeAdded` object containing the `Digest` header name and its value. Add this header to your request.

        Raises:
            MalformedHeaderError: If the `Want-Digest` header is malformed.
            RuntimeError: If the `cksum` command is not found on the system or if the command fails when using UNIXCKSUM.
            UnsatisfiableDigestError: If no acceptable digest algorithm is found. The server and client fail to negotiate a common algorithm.
            ValueError: If `all` is provided as `algorithms` without a `want_digest_header`.

        """
        if want_digest_header is not None:
            return DigestHeaderAlgorithm.handle_want_digest_header(
                instance,
                want_digest_header,
                algorithms,
            )
        if algorithms == "all":
            raise ValueError(
                "`all` is not a valid value for `algorithms` if no `want_digest_header` is provided.",
            )
        if algorithms == "auto":
            algorithms = [DigestHeaderAlgorithm.SHA256]
        header_value = ",".join(
            f"{alg.value}={alg.compute(instance)}" for alg in algorithms
        )
        return HeaderShouldBeAdded("Digest", header_value)

    @staticmethod
    def handle_want_digest_header(
        instance: bytes,
        want_digest_header: str,
        algorithms: Sequence["DigestHeaderAlgorithm"] | Literal["all", "auto"] = "auto",
    ) -> "HeaderShouldBeAdded":
        """Generate a `Digest` header based on the `Want-Digest` header from the server.

        Part of the negotiation process between client and server.
        Used by *clients* to handle a `Want-Digest` header from the server and decide which algorithms to use.
        This calls `make_digest_header` with the algorithms that the server wants, indicated by the `Want-Digest`.

        Args:
            instance: The instance bytes to compute the digest for. You have to negotiate with the server what exactly is part of this instance. Will use `make_digest_header` internally.
            want_digest_header: The value of the `Want-Digest` header from the response received from the server.
            algorithms: An allowlist of algorithms that the client is supposed to send if the `Want-Digest` requests it.

        Returns:
            A `HeaderShouldBeAdded` object containing the `Digest` header name and its value. Add this header to your request.

        Raises:
            MalformedHeaderError: If the `Want-Digest` header is malformed.
            RuntimeError: If the `cksum` command is not found on the system or if the command fails when using UNIXCKSUM.
            UnsatisfiableDigestError: If no acceptable digest algorithm is found. The server and client fail to negotiate a common algorithm.

        """
        wanted_digests = [
            alg
            for i, (alg, qvalue) in enumerate(
                sorted(
                    _parse_want_digest_header(want_digest_header).items(),
                    key=lambda item: 1.0 if item[1] is None else item[1],
                    reverse=True,
                ),
            )
            if qvalue != 0.0
            and (
                algorithms == "all"
                or (algorithms == "auto" and i == 0)
                or (not isinstance(algorithms, str) and alg in algorithms)
            )
        ]

        if not wanted_digests:
            raise UnsatisfiableDigestError("No acceptable digest algorithm found.")

        return DigestHeaderAlgorithm.make_digest_header(instance, wanted_digests)

    def compute(self, data: bytes) -> str:
        """Compute the digest of the given data using the specified algorithm.

        Args:
            data: The bytes to compute the checksum for.

        Returns:
            The computed digest. For UNIXSUM and UNIXCKSUM, this is a string representation of the checksum. For MD5, SHA, SHA256 and SHA512, this is a base64-encoded string of the hash.

        """
        match self:
            case DigestHeaderAlgorithm.UNIXSUM:
                return _bsdsum(data)
            case DigestHeaderAlgorithm.UNIXCKSUM:
                return _bsdcksum(data)
            case DigestHeaderAlgorithm.MD5:
                return base64.b64encode(hashlib.md5(data).digest()).decode()
            case DigestHeaderAlgorithm.SHA:
                return base64.b64encode(hashlib.sha1(data).digest()).decode()
            case DigestHeaderAlgorithm.SHA256:
                return base64.b64encode(hashlib.sha256(data).digest()).decode()
            case DigestHeaderAlgorithm.SHA512:
                return base64.b64encode(hashlib.sha512(data).digest()).decode()


def _make_wants_digest_header(
    qvalues: dict["DigestHeaderAlgorithm", float | None],
) -> str:
    """Create the `Want-Digest` header value from the `qvalues` dictionary.

    Args:
        qvalues: A dictionary of accepted algorithms and their qvalues. If `None` is provided, the algorithm will be appended without a specific qvalue, which is equivalent to a qvalue of 1.0.

    Returns:
        The `Want-Digest` header value as a string.

    """
    parts = []
    # With higher qvalues first
    for alg, qvalue in sorted(
        qvalues.items(),
        key=lambda item: 1.0 if item[1] is None else item[1],
        reverse=True,
    ):
        if qvalue is None:
            parts.append(alg.value)
        else:
            parts.append(f"{alg.value};q={qvalue:.1f}")
    return ",".join(parts)


def _parse_digest_header(
    digest_header: str,
    qvalues: dict[DigestHeaderAlgorithm, float | None],
) -> dict[DigestHeaderAlgorithm, str]:
    """Parse a `Digest` header into a dictionary of algorithms and their corresponding digests.

    The form of the header is expected to be:
        ```
        digest-algorithm "=" instance-digest ["," digest-algorithm "=" instance-digest]*
        ```
    where instance-digest is the base64-encoded hash of the instance using the specified digest-algorithm.
    For example:
        ```
        sha-256=sha-256-hash-of-instance, md5=md5-hash-of-instance, unixsum=unixsum-of-instance
        ```

    Args:
        digest_header: The value of the `Digest` header to parse.
        qvalues: A dictionary of accepted algorithms and their qvalues. An algorithm not listed here will be ignored when parsing. A qvalue of 0.0 will raise a ValueError if that algorithm is present in the header.

    Returns:
        A dictionary mapping algorithms to their corresponding base64-encoded digests. Only accepted algorithms that have a non-zero qvalue are included.

    Raises:
        MalformedHeaderError: If the `Digest` header is malformed. E.g. missing `=` or empty algorithm or digest.
        UnacceptableAlgorithmError: If the `Digest` header contains an algorithm with a qvalue of 0.0.

    """
    parsed_digests = {}
    for part in digest_header.split(","):
        if "=" not in part:
            raise MalformedHeaderError(
                f"Malformed Digest header part: {part}. Missing '='.",
            )
        alg_str, instance_digest = part.strip().split("=", 1)
        alg_str = alg_str.strip().lower()
        instance_digest = instance_digest.strip()
        if not alg_str or not instance_digest:
            raise MalformedHeaderError(
                f"Malformed Digest header part: {part}. Empty algorithm or digest.",
            )
        try:
            alg = DigestHeaderAlgorithm(alg_str)
        except ValueError:
            # Ignore unknown algorithms
            continue
        if alg not in qvalues:
            # Ignore algorithms that are not explicitly unacceptable
            continue
        if qvalues.get(alg) == 0.0:
            raise UnacceptableAlgorithmError(
                f"Algorithm {alg.value} not acceptable. qvalue is 0.0.",
            )
        parsed_digests[alg] = instance_digest
    return parsed_digests


def _parse_want_digest_header(
    want_digest_header: str,
) -> dict[DigestHeaderAlgorithm, float | None]:
    """Parse a `Want-Digest` header into a dictionary of algorithms and their corresponding qvalues.

    The form of the header is expected to be:
        ```
        digest-algorithm [";q=" qvalue] ["," digest-algorithm [";q=" qvalue]]*
        ```

    An algorithm without a qvalue is considered to have a qvalue of `None`, which is equivalent to `1.0`.

    Args:
        want_digest_header: The value of the `Want-Digest` header to parse.

    Returns:
        A dictionary mapping algorithms to their corresponding qvalues.

    Raises:
        MalformedHeaderError: If the `Want-Digest` header is malformed.
        UnacceptableAlgorithmError: If the `Want-Digest` header contains an algorithm with a qvalue of 0.0.

    """
    parsed_qvalues = {}
    for part in want_digest_header.split(","):
        part = part.strip()  # noqa: PLW2901
        if not part:
            raise MalformedHeaderError(
                f"Malformed Want-Digest header part: {part}. Empty part.",
            )
        if ";" in part:
            alg_str, qvalue_str = part.split(";", 1)
            alg_str = alg_str.strip().lower()
            qvalue_str = qvalue_str.strip()
            if not alg_str or not qvalue_str.startswith("q="):
                raise MalformedHeaderError(
                    f"Malformed Want-Digest header part: {part}.",
                )
            try:
                qvalue = float(qvalue_str[2:])
            except ValueError:
                raise MalformedHeaderError(
                    f"Malformed Want-Digest header part: {part}. Invalid qvalue.",
                ) from None
        else:
            alg_str = part
            qvalue = None

        try:
            alg = DigestHeaderAlgorithm(alg_str.strip().lower())
        except ValueError:
            # Ignore unknown algorithms
            continue
        parsed_qvalues[alg] = qvalue

    return parsed_qvalues


def _bsdsum(data: bytes) -> str:
    """Compute the BSD-style checksum of the given data. Should be equal to `sum` on a Unix system."""
    checksum = 0
    for b in data:
        if checksum & 1:
            checksum |= 0x10000
        checksum = checksum >> 1
        checksum = (checksum + b) & 0xFFFF
    return str(checksum)


def _bsdcksum(data: bytes) -> str:
    """Compute the BSD-style `chksum` of the given data.

    I could not understand the official documentation on this algorithm, so we just call it directly.
    Requires `cksum` command to be available on the system.

    Args:
        data: The bytes to compute the checksum for.

    Returns:
        The checksum as a string.

    Raises:
        RuntimeError: If the `cksum` command is not found on the system or if the command fails.

    """
    if shutil.which("cksum") is None:
        raise RuntimeError("cksum command not found. Cannot compute UNIXCKSUM.")

    proc = subprocess.run(
        ["cksum"],
        input=data,
        capture_output=True,
        check=True,
    )
    output = proc.stdout.decode().strip()
    return output.split()[0]


class HeaderShouldBeAdded(NamedTuple):
    """Container for a header and its value.

    It indicates that the header should be added to the request or response.
    You don't *have* to neither add it nor treat it as a header specifically, though it is recommended to do so.
    """

    header_name: str
    header_value: str
