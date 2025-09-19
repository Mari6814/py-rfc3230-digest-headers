[![Test](https://github.com/Mari6814/py-rfc3230-digest-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/Mari6814/py-rfc3230-digest-headers/actions/workflows/test.yml)
[![Coverage](https://github.com/Mari6814/py-rfc3230-digest-headers/raw/main/badges/coverage.svg)](https://github.com/Mari6814/py-rfc3230-digest-headers/raw/main/badges/coverage.svg)
[![Versions](https://github.com/Mari6814/py-rfc3230-digest-headers/raw/main/badges/python-versions.svg)](https://github.com/Mari6814/py-rfc3230-digest-headers/raw/main/badges/python-versions.svg)

# Introduction
A small library to provide the server and client side methods to require, negotiation and generate `Digest` HTTP headers as per [RFC 3230](https://datatracker.ietf.org/doc/html/rfc3230).
Clients can generate `Digest` headers of the form: `Digest: SHA-256=xyz, MD5=abc`. Server can require certain algorithms by sending `Want-Digest` headers of the form: `Want-Digest: SHA-256, SHA;q=0.5, MD5;q=0`.

# Installation
Install using pip:
```bash
pip install rfc3230-digest-headers
```

# Overview of the protocol
The protocol works as follows:
1. Client and server agree on what the `instance` bytes are for the endpoint in question. Usually the request body or the content of the resource before applying transformations.
2. Client sends request
3. If the client did not directly send a valid `Digest`, the server responds with `Want-Digest` header to indicate which algorithms it supports.
    - Form of the `Want-Digest` header: `Want-Digest: SHA-256, SHA;q=0.5, MD5;q=0`
    - The server can specify `qvalues` to indicate preference of algorithms.
    - No value equals `q=1.0`.
    - `q=0` means "do not use this algorithm".
4. Client generates `Digest` header using one of the supported algorithms and sends it in the request.
    - Form of the `Digest` header: `Digest: SHA-256=xyz, MD5=abc`
5. Server verifies the `Digest` header and processes the request.

# Usage
The library provides only one enum class, `DigestHeaderAlgorithm`, which can be used by server and client to fully specify, negotiate and generate `Digest` HTTP headers.
You do not use these algorithms directly, but instead have to use a couple of *static* methods provided by the enum class.

## Example: Generate a `Digest` header
The client generates a `Digest` for their *instance*.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

instance_bytes = b"Hello, World!"
(header_name, header_value) = DigestHeaderAlgorithm.make_digest_header(
    instance=instance_bytes,
    algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
)
print(header_name)  # "Digest"
print(header_value) # "SHA-256=..., MD5=..."
``` 

## Usage: Verify a `Digest` header
The server receives a request with a `Digest` header and verifies it.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

instance_bytes = b"Hello, World!"
request_headers = {"Digest": "SHA-256=..., MD5=..."}
is_valid, want_digest_header_should_be_added = DigestHeaderAlgorithm.verify_request(
    request_headers=request_headers,
    instance=instance_bytes,
    qvalues={
        DigestHeaderAlgorithm.SHA256: 1.0,
        DigestHeaderAlgorithm.SHA: 0.5,
        DigestHeaderAlgorithm.MD5: 0.0 # If the client sends MD5, they will receive an error
    },
)
print(is_valid)  # True if the Digest header is valid
print(want_digest_header_should_be_added)  # None if valid, otherwise contains the `Want-Digest` header to be sent to the client for negotiation
```

## Usage: Server-side negotiation of algorithms
The server can indicate which algorithms the endpoint requires by sending a `Want-Digest` header.
The header is automatically generated when attempting to verify invalid request headers.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

# Fake request from client without an invalid Digest header
instance_bytes = b"Hello, World!"
request_headers = {"Digest": "SHA-256=..., MD5=..."}
is_valid, want_digest_header_should_be_added = DigestHeaderAlgorithm.verify_request(
    request_headers=request_headers,
    instance=instance_bytes,
    qvalues={
        DigestHeaderAlgorithm.SHA256: 1.0,
        DigestHeaderAlgorithm.SHA: 0.5,
        DigestHeaderAlgorithm.MD5: 0.0 # If the client sends MD5, they will receive an error
    },
)
if want_digest_header_should_be_added:
    print(want_digest_header_should_be_added.header_name)  # "Want-Digest"
    print(want_digest_header_should_be_added.header_value) # "SHA-256, SHA
    # Send the response with the generated Want-Digest header
    ...
```
In this example the request fails because the client sent `MD5`, which is not supported by the server.

## Usage: Client-side negotiation of algorithms
When an endpoint responds with a `Want-Digest` header, the client can parse it and generate a valid `Digest` header.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

# Fake response from server with Want-Digest header
instance_bytes = b"Hello, World!"
response_headers = {"Want-Digest": "SHA-256, SHA;q=0.5, MD5;q=0"}
want_digest_header = DigestHeaderAlgorithm.parse_want_digest_header(
    response_headers=response_headers
)

# Parse the response and generate a valid Digest header (if possible)
if want_digest_header:
    (header_name, header_value) = DigestHeaderAlgorithm.make_digest_header(
        instance=instance_bytes,
        algorithms=want_digest_header.supported_algorithms
    )
    print(header_name)  # "Digest"
    print(header_value) # "SHA-256=..., SHA=..."
    # re-send the request with the generated Digest header
    ...
```
