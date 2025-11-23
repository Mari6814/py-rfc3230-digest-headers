[![Test](https://github.com/Mari6814/py-rfc3230-digest-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/Mari6814/py-rfc3230-digest-headers/actions/workflows/ci.yml)
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

## Functional Interface (Recommended)

The recommended way to use this library is via the functional interface in `rfc3230_digest_headers.functional`. It provides simple functions for generating and verifying Digest headers:

- `create_digest(instance, ...)`: Generate a Digest header for client requests.
- `verify_digest(request_headers, instance, ...)`: Verify Digest headers on the server.

### Example: Basic Client-Server Flow
Simply import the two functions from the package (no need for `.functional`), and use them as follows:

```python
from rfc3230_digest_headers import create_digest, verify_digest

# Client: prepare request
instance = b"Hello, World!"
digest_header = create_digest(instance)
request_headers = {digest_header.header_name: digest_header.header_value}

# Server: verify request
is_valid, want_digest = verify_digest(request_headers, instance)
if not is_valid and want_digest:
    # Server responds with Want-Digest header
    print(want_digest.header_name, want_digest.header_value)

# Client: handle Want-Digest and retry
if want_digest:
    digest_header = create_digest(instance, want_digest_header=want_digest.header_value)
    request_headers = {digest_header.header_name: digest_header.header_value}
    # Server verifies again
    is_valid, _ = verify_digest(request_headers, instance)
    print("Accepted?", is_valid)
```

### Configure which algorithms the server accepts
You can specify which algorithms the server accepts when verifying a `Digest` header by passing the `qvalues` parameter to `verify_digest`.
It should be a dictionary mapping `DigestHeaderAlgorithm` values to their respective _q-values_ (float between `0.0` and `1.0`, or `None` for default of `1.0`).
```python
from rfc3230_digest_headers import verify_digest, DigestHeaderAlgorithm

instance_bytes = b"Hello, World!"
request_headers = {"Digest": "SHA-256=..., MD5=..."}
is_valid, want_digest_header_should_be_added = verify_digest(
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

### Configure which algorithms to use for generating the `Digest` header on the client
You can specify which algorithms to use when generating the `Digest` header by passing the `algorithms` parameter to `create_digest`.
It can be a list of `DigestHeaderAlgorithm` values, or the special values `"auto"` (to use the highest priority algorithm from a `Want-Digest` header) or `"all"` (to use all acceptable algorithms from a `Want-Digest` header).

```python
from rfc3230_digest_headers import create_digest, DigestHeaderAlgorithm
instance = b"Hello, World!"
# Use only SHA-256 and MD5
digest_header = create_digest(
    instance,
    algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
)
print(digest_header.header_name, digest_header.header_value)
```

The `"auto"` and `"all"` options are used when negotiating algorithms based on a `Want-Digest` header received from the server.

```python
from rfc3230_digest_headers import create_digest, DigestHeaderAlgorithm
instance = b"Hello, World!"
want_digest_header_value = "SHA-256, SHA;q=0.5, MD5;q=0"
# Option 1: Use "auto" to select the highest priority algorithm
digest_header = create_digest(
    instance,
    algorithms="auto",
    want_digest_header=want_digest_header_value
)
print(digest_header.header_name, digest_header.header_value) # Will use SHA-256

# Option 2: Use "all" to include all acceptable algorithms
digest_header = create_digest(
    instance,
    algorithms="all",
    want_digest_header=want_digest_header_value
)
print(digest_header.header_name, digest_header.header_value) # Will use SHA-256 and SHA
```


## Older enum-oriented Interface
These usage examples demonstrate the older enum-oriented interface directly on `DigestHeaderAlgorithm`.

### Generate a `Digest` header

The client generates a `Digest` for their _instance_.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

instance_bytes = b"Hello, World!"
header = DigestHeaderAlgorithm.make_digest_header(
    instance=instance_bytes,
    algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]
)
print(header.header_name)  # "Digest"
print(header.header_value) # "SHA-256=..., MD5=..."
```

### Verify a `Digest` header

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

### Server-side negotiation of algorithms

The server can indicate which algorithms the endpoint requires by sending a `Want-Digest` header. The header is automatically generated when attempting to verify invalid request headers. In the following example, the client sends a `Digest` header with an unsupported algorithm (`MD5` with a _q-value_ of `0.0`), so the server responds with a `Want-Digest` header indicating which algorithms are supported.

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
    print(want_digest_header_should_be_added.header_value) # "SHA-256, SHA;q=0.5, MD5;q=0"
    # Send the response with the generated Want-Digest header
    ...
```

### Client-side negotiation of algorithms

When an endpoint responds with a `Want-Digest` header, the client can parse it and generate a valid `Digest` header. In the following example, imagine that we initially sent a request with `b'Hello, World!'` as body, and the server responded with an HTTP error code and a `Want-Digest` header. The client sees that its original request failed, and that the server wants a `Digest` header. The client then generates a valid `Digest` header using the highest priority algorithm from the `Want-Digest` header and re-sends the request.

```python
from rfc3230_digest_headers import DigestHeaderAlgorithm

# Fake response from server with Want-Digest header
instance_bytes = b"Hello, World!"
want_digest_header_value = "SHA-256, SHA;q=0.5, MD5;q=0"

# Option 1: Use make_digest_header with the want_digest_header parameter
# This will automatically handle negotiation
header = DigestHeaderAlgorithm.make_digest_header(
    instance=instance_bytes,
    algorithms="auto",  # Use the highest priority algorithm from Want-Digest
    want_digest_header=want_digest_header_value
)
print(header.header_name)   # "Digest"
print(header.header_value)  # "sha-256=..."

# Option 2: Explicitly use handle_want_digest_header (legacy approach)
header = DigestHeaderAlgorithm.handle_want_digest_header(
    instance=instance_bytes,
    want_digest_header=want_digest_header_value,
    algorithms="auto"  # Use the highest priority algorithm from Want-Digest
)
print(header.header_name)   # "Digest"
print(header.header_value)  # "sha-256=..."

# re-send the request with the generated Digest header
...
```

You can also use `algorithms="all"` to include all acceptable algorithms from the `Want-Digest` header, or provide an explicit list like `algorithms=[DigestHeaderAlgorithm.SHA256, DigestHeaderAlgorithm.MD5]` to only use specific algorithms that you support.
