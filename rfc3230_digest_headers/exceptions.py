class MalformedHeaderException(ValueError):
    """Exception raised when a Digest header is malformed."""



class UnacceptableAlgorithmException(ValueError):
    """Exception raised when a Digest header contains an unacceptable algorithm."""



class UnsatisfiableDigestException(ValueError):
    """Exception raised when no acceptable digest algorithm is found. This means that the server requested digests that the client can not produce."""

