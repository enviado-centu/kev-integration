"""Custom exceptions for Kev integration module."""


class KevError(Exception):
    """Base exception for all Kev-related errors."""
    pass


class KevConnectionError(KevError):
    """Raised when unable to connect to Kev server."""
    pass


class KevTimeoutError(KevError):
    """Raised when Kev request times out."""
    pass


class KevInvalidResponseError(KevError):
    """Raised when Kev returns an invalid or unexpected response."""
    pass


class KevRequestError(KevError):
    """Raised when Kev returns an HTTP error (4xx, 5xx)."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class KevValidationError(KevError):
    """Raised when request validation fails."""
    pass
