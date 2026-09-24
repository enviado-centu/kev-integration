"""Kev Integration Module - Phishing and threat detection using Kev decision models."""

from .service import KevService
from .models import PageAnalysisRequest, AnalysisResult
from .config import KevConfig
from .exceptions import (
    KevError,
    KevConnectionError,
    KevTimeoutError,
    KevInvalidResponseError,
    KevRequestError,
)

__version__ = "0.1.0"
__all__ = [
    "KevService",
    "PageAnalysisRequest",
    "AnalysisResult",
    "KevConfig",
    "KevError",
    "KevConnectionError",
    "KevTimeoutError",
    "KevInvalidResponseError",
    "KevRequestError",
]
