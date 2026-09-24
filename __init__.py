"""Kev Integration Module - Phishing and threat detection using Kev decision models."""

__version__ = "0.1.0"

# Al recolectar tests/, pytest importa este archivo suelto (sin paquete padre) porque la carpeta
# se llama "kev-integration", que no es un nombre de paquete válido. En ese caso no se exporta
# nada; los tests usan el paquete registrado como `kev_integration` en tests/conftest.py.
if __package__:
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
