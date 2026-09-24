"""Registra este repo como el paquete `kev_integration`, sin depender del nombre de la carpeta.

Los tests importan `kev_integration`, pero el repo se clona por defecto como `kev-integration`
(con guion, que no es un nombre de paquete válido).
"""

import importlib.util
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]

if "kev_integration" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "kev_integration", RAIZ / "__init__.py", submodule_search_locations=[str(RAIZ)]
    )
    modulo = importlib.util.module_from_spec(spec)
    sys.modules["kev_integration"] = modulo
    spec.loader.exec_module(modulo)


def _kev_responde(base_url: str) -> bool:
    import httpx

    try:
        httpx.get(f"{base_url.rstrip('/')}/v1/models", timeout=2.0)
        return True
    except httpx.HTTPError:
        return False


def pytest_collection_modifyitems(config, items):
    """Sin servidor Kev, los tests de integración que lo necesitan se omiten en vez de fallar."""
    import os

    import pytest

    necesitan_servidor = [i for i in items if "kev_service" in getattr(i, "fixturenames", ())]
    if not necesitan_servidor:
        return
    base_url = os.environ.get("KEV_BASE_URL", "http://localhost:8009")
    if _kev_responde(base_url):
        return
    motivo = pytest.mark.skip(reason=f"el servidor Kev no responde en {base_url}")
    for item in necesitan_servidor:
        item.add_marker(motivo)
