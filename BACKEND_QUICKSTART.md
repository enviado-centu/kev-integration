# Guía Rápida para el Backend

## Instalación

```bash
# Desde el directorio raíz del proyecto
pip install -r kev_integration/requirements.txt
```

## Uso Básico

```python
from kev_integration import KevService, PageAnalysisRequest

# 1. Inicializar servicio
service = KevService()  # Carga config desde variables de entorno

# 2. Crear request
request = PageAnalysisRequest(
    url="https://example.com/login",
    domain="example.com",
    title="Login Page",
    visible_text="Enter your credentials...",
)

# 3. Analizar
result = service.analyze(request)

# 4. Usar resultados
print(f"Phishing: {result.is_phishing.probability}")
print(f"Risk: {result.risk.score}")
```

## Variables de Entorno

```bash
KEV_BASE_URL=http://localhost:8009
KEV_MODEL=kev-latest
KEV_TIMEOUT=30
```

## Endpoint de Ejemplo (FastAPI)

```python
from fastapi import FastAPI, HTTPException
from kev_integration import KevService, PageAnalysisRequest, KevError

app = FastAPI()
kev_service = KevService()

@app.post("/api/analyze")
async def analyze_page(request: PageAnalysisRequest):
    """Analizar página para phishing/amenazas."""
    try:
        result = kev_service.analyze(request)
        
        return {
            "success": True,
            "data": {
                "is_phishing": result.is_phishing.probability,
                "is_malicious": result.is_malicious.probability,
                "threat_type": result.threat_type.value,
                "threat_confidence": result.threat_type.confidence,
                "risk_score": result.risk.score,
                "latency_ms": result.latency_ms,
            }
        }
    except KevError as e:
        raise HTTPException(status_code=503, detail=str(e))
```

## Respuesta del Backend

```json
{
  "success": true,
  "data": {
    "is_phishing": 0.91,
    "is_malicious": 0.87,
    "threat_type": "phishing",
    "threat_confidence": 0.91,
    "risk_score": 0.86,
    "latency_ms": 495.0
  }
}
```

## Manejo de Errores

```python
from kev_integration import (
    KevConnectionError,
    KevTimeoutError,
    KevRequestError,
)

try:
    result = service.analyze(request)
except KevConnectionError:
    # Kev no está disponible
    return {"error": "Service unavailable"}, 503
except KevTimeoutError:
    # Timeout en la solicitud
    return {"error": "Request timeout"}, 504
except KevRequestError as e:
    # Error de Kev
    return {"error": f"Kev error: {e.message}"}, 500
```

## Con Señales Externas

```python
result = service.analyze(
    request,
    domain_reputation=0.8,  # 0-1, mayor = más riesgoso
    url_heuristics=0.7,     # 0-1
)
```

## Estructura de PageAnalysisRequest

```python
PageAnalysisRequest(
    url="https://example.com",           # Requerido
    domain="example.com",                 # Requerido
    title="Page Title",                   # Opcional
    visible_text="Visible content...",    # Opcional
    page_content="<html>...</html>",      # Opcional
    links=["https://..."],                # Opcional
    metadata={"key": "value"},            # Opcional
)
```

## Estructura de AnalysisResult

```python
result.is_phishing.probability      # float 0-1
result.is_malicious.probability     # float 0-1
result.threat_type.value            # str: "phishing"|"malware"|"scam"|"benign"|"other"
result.threat_type.confidence       # float 0-1
result.threat_type.probabilities    # dict: {"phishing": 0.9, ...}
result.risk.score                   # float 0-1
result.latency_ms                   # float
```

## Iniciar Kev

```bash
# Desde el directorio kev/
uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8009
```

## Tests

```bash
# Tests unitarios (no requieren Kev)
python -m pytest kev_integration/tests/test_unit.py -v

# Tests de integración (requieren Kev corriendo)
KEV_BASE_URL=http://localhost:8009 python -m pytest kev_integration/tests/test_integration.py -v
```

## Documentación Completa

Ver `kev_integration/README.md` para más detalles.
