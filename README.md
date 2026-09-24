# Kev Integration Module

Módulo de integración para detección de phishing y amenazas usando Kev, un modelo de decisión preentrenado.

## Arquitectura

```
Browser Extension / Mobile App
        │
        ▼
┌──────────────────────┐
│   Backend Principal  │
│      (API REST)      │
└──────────┬───────────┘
           │
           │ analyze(page_data)
           ▼
┌──────────────────────┐
│    KEV MODULE        │
│                      │
│  - StateBuilder      │
│  - QuestionConfig    │
│  - KevClient         │
│  - ResultNormalizer  │
│  - RiskCalculator    │
│  - KevService        │
└──────────┬───────────┘
           │
           │ HTTP POST /v1/systemone
           ▼
┌──────────────────────┐
│    Kev Server        │
│  (localhost:8009)    │
└──────────────────────┘
```

## Instalación

### Requisitos

- Python 3.12+
- Kev server corriendo localmente o accesible

### Dependencias

```bash
pip install httpx pydantic
```

El módulo usa:
- `httpx` para HTTP client
- `pydantic` para validación de datos

## Configuración

### Variables de Entorno

```bash
KEV_BASE_URL=http://localhost:8009
KEV_MODEL=kev-latest
KEV_TIMEOUT=30
KEV_API_KEY=your_api_key_here  # opcional
```

### Configuración Programática

```python
from kev_integration import KevConfig

config = KevConfig(
    base_url="http://localhost:8009",
    model="kev-latest",
    timeout=30,
    api_key=None  # opcional
)
```

## Ejecutar Kev

Antes de usar el módulo, necesitas tener Kev corriendo:

```bash
# Desde el directorio de Kev
uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8009
```

Ver [README de Kev](../README.md) para más detalles.

## Uso

### Ejemplo Básico

```python
from kev_integration import KevService, PageAnalysisRequest

# Inicializar servicio (carga configuración desde variables de entorno)
service = KevService()

# Crear request de análisis
request = PageAnalysisRequest(
    url="https://suspicious-site.com/login",
    domain="suspicious-site.com",
    title="Account Login - Verify Your Identity",
    visible_text="Enter your username and password to continue. Your account will be suspended if you don't verify within 24 hours.",
)

# Analizar página
result = service.analyze(request)

# Acceder a resultados
print(f"Phishing: {result.is_phishing.probability:.2%}")
print(f"Malicioso: {result.is_malicious.probability:.2%}")
print(f"Tipo de amenaza: {result.threat_type.value}")
print(f"Confianza: {result.threat_type.confidence:.2%}")
print(f"Risk score: {result.risk.score:.2%}")
```

### Ejemplo con Datos Adicionales

```python
request = PageAnalysisRequest(
    url="https://example.com/login",
    domain="example.com",
    title="Login",
    visible_text="Ingrese sus credenciales para acceder a su cuenta",
    page_content="<html>...</html>",  # HTML completo
    links=["https://example.com/about", "https://example.com/contact"],
    metadata={
        "response_time_ms": 250,
        "ssl_valid": True,
        "server": "nginx",
    }
)

# Con scores externos opcionales
result = service.analyze(
    request,
    domain_reputation=0.1,  # 0-1, mayor = más riesgoso
    url_heuristics=0.3,
)
```

### Ejemplo de Respuesta

```json
{
  "is_phishing": {
    "probability": 0.91
  },
  "is_malicious": {
    "probability": 0.87
  },
  "threat_type": {
    "value": "phishing",
    "confidence": 0.91,
    "probabilities": {
      "phishing": 0.91,
      "malware": 0.04,
      "scam": 0.03,
      "benign": 0.01,
      "other": 0.01
    }
  },
  "risk": {
    "score": 0.86
  },
  "latency_ms": 495.0
}
```

## Integración con Backend Principal

### Ejemplo con FastAPI

```python
from fastapi import FastAPI, HTTPException
from kev_integration import KevService, PageAnalysisRequest, KevError

app = FastAPI()
kev_service = KevService()

@app.post("/analyze")
async def analyze_page(request: PageAnalysisRequest):
    try:
        result = kev_service.analyze(request)
        return {
            "is_phishing": result.is_phishing.probability,
            "is_malicious": result.is_malicious.probability,
            "threat_type": result.threat_type.value,
            "risk_score": result.risk.score,
        }
    except KevError as e:
        raise HTTPException(status_code=503, detail=str(e))
```

## Preguntas de Seguridad

El módulo hace 4 preguntas a Kev:

### 1. is_phishing (noul)
¿La página presenta señales de phishing o suplantación de identidad?

### 2. is_malicious (noul)
¿La página presenta indicios de contenido o actividad maliciosa?

### 3. threat_type (choice)
¿Qué tipo de amenaza representa esta página?
- `phishing`: Robo de credenciales
- `malware`: Distribución de software malicioso
- `scam`: Estafas o fraudes
- `benign`: Página legítima
- `other`: Otra amenaza

### 4. risk_level (score)
¿Cuál es el nivel de riesgo general?
- 0: Seguro
- 1: Bajo riesgo
- 2: Riesgo moderado
- 3: Alto riesgo
- 4: Crítico

## Manejo de Errores

```python
from kev_integration import (
    KevService,
    KevConnectionError,
    KevTimeoutError,
    KevRequestError,
    KevInvalidResponseError,
)

service = KevService()

try:
    result = service.analyze(request)
except KevConnectionError:
    print("No se pudo conectar a Kev")
except KevTimeoutError:
    print("La solicitud tardó demasiado")
except KevRequestError as e:
    print(f"Error de Kev: {e.status_code} - {e.message}")
except KevInvalidResponseError:
    print("Respuesta inválida de Kev")
```

## Testing

### Tests Unitarios

```bash
# Desde el directorio kev_integration
python -m pytest tests/ -v
```

### Tests con Kev Real

```bash
# Con Kev corriendo
KEV_BASE_URL=http://localhost:8009 python -m pytest tests/test_integration.py -v
```

## Extensibilidad

### Agregar Nuevas Preguntas

Edita `questions.py`:

```python
@staticmethod
def get_questions() -> Dict[str, Dict[str, Any]]:
    return {
        # ... preguntas existentes ...
        "new_question": {
            "type": "noul",  # o "choice" o "score"
            "instructions": "Tu pregunta aquí",
            # "criteria": {...}  # para choice/score
        }
    }
```

### Incorporar Señales Externas

El `RiskCalculator` está diseñado para extenderse:

```python
result = service.analyze(
    request,
    domain_reputation=get_domain_reputation(request.domain),
    url_heuristics=analyze_url_heuristics(request.url),
)
```

## Logging

El módulo usa logging estándar de Python:

```python
import logging

logging.basicConfig(level=logging.INFO)
# o más específico
logging.getLogger("kev_integration").setLevel(logging.DEBUG)
```

Los logs incluyen:
- Request started
- Kev request sent
- Kev response received
- Latency
- Result type
- Errors

**Nota:** No se registra contenido sensible (cookies, tokens, credenciales).

## Estructura del Módulo

```
kev_integration/
├── __init__.py           # Exportaciones públicas
├── config.py             # Configuración
├── exceptions.py         # Excepciones personalizadas
├── models.py             # Modelos de datos (DTOs)
├── state_builder.py      # Construir state desde page data
├── questions.py          # Definición de preguntas
├── client.py             # HTTP client para Kev
├── normalizer.py         # Normalizar respuestas de Kev
├── risk_assessment.py    # Calcular risk scores
├── service.py            # Servicio principal
└── tests/                # Tests unitarios e integración
```

## Principios de Diseño

- **Separación de responsabilidades**: Cada componente tiene una única responsabilidad
- **SOLID**: Principios de diseño orientado a objetos
- **Dependency Injection**: Configuración inyectable
- **Tipado fuerte**: Pydantic para validación
- **Bajo acoplamiento**: El backend no necesita conocer detalles de Kev
- **Extensibilidad**: Fácil agregar nuevas preguntas y señales
- **Testeabilidad**: Tests unitarios con mocks, sin necesidad de Kev corriendo

## Limitaciones

- Requiere Kev server corriendo
- Latencia depende del modelo y hardware (típicamente 50-500ms)
- Precisión depende del modelo Kev usado (0.8B, 4B, 9B, 27B)

## Licencia

Apache-2.0
