"""Question definitions for security analysis."""

from typing import Dict, Any


class QuestionConfig:
    """Centralized configuration for security questions.
    
    Defines the questions we ask Kev for phishing/threat detection.
    Each question has a unique ID, type, instructions, and criteria.
    """
    
    @staticmethod
    def get_questions() -> Dict[str, Dict[str, Any]]:
        """Get all security analysis questions.
        
        Returns:
            Dictionary of question definitions keyed by question ID
        """
        return {
            "is_phishing": {
                "type": "noul",
                "instructions": "¿La página presenta señales de phishing o suplantación de identidad? Evalúa si hay formularios que solicitan credenciales, logos de marcas conocidas en contextos sospechosos, URLs engañosas, o contenido que intenta hacerse pasar por una entidad legítima.",
            },
            "is_malicious": {
                "type": "noul",
                "instructions": "¿La página presenta indicios de contenido o actividad maliciosa? Evalúa si hay intentos de descarga automática, scripts sospechosos, redirecciones engañosas, advertencias falsas de seguridad, o contenido que intente instalar software no deseado.",
            },
            "threat_type": {
                "type": "choice",
                "instructions": "¿Qué tipo de amenaza representa esta página?",
                "criteria": {
                    "phishing": "Página que intenta robar credenciales o información personal haciéndose pasar por una entidad legítima",
                    "malware": "Página que distribuye software malicioso o intenta instalar código dañino",
                    "scam": "Página de estafa o fraude financiero, ofertas falsas, sorteos engañosos",
                    "benign": "Página legítima y segura sin indicios de amenaza",
                    "other": "Otro tipo de amenaza no clasificada en las categorías anteriores",
                },
            },
            "risk_level": {
                "type": "score",
                "instructions": "¿Cuál es el nivel de riesgo general de esta página?",
                "criteria": [
                    "Seguro - Página legítima sin riesgos aparentes",
                    "Bajo riesgo - Página mayormente segura con características menores sospechosas",
                    "Riesgo moderado - Página con múltiples señales de alerta",
                    "Alto riesgo - Página con fuertes indicios de ser maliciosa o fraudulenta",
                    "Crítico - Página claramente maliciosa o de phishing confirmado",
                ],
            },
        }
