"""HTTP client for Kev API."""

import logging
import time
from typing import Dict, Any
import httpx

from .config import KevConfig
from .exceptions import (
    KevConnectionError,
    KevTimeoutError,
    KevInvalidResponseError,
    KevRequestError,
)
from .models import KevRawResponse

logger = logging.getLogger(__name__)


class KevClient:
    """HTTP client for communicating with Kev server.
    
    Responsible exclusively for HTTP communication with the Kev API.
    Does not handle business logic or state transformation.
    """
    
    def __init__(self, config: KevConfig):
        """Initialize Kev client.
        
        Args:
            config: Kev configuration
        """
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.timeout = config.timeout
        self.api_key = config.api_key
        
        logger.debug(
            "KevClient initialized",
            extra={"base_url": self.base_url, "timeout": self.timeout}
        )
    
    def analyze(self, state: Dict[str, Any], questions: Dict[str, Any]) -> KevRawResponse:
        """Send analysis request to Kev.
        
        Args:
            state: State data to analyze
            questions: Question definitions
            
        Returns:
            Raw Kev response
            
        Raises:
            KevConnectionError: If unable to connect to Kev
            KevTimeoutError: If request times out
            KevRequestError: If Kev returns HTTP error
            KevInvalidResponseError: If response is invalid
        """
        url = f"{self.base_url}/v1/systemone"
        
        payload = {
            "state": state,
            "model": self.config.model,
            "questions": questions,
        }
        
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        logger.info(
            "Sending request to Kev",
            extra={
                "url": url,
                "model": self.config.model,
                "num_questions": len(questions),
            }
        )
        
        start_time = time.time()
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, json=payload, headers=headers)
                
            elapsed_ms = (time.time() - start_time) * 1000
            
            logger.info(
                "Kev response received",
                extra={
                    "status_code": response.status_code,
                    "latency_ms": round(elapsed_ms, 2),
                }
            )
            
            if response.status_code == 401:
                raise KevRequestError(401, "Authentication failed - check API key")
            
            if response.status_code == 422:
                error_detail = response.json().get("detail", "Validation error")
                raise KevRequestError(422, f"Request validation failed: {error_detail}")
            
            if response.status_code >= 500:
                raise KevRequestError(
                    response.status_code,
                    f"Kev server error: {response.text[:200]}"
                )
            
            if response.status_code >= 400:
                raise KevRequestError(
                    response.status_code,
                    f"Kev request error: {response.text[:200]}"
                )
            
            try:
                response_data = response.json()
            except Exception as e:
                raise KevInvalidResponseError(
                    f"Failed to parse Kev response as JSON: {str(e)}"
                )
            
            try:
                kev_response = KevRawResponse(**response_data)
            except Exception as e:
                raise KevInvalidResponseError(
                    f"Invalid Kev response structure: {str(e)}"
                )
            
            logger.debug(
                "Kev response parsed successfully",
                extra={
                    "model": kev_response.model,
                    "num_answers": len(kev_response.answers),
                    "latency_ms": kev_response.latency_ms,
                }
            )
            
            return kev_response
            
        except httpx.ConnectError as e:
            logger.error("Failed to connect to Kev", extra={"error": str(e)})
            raise KevConnectionError(f"Unable to connect to Kev at {self.base_url}: {str(e)}")
        
        except httpx.TimeoutException as e:
            logger.error("Kev request timed out", extra={"timeout": self.timeout})
            raise KevTimeoutError(f"Kev request timed out after {self.timeout} seconds")
        
        except httpx.HTTPError as e:
            logger.error("HTTP error during Kev request", extra={"error": str(e)})
            raise KevConnectionError(f"HTTP error: {str(e)}")
