"""State builder - transforms page data into Kev state format."""

import logging
from typing import Dict, Any
from .models import PageAnalysisRequest

logger = logging.getLogger(__name__)


class StateBuilder:
    """Builds structured state from page analysis requests.
    
    Responsible for transforming PageAnalysisRequest into the state format
    expected by Kev. This layer is separate from the HTTP client to maintain
    clear separation of concerns.
    """
    
    def build(self, request: PageAnalysisRequest) -> Dict[str, Any]:
        """Build state from page analysis request.
        
        Args:
            request: Page analysis request containing page data
            
        Returns:
            Structured state dictionary ready for Kev
        """
        logger.debug(
            "Building state for URL",
            extra={"url": request.url, "domain": request.domain}
        )
        
        state = request.to_state()
        
        logger.debug(
            "State built successfully",
            extra={
                "url": request.url,
                "state_keys": list(state.keys()),
                "has_visible_text": bool(request.visible_text),
                "has_page_content": bool(request.page_content),
            }
        )
        
        return state
