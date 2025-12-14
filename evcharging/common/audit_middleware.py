"""
FastAPI middleware for audit logging context.

Captures request metadata and propagates it through the request lifecycle
for consistent audit logging.
"""

import uuid
import os
from typing import Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger

from evcharging.common.audit_service import RequestContext


# Configuration for proxy headers
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"


class AuditContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware to capture and store request context for audit logging.
    
    Captures:
    - request_id: From X-Request-ID header or generates new UUID
    - ip: From X-Forwarded-For (if trusted) or client.host
    - endpoint: Request path
    - http_method: HTTP method
    
    Stores context in request.state for use by endpoints and audit service.
    """
    
    async def dispatch(self, request: Request, call_next):
        """Process request and inject audit context."""
        
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Determine client IP
        client_ip = self._get_client_ip(request)
        
        # Create request context
        ctx = RequestContext(
            request_id=request_id,
            ip=client_ip,
            endpoint=str(request.url.path),
            http_method=request.method
        )
        
        # Store in request state for access by endpoints
        request.state.audit_ctx = ctx
        
        # Log request (optional, for debugging)
        logger.debug(
            f"Request: {ctx.http_method} {ctx.endpoint} "
            f"[id={ctx.request_id}, ip={ctx.ip}]"
        )
        
        # Process request
        response: Response = await call_next(request)
        
        # Add request ID to response headers for traceability
        response.headers["X-Request-ID"] = request_id
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.
        
        Args:
            request: FastAPI request object
        
        Returns:
            Client IP address or "unknown"
        """
        # If behind proxy and we trust proxy headers
        if TRUST_PROXY_HEADERS:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                # X-Forwarded-For can contain multiple IPs, take the first (client)
                client_ip = forwarded_for.split(",")[0].strip()
                return client_ip
            
            # Try X-Real-IP as fallback
            real_ip = request.headers.get("X-Real-IP")
            if real_ip:
                return real_ip.strip()
        
        # Fall back to direct connection IP
        if request.client and request.client.host:
            return request.client.host
        
        return "unknown"


def get_audit_context(request: Request) -> Optional[RequestContext]:
    """
    Helper function to retrieve audit context from request.
    
    Args:
        request: FastAPI request object
    
    Returns:
        RequestContext if available, None otherwise
    """
    return getattr(request.state, "audit_ctx", None)


def get_audit_context_or_default(request: Request) -> RequestContext:
    """
    Helper function to retrieve audit context or create a default one.
    
    Args:
        request: FastAPI request object
    
    Returns:
        RequestContext (always returns a valid context)
    """
    ctx = get_audit_context(request)
    
    if ctx is None:
        # Fallback if middleware not configured
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            ip=request.client.host if request.client else "unknown",
            endpoint=str(request.url.path),
            http_method=request.method
        )
    
    return ctx
