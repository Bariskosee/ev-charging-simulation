"""
EV_Central Security REST API.

Provides endpoints for:
- CP authentication
- Key management (revoke, reset)
- Status management (revoke, out-of-service, restore)
- Security monitoring

Includes centralized audit logging for all security operations.
"""

from typing import Optional
from fastapi import FastAPI, HTTPException, status, Header, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from loguru import logger

from evcharging.apps.ev_central.main import get_controller, EVCentralController
from evcharging.common.cp_security import CPSecurityStatus
from evcharging.common.audit_service import get_audit_service, RequestContext
from evcharging.common.audit_middleware import (
    AuditContextMiddleware, 
    get_audit_context_or_default
)


# ========== Request/Response Models ==========

class CPAuthRequest(BaseModel):
    """Request to authenticate a CP."""
    cp_id: str = Field(..., description="Charging point identifier")
    credentials: str = Field(..., description="Secret credentials from EV_Registry registration")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "credentials": "a1b2c3d4e5f6..."
            }
        }
    }


class CPAuthTokenRequest(BaseModel):
    """Request to authenticate using token."""
    cp_id: str = Field(..., description="Charging point identifier")
    token: str = Field(..., description="JWT access token")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    }


class CPAuthResponse(BaseModel):
    """Response after authentication."""
    success: bool
    cp_id: str
    security_status: str
    is_authorized: bool
    message: str
    token: Optional[str] = None


class KeyOperationRequest(BaseModel):
    """Request for key operations."""
    cp_id: str = Field(..., description="Charging point identifier")
    reason: Optional[str] = Field(None, description="Reason for operation")


class StatusOperationRequest(BaseModel):
    """Request for status operations."""
    cp_id: str = Field(..., description="Charging point identifier")
    reason: str = Field(..., description="Reason for status change")


class OperationResponse(BaseModel):
    """Generic operation response."""
    success: bool
    cp_id: str
    message: str


class CPSecurityInfo(BaseModel):
    """CP security information."""
    cp_id: str
    security_status: str
    is_authenticated: bool
    has_encryption_key: bool
    last_auth_time: Optional[str]
    engine_state: str
    display_state: str


# ========== API Application ==========

def create_security_api(controller: EVCentralController) -> FastAPI:
    """
    Create FastAPI application for security operations.
    
    Args:
        controller: EV Central controller instance
        
    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="EV_Central Security API",
        description="Security operations for EV charging network",
        version="2.0.0"
    )
    
    # Add audit context middleware
    app.add_middleware(AuditContextMiddleware)
    
    # Get audit service
    audit = get_audit_service()
    
    # ========== Exception Handlers ==========
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle validation errors with audit logging."""
        ctx = get_audit_context_or_default(request)
        
        # Extract field names from validation errors (do NOT log values)
        field_errors = []
        for error in exc.errors():
            field_path = ".".join(str(loc) for loc in error['loc'])
            error_type = error['type']
            field_errors.append(f"{field_path}:{error_type}")
        
        fields_summary = ", ".join(field_errors[:5])  # Limit to 5 errors
        if len(field_errors) > 5:
            fields_summary += f" (+{len(field_errors) - 5} more)"
        
        # Write audit event
        audit.validation_error(
            ctx=ctx,
            fields_summary=fields_summary,
            metadata={"error_count": len(field_errors)}
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": exc.errors(),
                "request_id": ctx.request_id
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions with audit logging."""
        ctx = get_audit_context_or_default(request)
        
        # Get safe error message (do NOT expose full stack trace)
        error_type = type(exc).__name__
        safe_message = str(exc)[:200]  # Limit message length
        
        # Write audit event
        audit.error(
            ctx=ctx,
            error_type=error_type,
            safe_message=safe_message,
            metadata={"endpoint": ctx.endpoint, "method": ctx.http_method}
        )
        
        # Log full error for debugging
        logger.exception(f"Unhandled exception in {ctx.endpoint}: {exc}")
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "error_type": error_type,
                "request_id": ctx.request_id
            }
        )
    
    # Helper function for admin authentication
    async def verify_admin_key(request: Request, x_admin_key: Optional[str] = Header(None)) -> bool:
        """Verify admin API key with audit logging."""
        ctx = get_audit_context_or_default(request)
        
        # Load from environment - no hardcoded fallback for security
        import os
        expected_key = os.environ.get("EV_ADMIN_KEY")
        
        if not expected_key:
            logger.error("EV_ADMIN_KEY environment variable not set - admin operations disabled")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Admin operations are not configured"
            )
        
        if not x_admin_key or x_admin_key != expected_key:
            # Log unauthorized admin access attempt as security incident
            audit.incident(
                who_or_unknown="admin",
                ctx=ctx,
                incident_type=audit.INCIDENT_UNAUTHORIZED_ADMIN,
                description=f"Unauthorized admin access attempt to {ctx.endpoint}",
                metadata={"provided_key": "***" if x_admin_key else None}
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing admin key"
            )
        return True
    
    # ========== Authentication Endpoints ==========
    
    @app.post(
        "/auth/credentials",
        response_model=CPAuthResponse,
        summary="Authenticate CP with credentials",
        description="Authenticate a charging point using EV_Registry-issued credentials"
    )
    async def authenticate_with_credentials(req: CPAuthRequest, request: Request):
        """Authenticate a CP using credentials."""
        ctx = get_audit_context_or_default(request)
        
        try:
            result = controller.cp_security.authenticate_cp(
                req.cp_id,
                req.credentials
            )
            
            # Audit logging based on result
            if result.success and result.is_authorized():
                # Auth success
                audit.auth_success(
                    cp_id=req.cp_id,
                    ctx=ctx,
                    metadata={"security_status": result.status.value if result.status else "UNKNOWN"}
                )
            else:
                # Auth failure
                reason_code = (
                    audit.REASON_REVOKED if result.status == CPSecurityStatus.REVOKED
                    else audit.REASON_OUT_OF_SERVICE if result.status == CPSecurityStatus.OUT_OF_SERVICE
                    else audit.REASON_INVALID_CREDENTIALS
                )
                audit.auth_fail(
                    cp_id_or_unknown=req.cp_id,
                    ctx=ctx,
                    reason_code=reason_code,
                    description=result.reason or "Authentication failed",
                    metadata={"security_status": result.status.value if result.status else "UNKNOWN"}
                )
                # Check for brute force
                audit.detect_and_report_brute_force(req.cp_id, ctx)
            
            return CPAuthResponse(
                success=result.success,
                cp_id=result.cp_id,
                security_status=result.status.value if result.status else "UNKNOWN",
                is_authorized=result.is_authorized(),
                message=result.reason or "Authentication processed",
                token=result.token
            )
        
        except Exception as e:
            logger.error(f"Authentication endpoint error: {e}")
            
            # Audit error
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who=req.cp_id,
                metadata={"operation": "auth_credentials"}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentication failed: {str(e)}"
            )
    
    @app.post(
        "/auth/token",
        response_model=CPAuthResponse,
        summary="Authenticate CP with token",
        description="Authenticate a charging point using JWT token"
    )
    async def authenticate_with_token(req: CPAuthTokenRequest, request: Request):
        """Authenticate a CP using JWT token."""
        ctx = get_audit_context_or_default(request)
        
        try:
            result = controller.cp_security.verify_token(req.token)
            
            if not result:
                # Invalid token
                audit.auth_fail(
                    cp_id_or_unknown=req.cp_id,
                    ctx=ctx,
                    reason_code=audit.REASON_INVALID_TOKEN,
                    description="Invalid or expired token"
                )
                audit.detect_and_report_brute_force(req.cp_id, ctx)
                
                return CPAuthResponse(
                    success=False,
                    cp_id=req.cp_id,
                    security_status="UNKNOWN",
                    is_authorized=False,
                    message="Invalid token"
                )
            
            if result.cp_id != req.cp_id:
                # Token CP ID mismatch
                audit.auth_fail(
                    cp_id_or_unknown=req.cp_id,
                    ctx=ctx,
                    reason_code=audit.REASON_INVALID_TOKEN,
                    description=f"Token CP ID mismatch: expected {req.cp_id}, got {result.cp_id}"
                )
                audit.detect_and_report_brute_force(req.cp_id, ctx)
                
                return CPAuthResponse(
                    success=False,
                    cp_id=req.cp_id,
                    security_status="UNKNOWN",
                    is_authorized=False,
                    message="Token CP ID mismatch"
                )
            
            # Token valid - audit success
            if result.is_authorized():
                audit.auth_success(
                    cp_id=result.cp_id,
                    ctx=ctx,
                    metadata={
                        "security_status": result.status.value if result.status else "UNKNOWN",
                        "auth_method": "token"
                    }
                )
            else:
                # Token valid but CP not authorized (revoked/out of service)
                reason_code = (
                    audit.REASON_REVOKED if result.status == CPSecurityStatus.REVOKED
                    else audit.REASON_OUT_OF_SERVICE
                )
                audit.auth_fail(
                    cp_id_or_unknown=result.cp_id,
                    ctx=ctx,
                    reason_code=reason_code,
                    description=result.reason or "Token valid but CP not authorized"
                )
            
            return CPAuthResponse(
                success=result.success,
                cp_id=result.cp_id,
                security_status=result.status.value if result.status else "UNKNOWN",
                is_authorized=result.is_authorized(),
                message=result.reason or "Token valid",
                token=req.token
            )
        
        except Exception as e:
            logger.error(f"Token authentication endpoint error: {e}")
            
            # Audit error
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who=req.cp_id,
                metadata={"operation": "auth_token"}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token authentication failed: {str(e)}"
            )
    
    # ========== Key Management Endpoints (Admin Only) ==========
    
    @app.post(
        "/keys/generate",
        response_model=OperationResponse,
        summary="Generate encryption key for CP",
        description="Generate a new encryption key for a charging point (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def generate_key(req: KeyOperationRequest, request: Request):
        """Generate a new encryption key for a CP."""
        ctx = get_audit_context_or_default(request)
        
        try:
            success = controller.cp_security.generate_key_for_cp(req.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate key"
                )
            
            # Update CP state
            if req.cp_id in controller.charging_points:
                controller.charging_points[req.cp_id].has_encryption_key = True
            
            # Audit: KEY_GENERATE
            audit.key_generate(
                cp_id=req.cp_id,
                ctx=ctx,
                metadata={"reason": req.reason}
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message="Encryption key generated successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key generation error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "key_generate", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Key generation failed: {str(e)}"
            )
    
    @app.post(
        "/keys/revoke",
        response_model=OperationResponse,
        summary="Revoke CP encryption key",
        description="Revoke a CP's encryption key (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def revoke_key(req: KeyOperationRequest, request: Request):
        """Revoke a CP's encryption key."""
        ctx = get_audit_context_or_default(request)
        
        try:
            success = controller.cp_security.revoke_key_for_cp(req.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Key not found or already revoked"
                )
            
            # Update CP state
            if req.cp_id in controller.charging_points:
                controller.charging_points[req.cp_id].has_encryption_key = False
            
            # Audit: KEY_REVOKE
            audit.key_revoke(
                cp_id=req.cp_id,
                ctx=ctx,
                reason=req.reason,
                metadata={"reason": req.reason}
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message="Encryption key revoked successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key revocation error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "key_revoke", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Key revocation failed: {str(e)}"
            )
    
    @app.post(
        "/keys/reset",
        response_model=OperationResponse,
        summary="Reset (rotate) CP encryption key",
        description="Reset a CP's encryption key by revoking old and generating new (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def reset_key(req: KeyOperationRequest, request: Request):
        """Reset a CP's encryption key."""
        ctx = get_audit_context_or_default(request)
        
        try:
            success = controller.cp_security.reset_key_for_cp(req.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to reset key"
                )
            
            # Update CP state
            if req.cp_id in controller.charging_points:
                controller.charging_points[req.cp_id].has_encryption_key = True
            
            # Audit: KEY_RESET
            audit.key_reset(
                cp_id=req.cp_id,
                ctx=ctx,
                reason=req.reason,
                metadata={"reason": req.reason}
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message="Encryption key reset successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key reset error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "key_reset", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Key reset failed: {str(e)}"
            )
    
    # ========== Status Management Endpoints (Admin Only) ==========
    
    @app.post(
        "/status/revoke",
        response_model=OperationResponse,
        summary="Revoke CP access",
        description="Revoke a CP's access (CRITICAL - blocks all operations) (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def revoke_cp(req: StatusOperationRequest, request: Request):
        """Revoke a CP's access."""
        ctx = get_audit_context_or_default(request)
        
        try:
            # Get old status before change
            old_status = "UNKNOWN"
            if req.cp_id in controller.charging_points:
                old_status = controller.charging_points[req.cp_id].security_status.value
            
            controller.revoke_cp_access(req.cp_id, req.reason)
            
            # Audit: STATUS_CHANGE
            audit.status_change(
                cp_id=req.cp_id,
                ctx=ctx,
                old_status=old_status,
                new_status="REVOKED",
                reason=req.reason
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message=f"CP revoked: {req.reason}"
            )
        
        except Exception as e:
            logger.error(f"CP revocation error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "revoke_cp", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"CP revocation failed: {str(e)}"
            )
    
    @app.post(
        "/status/out-of-service",
        response_model=OperationResponse,
        summary="Set CP out of service",
        description="Mark a CP as out of service (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def set_out_of_service(req: StatusOperationRequest, request: Request):
        """Set a CP as out of service."""
        ctx = get_audit_context_or_default(request)
        
        try:
            # Get old status before change
            old_status = "UNKNOWN"
            if req.cp_id in controller.charging_points:
                old_status = controller.charging_points[req.cp_id].security_status.value
            
            controller.set_cp_out_of_service(req.cp_id, req.reason)
            
            # Audit: STATUS_CHANGE
            audit.status_change(
                cp_id=req.cp_id,
                ctx=ctx,
                old_status=old_status,
                new_status="OUT_OF_SERVICE",
                reason=req.reason
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message=f"CP set to OUT_OF_SERVICE: {req.reason}"
            )
        
        except Exception as e:
            logger.error(f"Out-of-service operation error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "set_out_of_service", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Operation failed: {str(e)}"
            )
    
    @app.post(
        "/status/restore",
        response_model=OperationResponse,
        summary="Restore CP to active",
        description="Restore a CP from OUT_OF_SERVICE to ACTIVE (admin only)",
        dependencies=[Depends(verify_admin_key)]
    )
    async def restore_cp(req: KeyOperationRequest, request: Request):
        """Restore a CP to active status."""
        ctx = get_audit_context_or_default(request)
        
        try:
            # Get old status before change
            old_status = "UNKNOWN"
            if req.cp_id in controller.charging_points:
                old_status = controller.charging_points[req.cp_id].security_status.value
            
            controller.restore_cp_to_active(req.cp_id)
            
            # Audit: STATUS_CHANGE
            audit.status_change(
                cp_id=req.cp_id,
                ctx=ctx,
                old_status=old_status,
                new_status="ACTIVE",
                reason=req.reason or "Restored by admin"
            )
            
            return OperationResponse(
                success=True,
                cp_id=req.cp_id,
                message="CP restored to ACTIVE"
            )
        
        except Exception as e:
            logger.error(f"CP restoration error: {e}")
            
            audit.error(
                ctx=ctx,
                error_type=type(e).__name__,
                safe_message=str(e)[:200],
                who="admin",
                metadata={"operation": "restore_cp", "cp_id": req.cp_id}
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"CP restoration failed: {str(e)}"
            )
    
    # ========== Monitoring Endpoints ==========
    
    @app.get(
        "/security/status/{cp_id}",
        response_model=CPSecurityInfo,
        summary="Get CP security status",
        description="Get security information for a specific CP"
    )
    async def get_cp_security_status(cp_id: str):
        """Get security status for a CP."""
        try:
            if cp_id not in controller.charging_points:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"CP {cp_id} not found"
                )
            
            cp = controller.charging_points[cp_id]
            
            return CPSecurityInfo(
                cp_id=cp.cp_id,
                security_status=cp.security_status.value,
                is_authenticated=cp.is_authenticated,
                has_encryption_key=cp.has_encryption_key,
                last_auth_time=cp.last_auth_time.isoformat() if cp.last_auth_time else None,
                engine_state=cp.state.value,
                display_state=cp.get_display_state()
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security status query error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get security status: {str(e)}"
            )
    
    @app.get(
        "/security/status",
        summary="Get all CP security statuses",
        description="Get security information for all CPs"
    )
    async def get_all_security_statuses():
        """Get security status for all CPs."""
        try:
            return {
                "cps": [
                    {
                        "cp_id": cp.cp_id,
                        "security_status": cp.security_status.value,
                        "is_authenticated": cp.is_authenticated,
                        "has_encryption_key": cp.has_encryption_key,
                        "last_auth_time": cp.last_auth_time.isoformat() if cp.last_auth_time else None,
                        "engine_state": cp.state.value,
                        "display_state": cp.get_display_state(),
                        # Encryption error display
                        "communication_status": cp.communication_status,
                        "encryption_error": cp.encryption_error,
                        "encryption_error_type": cp.encryption_error_type,
                        "encryption_error_timestamp": (
                            cp.encryption_error_timestamp.isoformat() 
                            if cp.encryption_error_timestamp else None
                        )
                    }
                    for cp in controller.charging_points.values()
                ],
                "total_cps": len(controller.charging_points),
                "authenticated_cps": sum(1 for cp in controller.charging_points.values() if cp.is_authenticated),
                "active_cps": sum(1 for cp in controller.charging_points.values() if cp.security_status == CPSecurityStatus.ACTIVE),
                "encryption_error_cps": sum(
                    1 for cp in controller.charging_points.values() 
                    if cp.communication_status == "ENCRYPTION_ERROR"
                )
            }
        
        except Exception as e:
            logger.error(f"All security statuses query error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get security statuses: {str(e)}"
            )
    
    @app.get(
        "/security/encryption-errors",
        summary="Get all encryption errors",
        description="Get all active encryption/decryption errors across CPs"
    )
    async def get_encryption_errors():
        """Get all active encryption errors."""
        from evcharging.common.encrypted_kafka import get_encryption_error_tracker
        
        tracker = get_encryption_error_tracker()
        
        return {
            "active_errors": tracker.get_error_list(),
            "error_count": len(tracker.get_all_errors()),
            "recent_history": tracker.get_history(limit=20),
            "cp_errors": [
                {
                    "cp_id": cp.cp_id,
                    "communication_status": cp.communication_status,
                    "encryption_error": cp.encryption_error,
                    "encryption_error_type": cp.encryption_error_type,
                    "encryption_error_timestamp": (
                        cp.encryption_error_timestamp.isoformat() 
                        if cp.encryption_error_timestamp else None
                    )
                }
                for cp in controller.charging_points.values()
                if cp.communication_status == "ENCRYPTION_ERROR"
            ]
        }
    
    @app.get("/health", summary="Health check")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "ev-central-security"}
    
    return app
