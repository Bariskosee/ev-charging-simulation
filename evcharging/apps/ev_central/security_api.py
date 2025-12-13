"""
EV_Central Security REST API.

Provides endpoints for:
- CP authentication
- Key management (revoke, reset)
- Status management (revoke, out-of-service, restore)
- Security monitoring
"""

from typing import Optional
from fastapi import FastAPI, HTTPException, status, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from loguru import logger

from evcharging.apps.ev_central.main import get_controller, EVCentralController
from evcharging.common.cp_security import CPSecurityStatus


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
    
    # Helper function for admin authentication
    async def verify_admin_key(x_admin_key: Optional[str] = Header(None)) -> bool:
        """Verify admin API key."""
        # In production, load from secure config
        import os
        expected_key = os.environ.get("EV_ADMIN_KEY", "admin-secret-change-in-production")
        
        if not x_admin_key or x_admin_key != expected_key:
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
    async def authenticate_with_credentials(request: CPAuthRequest):
        """Authenticate a CP using credentials."""
        try:
            result = controller.cp_security.authenticate_cp(
                request.cp_id,
                request.credentials
            )
            
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
    async def authenticate_with_token(request: CPAuthTokenRequest):
        """Authenticate a CP using JWT token."""
        try:
            result = controller.cp_security.verify_token(request.token)
            
            if not result:
                return CPAuthResponse(
                    success=False,
                    cp_id=request.cp_id,
                    security_status="UNKNOWN",
                    is_authorized=False,
                    message="Invalid token"
                )
            
            if result.cp_id != request.cp_id:
                return CPAuthResponse(
                    success=False,
                    cp_id=request.cp_id,
                    security_status="UNKNOWN",
                    is_authorized=False,
                    message="Token CP ID mismatch"
                )
            
            return CPAuthResponse(
                success=result.success,
                cp_id=result.cp_id,
                security_status=result.status.value if result.status else "UNKNOWN",
                is_authorized=result.is_authorized(),
                message=result.reason or "Token valid",
                token=request.token
            )
        
        except Exception as e:
            logger.error(f"Token authentication endpoint error: {e}")
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
    async def generate_key(request: KeyOperationRequest):
        """Generate a new encryption key for a CP."""
        try:
            success = controller.cp_security.generate_key_for_cp(request.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate key"
                )
            
            # Update CP state
            if request.cp_id in controller.charging_points:
                controller.charging_points[request.cp_id].has_encryption_key = True
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message="Encryption key generated successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key generation error: {e}")
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
    async def revoke_key(request: KeyOperationRequest):
        """Revoke a CP's encryption key."""
        try:
            success = controller.cp_security.revoke_key_for_cp(request.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Key not found or already revoked"
                )
            
            # Update CP state
            if request.cp_id in controller.charging_points:
                controller.charging_points[request.cp_id].has_encryption_key = False
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message="Encryption key revoked successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key revocation error: {e}")
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
    async def reset_key(request: KeyOperationRequest):
        """Reset a CP's encryption key."""
        try:
            success = controller.cp_security.reset_key_for_cp(request.cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to reset key"
                )
            
            # Update CP state
            if request.cp_id in controller.charging_points:
                controller.charging_points[request.cp_id].has_encryption_key = True
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message="Encryption key reset successfully"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Key reset error: {e}")
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
    async def revoke_cp(request: StatusOperationRequest):
        """Revoke a CP's access."""
        try:
            controller.revoke_cp_access(request.cp_id, request.reason)
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message=f"CP revoked: {request.reason}"
            )
        
        except Exception as e:
            logger.error(f"CP revocation error: {e}")
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
    async def set_out_of_service(request: StatusOperationRequest):
        """Set a CP as out of service."""
        try:
            controller.set_cp_out_of_service(request.cp_id, request.reason)
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message=f"CP set to OUT_OF_SERVICE: {request.reason}"
            )
        
        except Exception as e:
            logger.error(f"Out-of-service operation error: {e}")
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
    async def restore_cp(request: KeyOperationRequest):
        """Restore a CP to active status."""
        try:
            controller.restore_cp_to_active(request.cp_id)
            
            return OperationResponse(
                success=True,
                cp_id=request.cp_id,
                message="CP restored to ACTIVE"
            )
        
        except Exception as e:
            logger.error(f"CP restoration error: {e}")
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
                        "display_state": cp.get_display_state()
                    }
                    for cp in controller.charging_points.values()
                ],
                "total_cps": len(controller.charging_points),
                "authenticated_cps": sum(1 for cp in controller.charging_points.values() if cp.is_authenticated),
                "active_cps": sum(1 for cp in controller.charging_points.values() if cp.security_status == CPSecurityStatus.ACTIVE)
            }
        
        except Exception as e:
            logger.error(f"All security statuses query error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get security statuses: {str(e)}"
            )
    
    @app.get("/health", summary="Health check")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "ev-central-security"}
    
    return app
