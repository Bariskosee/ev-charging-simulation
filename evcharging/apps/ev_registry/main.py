"""
EV Registry - Charging Point Registration and Authentication Service

REST API for:
- CP registration (POST /cp/register)
- CP deregistration (DELETE /cp/{cpId})
- CP authentication (POST /cp/authenticate)
- CP query (GET /cp, GET /cp/{cpId})
"""

import argparse
import sys
from typing import Optional, List
from datetime import datetime
from fastapi import FastAPI, HTTPException, status, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
from loguru import logger

from evcharging.common.config import RegistryConfig
from evcharging.common.database import CPRegistryDB
from evcharging.common.security import SecurityManager, create_security_manager, validate_admin_key
from evcharging.common.utils import utc_now


# ========== Request/Response Models ==========

class CPRegisterRequest(BaseModel):
    """Request to register a charging point."""
    cp_id: str = Field(..., description="Charging point identifier", min_length=3, max_length=64)
    location: str = Field(..., description="CP location (city/address)", min_length=2, max_length=256)
    certificate_pem: Optional[str] = Field(None, description="Optional PEM-encoded client certificate")
    metadata: Optional[dict] = Field(None, description="Optional metadata")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "location": "Berlin",
                "metadata": {"power_rating": "22kW", "type": "AC"}
            }
        }
    }


class CPRegisterResponse(BaseModel):
    """Response after successful CP registration."""
    cp_id: str
    location: str
    status: str
    credentials: str = Field(..., description="Secret credentials for authentication (store securely)")
    token: str = Field(..., description="JWT access token for authentication with EV_Central")
    token_expires_at: str
    registration_date: str
    message: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "location": "Berlin",
                "status": "REGISTERED",
                "credentials": "a1b2c3d4e5f6...",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_expires_at": "2025-12-12T10:30:00Z",
                "registration_date": "2025-12-11T10:30:00Z",
                "message": "CP registered successfully"
            }
        }
    }


class CPAuthenticateRequest(BaseModel):
    """Request to authenticate a charging point."""
    cp_id: str = Field(..., description="Charging point identifier")
    credentials: str = Field(..., description="Secret credentials provided during registration")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "credentials": "a1b2c3d4e5f6..."
            }
        }
    }


class CPAuthenticateResponse(BaseModel):
    """Response after successful authentication."""
    cp_id: str
    location: str
    status: str
    token: str = Field(..., description="JWT access token")
    token_expires_at: str
    last_authenticated: str
    message: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "cp_id": "CP-001",
                "location": "Berlin",
                "status": "REGISTERED",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_expires_at": "2025-12-12T10:30:00Z",
                "last_authenticated": "2025-12-11T10:30:00Z",
                "message": "Authentication successful"
            }
        }
    }


class CPInfoResponse(BaseModel):
    """Response with CP information."""
    cp_id: str
    location: str
    status: str
    registration_date: str
    deregistration_date: Optional[str]
    last_authenticated: Optional[str]
    has_certificate: bool
    metadata: Optional[dict]


class CPListResponse(BaseModel):
    """Response with list of CPs."""
    cps: List[CPInfoResponse]
    total: int
    limit: int
    offset: int


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    timestamp: str


# ========== FastAPI Application ==========

def create_app(config: RegistryConfig) -> FastAPI:
    """Create and configure FastAPI application."""
    
    app = FastAPI(
        title="EV Registry API",
        description="Charging Point Registration and Authentication Service",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Initialize components
    db = CPRegistryDB(config.db_path)
    security_mgr = create_security_manager(
        secret_key=config.secret_key,
        token_expiration_hours=config.token_expiration_hours,
        jwt_issuer=config.jwt_issuer,
        jwt_audience=config.jwt_audience
    )
    
    # Store in app state
    app.state.db = db
    app.state.security = security_mgr
    app.state.config = config
    
    # Security validation
    if config.tls_enabled and (not config.tls_cert_file or not config.tls_key_file):
        if not config.allow_insecure:
            logger.error("TLS is enabled but certificate files not provided. Set allow_insecure=true for dev only.")
            raise ValueError("TLS configuration incomplete")
        else:
            logger.warning("⚠️  Running in INSECURE mode - TLS disabled. DO NOT USE IN PRODUCTION!")
    
    if not config.tls_enabled and not config.allow_insecure:
        logger.error("TLS is disabled but allow_insecure is false. Enable TLS or set allow_insecure=true.")
        raise ValueError("Secure transport required - enable TLS or explicitly allow insecure mode")
    
    logger.info(f"Initialized EV Registry with database: {config.db_path}")
    logger.info(f"TLS enabled: {config.tls_enabled}")
    logger.info(f"Certificate authentication required: {config.require_certificate}")
    logger.info(f"Token expiration: {config.token_expiration_hours} hours")
    logger.info(f"JWT issuer: {config.jwt_issuer}, audience: {config.jwt_audience}")
    
    # ========== Endpoints ==========
    
    @app.get("/", tags=["Health"])
    async def root():
        """Health check endpoint."""
        return {
            "service": "EV Registry",
            "status": "operational",
            "version": "2.0.0",
            "timestamp": utc_now().isoformat()
        }
    
    @app.post(
        "/cp/register",
        response_model=CPRegisterResponse,
        status_code=status.HTTP_200_OK,
        tags=["Registration"]
    )
    async def register_cp(
        request: CPRegisterRequest,
        x_registry_api_key: Optional[str] = Header(None, alias=config.api_key_header),
        x_existing_credentials: Optional[str] = Header(None, description="Existing credentials for re-registration")
    ):
        """
        Register a new charging point or re-register existing CP.
        
        - Validates CP ID and location
        - Generates secure credentials
        - Stores CP information in registry database
        - Returns credentials and access token
        
        **Security**: 
        - Credentials are returned only once during registration
        - Re-registration requires either existing credentials OR admin API key
        - Store credentials securely - they cannot be retrieved later
        
        **Re-registration Protection**:
        To update an existing CP, provide EITHER:
        - `X-Existing-Credentials` header with current credentials, OR
        - `X-Registry-API-Key` header with admin key (if configured)
        """
        try:
            # Validate input
            if not security_mgr.validate_cp_id(request.cp_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid CP ID format. Must be 3-64 alphanumeric characters, hyphens, or underscores."
                )
            
            if not security_mgr.validate_location(request.location):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid location. Must be 2-256 characters."
                )
            
            # Check if CP already exists
            existing_cp = db.get_cp(request.cp_id)
            is_reregistration = existing_cp is not None
            
            if is_reregistration:
                # RE-REGISTRATION: Require proof of ownership
                logger.info(f"Re-registration attempt for existing CP: {request.cp_id}")
                
                # Option 1: Verify existing credentials
                credentials_verified = False
                if x_existing_credentials:
                    stored_hash = db.get_cp_credentials(request.cp_id)
                    if stored_hash and security_mgr.verify_credentials(x_existing_credentials, stored_hash):
                        credentials_verified = True
                        logger.info(f"Re-registration authorized via existing credentials for {request.cp_id}")
                
                # Option 2: Verify admin API key
                admin_authorized = False
                if x_registry_api_key:
                    if validate_admin_key(x_registry_api_key, config.admin_api_key):
                        admin_authorized = True
                        logger.info(f"Re-registration authorized via admin key for {request.cp_id}")
                
                # Reject if neither authorization method succeeded
                if not credentials_verified and not admin_authorized:
                    logger.warning(
                        f"Unauthorized re-registration attempt for {request.cp_id} - "
                        "no valid credentials or admin key provided"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Re-registration requires existing credentials (X-Existing-Credentials header) "
                               "or admin authorization (X-Registry-API-Key header)"
                    )
            # Validate input
            if not security_mgr.validate_cp_id(request.cp_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid CP ID format. Must be 3-64 alphanumeric characters, hyphens, or underscores."
                )
            
            if not security_mgr.validate_location(request.location):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid location. Must be 2-256 characters."
                )
            
            # Generate credentials
            credentials = security_mgr.generate_credentials(32)
            credentials_hash = security_mgr.hash_credentials(credentials)
            
            # Extract certificate fingerprint if provided
            cert_fingerprint = None
            if request.certificate_pem:
                try:
                    cert_fingerprint = security_mgr.extract_certificate_fingerprint(
                        request.certificate_pem
                    )
                    logger.info(f"Certificate fingerprint extracted for {request.cp_id}")
                except ValueError as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid certificate: {str(e)}"
                    )
            elif config.require_certificate:
                # Certificate is required but not provided
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Client certificate is required for registration"
                )
            
            # Store metadata as JSON
            metadata_json = None
            if request.metadata:
                import json
                metadata_json = json.dumps(request.metadata)
            
            # Register in database
            is_new = db.register_cp(
                cp_id=request.cp_id,
                location=request.location,
                credentials_hash=credentials_hash,
                certificate_fingerprint=cert_fingerprint,
                metadata=metadata_json
            )
            
            # Create access token
            token = security_mgr.create_access_token(
                cp_id=request.cp_id,
                location=request.location
            )
            
            # Calculate token expiration
            token_expires_at = (
                utc_now().replace(microsecond=0) +
                __import__('datetime').timedelta(hours=config.token_expiration_hours)
            ).isoformat()
            
            registration_date = utc_now().isoformat()
            
            action = "re-registered" if is_reregistration else "registered"
            logger.info(
                f"CP {action}: {request.cp_id} at {request.location} "
                f"(cert={cert_fingerprint is not None})"
            )
            
            return CPRegisterResponse(
                cp_id=request.cp_id,
                location=request.location,
                status="REGISTERED",
                credentials=credentials,
                token=token,
                token_expires_at=token_expires_at,
                registration_date=registration_date,
                message="CP registered successfully. Store credentials securely - they cannot be retrieved later."
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error registering CP {request.cp_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during registration"
            )
    
    @app.delete(
        "/cp/{cp_id}",
        status_code=status.HTTP_200_OK,
        tags=["Registration"]
    )
    async def deregister_cp(cp_id: str):
        """
        Deregister a charging point.
        
        - Marks CP as deregistered
        - Prevents further authentication
        - Does not delete historical data
        """
        try:
            success = db.deregister_cp(cp_id)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"CP {cp_id} not found or already deregistered"
                )
            
            logger.info(f"CP deregistered: {cp_id}")
            
            return {
                "cp_id": cp_id,
                "status": "DEREGISTERED",
                "message": "CP deregistered successfully",
                "timestamp": utc_now().isoformat()
            }
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deregistering CP {cp_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during deregistration"
            )
    
    @app.post(
        "/cp/authenticate",
        response_model=CPAuthenticateResponse,
        status_code=status.HTTP_200_OK,
        tags=["Authentication"]
    )
    async def authenticate_cp(
        request: CPAuthenticateRequest,
        x_client_cert_fingerprint: Optional[str] = Header(None, description="Client certificate fingerprint (if required)")
    ):
        """
        Authenticate a charging point using credentials.
        
        - Validates CP ID and credentials
        - Verifies certificate fingerprint if required
        - Returns new access token if successful
        - Updates last authentication timestamp
        
        **Returns 401** for any authentication failure (normalized error response).
        
        **Certificate Authentication**:
        If certificate authentication is required, provide the SHA-256 fingerprint
        in the `X-Client-Cert-Fingerprint` header.
        """
        try:
            # Get CP from database
            cp_info = db.get_cp(request.cp_id)
            
            # Normalize all auth failures to 401 to prevent information leakage
            if not cp_info:
                logger.warning(f"Authentication failed: unknown CP {request.cp_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Check if CP is deregistered (still use 401, not 403)
            if cp_info['status'] != 'REGISTERED':
                logger.warning(f"Authentication failed: CP {request.cp_id} is {cp_info['status']}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Verify credentials
            credentials_hash = db.get_cp_credentials(request.cp_id)
            if not credentials_hash:
                logger.error(f"Authentication failed: No credentials found for {request.cp_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            if not security_mgr.verify_credentials(request.credentials, credentials_hash):
                logger.warning(f"Authentication failed: Invalid credentials for {request.cp_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Enforce certificate requirement if configured
            if config.require_certificate:
                stored_fingerprint = cp_info.get('certificate_fingerprint')
                
                if not stored_fingerprint:
                    logger.error(
                        f"Authentication failed: Certificate required but not registered for {request.cp_id}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication failed"
                    )
                
                if not x_client_cert_fingerprint:
                    logger.warning(
                        f"Authentication failed: Certificate required but not provided for {request.cp_id}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication failed"
                    )
                
                # Normalize fingerprint format (remove colons, uppercase)
                provided_fp = x_client_cert_fingerprint.replace(":", "").upper()
                stored_fp = stored_fingerprint.replace(":", "").upper()
                
                if provided_fp != stored_fp:
                    logger.warning(
                        f"Authentication failed: Certificate fingerprint mismatch for {request.cp_id}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication failed"
                    )
            
            # Update last authenticated timestamp
            db.update_last_authenticated(request.cp_id)
            
            # Create new access token
            token = security_mgr.create_access_token(
                cp_id=request.cp_id,
                location=cp_info['location']
            )
            
            token_expires_at = (
                utc_now().replace(microsecond=0) +
                __import__('datetime').timedelta(hours=config.token_expiration_hours)
            ).isoformat()
            
            last_authenticated = utc_now().isoformat()
            
            logger.info(f"CP authenticated successfully: {request.cp_id}")
            
            return CPAuthenticateResponse(
                cp_id=request.cp_id,
                location=cp_info['location'],
                status=cp_info['status'],
                token=token,
                token_expires_at=token_expires_at,
                last_authenticated=last_authenticated,
                message="Authentication successful"
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error authenticating CP {request.cp_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during authentication"
            )
    
    @app.get(
        "/cp/{cp_id}",
        response_model=CPInfoResponse,
        status_code=status.HTTP_200_OK,
        tags=["Query"]
    )
    async def get_cp(cp_id: str):
        """
        Get information about a specific charging point.
        
        **Does not return credentials** - only public information.
        """
        try:
            cp_info = db.get_cp(cp_id)
            
            if not cp_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"CP {cp_id} not found"
                )
            
            # Parse metadata if present
            metadata = None
            if cp_info.get('metadata'):
                import json
                try:
                    metadata = json.loads(cp_info['metadata'])
                except:
                    pass
            
            return CPInfoResponse(
                cp_id=cp_info['cp_id'],
                location=cp_info['location'],
                status=cp_info['status'],
                registration_date=cp_info['registration_date'],
                deregistration_date=cp_info.get('deregistration_date'),
                last_authenticated=cp_info.get('last_authenticated'),
                has_certificate=cp_info.get('certificate_fingerprint') is not None,
                metadata=metadata
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting CP {cp_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
    
    @app.get(
        "/cp",
        response_model=CPListResponse,
        status_code=status.HTTP_200_OK,
        tags=["Query"]
    )
    async def list_cps(
        status_filter: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ):
        """
        List all charging points with optional filtering.
        
        - **status_filter**: Filter by status ('REGISTERED' or 'DEREGISTERED')
        - **limit**: Maximum number of results (default 100, max 1000)
        - **offset**: Number of results to skip for pagination
        """
        try:
            # Validate parameters
            if limit < 1 or limit > 1000:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Limit must be between 1 and 1000"
                )
            
            if offset < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Offset must be non-negative"
                )
            
            if status_filter and status_filter not in ['REGISTERED', 'DEREGISTERED']:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="status_filter must be 'REGISTERED' or 'DEREGISTERED'"
                )
            
            # Get CPs from database
            cps = db.list_cps(status=status_filter, limit=limit, offset=offset)
            total = db.count_cps(status=status_filter)
            
            # Convert to response models
            cp_responses = []
            for cp in cps:
                metadata = None
                if cp.get('metadata'):
                    import json
                    try:
                        metadata = json.loads(cp['metadata'])
                    except:
                        pass
                
                cp_responses.append(CPInfoResponse(
                    cp_id=cp['cp_id'],
                    location=cp['location'],
                    status=cp['status'],
                    registration_date=cp['registration_date'],
                    deregistration_date=cp.get('deregistration_date'),
                    last_authenticated=cp.get('last_authenticated'),
                    has_certificate=cp.get('certificate_fingerprint') is not None,
                    metadata=metadata
                ))
            
            return CPListResponse(
                cps=cp_responses,
                total=total,
                limit=limit,
                offset=offset
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error listing CPs: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        """Custom exception handler for consistent error responses."""
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=exc.detail,
                detail=getattr(exc, 'detail', None),
                timestamp=utc_now().isoformat()
            ).model_dump()
        )
    
    return app


# ========== Main Entry Point ==========

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="EV Registry - CP Registration & Authentication Service")
    parser.add_argument("--port", type=int, help="API port (overrides config)")
    parser.add_argument("--db-path", type=str, help="Database file path (overrides config)")
    parser.add_argument("--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
    parser.add_argument("--tls-cert", type=str, help="Path to TLS certificate file")
    parser.add_argument("--tls-key", type=str, help="Path to TLS private key file")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Load configuration
    config = RegistryConfig()
    
    # Override with CLI arguments
    if args.port:
        config.api_port = args.port
    if args.db_path:
        config.db_path = args.db_path
    if args.log_level:
        config.log_level = args.log_level
    if args.tls_cert:
        config.tls_cert_file = args.tls_cert
        config.tls_enabled = True
    if args.tls_key:
        config.tls_key_file = args.tls_key
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> | <level>{message}</level>",
        level=config.log_level,
        colorize=True
    )
    
    logger.info("=" * 60)
    logger.info("EV Registry - Charging Point Registration & Authentication")
    logger.info("=" * 60)
    logger.info(f"API Port: {config.api_port}")
    logger.info(f"Database: {config.db_path}")
    logger.info(f"TLS Enabled: {config.tls_enabled}")
    logger.info(f"Log Level: {config.log_level}")
    
    # Create FastAPI app
    app = create_app(config)
    
    # Prepare SSL context if TLS is enabled
    ssl_kwargs = {}
    if config.tls_enabled:
        if not config.tls_cert_file or not config.tls_key_file:
            logger.error("TLS enabled but certificate/key files not specified")
            sys.exit(1)
        
        ssl_kwargs = {
            "ssl_certfile": config.tls_cert_file,
            "ssl_keyfile": config.tls_key_file
        }
        logger.info(f"TLS Certificate: {config.tls_cert_file}")
        logger.info(f"TLS Key: {config.tls_key_file}")
    
    logger.info("=" * 60)
    logger.info("Starting EV Registry API server...")
    logger.info(f"API documentation: {'https' if config.tls_enabled else 'http'}://localhost:{config.api_port}/docs")
    logger.info("=" * 60)
    
    # Run server
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=config.api_port,
            log_level=config.log_level.lower(),
            **ssl_kwargs
        )
    except KeyboardInterrupt:
        logger.info("Shutting down EV Registry...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
