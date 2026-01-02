"""
Configuration management using Pydantic settings and environment variables.
Supports both .env files and CLI arguments.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class CentralConfig(BaseSettings):
    """Configuration for EV Central service."""
    
    listen_port: int = Field(default=9999, description="TCP control plane port")
    http_port: int = Field(default=8000, description="HTTP dashboard port")
    kafka_bootstrap: str = Field(default="kafka:9092", description="Kafka bootstrap servers")
    db_url: Optional[str] = Field(default=None, description="Database URL (optional)")
    log_level: str = Field(default="INFO", description="Logging level")
    
    model_config = SettingsConfigDict(
        env_prefix="CENTRAL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class CPEngineConfig(BaseSettings):
    """Configuration for CP Engine service."""
    
    kafka_bootstrap: str = Field(default="kafka:9092", description="Kafka bootstrap servers")
    cp_id: str = Field(..., description="Charging Point ID")
    health_port: int = Field(default=8001, description="TCP health check port")
    log_level: str = Field(default="INFO", description="Logging level")
    telemetry_interval: float = Field(default=1.0, description="Telemetry emission interval (seconds)")
    kw_rate: float = Field(default=22.0, description="Power delivery rate in kW")
    euro_rate: float = Field(default=0.30, description="Cost per kWh in euros")
    max_session_seconds: Optional[int] = Field(default=None, description="Maximum session duration in seconds (None = unlimited)")
    
    model_config = SettingsConfigDict(
        env_prefix="CP_ENGINE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class CPMonitorConfig(BaseSettings):
    """Configuration for CP Monitor service."""
    
    cp_id: str = Field(..., description="Charging Point ID")
    location: str = Field(default="Unknown", description="CP location (city/address)")
    cp_e_host: str = Field(default="localhost", description="CP Engine host")
    cp_e_port: int = Field(default=8001, description="CP Engine port")
    central_host: str = Field(default="localhost", description="Central host")
    central_port: int = Field(default=8000, description="Central HTTP port")
    health_interval: float = Field(default=1.0, description="Health check interval (seconds)")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # EV_Registry settings for secure CP authentication
    registry_url: str = Field(
        default="http://localhost:8080",
        description="EV_Registry API URL"
    )
    registry_enabled: bool = Field(
        default=True,
        description="Enable registration with EV_Registry (set to False for legacy mode)"
    )
    registry_verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates when connecting to Registry"
    )
    registry_admin_api_key: Optional[str] = Field(
        default=None,
        description="Admin API key for new CP registration"
    )
    
    model_config = SettingsConfigDict(
        env_prefix="CP_MONITOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class DriverConfig(BaseSettings):
    """Configuration for Driver client."""
    
    driver_id: str = Field(..., description="Driver identifier")
    kafka_bootstrap: str = Field(default="kafka:9092", description="Kafka bootstrap servers")
    requests_file: Optional[str] = Field(default=None, description="File with CP IDs to request")
    request_interval: float = Field(default=4.0, description="Interval between requests (seconds)")
    log_level: str = Field(default="INFO", description="Logging level")
    dashboard_port: int = Field(default=8100, description="HTTP dashboard port")
    central_http_url: str = Field(default="http://localhost:8000", description="EV Central HTTP base URL")
    auto_run_requests: bool = Field(default=False, description="Automatically run scripted requests on startup")
    
    model_config = SettingsConfigDict(
        env_prefix="DRIVER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class RegistryConfig(BaseSettings):
    """Configuration for EV Registry service."""
    
    api_port: int = Field(default=8080, description="REST API port")
    db_path: str = Field(default="ev_charging.db", description="Database file path")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # TLS/SSL Configuration (MANDATORY for production)
    tls_enabled: bool = Field(default=True, description="Enable HTTPS/TLS (REQUIRED for production)")
    tls_cert_file: Optional[str] = Field(default=None, description="Path to TLS certificate file")
    tls_key_file: Optional[str] = Field(default=None, description="Path to TLS private key file")
    allow_insecure: bool = Field(default=False, description="Allow insecure HTTP (dev only - DO NOT USE IN PRODUCTION)")
    
    # Security Settings
    token_expiration_hours: int = Field(default=24, description="Authentication token expiration in hours")
    secret_key: str = Field(..., description="Secret key for token signing (REQUIRED - must be strong random value)")
    jwt_issuer: str = Field(default="ev-registry", description="JWT issuer claim")
    jwt_audience: str = Field(default="ev-central", description="JWT audience claim")
    require_certificate: bool = Field(default=False, description="Require client certificates for authentication")
    
    # API Security
    api_key_header: str = Field(default="X-Registry-API-Key", description="API key header name")
    admin_api_key: Optional[str] = Field(default=None, description="Admin API key for management endpoints (required for re-registration)")
    
    model_config = SettingsConfigDict(
        env_prefix="REGISTRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class WeatherConfig(BaseSettings):
    """Configuration for the weather component"""
    openweather_api_key: str = Field(default="X-OpenWeather-API-Key", description="API key to access OpenWeather")
    central_http_url: str = Field(default="http://localhost:8000", description="EV Central HTTP base URL")
    poll_interval: int = Field(default=4, description="Interval in which the EV_W poll data from OpenWeather")
    city_file: str = Field(default="/app/evcharging/common/CP_cities.txt", description="File in which are kept the cities")
    log_level: str = Field(default="INFO", description="Logging level")

    model_config = SettingsConfigDict(
        env_prefix="WEATHER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Kafka topic names
TOPICS = {
    "CENTRAL_COMMANDS": "central.commands",
    "CP_STATUS": "cp.status",
    "CP_TELEMETRY": "cp.telemetry",
    "CP_SESSION_END": "cp.session_end",
    "DRIVER_REQUESTS": "driver.requests",
    "DRIVER_UPDATES": "driver.updates",
    "TICKET_TO_DRIVER": "driver.ticket"
}
