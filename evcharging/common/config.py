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
    cp_e_host: str = Field(default="localhost", description="CP Engine host")
    cp_e_port: int = Field(default=8001, description="CP Engine port")
    central_host: str = Field(default="localhost", description="Central host")
    central_port: int = Field(default=8000, description="Central HTTP port")
    health_interval: float = Field(default=1.0, description="Health check interval (seconds)")
    log_level: str = Field(default="INFO", description="Logging level")
    
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


# Kafka topic names
TOPICS = {
    "CENTRAL_COMMANDS": "central.commands",
    "CP_STATUS": "cp.status",
    "CP_TELEMETRY": "cp.telemetry",
    "DRIVER_REQUESTS": "driver.requests",
    "DRIVER_UPDATES": "driver.updates",
}
