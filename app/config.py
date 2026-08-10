from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "AI SSH Honeypot CDIO4"
    web_host: str = "0.0.0.0"
    web_port: int = 8000

    ssh_host: str = "0.0.0.0"
    ssh_port: int = 2222
    start_ssh_server: bool = True
    accept_any_password: bool = True
    honeypot_username: str = "guest"
    honeypot_password: str = "guest"

    admin_username: str = "admin"
    admin_password: str = "change-this-password"

    database_url: str = "sqlite:///./data/honeypot.db"
    ssh_host_key_path: Path = Path("./data/ssh_host_key")

    enable_llm: bool = False
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = 12.0

    max_command_length: int = Field(default=2048, ge=128, le=16384)
    max_response_length: int = Field(default=6000, ge=512, le=50000)
    session_idle_timeout_seconds: int = Field(default=900, ge=60, le=86400)


@lru_cache
def get_settings() -> Settings:
    return Settings()
