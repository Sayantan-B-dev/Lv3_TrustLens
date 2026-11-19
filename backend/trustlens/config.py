"""Environment-driven configuration.

All secrets are optional: TrustLens must run end-to-end locally with an empty
environment file. Nothing here ever contains a real credential.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(_BACKEND_DIR / ".env"), str(_BACKEND_DIR.parent / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- application -----------------------------------------------------
    app_name: str = "TrustLens"
    environment: str = "development"
    api_prefix: str = "/api/v1"
    frontend_url: str = "http://localhost:3000"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    log_level: str = "INFO"

    # --- database --------------------------------------------------------
    # Local-first MongoDB. Point MONGODB_URL at any local or shared cluster;
    # MONGODB_DB stays dedicated so TrustLens never collides with other apps.
    mongodb_url: str = "mongodb://127.0.0.1:27017"
    mongodb_db: str = "trustlens"
    mongodb_timeout_ms: int = 5000
    auto_create_schema: bool = True
    seed_demo_data: bool = False

    # --- sessions / auth -------------------------------------------------
    session_secret: str = "dev-only-insecure-session-secret-change-me"
    cookie_secure: bool = False
    session_days: int = 30
    anonymous_access_enabled: bool = True
    google_client_id: str = ""
    google_client_secret: str = ""
    # Default points at the Next.js proxy so the cookie is set on the browser-visible host.
    google_redirect_uri: str = "http://localhost:3000/api/v1/auth/google/callback"

    # --- retention / privacy --------------------------------------------
    anonymous_retention_days: int = 7
    user_retention_days: int = 90

    # --- worker ----------------------------------------------------------
    worker_enabled: bool = True
    worker_name: str = "embedded-worker"
    worker_poll_seconds: float = 1.0
    worker_lease_seconds: int = 180
    job_max_attempts: int = 4
    job_retry_base_seconds: int = 15

    # --- rate limiting ---------------------------------------------------
    rate_limit_per_minute: int = 30
    general_rate_limit_per_minute: int = 240

    # --- safe fetching ---------------------------------------------------
    fetch_timeout_seconds: float = 8.0
    fetch_connect_timeout_seconds: float = 5.0
    fetch_max_bytes: int = 65536
    fetch_max_redirects: int = 5
    fetch_user_agent: str = "TrustLens/1.0 (passive security inspection)"
    allowed_ports: str = "80,443"
    allow_private_targets_for_tests: bool = False
    max_input_chars: int = 20000

    # --- threat intelligence --------------------------------------------
    threat_intel_enabled: bool = True
    urlhaus_api_url: str = "https://urlhaus-api.abuse.ch/v1/url/"
    urlhaus_auth_key: str = ""
    urlhaus_timeout_seconds: float = 6.0
    crt_sh_url: str = "https://crt.sh/"
    ct_lookup_enabled: bool = True
    ct_timeout_seconds: float = 8.0

    # --- AI ---------------------------------------------------------------
    ai_provider: str = "auto"  # auto | none | mock | openai
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: float = 20.0
    ai_max_input_chars: int = 6000

    # --- Web3 report integrity -------------------------------------------
    chain_rpc_url: str = "http://127.0.0.1:8545"
    chain_rpc_timeout_seconds: float = 5.0
    chain_id: int = 31337
    chain_contract_address: str = ""
    chain_private_key: str = ""  # local anvil/hardhat dev key ONLY
    chain_explorer_base: str = ""

    # --- derived helpers --------------------------------------------------
    @property
    def cors_origin_list(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        frontend = self.frontend_url.strip().rstrip("/")
        if frontend and frontend not in origins:
            origins.append(frontend)
        return origins

    @property
    def allowed_port_set(self) -> set[int]:
        ports: set[int] = set()
        for raw in self.allowed_ports.split(","):
            raw = raw.strip()
            if raw.isdigit():
                ports.add(int(raw))
        return ports or {80, 443}

    @property
    def oauth_configured(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)

    @property
    def active_ai_provider(self) -> str:
        provider = self.ai_provider.strip().lower()
        if provider == "auto":
            return "openai" if self.ai_api_key else "deterministic"
        if provider == "openai" and not self.ai_api_key:
            return "deterministic"
        if provider not in {"none", "mock", "openai", "deterministic"}:
            return "deterministic"
        return provider

    @property
    def chain_configured(self) -> bool:
        return bool(self.chain_contract_address and self.chain_rpc_url)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
