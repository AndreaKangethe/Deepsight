from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./asivm.db"
    secret_key: str = "change-me-in-production"
    access_token_minutes: int = 480
    nvd_api_key: str | None = None
    min_match_confidence: float = 0.5
    scheduler_enabled: bool = True
    auto_intel_sync: bool = False  # daily KEV + EPSS refresh (outbound traffic)
    nmap_path: str = "nmap"
    trivy_path: str = "trivy"
    scan_timeout_seconds: int = 3600
    max_scan_hosts: int = 65536
    stale_after_days: int = 30
    model_dir: str = "./models"  # where trained model files are stored

    model_config = {"env_prefix": "ASIVM_"}


settings = Settings()
