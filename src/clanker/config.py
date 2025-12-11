from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite:///./clanker.db")
    nmap_path: str = Field(default="nmap")
    rules_path: Path = Field(default=Path(__file__).resolve().parent / "rules" / "basic_rules.json")
    xml_output_dir: Path = Field(default=Path("./scan_artifacts"))
    scan_retry_limit: int = Field(default=1, ge=0, le=5)
    nvd_cache_dir: Path = Field(default=Path("./data/nvd_cache"))
    nvd_recent_feed_url: str = Field(
        default="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
    )
    nvd_sync_enabled: bool = Field(default=True)
    nvd_cache_ttl_hours: int = Field(default=24, ge=1, le=168)
    nvd_feed_sync_interval_hours: int = Field(default=24, ge=1, le=168)
    nvd_max_reference_urls: int = Field(default=6, ge=1, le=20)
    cpe_map_path: Path = Field(default=Path(__file__).resolve().parent / "core" / "cpe_map.json")
    protocol_fingerprinting_enabled: bool = Field(default=True)
    fingerprint_timeout_seconds: float = Field(default=3.0)
    fingerprint_http_follow_redirects: bool = Field(default=False)
    rule_gap_path: Path = Field(default=Path("./scan_artifacts/rule_gaps.jsonl"))


settings = Settings()
settings.xml_output_dir.mkdir(parents=True, exist_ok=True)
settings.nvd_cache_dir.mkdir(parents=True, exist_ok=True)
settings.rule_gap_path.parent.mkdir(parents=True, exist_ok=True)
