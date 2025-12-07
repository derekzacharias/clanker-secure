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


settings = Settings()
settings.xml_output_dir.mkdir(parents=True, exist_ok=True)
