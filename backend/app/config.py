from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

API_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = API_DIR.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(API_DIR / ".env", REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = ""

settings = Settings()


def require_aws_env() -> None:
    missing: list[str] = []
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"):
        val = getattr(settings, name, "") or ""
        if not str(val).strip():
            missing.append(name)
    if missing:
        raise RuntimeError(
            f"AWS settings are missing or empty: {', '.join(missing)}. "
            f"Define them in your .env file"
        )