"""
Global settings for logforge, loaded exclusively from .env via pydantic-settings.
Never read os.environ directly elsewhere in the codebase — use `settings` from here.
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator
from urllib.parse import urlparse
import warnings


class Settings(BaseSettings):
    ANTHROPIC_API_KEY: str
    FP_BASE_URL: str = "http://localhost:8000"
    FP_API_TOKEN: str = ""
    CLAUDE_MODEL: str = "claude-sonnet-4-20250514"

    @field_validator("ANTHROPIC_API_KEY")
    @classmethod
    def api_key_must_be_set(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to your .env file before running logforge."
            )
        return v

    @field_validator("FP_BASE_URL")
    @classmethod
    def validate_fp_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"FP_BASE_URL must use http or https scheme: {v}")
        if not parsed.netloc:
            raise ValueError(f"FP_BASE_URL has no host: {v}")
        if parsed.scheme == "http" and not parsed.netloc.startswith(("localhost", "127.")):
            warnings.warn(
                f"FP_BASE_URL uses http for a non-localhost host. "
                f"FP_API_TOKEN will be transmitted in cleartext: {v}",
                stacklevel=2,
            )
        return v

    model_config = {"env_file": ".env"}


settings = Settings()
