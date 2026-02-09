from pathlib import Path

from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    api_key: str = "dev-api-key"
    model_path: str = "models/phishing_model.pkl"
    debug: bool = False

    model_config = {"env_file": str(BASE_DIR / ".env"), "env_prefix": "PHISHING_"}


settings = Settings()
