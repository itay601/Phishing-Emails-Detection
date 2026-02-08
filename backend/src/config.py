from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_key: str = "dev-api-key"
    model_path: str = "models/phishing_model.pkl"
    debug: bool = False

    model_config = {"env_file": ".env", "env_prefix": "PHISHING_"}


settings = Settings()
