"""Load and expose project configuration from config.toml."""

import tomllib
from pathlib import Path

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.toml"


def load(path: Path | None = None) -> dict:
    config_path = path or _DEFAULT_CONFIG_PATH
    with open(config_path, "rb") as fh:
        return tomllib.load(fh)


# Module-level singleton loaded at import time.
_config: dict | None = None


def get() -> dict:
    global _config
    if _config is None:
        _config = load()
    return _config
