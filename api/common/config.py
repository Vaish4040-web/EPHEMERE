"""Settings shared by all services. Values come from environment variables or the repo's .env file."""
import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_env(path=None, environ=None):
    """Read KEY=VALUE lines from a .env file. Real environment variables always win."""
    environ = os.environ if environ is None else environ
    path = Path(path) if path else REPO_ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    internal_secret: str
    data_dir: Path
    gateway_port: int = 8000
    proxy_port: int = 8001
    access_port: int = 8002
    ipfs_api_port: int = 5101
    web_port: int = 3000

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"

    @property
    def access_url(self) -> str:
        return f"http://127.0.0.1:{self.access_port}"

    @property
    def ipfs_url(self) -> str:
        return f"http://127.0.0.1:{self.ipfs_api_port}"

    @classmethod
    def from_env(cls, environ=None, read_env_file=True):
        environ = os.environ if environ is None else environ
        if read_env_file:
            load_env(environ=environ)
        secret = environ.get("INTERNAL_SECRET", "")
        if len(secret) < 16 or secret.startswith("change-me"):
            raise ValueError(
                "INTERNAL_SECRET is missing, too short (needs 16+ characters) or still the example value. "
                "Run `python demo/run_all.py` once (it creates the .env file), or copy .env.example to .env."
            )
        data_dir = Path(environ.get("DATA_DIR") or REPO_ROOT / ".data")
        return cls(
            internal_secret=secret,
            data_dir=data_dir,
            gateway_port=int(environ.get("GATEWAY_PORT", 8000)),
            proxy_port=int(environ.get("PROXY_PORT", 8001)),
            access_port=int(environ.get("ACCESS_PORT", 8002)),
            ipfs_api_port=int(environ.get("IPFS_API_PORT", 5101)),
            web_port=int(environ.get("WEB_PORT", 3000)),
        )
