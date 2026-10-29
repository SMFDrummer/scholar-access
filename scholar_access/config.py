"""平台相关的路径与配置文件。"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_NAME = "scholar-access"
DEFAULT_PORT = 5380
DEFAULT_DOH_PATH = "/dns-query"


def app_dir() -> Path:
    """用户级数据目录（证书、配置、日志都在这里）。"""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData/Local")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local/share")
    return Path(base) / APP_NAME


def cert_dir() -> Path:
    return app_dir() / "certs"


def config_path() -> Path:
    return app_dir() / "config.json"


def log_path() -> Path:
    return app_dir() / "router.log"


@dataclass
class Config:
    port: int = DEFAULT_PORT
    host: str = "127.0.0.1"
    upstream: str = "https://doh.scholar.work/dns-query"
    sysdns: list[str] = field(default_factory=list)   # 空 = 自动探测
    verbose: bool = False
    tls: bool = True
    use_trusted_cert: bool = True   # False = 用一次性自签证书（需要浏览器忽略证书）

    @property
    def doh_url(self) -> str:
        scheme = "https" if self.tls else "http"
        return "%s://%s:%d%s" % (scheme, self.host, self.port, DEFAULT_DOH_PATH)

    @property
    def stats_url(self) -> str:
        scheme = "https" if self.tls else "http"
        return "%s://%s:%d/stats" % (scheme, self.host, self.port)


def load(path: Path | None = None) -> Config:
    target = path or config_path()
    try:
        raw = json.loads(target.read_text("utf-8"))
    except (OSError, ValueError):
        return Config()
    config = Config()
    for key, value in raw.items():
        if hasattr(config, key) and not key.startswith("_"):
            setattr(config, key, value)
    return config


def save(config: Config, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(config), indent=2, ensure_ascii=False), "utf-8")
    return target
