"""开机自启：Windows 启动项 / macOS LaunchAgent / Linux systemd --user。"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

APP_ID = "scholar-access"


def package_root() -> Path:
    """``scholar_access`` 包的父目录。

    从源码运行时需要它，否则 ``python -m scholar_access`` 在别的 cwd 下会找不到包。
    pip 安装后这个路径无所谓，但设上也无害。
    """
    return Path(__file__).resolve().parent.parent


def _pythonw() -> str:
    exe = Path(sys.executable)
    if os.name == "nt":
        candidate = exe.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(exe)


def launch_command(extra: list[str] | None = None) -> list[str]:
    return [_pythonw(), "-m", "scholar_access", "run", "--quiet"] + list(extra or [])


def _quote_command() -> str:
    return " ".join('"%s"' % part if " " in part else part for part in launch_command())


# ------------------------------------------------------------------ Windows ---

def startup_dir() -> Path:
    return (Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming")))
            / "Microsoft/Windows/Start Menu/Programs/Startup")


def _windows_vbs_path() -> Path:
    return startup_dir() / ("%s.vbs" % APP_ID)


def install_windows() -> tuple[bool, str]:
    startup_dir().mkdir(parents=True, exist_ok=True)
    vbs = (
        'Set sh = CreateObject("WScript.Shell")\r\n'
        'sh.CurrentDirectory = "%s"\r\n'
        'sh.Run "%s", 0, False\r\n'
        % (str(package_root()).replace('"', '""'), _quote_command().replace('"', '""'))
    )
    path = _windows_vbs_path()
    path.write_text(vbs, encoding="utf-8")
    return True, "已写入启动项 %s" % path


def uninstall_windows() -> tuple[bool, str]:
    path = _windows_vbs_path()
    if path.exists():
        path.unlink()
        return True, "已删除启动项 %s" % path
    return True, "启动项本来就不存在"


# -------------------------------------------------------------------- macOS ---

def _launchagent_path() -> Path:
    return Path.home() / "Library/LaunchAgents" / ("io.github.%s.plist" % APP_ID)


def install_macos() -> tuple[bool, str]:
    plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.github.%s</string>
  <key>ProgramArguments</key>
  <array>
%s
  </array>
  <key>WorkingDirectory</key><string>%s</string>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
""" % (APP_ID,
       "\n".join("    <string>%s</string>" % part for part in launch_command()),
       package_root(),
       Path.home() / "Library/Logs" / ("%s.log" % APP_ID),
       Path.home() / "Library/Logs" / ("%s.err.log" % APP_ID))
    path = _launchagent_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plist, encoding="utf-8")
    if shutil.which("launchctl"):
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True, check=False)
        subprocess.run(["launchctl", "load", str(path)], capture_output=True, check=False)
    return True, "已写入 LaunchAgent %s" % path


def uninstall_macos() -> tuple[bool, str]:
    path = _launchagent_path()
    if path.exists():
        if shutil.which("launchctl"):
            subprocess.run(["launchctl", "unload", str(path)], capture_output=True, check=False)
        path.unlink()
        return True, "已删除 LaunchAgent %s" % path
    return True, "LaunchAgent 本来就不存在"


# -------------------------------------------------------------------- Linux ---

def _systemd_path() -> Path:
    return Path.home() / ".config/systemd/user" / ("%s.service" % APP_ID)


def install_linux() -> tuple[bool, str]:
    unit = """[Unit]
Description=scholar-access local DoH router
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
""" % (package_root(), " ".join(launch_command()))
    path = _systemd_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(unit, encoding="utf-8")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, check=False)
        subprocess.run(["systemctl", "--user", "enable", "--now", "%s.service" % APP_ID],
                       capture_output=True, check=False)
    return True, "已写入 systemd 用户服务 %s" % path


def uninstall_linux() -> tuple[bool, str]:
    path = _systemd_path()
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", "%s.service" % APP_ID],
                       capture_output=True, check=False)
    if path.exists():
        path.unlink()
        return True, "已删除 %s" % path
    return True, "服务本来就不存在"


# --------------------------------------------------------------------- 统一 ---

def install() -> tuple[bool, str]:
    if os.name == "nt":
        return install_windows()
    if sys.platform == "darwin":
        return install_macos()
    return install_linux()


def uninstall() -> tuple[bool, str]:
    if os.name == "nt":
        return uninstall_windows()
    if sys.platform == "darwin":
        return uninstall_macos()
    return uninstall_linux()


def describe() -> str:
    if os.name == "nt":
        path = _windows_vbs_path()
        return "启动项：%s（%s）" % (path, "已安装" if path.exists() else "未安装")
    if sys.platform == "darwin":
        path = _launchagent_path()
        return "LaunchAgent：%s（%s）" % (path, "已安装" if path.exists() else "未安装")
    path = _systemd_path()
    return "systemd 用户服务：%s（%s）" % (path, "已安装" if path.exists() else "未安装")
