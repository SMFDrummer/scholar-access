"""命令行入口：``scholar-access <run|install|uninstall|status|selftest|doctor|cert>``。"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, autostart, certs, config as cfg, dnsmsg, server, upstream

BANNER = "scholar-access %s — 让普通浏览器用上学校的 DoH 通道" % __version__


# ------------------------------------------------------------------ 小工具 ---

def _log_factory(verbose: bool, *, to_file: Path | None = None):
    lock_holder = {"fp": None}
    if to_file is not None:
        to_file.parent.mkdir(parents=True, exist_ok=True)
        lock_holder["fp"] = open(to_file, "a", encoding="utf-8", buffering=1)
        lock_holder["fp"].write("\n=== %s ===\n" % time.strftime("%Y-%m-%d %H:%M:%S"))

    def log(message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (stamp, message)
        fp = lock_holder["fp"]
        if fp is not None:
            fp.write(line + "\n")
        elif verbose:
            print(line, flush=True)

    return log


def _pid_path() -> Path:
    return cfg.app_dir() / "router.pid"


def _write_pid(pid: int) -> None:
    try:
        _pid_path().write_text(str(pid), "utf-8")
    except OSError:
        pass


def _read_pid() -> int | None:
    try:
        return int(_pid_path().read_text("utf-8").strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH"],
                             capture_output=True, text=True, check=False)
        return str(pid) in (out.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _urlopen(url: str, *, cafile: Path | None = None, timeout: float = 5.0, data=None,
             content_type: str | None = None) -> bytes:
    if url.startswith("https"):
        if cafile is not None and Path(cafile).exists():
            context = ssl.create_default_context(cafile=str(cafile))
        else:
            context = ssl._create_unverified_context()
    else:
        context = None
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read()


def fetch_stats(conf: cfg.Config, *, timeout: float = 4.0) -> dict | None:
    try:
        raw = _urlopen(conf.stats_url, cafile=cfg.cert_dir() / "ca.crt.pem", timeout=timeout)
        return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def wait_for_router(conf: cfg.Config, *, seconds: float = 20.0) -> dict | None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        stats = fetch_stats(conf, timeout=1.5)
        if stats:
            return stats
        time.sleep(0.4)
    return None


# ----------------------------------------------------------------- 子命令 ---

def cmd_run(args) -> int:
    conf = cfg.load()
    if args.port:
        conf.port = args.port
    if args.host:
        conf.host = args.host
    if args.upstream:
        conf.upstream = args.upstream
    if args.sysdns:
        conf.sysdns = [s.strip() for s in args.sysdns.split(",") if s.strip()]
    if args.verbose:
        conf.verbose = True
    if args.no_tls:
        conf.tls = False
    if args.plain_http:
        conf.tls = False

    to_file = None if args.foreground else cfg.log_path()
    log = _log_factory(verbose=True, to_file=to_file)

    certfile = keyfile = None
    if conf.tls:
        identity = certs.load_identity(cfg.cert_dir())
        certfile, keyfile = identity.server_pem_path, identity.server_key_path

    sysdns_servers = conf.sysdns or upstream.detect_system_dns(cfg.app_dir())
    school = upstream.SchoolDoH(conf.upstream, log=log)
    sysdns = upstream.SystemDNS(sysdns_servers, log=log)
    from .router import Router
    router = Router(school, sysdns, verbose=conf.verbose, log=log,
                    schedule_retry=not args.no_retry)

    try:
        httpd = server.make_server(
            router, host=conf.host, port=conf.port,
            certfile=certfile, keyfile=keyfile,
            stats_provider=router.snapshot, log=log,
        )
    except OSError as exc:
        print("无法监听 %s:%d — %s" % (conf.host, conf.port, exc), file=sys.stderr)
        print("端口可能被占用，换一个：scholar-access run --port 5381", file=sys.stderr)
        return 2

    _write_pid(os.getpid())
    log("listening on %s (sysdns=%s)" % (conf.doh_url, sysdns.describe()))
    if conf.tls:
        log("注意：浏览器需要信任本地 CA，否则先运行 scholar-access install")
    try:
        server.serve_forever(httpd)
    finally:
        try:
            _pid_path().unlink()
        except OSError:
            pass
    return 0


def cmd_install(args) -> int:
    print(BANNER)
    conf = cfg.load()
    if args.port:
        conf.port = args.port
    if args.upstream:
        conf.upstream = args.upstream
    if args.no_tls:
        conf.tls = False
    saved = cfg.save(conf)
    print("· 配置已写入 %s" % saved)

    identity = certs.load_identity(cfg.cert_dir(), regenerate=args.regenerate_cert)
    print("· 证书已就绪：%s" % identity.server_pem_path)
    print("  CA 指纹 %s" % (identity.ca_fingerprint or "(复用已有证书)"))

    if conf.tls and not args.skip_ca:
        if _ca_already_trusted(identity):
            print("· CA 已在信任库中，跳过安装")
        else:
            ok, message = certs.install_ca(identity.ca_pem_path)
            print(("· 安装 CA：" if ok else "! 安装 CA 失败：") + message)
            if not ok:
                print("  可以稍后手动执行：scholar-access cert --install")
    elif not conf.tls:
        print("! 未启用 TLS：浏览器不会接受 http:// 的 DoH 模板，仅适合调试")

    if not args.no_autostart:
        ok, message = autostart.install()
        print(("· 开机自启：" if ok else "! 开机自启失败：") + message)

    if not args.no_start:
        _stop_existing(quiet=True)
        _spawn_background()
        stats = wait_for_router(conf)
        if stats:
            print("· 路由已在后台运行（%s）" % conf.doh_url)
        else:
            print("! 后台启动似乎失败，看看日志：%s" % cfg.log_path())

    _print_next_steps(conf)
    return 0


def _ca_already_trusted(identity) -> bool:
    """用"只信系统库"的上下文连一下本地服务：能握手成功说明 CA 已经装好了。"""
    conf = cfg.load()
    if not conf.tls:
        return True
    try:
        context = ssl.create_default_context()          # 默认只信任系统证书库
        with socket.create_connection((conf.host, conf.port), timeout=1.5) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1"):
                return True
    except (OSError, ssl.SSLError):
        return False


def _print_next_steps(conf: cfg.Config) -> None:
    print()
    print("接下来（每台电脑只需要做一次）：")
    print("  1. 打开浏览器设置里的“安全 DNS / DNS over HTTPS”，选择“自定义”，填入：")
    print("       %s" % conf.doh_url)
    print("  2. 浏览器：Chrome / Edge / Helium 在 设置 → 隐私和安全 → 安全 → 使用安全 DNS")
    print("     Firefox 在 设置 → 隐私与安全 → 启用基于 HTTPS 的 DNS → 最大保护")
    print("  3. 想确认状态，运行：scholar-access status")
    print()
    print("卸载：scholar-access uninstall")


def _spawn_background() -> None:
    root = str(autostart.package_root())
    cmd = autostart.launch_command()
    env = dict(os.environ)
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    kwargs = dict(cwd=root, env=env, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, close_fds=True)
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(cmd, **kwargs)


def _stop_existing(*, quiet: bool = False) -> bool:
    pid = _read_pid()
    if not pid or not _pid_alive(pid):
        if not quiet:
            print("· 没有发现正在运行的路由进程")
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, check=False)
        else:
            os.kill(pid, signal.SIGTERM)
        time.sleep(0.6)
    except OSError:
        pass
    try:
        _pid_path().unlink()
    except OSError:
        pass
    if not quiet:
        print("· 已停止路由进程 (PID %d)" % pid)
    return True


def cmd_uninstall(args) -> int:
    _stop_existing()
    ok, message = autostart.uninstall()
    print(("· 开机自启：" if ok else "! 开机自启：") + message)
    ca_path = cfg.cert_dir() / "ca.crt.pem"
    if ca_path.exists():
        if args.keep_ca:
            print("· 保留 CA 证书（--keep-ca）")
        else:
            ok, message = certs.uninstall_ca(ca_path)
            print(("· 移除 CA：" if ok else "! 移除 CA 失败：") + message)
    if args.purge:
        import shutil
        shutil.rmtree(cfg.app_dir(), ignore_errors=True)
        print("· 已删除数据目录 %s" % cfg.app_dir())
    print()
    print("记得把浏览器里的安全 DNS 改回默认，否则会打不开任何网页。")
    return 0


def cmd_status(args) -> int:
    conf = cfg.load()
    stats = fetch_stats(conf)
    if not stats:
        print("× 路由没有在运行（%s 无响应）" % conf.stats_url)
        print("  启动：scholar-access run    或    scholar-access install")
        return 1
    print(BANNER)
    print("服务地址   : %s" % conf.doh_url)
    print("学校 DoH   : %s" % stats.get("upstream"))
    print("系统 DNS   : %s" % stats.get("sysdns"))
    print("运行时长   : %ds" % stats.get("uptime_s", 0))
    print("缓存条目   : %s" % stats.get("cache_entries"))
    print()
    print("查询 %(queries)d  |  学校命中 %(school_hit)d  |  学校未答 %(school_miss)d" % stats)
    print("回退系统DNS %(fallback)d  |  缓存 %(cached)d  |  失败 %(serverfail)d" % stats)
    print("学校请求 %(school_requests)d  |  学校失败 %(school_failures)d  |  后台补答 %(bg_retry_ok)d" % stats)
    if stats.get("school_hit", 0) == 0 and stats.get("queries", 0) > 5:
        print()
        print("! 学校 DoH 一次都没命中，检查：网络是否在校园网、--upstream 是否写错")
    return 0


def cmd_selftest(args) -> int:
    conf = cfg.load()
    stats = fetch_stats(conf, timeout=2.0)
    if not stats:
        print("× 路由没在运行，先执行 scholar-access run")
        return 1
    cafile = cfg.cert_dir() / "ca.crt.pem"
    targets = [("www.google.com", dnsmsg.TYPE_A), ("github.com", dnsmsg.TYPE_A),
               ("www.baidu.com", dnsmsg.TYPE_A), ("api.github.com", dnsmsg.TYPE_A)]
    failures = 0
    for name, qtype in targets:
        packet = dnsmsg.build_query(name, qtype)
        try:
            raw = _urlopen(conf.doh_url, cafile=cafile, timeout=6.0, data=packet,
                           content_type="application/dns-message")
        except Exception as exc:
            print("× %-16s 请求失败：%r" % (name, exc))
            failures += 1
            continue
        answers = dnsmsg.answer_count(raw)
        rcode = dnsmsg.rcode_of(raw)
        mark = "√" if answers and rcode == 0 else "×"
        print("%s %-16s rcode=%d answers=%d" % (mark, name, rcode, answers))
        if not answers:
            failures += 1
    after = fetch_stats(conf, timeout=2.0) or {}
    if after.get("school_hit"):
        print("  学校 DoH 命中 %d 次" % after["school_hit"])
    return 0 if failures == 0 else 1


def cmd_cert(args) -> int:
    identity = certs.load_identity(cfg.cert_dir(), regenerate=args.regenerate)
    if args.install:
        ok, message = certs.install_ca(identity.ca_pem_path)
        print(("· " if ok else "! ") + message)
        return 0 if ok else 1
    if args.uninstall:
        ok, message = certs.uninstall_ca(identity.ca_pem_path)
        print(("· " if ok else "! ") + message)
        return 0 if ok else 1
    print("CA 证书     : %s" % identity.ca_pem_path)
    print("服务器证书  : %s" % identity.server_pem_path)
    if identity.ca_fingerprint:
        print("CA SHA-256  : %s" % identity.ca_fingerprint)
    return 0


def cmd_doctor(args) -> int:
    print(BANNER)
    problems = 0
    print("Python      : %s" % sys.version.split()[0])
    conf = cfg.load()
    print("配置        : %s" % cfg.config_path())

    servers = upstream.detect_system_dns(None)
    print("系统 DNS    : %s" % (", ".join(servers) or "(未探测到)"))

    try:
        with socket.create_connection((urllib_split_host(conf.upstream), 443), timeout=4):
            print("学校 DoH    : 可连通 (%s)" % conf.upstream)
    except OSError as exc:
        problems += 1
        print("学校 DoH    : × 连不上 %s (%s)" % (conf.upstream, exc))

    stats = fetch_stats(conf, timeout=1.5)
    running = bool(stats)

    sock = socket.socket()
    try:
        sock.bind((conf.host, conf.port))
    except OSError as exc:
        if running:
            print("本地端口    : %s:%d 由本工具占用（正常）" % (conf.host, conf.port))
        else:
            problems += 1
            print("本地端口    : × %s:%d 被其它程序占用 (%s)" % (conf.host, conf.port, exc))
    else:
        print("本地端口    : %s:%d 可用" % (conf.host, conf.port))
    finally:
        sock.close()

    ca_path = cfg.cert_dir() / "ca.crt.pem"
    print("CA 证书     : %s" % ("已生成 %s" % ca_path if ca_path.exists() else "尚未生成"))
    print("自启状态    : %s" % autostart.describe())
    print("运行状态    : %s" % ("运行中" if running else "未运行"))
    return 0 if problems == 0 else 1


def urllib_split_host(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).hostname or ""


def cmd_version(args) -> int:
    print(BANNER)
    return 0


# -------------------------------------------------------------------- 入口 ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scholar-access",
        description="把学校的 DoH 通道变成浏览器可以直接填的安全 DNS 地址。",
    )
    parser.add_argument("--version", action="version", version="scholar-access %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="前台运行路由（推荐给 systemd/launchd 调用）")
    p_run.add_argument("--port", type=int)
    p_run.add_argument("--host")
    p_run.add_argument("--upstream", help="学校 DoH 地址")
    p_run.add_argument("--sysdns", help="逗号分隔的备用 DNS，如 223.5.5.5,119.29.29.29")
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--quiet", action="store_true", help="静默模式（自启时使用）")
    p_run.add_argument("--no-tls", action="store_true")
    p_run.add_argument("--plain-http", action="store_true", help="同 --no-tls")
    p_run.add_argument("--foreground", action="store_true", help="日志打到终端而不是文件")
    p_run.add_argument("--no-retry", action="store_true", help="关闭后台补答")
    p_run.set_defaults(func=cmd_run)

    p_install = sub.add_parser("install", help="一键安装：生成证书、信任 CA、设置自启并启动")
    p_install.add_argument("--port", type=int)
    p_install.add_argument("--upstream")
    p_install.add_argument("--no-tls", action="store_true")
    p_install.add_argument("--skip-ca", action="store_true", help="不安装 CA（稍后手动）")
    p_install.add_argument("--no-autostart", action="store_true")
    p_install.add_argument("--no-start", action="store_true")
    p_install.add_argument("--regenerate-cert", action="store_true")
    p_install.set_defaults(func=cmd_install)

    p_un = sub.add_parser("uninstall", help="停止、取消自启、移除 CA")
    p_un.add_argument("--keep-ca", action="store_true")
    p_un.add_argument("--purge", action="store_true", help="连配置和证书目录一起删除")
    p_un.set_defaults(func=cmd_uninstall)

    p_status = sub.add_parser("status", help="查看运行状态和命中统计")
    p_status.set_defaults(func=cmd_status)

    p_test = sub.add_parser("selftest", help="用几个域名验证本地 DoH 是否可用")
    p_test.set_defaults(func=cmd_selftest)

    p_cert = sub.add_parser("cert", help="查看 / 安装 / 移除本地 CA")
    p_cert.add_argument("--install", action="store_true")
    p_cert.add_argument("--uninstall", action="store_true")
    p_cert.add_argument("--regenerate", action="store_true")
    p_cert.set_defaults(func=cmd_cert)

    p_doctor = sub.add_parser("doctor", help="体检：端口、上游、证书、自启")
    p_doctor.set_defaults(func=cmd_doctor)

    p_stop = sub.add_parser("stop", help="停止后台路由")
    p_stop.set_defaults(func=lambda a: (0 if _stop_existing() or True else 0))

    return parser


def _setup_console() -> None:
    """统一输出编码：Windows 控制台默认 cp936，会把中文吐成乱码。"""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
