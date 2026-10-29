"""纯标准库的 RSA 密钥与 X.509 证书生成 / 安装。

为什么不依赖 ``cryptography``：

* 这个工具的目标是"同学双击一下就能用"，装依赖是失败率最高的一环；
* 只需要一个自签 CA + 一张给 127.0.0.1 用的服务器证书，标准库（``hashlib`` +
  ``secrets`` + ``pow``）足够把 PKCS#1 / X.509 DER 手工拼出来。

安全性说明：CA 私钥只落在本机 ``~/.scholar-access/`` 目录里，权限 0600，
只用来签一张 CN/SAN 为 ``127.0.0.1`` 的服务器证书。它不是通用 CA，
不要拿它去签发别的域名。
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------- ASN.1 ---

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8 = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_UTCTIME = 0x17
TAG_CTX_0 = 0xA0
TAG_CTX_3 = 0xA3

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_COMMON_NAME = "2.5.4.3"
OID_ORGANIZATION = "2.5.4.10"
OID_ORGANIZATIONAL_UNIT = "2.5.4.11"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_SUBJECT_KEY_ID = "2.5.29.14"
OID_AUTHORITY_KEY_ID = "2.5.29.35"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _int(value: int) -> bytes:
    if value == 0:
        return _tlv(TAG_INTEGER, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")  # 高位补 0 保证正数
    return _tlv(TAG_INTEGER, raw)


def _seq(*items: bytes) -> bytes:
    return _tlv(TAG_SEQUENCE, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(TAG_SET, b"".join(items))


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(TAG_OID, body)


def _bit_string(data: bytes, unused: int = 0) -> bytes:
    return _tlv(TAG_BIT_STRING, bytes([unused]) + data)


def _octet_string(data: bytes) -> bytes:
    return _tlv(TAG_OCTET_STRING, data)


def _utf8(text: str) -> bytes:
    return _tlv(TAG_UTF8, text.encode("utf-8"))


def _boolean(value: bool) -> bytes:
    return _tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def _name(cn: str, org: str | None = None) -> bytes:
    rdns = [_set(_seq(_oid(OID_COMMON_NAME), _utf8(cn)))]
    if org:
        rdns.append(_set(_seq(_oid(OID_ORGANIZATION), _utf8(org))))
    return _seq(*rdns)


def _utctime(when: _dt.datetime) -> bytes:
    return _tlv(TAG_UTCTIME, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _pem(label: str, der: bytes) -> str:
    # 先把 base64 里的换行全去掉，再按 64 列重新折行（否则行里会夹着换行）
    body = "".join(base64.encodebytes(der).decode("ascii").split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


# ----------------------------------------------------------------------- RSA ---

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
]


def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + int.from_bytes(os.urandom(16), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = int.from_bytes(os.urandom(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | 1            # 置最高位、强制奇数
        candidate |= 1 << (bits - 2)                  # 保证 p*q 位宽正确
        if candidate % 3 == 0:
            continue
        # 小素数快速筛掉绝大多数合数，避免每次都跑 Miller-Rabin
        if any(candidate % p == 0 for p in _SMALL_PRIMES[3:]):
            continue
        if _is_probable_prime(candidate):
            return candidate


@dataclass
class KeyPair:
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0
    dp: int = 0
    dq: int = 0
    qi: int = 0
    bits: int = 2048

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    # --- 序列化 ---------------------------------------------------------
    def to_pkcs1_der(self) -> bytes:
        return _seq(
            _int(0), _int(self.n), _int(self.e), _int(self.d),
            _int(self.p), _int(self.q), _int(self.dp), _int(self.dq), _int(self.qi),
        )

    def to_public_der(self) -> bytes:
        return _seq(_int(self.n), _int(self.e))

    def to_pem(self) -> str:
        return _pem("RSA PRIVATE KEY", self.to_pkcs1_der())

    def sign_sha256(self, message: bytes) -> bytes:
        """PKCS#1 v1.5 + SHA-256 签名。"""
        digest = hashlib.sha256(message).digest()
        digest_info = _seq(_seq(_oid(OID_SHA256), _tlv(TAG_NULL, b"")), _octet_string(digest))
        padding_len = self.size_bytes - len(digest_info) - 3
        if padding_len < 8:
            raise ValueError("RSA key too small for SHA-256 signature")
        block = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
        signature = pow(int.from_bytes(block, "big"), self.d, self.n)
        return signature.to_bytes(self.size_bytes, "big")


def generate_rsa_key(bits: int = 2048, e: int = 65537) -> KeyPair:
    """生成 RSA 密钥对（纯 Python，2048 位大约 1 秒）。"""
    if bits < 2048:
        raise ValueError("RSA key must be at least 2048 bits")
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue
        return KeyPair(
            n=n, e=e, d=d, p=p, q=q,
            dp=d % (p - 1), dq=d % (q - 1),
            qi=pow(q, -1, p), bits=bits,
        )


# ---------------------------------------------------------------------- X.509 ---

def _algorithm_identifier(oid: str) -> bytes:
    return _seq(_oid(oid), _tlv(TAG_NULL, b""))


def _subject_public_key_info(key: KeyPair) -> bytes:
    return _seq(_algorithm_identifier(OID_RSA_ENCRYPTION), _bit_string(key.to_public_der()))


def _key_identifier(key: KeyPair) -> bytes:
    return hashlib.sha1(key.to_public_der()).digest()


def _general_name_dns(name: str) -> bytes:
    return _tlv(0x82, name.encode("ascii"))


def _general_name_ipv4(ip: str) -> bytes:
    return _tlv(0x87, bytes(int(x) for x in ip.split(".")))


def _extension(oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [_oid(oid)]
    if critical:
        parts.append(_boolean(True))
    parts.append(_octet_string(value))
    return _seq(*parts)


def build_certificate(
    *,
    subject_cn: str,
    subject_org: str | None,
    subject_key: KeyPair,
    issuer_name: bytes | None,
    issuer_key: KeyPair,
    issuer_key_id: bytes | None,
    is_ca: bool,
    sans: list[str] = (),
    days: int = 3650,
    serial: int | None = None,
) -> bytes:
    """返回 DER 编码的证书；``issuer_name`` 为 None 时是自签名（CA 证书）。"""
    not_before = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)
    not_after = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days)
    if serial is None:
        serial = int.from_bytes(os.urandom(16), "big") >> 1

    name = _name(subject_cn, subject_org)
    issuer = issuer_name if issuer_name is not None else name

    extensions: list[bytes] = []
    if is_ca:
        extensions.append(_extension(OID_BASIC_CONSTRAINTS, _seq(_boolean(True)), critical=True))
        # keyCertSign(5) + cRLSign(6)
        extensions.append(_extension(OID_KEY_USAGE, _bit_string(b"\x06", unused=1), critical=True))
    else:
        extensions.append(_extension(OID_BASIC_CONSTRAINTS, _seq(), critical=True))
        # digitalSignature(0) + keyEncipherment(2)
        extensions.append(_extension(OID_KEY_USAGE, _bit_string(b"\xa0", unused=5), critical=True))
        extensions.append(
            _extension(OID_EXT_KEY_USAGE, _seq(_oid(OID_SERVER_AUTH)), critical=False)
        )

    if sans:
        entries = []
        for san in sans:
            if san.count(".") == 3 and all(part.isdigit() for part in san.split(".")):
                entries.append(_general_name_ipv4(san))
            else:
                entries.append(_general_name_dns(san))
        extensions.append(
            _extension(OID_SUBJECT_ALT_NAME, _seq(*entries), critical=False)
        )

    extensions.append(
        _extension(OID_SUBJECT_KEY_ID, _octet_string(_key_identifier(subject_key)),
                   critical=False)
    )
    if issuer_key_id is not None:
        extensions.append(
            _extension(
                OID_AUTHORITY_KEY_ID,
                _seq(_tlv(0x80, issuer_key_id)),
                critical=False,
            )
        )

    tbs = _seq(
        _tlv(TAG_CTX_0, _int(2)),                  # version v3
        _int(serial),
        _algorithm_identifier(OID_SHA256_WITH_RSA),
        issuer,
        _seq(_utctime(not_before), _utctime(not_after)),
        name,
        _subject_public_key_info(subject_key),
        _tlv(TAG_CTX_3, _seq(*extensions)),
    )
    signature = issuer_key.sign_sha256(tbs)
    return _seq(tbs, _algorithm_identifier(OID_SHA256_WITH_RSA), _bit_string(signature))


@dataclass
class Identity:
    """一套 CA + 服务器证书。"""

    ca_key: KeyPair
    ca_der: bytes
    server_key: KeyPair
    server_der: bytes
    ca_pem_path: Path
    ca_key_path: Path
    server_pem_path: Path
    server_key_path: Path
    extra: dict = field(default_factory=dict)

    @property
    def ca_pem(self) -> str:
        return _pem("CERTIFICATE", self.ca_der)

    @property
    def ca_fingerprint(self) -> str:
        digest = hashlib.sha256(self.ca_der).hexdigest().upper()
        return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def create_identity(directory: Path, *, host: str = "127.0.0.1",
                    days: int = 397, ca_days: int = 3650,
                    common_name: str = "scholar-access local DoH") -> Identity:
    """生成 CA 与服务器证书并写入目录。"""
    directory.mkdir(parents=True, exist_ok=True)

    ca_key = generate_rsa_key(2048)
    ca_name = _name("scholar-access Local CA", "scholar-access")
    ca_der = build_certificate(
        subject_cn="scholar-access Local CA",
        subject_org="scholar-access",
        subject_key=ca_key,
        issuer_name=None,
        issuer_key=ca_key,
        issuer_key_id=None,
        is_ca=True,
        days=ca_days,
    )

    server_key = generate_rsa_key(2048)
    sans = [host, "localhost"]
    server_der = build_certificate(
        subject_cn=common_name,
        subject_org=None,
        subject_key=server_key,
        issuer_name=ca_name,
        issuer_key=ca_key,
        issuer_key_id=_key_identifier(ca_key),
        is_ca=False,
        sans=sans,
        days=days,
    )

    ca_pem_path = directory / "ca.crt.pem"
    ca_key_path = directory / "ca.key.pem"
    server_pem_path = directory / "server.crt.pem"
    server_key_path = directory / "server.key.pem"

    ca_pem_path.write_text(_pem("CERTIFICATE", ca_der), encoding="ascii")
    server_pem_path.write_text(_pem("CERTIFICATE", server_der), encoding="ascii")
    _write_private(ca_key_path, ca_key.to_pem())
    _write_private(server_key_path, server_key.to_pem())

    return Identity(
        ca_key=ca_key, ca_der=ca_der,
        server_key=server_key, server_der=server_der,
        ca_pem_path=ca_pem_path, ca_key_path=ca_key_path,
        server_pem_path=server_pem_path, server_key_path=server_key_path,
    )


def load_identity(directory: Path, *, host: str = "127.0.0.1", days: int = 397,
                  regenerate: bool = False) -> Identity:
    """读取已有的证书；不存在或已过期则重新生成。"""
    ca_pem_path = directory / "ca.crt.pem"
    ca_key_path = directory / "ca.key.pem"
    server_pem_path = directory / "server.crt.pem"
    server_key_path = directory / "server.key.pem"

    if not regenerate and all(p.exists() for p in
                              (ca_pem_path, ca_key_path, server_pem_path, server_key_path)):
        if not _cert_needs_renewal(server_pem_path):
            return Identity(
                ca_key=None, ca_der=b"", server_key=None, server_der=b"",
                ca_pem_path=ca_pem_path, ca_key_path=ca_key_path,
                server_pem_path=server_pem_path, server_key_path=server_key_path,
            )
    return create_identity(directory, host=host, days=days)


def _cert_needs_renewal(cert_path: Path, margin_days: int = 20) -> bool:
    """用 ssl 读出 notAfter 判断是否快过期（不引入额外依赖）。"""
    try:
        import ssl
        info = ssl._ssl._test_decode_cert(str(cert_path))  # type: ignore[attr-defined]
        not_after = _dt.datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return not_after - _dt.datetime.utcnow() < _dt.timedelta(days=margin_days)
    except Exception:
        return False


# ------------------------------------------------------------- 证书安装 / 卸载 ---

def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_macos() -> bool:
    return sys.platform == "darwin"


def install_ca(ca_pem_path: Path, *, dry_run: bool = False) -> tuple[bool, str]:
    """把 CA 装进"当前用户"的信任库，返回 (是否成功, 说明)。"""
    if is_windows():
        return _install_ca_windows(ca_pem_path, dry_run=dry_run)
    if is_macos():
        return _install_ca_macos(ca_pem_path, dry_run=dry_run)
    return _install_ca_linux(ca_pem_path, dry_run=dry_run)


def _certutil() -> str | None:
    return shutil.which("certutil")


def _install_ca_windows(ca_pem_path: Path, *, dry_run: bool = False) -> tuple[bool, str]:
    # 用 .NET 的 X509Store 直接写 CurrentUser\Root：不弹"安全警告"窗口，
    # 也不需要管理员权限。certutil -addstore 会弹窗并可能卡住，故不用它。
    der_path = ca_pem_path.with_suffix(".cer")
    der_path.write_bytes(_pem_to_der(ca_pem_path.read_text(encoding="ascii")))
    ps = (
        "$ErrorActionPreference='Stop';"
        "$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%s');"
        "$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser');"
        "$s.Open('ReadWrite');"
        "if (-not ($s.Certificates | Where-Object { $_.Thumbprint -eq $c.Thumbprint })) { $s.Add($c) };"
        "$s.Close();"
        "Write-Output $c.Thumbprint"
    ) % str(der_path).replace("'", "''")
    if dry_run:
        return True, "would run: powershell -NoProfile -Command <%d chars>" % len(ps)
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "调用 PowerShell 失败: %s" % exc
    if out.returncode == 0:
        return True, "已安装到 当前用户\\受信任的根证书颁发机构 (Thumbprint %s)" % out.stdout.strip()
    return False, (out.stderr or out.stdout or "未知错误").strip()


def _install_ca_macos(ca_pem_path: Path, *, dry_run: bool = False) -> tuple[bool, str]:
    keychain = Path.home() / "Library/Keychains/login.keychain-db"
    cmd = ["security", "add-trusted-cert", "-r", "trustRoot", "-k", str(keychain),
           str(ca_pem_path)]
    if dry_run:
        return True, "would run: " + " ".join(cmd)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "调用 security 失败: %s" % exc
    if out.returncode == 0:
        return True, "已加入登录钥匙串并设为始终信任"
    return False, (out.stderr or out.stdout or "未知错误").strip()


def _install_ca_linux(ca_pem_path: Path, *, dry_run: bool = False) -> tuple[bool, str]:
    """Linux 上各发行版差异大：能自动做的只有 NSS（Chrome/Chromium）用户库。"""
    notes = []
    nssdb = Path.home() / ".pki/nssdb"
    if shutil.which("certutil") and nssdb.exists():
        cmd = ["certutil", "-d", "sql:%s" % nssdb, "-A", "-t", "C,,",
               "-n", "scholar-access", "-i", str(ca_pem_path)]
        if not dry_run:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
                notes.append("已加入 NSS 数据库（Chrome/Chromium）")
            except (OSError, subprocess.SubprocessError) as exc:
                notes.append("certutil 失败: %s" % exc)
        else:
            notes.append("would run: " + " ".join(cmd))
    notes.append(
        "系统级信任需要手动执行（需要 root）："
        "sudo cp %s /usr/local/share/ca-certificates/scholar-access.crt && "
        "sudo update-ca-certificates" % ca_pem_path
    )
    return True, "；".join(notes)


def uninstall_ca(ca_pem_path: Path) -> tuple[bool, str]:
    if is_windows():
        der_path = ca_pem_path.with_suffix(".cer")
        target = der_path if der_path.exists() else ca_pem_path
        ps = (
            "$ErrorActionPreference='Stop';"
            "$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%s');"
            "$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser');"
            "$s.Open('ReadWrite');"
            "$s.Certificates | Where-Object { $_.Thumbprint -eq $c.Thumbprint } | ForEach-Object { $s.Remove($_) };"
            "$s.Close(); Write-Output 'removed'"
        ) % str(target).replace("'", "''")
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True, timeout=120)
            return out.returncode == 0, (out.stdout or out.stderr).strip()
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
    if is_macos():
        try:
            out = subprocess.run(
                ["security", "remove-trusted-cert", "-d", str(ca_pem_path)],
                capture_output=True, text=True, timeout=120,
            )
            return out.returncode == 0, (out.stdout or out.stderr).strip()
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
    return False, "Linux 请手动删除 /usr/local/share/ca-certificates/ 下对应证书并 update-ca-certificates"


def _pem_to_der(pem_text: str) -> bytes:
    body = "".join(
        line.strip() for line in pem_text.splitlines()
        if line.strip() and not line.startswith("-----")
    )
    return base64.b64decode(body)
