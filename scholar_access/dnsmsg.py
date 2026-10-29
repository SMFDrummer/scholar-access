"""DNS wire-format helpers (RFC 1035).

只处理本工具需要的部分：构造查询、读题目、数应答、取 TTL、改事务 ID。
"""

from __future__ import annotations

import random
import struct

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SVCB = 64
TYPE_HTTPS = 65
TYPE_OPT = 41

CLASS_IN = 1

# 需要"先问学校 DoH"的类型；其它类型（HTTPS/SVCB/TXT…）直接交给系统 DNS 更快
SCHOOL_TYPES = (TYPE_A, TYPE_AAAA)

MAX_PACKET = 4096

TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG",
    48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 257: "CAA",
}


def type_name(qtype: int) -> str:
    return TYPE_NAMES.get(qtype, "TYPE%d" % qtype)


def build_query(name: str, qtype: int = TYPE_A, qid: int | None = None) -> bytes:
    """构造一条查询报文。"""
    if qid is None:
        qid = random.randrange(0, 0x10000)
    header = struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)  # RD=1
    body = b""
    label = name.rstrip(".")
    if label:
        for part in label.split("."):
            raw = part.encode("idna") if any(ord(ch) > 127 for ch in part) else part.encode("ascii")
            if not 0 < len(raw) < 64:
                raise ValueError("bad label %r in %r" % (part, name))
            body += bytes([len(raw)]) + raw
    body += b"\x00" + struct.pack("!HH", qtype, CLASS_IN)
    return header + body


def _skip_name(data: bytes, pos: int) -> int | None:
    """跳过（可能是压缩指针的）域名，返回下一个位置。"""
    n = len(data)
    while pos < n:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:      # 压缩指针，2 字节结束
            return pos + 2 if pos + 1 < n else None
        if length & 0xC0:
            return None
        pos += 1 + length
    return None


def parse_question(packet: bytes) -> tuple[str, int, int] | None:
    """返回 (qname, qtype, qclass)；报文不含题目时返回 None。"""
    if len(packet) < 12:
        return None
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    labels: list[str] = []
    while pos < len(packet):
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            return None
        pos += 1
        if pos + length > len(packet):
            return None
        labels.append(packet[pos:pos + length].decode("latin-1"))
        pos += length
    if pos + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    name = ".".join(labels)
    return (name if name else "."), qtype, qclass


def question_end(packet: bytes) -> int | None:
    """题目区结束位置（用于取 EDNS OPT 之类的附加数据）。"""
    if len(packet) < 12:
        return None
    pos = _skip_name(packet, 12)
    if pos is None or pos + 4 > len(packet):
        return None
    return pos + 4


def answer_count(packet: bytes | None) -> int:
    if not packet or len(packet) < 12:
        return 0
    return struct.unpack("!H", packet[6:8])[0]


def rcode_of(packet: bytes | None) -> int:
    if not packet or len(packet) < 12:
        return -1
    return packet[3] & 0x0F


def is_truncated(packet: bytes | None) -> bool:
    if not packet or len(packet) < 12:
        return False
    return bool(packet[2] & 0x02)


def min_ttl(packet: bytes | None, default: int = 60, floor: int = 15, ceiling: int = 600) -> int:
    """取应答区第一条记录的 TTL（够用即可，不做完整解析）。"""
    if not packet or len(packet) < 12:
        return default
    try:
        qd = struct.unpack("!H", packet[4:6])[0]
        pos = 12
        for _ in range(qd):
            nxt = _skip_name(packet, pos)
            if nxt is None:
                return default
            pos = nxt + 4
        nxt = _skip_name(packet, pos)
        if nxt is None or nxt + 10 > len(packet):
            return default
        ttl = struct.unpack("!I", packet[nxt + 4:nxt + 8])[0]
        return max(floor, min(ttl, ceiling))
    except (struct.error, IndexError):
        return default


def fix_id(response: bytes | None, qid: int) -> bytes:
    """把响应里的 ID 改回请求的 ID。

    Chromium 会校验事务 ID，缓存复用/上游改写 ID 时必须回写，否则
    ERR_DNS_MALFORMED_RESPONSE。
    """
    if not response or len(response) < 12:
        return response or b""
    return struct.pack("!H", qid & 0xFFFF) + response[2:]


def packet_id(packet: bytes) -> int:
    if len(packet) < 2:
        return 0
    return struct.unpack("!H", packet[0:2])[0]


def make_servfail(query: bytes) -> bytes:
    """回一个 SERVFAIL（当上游和系统 DNS 都给不出答案时）。"""
    qid = packet_id(query)
    flags = 0x8182  # QR=1, RA=1, RCODE=2
    return struct.pack("!HHHHHH", qid, flags, 0, 0, 0, 0)


def parse_answers(packet: bytes) -> list[tuple[str, int, str]]:
    """尽力解析应答区，返回 [(name, type, 可读值)]，用于自检和调试输出。"""
    results: list[tuple[str, int, str]] = []
    if not packet or len(packet) < 12:
        return results
    try:
        qd = struct.unpack("!H", packet[4:6])[0]
        an = struct.unpack("!H", packet[6:8])[0]
        pos = 12
        for _ in range(qd):
            nxt = _skip_name(packet, pos)
            if nxt is None:
                return results
            pos = nxt + 4
        for _ in range(an):
            nxt = _skip_name(packet, pos)
            if nxt is None or nxt + 10 > len(packet):
                return results
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[nxt:nxt + 10])
            start = nxt + 10
            rdata = packet[start:start + rdlen]
            if rtype == TYPE_A and len(rdata) == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == TYPE_AAAA and len(rdata) == 16:
                value = ":".join("%x" % ((rdata[i] << 8) | rdata[i + 1])
                                 for i in range(0, 16, 2))
            elif rtype == TYPE_CNAME:
                value = _read_name(packet, start) or "?"
            else:
                value = "%d bytes" % rdlen
            results.append((_read_name(packet, pos) or "?", rtype, value))
            pos = start + rdlen
    except (struct.error, IndexError):
        pass
    return results


def _read_name(packet: bytes, pos: int) -> str | None:
    labels: list[str] = []
    seen = 0
    while pos < len(packet) and seen < 64:
        length = packet[pos]
        if length == 0:
            return ".".join(labels) or "."
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet):
                return None
            pos = ((length & 0x3F) << 8) | packet[pos + 1]
            seen += 1
            continue
        if length & 0xC0:
            return None
        pos += 1
        labels.append(packet[pos:pos + length].decode("latin-1"))
        pos += length
        seen += 1
    return ".".join(labels) or None
