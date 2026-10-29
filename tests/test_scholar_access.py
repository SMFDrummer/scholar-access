"""dnsmsg / router / certs 的单元测试（只用标准库 unittest）。

跑法：``python -m unittest discover -s tests -v``
"""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scholar_access import certs, dnsmsg  # noqa: E402
from scholar_access.router import Router  # noqa: E402


def make_response(query: bytes, answers: list[tuple[int, bytes]], ttl: int = 300) -> bytes:
    """按查询造一个应答报文，用于测试。"""
    qname, qtype, qclass = dnsmsg.parse_question(query)
    question = query[12:]
    header = struct.pack("!HHHHHH", dnsmsg.packet_id(query), 0x8180, 1, len(answers), 0, 0)
    body = b""
    for rtype, rdata in answers:
        # NAME(指针) TYPE CLASS TTL RDLENGTH，别漏了 CLASS，否则后面全错位
        body += struct.pack("!HHHIH", 0xC00C, rtype, 1, ttl, len(rdata)) + rdata
    return header + question + body


class DnsMessageTests(unittest.TestCase):
    def test_query_roundtrip(self):
        packet = dnsmsg.build_query("www.google.com", dnsmsg.TYPE_A, qid=0x1234)
        self.assertEqual(dnsmsg.packet_id(packet), 0x1234)
        self.assertEqual(dnsmsg.parse_question(packet), ("www.google.com", 1, 1))

    def test_query_root_and_idn(self):
        self.assertEqual(dnsmsg.parse_question(dnsmsg.build_query(".", 2))[0], ".")
        self.assertEqual(dnsmsg.parse_question(dnsmsg.build_query("例子.测试"))[1], 1)

    def test_fix_id(self):
        packet = dnsmsg.build_query("example.com", qid=0x0042)
        response = make_response(packet, [(1, b"\x01\x02\x03\x04")], ttl=60)
        fixed = dnsmsg.fix_id(response, 0x9999)
        self.assertEqual(dnsmsg.packet_id(fixed), 0x9999)
        self.assertEqual(fixed[2:], response[2:])

    def test_answer_count_and_rcode(self):
        packet = dnsmsg.build_query("example.com")
        response = make_response(packet, [(1, b"\x01\x02\x03\x04"), (1, b"\x05\x06\x07\x08")])
        self.assertEqual(dnsmsg.answer_count(response), 2)
        self.assertEqual(dnsmsg.rcode_of(response), 0)
        self.assertEqual(dnsmsg.rcode_of(dnsmsg.make_servfail(packet)), 2)

    def test_min_ttl_clamps(self):
        packet = dnsmsg.build_query("example.com")
        self.assertEqual(dnsmsg.min_ttl(make_response(packet, [(1, b"\x01\x01\x01\x01")], ttl=5)), 15)
        self.assertEqual(dnsmsg.min_ttl(make_response(packet, [(1, b"\x01\x01\x01\x01")], ttl=99999)), 600)

    def test_parse_answers(self):
        packet = dnsmsg.build_query("example.com")
        response = make_response(packet, [(1, bytes([93, 184, 216, 34]))])
        self.assertEqual(dnsmsg.parse_answers(response)[0][2], "93.184.216.34")

    def test_truncated_flag(self):
        packet = dnsmsg.build_query("example.com")
        response = bytearray(make_response(packet, [(1, b"\x01\x01\x01\x01")]))
        response[2] |= 0x02
        self.assertTrue(dnsmsg.is_truncated(bytes(response)))


class FakeSchool:
    """学校 DoH 的替身：按域名返回固定报文或 None。"""

    def __init__(self, table: dict, requests: int = 0):
        self.table = table
        self.requests = requests
        self.failures = 0
        self.url = "fake://school"

    def query(self, packet):
        self.requests += 1
        name = dnsmsg.parse_question(packet)[0]
        return self.table.get(name)


class FakeSystemDNS:
    def __init__(self, table: dict, calls: list | None = None):
        self.table = table
        self.calls = calls if calls is not None else []
        self.queries = 0

    def query(self, packet):
        self.queries += 1
        name = dnsmsg.parse_question(packet)[0]
        self.calls.append(name)
        return self.table.get(name)

    def describe(self):
        return "fake-system"


class RouterTests(unittest.TestCase):
    def build(self, school_table, sys_table, **kwargs):
        school = FakeSchool(school_table)
        sysdns = FakeSystemDNS(sys_table)
        return Router(school, sysdns, schedule_retry=False, **kwargs), school, sysdns

    def test_school_hit_wins(self):
        query = dnsmsg.build_query("www.google.com")
        school_packet = make_response(query, [(1, b"\xcd\xa4\x32\xcc")])   # 205.164.50.204
        router, school, _sys = self.build({"www.google.com": school_packet}, {})
        response = router.resolve(query)
        self.assertEqual(dnsmsg.parse_answers(response)[0][2], "205.164.50.204")
        self.assertEqual(router.stats["school_hit"], 1)

    def test_fallback_when_school_has_no_answer(self):
        query = dnsmsg.build_query("api.github.com")
        sys_packet = make_response(query, [(1, bytes([20, 205, 243, 168]))])
        router, _school, _sys = self.build({}, {"api.github.com": sys_packet})
        response = router.resolve(query)
        self.assertEqual(dnsmsg.parse_answers(response)[0][2], "20.205.243.168")
        self.assertEqual(router.stats["fallback"], 1)

    def test_cache_serves_second_query(self):
        query = dnsmsg.build_query("www.google.com")
        school_packet = make_response(query, [(1, b"\xcd\xa4\x32\xcc")])
        router, school, _sys = self.build({"www.google.com": school_packet}, {})
        router.resolve(query)
        second = dnsmsg.build_query("www.google.com")
        response = router.resolve(second)
        self.assertEqual(router.stats["cached"], 1)
        self.assertEqual(school.requests, 1)
        self.assertEqual(dnsmsg.packet_id(response), dnsmsg.packet_id(second))

    def test_both_upstreams_fail_gives_servfail(self):
        query = dnsmsg.build_query("nowhere.example")
        router, _school, _sys = self.build({}, {})
        response = router.resolve(query)
        self.assertEqual(dnsmsg.rcode_of(response), 2)
        self.assertEqual(router.stats["serverfail"], 1)

    def test_non_address_types_skip_school(self):
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_HTTPS)
        sys_packet = make_response(query, [(dnsmsg.TYPE_HTTPS, b"\x00\x01\x00")])
        router, school, _sys = self.build({}, {"example.com": sys_packet})
        router.resolve(query)
        self.assertEqual(school.requests, 0)
        self.assertEqual(router.stats["passthrough"], 1)

    def test_garbage_packet_is_servfail(self):
        router, _school, _sys = self.build({}, {})
        self.assertEqual(dnsmsg.rcode_of(router.resolve(b"\x00\x01")), 2)


class CertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.identity = certs.create_identity(cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_files_written(self):
        for path in (self.identity.ca_pem_path, self.identity.server_pem_path,
                     self.identity.server_key_path):
            self.assertTrue(path.exists(), path)
            self.assertGreater(path.stat().st_size, 500)

    def test_pem_labels(self):
        self.assertIn("BEGIN CERTIFICATE", self.identity.ca_pem_path.read_text("ascii"))
        self.assertIn("BEGIN RSA PRIVATE KEY",
                      self.identity.server_key_path.read_text("ascii"))

    def test_private_key_permissions(self):
        if sys.platform == "win32":
            self.skipTest("Windows 不适用 POSIX 权限")
        mode = self.identity.server_key_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_ssl_can_load_certificate(self):
        import ssl
        info = ssl._ssl._test_decode_cert(str(self.identity.server_pem_path))
        self.assertEqual(info["subject"][0][0][1], "scholar-access local DoH")
        self.assertIn("127.0.0.1", [value for kind, value in info["subjectAltName"]])

    def test_ssl_can_load_key_chain(self):
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.identity.server_pem_path),
                                str(self.identity.server_key_path))
        self.assertIsNotNone(context)

    def test_self_signed_ca_verifies_leaf(self):
        context = certs.build_certificate
        self.assertTrue(callable(context))
        self.assertEqual(len(self.identity.ca_fingerprint.split(":")), 32)


class InstallerHelpersTests(unittest.TestCase):
    def test_launch_command_uses_module_entry(self):
        from scholar_access import autostart
        command = autostart.launch_command()
        self.assertIn("-m", command)
        self.assertIn("scholar_access", command)
        self.assertIn("run", command)

    def test_doh_url_format(self):
        from scholar_access import config as cfg
        conf = cfg.Config(port=1234)
        self.assertEqual(conf.doh_url, "https://127.0.0.1:1234/dns-query")
        conf.tls = False
        self.assertEqual(conf.doh_url, "http://127.0.0.1:1234/dns-query")


if __name__ == "__main__":
    unittest.main()
