"""核心分流逻辑。

对一个查询做三件事：

1. A/AAAA：**同时**问学校 DoH 和系统 DNS，先到者优先，但学校结果优先采用；
2. 学校拒绝/超时：用系统 DNS 的结果先顶上，同时后台重试学校（拿到就覆盖缓存）；
3. 学校 DoH 只会答白名单域名，其它域名本来就得靠系统 DNS，所以回退是常态而非异常。
"""

from __future__ import annotations

import threading
import time

from . import dnsmsg


class Router:
    def __init__(self, school, sysdns, *, verbose: bool = False, log=None,
                 join_timeout: float = 2.5, cache_positive: int = 120,
                 cache_negative: int = 30, fallback_ttl_cap: int = 45,
                 schedule_retry: bool = True):
        self.school = school
        self.sysdns = sysdns
        self.verbose = verbose
        self._log = log or (lambda *a, **k: None)
        self.join_timeout = join_timeout
        self.cache_positive = cache_positive
        self.cache_negative = cache_negative
        self.fallback_ttl_cap = fallback_ttl_cap
        self.schedule_retry = schedule_retry

        self._cache: dict[tuple, tuple[bytes, float]] = {}
        self._cache_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.stats = {
            "queries": 0, "school_hit": 0, "school_miss": 0, "fallback": 0,
            "cached": 0, "serverfail": 0, "passthrough": 0, "bg_retry_ok": 0,
        }
        self.started_at = time.time()

    # --- 统计 -----------------------------------------------------------
    def _bump(self, key: str, n: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + n

    def snapshot(self) -> dict:
        with self._stats_lock:
            data = dict(self.stats)
        with self._cache_lock:
            data["cache_entries"] = len(self._cache)
        data["uptime_s"] = int(time.time() - self.started_at)
        data["upstream"] = getattr(self.school, "url", "")
        data["sysdns"] = self.sysdns.describe() if hasattr(self.sysdns, "describe") else ""
        data["school_requests"] = getattr(self.school, "requests", 0)
        data["school_failures"] = getattr(self.school, "failures", 0)
        return data

    # --- 缓存 -----------------------------------------------------------
    def _cache_get(self, key: tuple) -> bytes | None:
        now = time.time()
        with self._cache_lock:
            item = self._cache.get(key)
            if item is None:
                return None
            packet, expires_at = item
            if expires_at <= now:
                self._cache.pop(key, None)
                return None
        self._bump("cached")
        return packet

    def _cache_put(self, key: tuple, packet: bytes | None, ttl: int | None = None) -> None:
        if not packet:
            return
        if ttl is None:
            if dnsmsg.rcode_of(packet) not in (0, 3):
                return
            ttl = dnsmsg.min_ttl(
                packet,
                default=self.cache_positive if dnsmsg.answer_count(packet) else self.cache_negative,
            )
        with self._cache_lock:
            if len(self._cache) > 4096:      # 简单上限，避免长期运行无限增长
                self._cache.clear()
            self._cache[key] = (packet, time.time() + max(5, ttl))

    # --- 主入口 ---------------------------------------------------------
    def resolve(self, packet: bytes) -> bytes:
        qid = dnsmsg.packet_id(packet)
        self._bump("queries")

        question = dnsmsg.parse_question(packet)
        if question is None:
            self._bump("serverfail")
            return dnsmsg.make_servfail(packet)
        name, qtype, qclass = question
        key = (name.lower(), qtype, qclass)

        cached = self._cache_get(key)
        if cached is not None:
            return dnsmsg.fix_id(cached, qid)

        if qtype not in dnsmsg.SCHOOL_TYPES:
            # HTTPS/SVCB/TXT 之类学校 DoH 一般也不答，直接走系统 DNS 更快
            self._bump("passthrough")
            response = self.sysdns.query(packet)
            if response:
                self._cache_put(key, response)
                return dnsmsg.fix_id(response, qid)
            self._bump("serverfail")
            return dnsmsg.make_servfail(packet)

        # A/AAAA：并行问两条腿
        holder: dict[str, bytes | None] = {}

        def _sys_worker() -> None:
            holder["sys"] = self.sysdns.query(packet)

        worker = threading.Thread(target=_sys_worker, name="sysdns", daemon=True)
        worker.start()

        school_started = time.time()
        school_response = self.school.query(packet)
        school_ok = bool(school_response) and dnsmsg.rcode_of(school_response) == 0 \
            and dnsmsg.answer_count(school_response) > 0

        if school_ok:
            self._bump("school_hit")
            if self.verbose:
                self._log("SCHOOL %s type=%d answers=%d %dms" % (
                    name, qtype, dnsmsg.answer_count(school_response),
                    int((time.time() - school_started) * 1000)))
            self._cache_put(key, school_response)
            # 让系统 DNS 线程自己收尾，别等它
            return dnsmsg.fix_id(school_response, qid)

        self._bump("school_miss")
        if self.verbose:
            rcode = dnsmsg.rcode_of(school_response) if school_response else "none"
            self._log("MISS %s type=%d rcode=%s %dms" % (
                name, qtype, rcode, int((time.time() - school_started) * 1000)))

        worker.join(self.join_timeout)
        sys_response = holder.get("sys")
        sys_ok = bool(sys_response) and dnsmsg.rcode_of(sys_response) in (0, 3)

        if sys_ok:
            self._bump("fallback")
            if self.verbose:
                self._log("SYS %s type=%d answers=%d" % (
                    name, qtype, dnsmsg.answer_count(sys_response)))
            self._cache_put(key, sys_response,
                            ttl=min(dnsmsg.min_ttl(sys_response, default=self.fallback_ttl_cap),
                                    self.fallback_ttl_cap))
            if self.schedule_retry:
                threading.Thread(target=self._retry_school, args=(key, packet),
                                 name="doh-retry", daemon=True).start()
            return dnsmsg.fix_id(sys_response, qid)

        self._bump("serverfail")
        if self.verbose:
            self._log("FAIL %s type=%d (school+sys all failed)" % (name, qtype))
        return dnsmsg.make_servfail(packet)

    # --- 后台重试 -------------------------------------------------------
    def _retry_school(self, key: tuple, packet: bytes) -> None:
        for attempt, delay in enumerate((0.5, 1.0, 1.5), start=1):
            time.sleep(delay)
            response = self.school.query(packet)
            if response and dnsmsg.rcode_of(response) == 0 and dnsmsg.answer_count(response) > 0:
                self._cache_put(key, response)
                self._bump("bg_retry_ok")
                if self.verbose:
                    self._log("SCHOOL+ %s type=%d (bg retry %d)" % (
                        key[0], key[1], attempt))
                return
