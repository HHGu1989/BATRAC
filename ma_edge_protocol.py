#!/usr/bin/env python3
"""Protocol core for Ma et al. (JSA 2025) threaded reproduction."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import Curve, SECP256R1, scalar_mult
from protocol import int_to_bytes


SCALAR_LEN = 32
RID_LEN = 16
TIMESTAMP_WINDOW = 300


def _norm(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part, SCALAR_LEN)
    if isinstance(part, tuple):
        from protocol import encode_point
        return encode_point(part)
    raise TypeError(f"unsupported part type: {type(part)!r}")


def H_bytes(domain_sep: bytes, *parts: Any, length: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.sha256()
        h.update(domain_sep)
        h.update(int_to_bytes(counter, 4))
        for part in parts:
            h.update(_norm(part))
        out += h.digest()
        counter += 1
    return out[:length]


def H_scalar(modulus: int, domain_sep: bytes, *parts: Any) -> int:
    return int.from_bytes(H_bytes(domain_sep, *parts, length=SCALAR_LEN), "big") % modulus or 1


def xor_bytes(left: bytes, right: bytes) -> bytes:
    size = max(len(left), len(right))
    left = left.rjust(size, b"\x00")
    right = right.rjust(size, b"\x00")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class MaCredential:
    rid: str
    pid1: tuple[int, int]
    pid2: bytes
    psk: int
    r: int
    R: tuple[int, int]


@dataclass(frozen=True)
class MaMessagePacket:
    sender_pid1: tuple[int, int]
    sender_pid2: bytes
    R_i: tuple[int, int]
    s_i: int
    message: bytes
    ts: int


class MaKGC:
    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.P = (curve.gx, curve.gy)
        self.msk = secrets.randbelow(curve.n - 1) + 1
        self.Ppub = scalar_mult(curve, self.msk, self.P)
        self._registry: dict[str, tuple[bytes, bytes, int]] = {}

    def register_sd(self, rid: str) -> MaCredential:
        rid_bytes = rid.encode("utf-8")[:RID_LEN].ljust(RID_LEN, b"\x00")
        y = secrets.randbelow(self.curve.n - 1) + 1
        pid1 = scalar_mult(self.curve, y, self.P)
        pid2 = H_bytes(b"MA_H1", rid_bytes, int_to_bytes(y), length=16)
        pid = pid1, pid2
        h2 = H_scalar(self.curve.n, b"MA_H2", pid1, pid2)
        psk = (y + self.msk * h2) % self.curve.n
        r = secrets.randbelow(self.curve.n - 1) + 1
        R = scalar_mult(self.curve, r, self.P)
        self._registry[rid] = (rid_bytes, pid2, y)
        return MaCredential(rid, pid1, pid2, psk, r, R)

    def update_sd(self, rid: str) -> MaCredential:
        return self.register_sd(rid)

    def trace(self, pid2: bytes) -> str | None:
        for rid, (_rid_bytes, stored_pid2, _y) in self._registry.items():
            if stored_pid2 == pid2:
                return rid
        return None


class MaEdgeServer:
    def __init__(self, kgc: MaKGC):
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P

    def verify_batch(self, packets: list[MaMessagePacket], current_time: int | None = None) -> bool:
        if not packets:
            return True
        s_sum = 0
        rhs = (None, None)
        for pkt in packets:
            if current_time is not None and (pkt.ts > current_time or current_time - pkt.ts > TIMESTAMP_WINDOW):
                return False
            h2 = H_scalar(self.curve.n, b"MA_H2", pkt.sender_pid1, pkt.sender_pid2)
            h3 = H_scalar(self.curve.n, b"MA_H3", pkt.message, pkt.R_i)
            s_sum = (s_sum + pkt.s_i) % self.curve.n
            term = scalar_mult(self.curve, h3, point_add(self.curve, pkt.sender_pid1, scalar_mult(self.curve, h2, self.kgc.Ppub)))
            term = point_add(self.curve, pkt.R_i, term)
            rhs = term if rhs == (None, None) else point_add(self.curve, rhs, term)
        lhs = scalar_mult(self.curve, s_sum, self.P)
        return lhs == rhs

    def identify_invalid_indices(self, packets: list[MaMessagePacket], current_time: int | None = None) -> list[int]:
        invalid: list[int] = []

        def rec(offset: int, segment: list[MaMessagePacket]):
            if not segment:
                return
            if self.verify_batch(segment, current_time):
                return
            if len(segment) == 1:
                invalid.append(offset)
                return
            mid = len(segment) // 2
            rec(offset, segment[:mid])
            rec(offset + mid, segment[mid:])

        from ecc import point_add
        rec(0, packets)
        invalid.sort()
        return invalid


def point_add(curve: Curve, p1, p2):
    from ecc import point_add as _pa
    return _pa(curve, p1, p2)


class MaDevice:
    def __init__(self, rid: str, kgc: MaKGC):
        self.rid = rid
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P
        self.credential: MaCredential | None = None

    def load_credential(self, credential: MaCredential):
        self.credential = credential

    def sign(self, message: bytes, timestamp: int) -> MaMessagePacket:
        c = self.credential
        if c is None:
            raise RuntimeError("device not registered")
        h3 = H_scalar(self.curve.n, b"MA_H3", message, c.R)
        s = (c.r + h3 * c.psk) % self.curve.n
        return MaMessagePacket(c.pid1, c.pid2, c.R, s, message, timestamp)

