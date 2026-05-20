#!/usr/bin/env python3
"""Threaded-reproducible protocol core for Cui et al. (TNSM 2023).

Paper: "Efficient Batch Authentication Scheme Based on Edge Computing in IIoT"

Focus:
- KDC parameter generation
- SD pseudonym / signing-key material distribution
- SD-side encrypt + sign
- ES-side batch verification with recursive invalid isolation
- ES hash-chain notification signing
- SD-side notification verification + message recovery
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import Curve, SECP256R1, is_on_curve, point_add, scalar_mult
from protocol import decode_point, encode_point, int_to_bytes, xor_bytes


POINT_LEN = 65
SCALAR_LEN = 32
CHAIN_LEN = 64
TIMESTAMP_WINDOW = 300


def _norm_part(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part, SCALAR_LEN)
    if isinstance(part, tuple):
        return encode_point(part)
    raise TypeError(f"unsupported hash part: {type(part)!r}")


def H_bytes(domain_sep: bytes, *parts: Any, length: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.sha256()
        h.update(domain_sep)
        h.update(int_to_bytes(counter, 4))
        for part in parts:
            h.update(_norm_part(part))
        out += h.digest()
        counter += 1
    return out[:length]


def H_scalar(modulus: int, domain_sep: bytes, *parts: Any) -> int:
    return int.from_bytes(H_bytes(domain_sep, *parts, length=SCALAR_LEN), "big") % modulus or 1


def xor_stream(key: bytes, data: bytes) -> bytes:
    stream = H_bytes(b"CUI_ENC", key, length=len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


def pid_hash(seed: bytes) -> bytes:
    return hashlib.sha256(b"CUI_PID" + seed).digest()


def vk_hash(seed: bytes) -> bytes:
    return hashlib.sha256(b"CUI_VK" + seed).digest()


def iter_hash(seed: bytes, steps: int, fn) -> bytes:
    out = seed
    for _ in range(steps):
        out = fn(out)
    return out


def encode_acl(sd_id: str, expire_time: int, pid: bytes) -> bytes:
    return json.dumps(
        {"sd_id": sd_id, "expire_time": expire_time, "pid": pid.hex()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_acl(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def packet_hash(packet: "CuiMessagePacket") -> bytes:
    return H_bytes(
        b"CUI_PKT_HASH",
        packet.sender_pid,
        packet.U_i,
        packet.R_i,
        packet.delta_i,
        packet.ciphertext,
        packet.ts,
        length=32,
    )


@dataclass(frozen=True)
class CuiPublicKey:
    U_i: tuple[int, int]
    hi_i: int


@dataclass(frozen=True)
class CuiPseudoMaterial:
    pid: bytes
    U_i: tuple[int, int]
    u_i: int
    ski_i: int
    hi_i: int
    expire_time: int


@dataclass(frozen=True)
class CuiMessagePacket:
    sender_pid: bytes
    U_i: tuple[int, int]
    R_i: tuple[int, int]
    delta_i: int
    ciphertext: bytes
    ts: int
    dest_id: str


@dataclass(frozen=True)
class CuiNotification:
    vk_xor: bytes
    mac: bytes
    valid_hashes: list[bytes]
    invalid_hashes: list[bytes]
    ts: int


@dataclass(frozen=True)
class DeliveredPlaintext:
    sender_pid: bytes
    plaintext: bytes
    ts: int


class CuiKDC:
    def __init__(self, curve: Curve = SECP256R1, chain_len: int = CHAIN_LEN):
        self.curve = curve
        self.P = (curve.gx, curve.gy)
        self.s = secrets.randbelow(curve.n - 1) + 1
        self.Ppub = scalar_mult(curve, self.s, self.P)
        self.gsk = secrets.randbelow(curve.n - 1) + 1
        self.seed = secrets.token_bytes(32)
        self.chain_len = chain_len

    def register_sd(self, sd_id: str, count: int | None = None, start_time: int = 0) -> tuple[list[CuiPseudoMaterial], bytes, int]:
        count = count or self.chain_len
        materials = []
        for idx in range(1, count + 1):
            expire_time = start_time + idx + TIMESTAMP_WINDOW
            u_i = secrets.randbelow(self.curve.n - 1) + 1
            U_i = scalar_mult(self.curve, u_i, self.P)
            pid = xor_bytes(sd_id.encode("utf-8"), H_bytes(b"CUI_H1_PID", scalar_mult(self.curve, self.s, U_i), length=len(sd_id.encode("utf-8"))))
            hi_i = H_scalar(self.curve.n, b"CUI_H2", pid, U_i)
            ski_i = (self.s + u_i) % self.curve.n
            materials.append(CuiPseudoMaterial(pid, U_i, u_i, ski_i, hi_i, expire_time))
        vk_latest = iter_hash(self.seed, self.chain_len, vk_hash)
        return materials, vk_latest, self.gsk


class CuiEdgeServer:
    def __init__(self, es_id: str, kgc: CuiKDC):
        self.es_id = es_id
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P
        self.seed = kgc.seed
        self.current_vk_index = kgc.chain_len
        self.registry: dict[bytes, CuiPseudoMaterial] = {}

    def register_materials(self, materials: list[CuiPseudoMaterial]):
        for item in materials:
            self.registry[item.pid] = item

    def verify_batch(self, packets: list[CuiMessagePacket], current_time: int | None = None) -> bool:
        if not packets:
            return True
        sigma_sum = 0
        rhs = (None, None)
        for pkt in packets:
            if not is_on_curve(self.curve, pkt.U_i) or not is_on_curve(self.curve, pkt.R_i):
                return False
            material = self.registry.get(pkt.sender_pid)
            if material is None:
                return False
            if current_time is not None:
                if pkt.ts > current_time or current_time - pkt.ts > TIMESTAMP_WINDOW:
                    return False
                if current_time > material.expire_time:
                    return False
            h_star = H_scalar(self.curve.n, b"CUI_H3", pkt.sender_pid, pkt.R_i, pkt.U_i, pkt.ciphertext, pkt.ts)
            sigma_sum = (sigma_sum + pkt.delta_i) % self.curve.n
            term1 = scalar_mult(self.curve, h_star, self.kgc.Ppub)
            term2 = scalar_mult(self.curve, h_star, pkt.U_i)
            term3 = scalar_mult(self.curve, material.hi_i, pkt.R_i)
            term = point_add(self.curve, term1, point_add(self.curve, term2, term3))
            rhs = term if rhs == (None, None) else point_add(self.curve, rhs, term)
        lhs = scalar_mult(self.curve, sigma_sum, self.P)
        return lhs == rhs

    def identify_invalid_indices(self, packets: list[CuiMessagePacket], current_time: int | None = None) -> list[int]:
        invalid: list[int] = []

        def rec(offset: int, segment: list[CuiMessagePacket]):
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

        rec(0, packets)
        invalid.sort()
        return invalid

    def sign_notification(self, valid_hashes: list[bytes], invalid_hashes: list[bytes], current_time: int) -> CuiNotification:
        if self.current_vk_index <= 0:
            raise ValueError("verification key chain exhausted")
        vk_curr = iter_hash(self.seed, self.current_vk_index, vk_hash)
        vk_prev = iter_hash(self.seed, self.current_vk_index - 1, vk_hash)
        self.current_vk_index -= 1
        fin_blob = b"".join(valid_hashes + invalid_hashes)
        mac = H_bytes(b"CUI_H5", fin_blob, vk_prev, vk_curr, current_time, length=32)
        return CuiNotification(vk_xor=xor_bytes(vk_prev, vk_curr), mac=mac, valid_hashes=valid_hashes, invalid_hashes=invalid_hashes, ts=current_time)


class CuiSmartDevice:
    def __init__(self, sd_id: str, kgc: CuiKDC):
        self.sd_id = sd_id
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P
        self.gsk_pub = scalar_mult(self.curve, self.kgc.gsk, self.P)
        self.materials: list[CuiPseudoMaterial] = []
        self.current_index = 0
        self.current_vk = b""
        self.verified_notifications: set[bytes] = set()

    def load_registration(self, materials: list[CuiPseudoMaterial], vk_latest: bytes, gsk: int):
        self.materials = materials
        self.current_index = 0
        self.current_vk = vk_latest
        self.gsk_pub = scalar_mult(self.curve, gsk, self.P)
        self.verified_notifications.clear()

    def next_material(self) -> CuiPseudoMaterial:
        if self.current_index >= len(self.materials):
            raise ValueError("no more pseudonym materials")
        item = self.materials[self.current_index]
        self.current_index += 1
        return item

    def encrypt_and_sign(self, material: CuiPseudoMaterial, dest_id: str, message: bytes, timestamp: int) -> CuiMessagePacket:
        r_i = secrets.randbelow(self.curve.n - 1) + 1
        R_i = scalar_mult(self.curve, r_i, self.P)
        ekey = H_bytes(b"CUI_H1_ENC", scalar_mult(self.curve, r_i, self.gsk_pub), length=len(message))
        ciphertext = xor_stream(ekey, message)
        h_star = H_scalar(self.curve.n, b"CUI_H3", material.pid, R_i, material.U_i, ciphertext, timestamp)
        delta = (material.ski_i * h_star + r_i * material.hi_i) % self.curve.n
        return CuiMessagePacket(material.pid, material.U_i, R_i, delta, ciphertext, timestamp, dest_id)

    def verify_notification_and_recover(self, notification: CuiNotification, packet: CuiMessagePacket) -> DeliveredPlaintext | None:
        notif_id = notification.mac + int_to_bytes(notification.ts, 8)
        if notif_id not in self.verified_notifications:
            vk_prev = xor_bytes(notification.vk_xor, self.current_vk)
            fin_blob = b"".join(notification.valid_hashes + notification.invalid_hashes)
            expected = H_bytes(b"CUI_H5", fin_blob, vk_prev, self.current_vk, notification.ts, length=32)
            if expected != notification.mac:
                return None
            self.current_vk = vk_prev
            self.verified_notifications.add(notif_id)
        ph = packet_hash(packet)
        if ph in notification.invalid_hashes or ph not in notification.valid_hashes:
            return None
        ekey = H_bytes(b"CUI_H1_ENC", scalar_mult(self.curve, self.kgc.gsk, packet.R_i), length=len(packet.ciphertext))
        plaintext = xor_stream(ekey, packet.ciphertext)
        return DeliveredPlaintext(packet.sender_pid, plaintext, packet.ts)
