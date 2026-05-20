#!/usr/bin/env python3
"""Lightweight protocol-level reproduction of ECroA.

Paper: "ECroA: Efficient Cross-Domain Authentication in Dynamic Digital Twins of
Wireless Industrial IoT" (IEEE JSAC, 2026).

This implementation focuses on the protocol flow and actor interaction model:
- MEC/domain initialization with distributed key publication
- DT registration with pseudonym generation
- cross-domain message signing
- per-domain signature aggregation and batch verification
- fallback individual verification when a domain batch fails

To keep the repo dependency-free and compatible with the existing threaded
reproductions, we model the pairing-based algebra over an abstract cyclic group
modulo the selected curve order. This preserves the message flow and
verification logic needed for threaded simulation, but it is not a production or
cryptographically faithful pairing implementation.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import Curve, SECP256R1


SCALAR_LEN = 32
RID_LEN = 16
SESSION_KEY_LEN = 32


def int_to_bytes(value: int, length: int = SCALAR_LEN) -> bytes:
    return int(value).to_bytes(length, "big")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    size = max(len(left), len(right))
    left = left.rjust(size, b"\x00")
    right = right.rjust(size, b"\x00")
    return bytes(a ^ b for a, b in zip(left, right))


def _norm(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part)
    raise TypeError(f"unsupported hash part type: {type(part)!r}")


def H_bytes(domain_sep: bytes, *parts: Any, length: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.sha256()
        h.update(domain_sep)
        h.update(counter.to_bytes(4, "big"))
        for part in parts:
            h.update(_norm(part))
        out += h.digest()
        counter += 1
    return out[:length]


def H_scalar(modulus: int, domain_sep: bytes, *parts: Any) -> int:
    return int.from_bytes(H_bytes(domain_sep, *parts, length=SCALAR_LEN), "big") % modulus or 1


def group_add(modulus: int, a: int, b: int) -> int:
    return (a + b) % modulus


def group_scalar_mult(modulus: int, scalar: int, elem: int) -> int:
    return (scalar * elem) % modulus


def pairing(modulus: int, a: int, b: int) -> int:
    # Abstract bilinear map over scalar representatives.
    return (a * b) % modulus


@dataclass(frozen=True)
class DomainRecord:
    domain_id: str
    Ppub1: int
    Ppub2: int


@dataclass(frozen=True)
class DTCredential:
    rid: str
    domain_id: str
    id1: int
    id2: bytes
    sk1: int
    sk2: int


@dataclass(frozen=True)
class SignedPacket:
    sender_rid: str
    sender_domain: str
    id1: int
    id2: bytes
    message: bytes
    sigma: int
    target_dt: str


class BlockchainLedger:
    """Shared consortium-ledger abstraction used by all MEC actors."""

    def __init__(self):
        self.domain_records: dict[str, DomainRecord] = {}
        self.dt_registry: dict[tuple[str, int, bytes], str] = {}

    def publish_domain(self, record: DomainRecord):
        self.domain_records[record.domain_id] = record

    def register_dt(self, credential: DTCredential):
        self.dt_registry[(credential.domain_id, credential.id1, credential.id2)] = credential.rid

    def get_domain(self, domain_id: str) -> DomainRecord:
        return self.domain_records[domain_id]

    def trace_identity(self, domain_id: str, id1: int, id2: bytes) -> str | None:
        return self.dt_registry.get((domain_id, id1, id2))


class MEC:
    def __init__(self, domain_id: str, curve: Curve = SECP256R1):
        self.domain_id = domain_id
        self.curve = curve
        self.q = curve.n
        self.s1 = secrets.randbelow(self.q - 1) + 1
        self.s2 = secrets.randbelow(self.q - 1) + 1
        self.Ppub1 = self.s1
        self.Ppub2 = self.s2

    def domain_record(self) -> DomainRecord:
        return DomainRecord(self.domain_id, self.Ppub1, self.Ppub2)

    def register_dt(self, rid: str) -> DTCredential:
        rid_bytes = rid.encode("utf-8")[:RID_LEN].ljust(RID_LEN, b"\x00")
        r = secrets.randbelow(self.q - 1) + 1
        id1 = r  # Scalar representative of rP.
        mask = H_bytes(b"ECROA_ID2", group_scalar_mult(self.q, r, self.Ppub1), length=len(rid_bytes))
        id2 = xor_bytes(rid_bytes, mask)
        h_id = H_scalar(self.q, b"ECROA_HID", id1, id2)
        sk1 = group_scalar_mult(self.q, self.s1, id1)
        sk2 = group_scalar_mult(self.q, self.s2, h_id)
        return DTCredential(rid, self.domain_id, id1, id2, sk1, sk2)


class DigitalTwin:
    def __init__(self, rid: str, credential: DTCredential, curve: Curve = SECP256R1):
        self.rid = rid
        self.credential = credential
        self.curve = curve
        self.q = curve.n

    def sign_message(self, message: bytes, target_dt: str) -> SignedPacket:
        h_m = H_scalar(self.q, b"ECROA_MSG", message)
        sigma = group_add(self.q, self.credential.sk1, group_scalar_mult(self.q, h_m, self.credential.sk2))
        return SignedPacket(
            sender_rid=self.rid,
            sender_domain=self.credential.domain_id,
            id1=self.credential.id1,
            id2=self.credential.id2,
            message=message,
            sigma=sigma,
            target_dt=target_dt,
        )


def verify_single_packet(packet: SignedPacket, record: DomainRecord, modulus: int) -> bool:
    h_m = H_scalar(modulus, b"ECROA_MSG", packet.message)
    h_id = H_scalar(modulus, b"ECROA_HID", packet.id1, packet.id2)
    expected = (
        pairing(modulus, packet.id1, record.Ppub1)
        + pairing(modulus, group_scalar_mult(modulus, h_m, h_id), record.Ppub2)
    ) % modulus
    return packet.sigma == expected


def aggregate_domain_packets(packets: list[SignedPacket], modulus: int) -> int:
    acc = 0
    for packet in packets:
        acc = group_add(modulus, acc, packet.sigma)
    return acc


def verify_domain_batch(packets: list[SignedPacket], record: DomainRecord, modulus: int) -> bool:
    agg_sigma = aggregate_domain_packets(packets, modulus)
    left = pairing(modulus, agg_sigma, 1)
    sum_id1 = 0
    sum_h = 0
    for packet in packets:
        h_m = H_scalar(modulus, b"ECROA_MSG", packet.message)
        h_id = H_scalar(modulus, b"ECROA_HID", packet.id1, packet.id2)
        sum_id1 = group_add(modulus, sum_id1, packet.id1)
        sum_h = group_add(modulus, sum_h, group_scalar_mult(modulus, h_m, h_id))
    right = (pairing(modulus, sum_id1, record.Ppub1) + pairing(modulus, sum_h, record.Ppub2)) % modulus
    return left == right

