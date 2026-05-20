#!/usr/bin/env python3
"""Strict formula-oriented reproduction of PPT-CLAMA.

This module follows the paper equations for:
- Setup by KGC and TRA
- User registration through M1 / M2 / M3
- Mutual authentication through Req={M4,T2} and Rep={M5,T4}
- Session-key derivation through H7(T3, h5)

The implementation is a study artifact. It mirrors the paper's message flow
and algebra, but it is not hardened for production deployment.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import Curve, SECP256R1, INFINITY, is_on_curve, point_add, scalar_mult


SCALAR_LEN = 32
POINT_LEN = 65
LENGTH_LEN = 2
TIMESTAMP_LEN = 8
SESSION_KEY_LEN = 32


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value == 0 and length is None:
        return b"\x00"
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    size = max(len(left), len(right))
    left = left.rjust(size, b"\x00")
    right = right.rjust(size, b"\x00")
    return bytes(a ^ b for a, b in zip(left, right))


def encode_point(point) -> bytes:
    if point == INFINITY:
        return b"\x00"
    x, y = point
    return b"\x04" + int_to_bytes(x, 32) + int_to_bytes(y, 32)


def decode_point(data: bytes):
    if data == b"\x00":
        return INFINITY
    if len(data) != POINT_LEN or data[0] != 4:
        raise ValueError("invalid uncompressed point encoding")
    return (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))


def inv_mod(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def _point_scalar(curve: Curve, scalar: int, point):
    return scalar_mult(curve, scalar % curve.n, point)


def _norm_part(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part, SCALAR_LEN)
    if isinstance(part, tuple):
        return encode_point(part)
    raise TypeError(f"unsupported hash input type: {type(part)!r}")


def _hash_bytes(domain_sep: bytes, *parts: Any, length: int) -> bytes:
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


def _hash_scalar(modulus: int, domain_sep: bytes, *parts: Any) -> int:
    value = int.from_bytes(_hash_bytes(domain_sep, *parts, length=SCALAR_LEN), "big") % modulus
    return value or 1


def H1_scalar(modulus: int, left: Any, right: Any) -> int:
    return _hash_scalar(modulus, b"H1", left, right)


def H2_mask(length: int, point) -> bytes:
    return _hash_bytes(b"H2", point, length=length)


def H3_mask(length: int, point, delta_t: int) -> bytes:
    return _hash_bytes(b"H3", point, int_to_bytes(delta_t, TIMESTAMP_LEN), length=length)


def H4_scalar(modulus: int, pid: bytes, P_i, R_i) -> int:
    return _hash_scalar(modulus, b"H4", pid, P_i, R_i)


def H5_scalar(modulus: int, pid_a: bytes, pid_b: bytes, T1, T2, P_a, R_a, P_b, R_b, Ppub, t_a: int) -> int:
    return _hash_scalar(modulus, b"H5", pid_a, pid_b, T1, T2, P_a, R_a, P_b, R_b, Ppub, t_a)


def H6_scalar(modulus: int, T1, T2, h5: int) -> int:
    return _hash_scalar(modulus, b"H6", T1, T2, h5)


def H7_key(T3, h5: int) -> bytes:
    return _hash_bytes(b"H7", T3, h5, length=SESSION_KEY_LEN)


def _ensure_point(curve: Curve, point, label: str):
    if not is_on_curve(curve, point):
        raise ValueError(f"{label} is not on the curve")


def _pack_length_prefixed(blob: bytes) -> bytes:
    return int_to_bytes(len(blob), LENGTH_LEN) + blob


def _unpack_length_prefixed(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    if offset + LENGTH_LEN > len(data):
        raise ValueError("truncated length-prefixed field")
    size = int.from_bytes(data[offset:offset + LENGTH_LEN], "big")
    start = offset + LENGTH_LEN
    end = start + size
    if end > len(data):
        raise ValueError("truncated length-prefixed payload")
    return data[start:end], end


def encode_pid(pid1: bytes, delta_t: int) -> bytes:
    return _pack_length_prefixed(pid1) + int_to_bytes(delta_t, TIMESTAMP_LEN)


def decode_pid(pid: bytes) -> tuple[bytes, int]:
    pid1, offset = _unpack_length_prefixed(pid, 0)
    if offset + TIMESTAMP_LEN != len(pid):
        raise ValueError("invalid PID encoding")
    delta_t = int.from_bytes(pid[offset:offset + TIMESTAMP_LEN], "big")
    return pid1, delta_t


def _pack_m1_payload(rid: str, P_i, h1: int) -> bytes:
    rid_bytes = rid.encode("utf-8")
    return _pack_length_prefixed(rid_bytes) + encode_point(P_i) + int_to_bytes(h1, SCALAR_LEN)


def _unpack_m1_payload(payload: bytes) -> tuple[str, tuple[int, int], int]:
    rid_bytes, offset = _unpack_length_prefixed(payload, 0)
    end_pi = offset + POINT_LEN
    end_h1 = end_pi + SCALAR_LEN
    if end_h1 != len(payload):
        raise ValueError("invalid M1 payload")
    return rid_bytes.decode("utf-8"), decode_point(payload[offset:end_pi]), int.from_bytes(payload[end_pi:end_h1], "big")


def _pack_m2_payload(pid: bytes, P_i, h2: int) -> bytes:
    return _pack_length_prefixed(pid) + encode_point(P_i) + int_to_bytes(h2, SCALAR_LEN)


def _unpack_m2_payload(payload: bytes) -> tuple[bytes, tuple[int, int], int]:
    pid, offset = _unpack_length_prefixed(payload, 0)
    end_pi = offset + POINT_LEN
    end_h2 = end_pi + SCALAR_LEN
    if end_h2 != len(payload):
        raise ValueError("invalid M2 payload")
    return pid, decode_point(payload[offset:end_pi]), int.from_bytes(payload[end_pi:end_h2], "big")


def _pack_m3_payload(pid: bytes, R_i, d_i: int) -> bytes:
    return _pack_length_prefixed(pid) + encode_point(R_i) + int_to_bytes(d_i, SCALAR_LEN)


def _unpack_m3_payload(payload: bytes) -> tuple[bytes, tuple[int, int], int]:
    pid, offset = _unpack_length_prefixed(payload, 0)
    end_ri = offset + POINT_LEN
    end_di = end_ri + SCALAR_LEN
    if end_di != len(payload):
        raise ValueError("invalid M3 payload")
    return pid, decode_point(payload[offset:end_ri]), int.from_bytes(payload[end_ri:end_di], "big")


def _pack_m4_payload(S: int, pid_a: bytes, P_a, R_a, t_a: int) -> bytes:
    return int_to_bytes(S, SCALAR_LEN) + _pack_length_prefixed(pid_a) + encode_point(P_a) + encode_point(R_a) + int_to_bytes(t_a, TIMESTAMP_LEN)


def _unpack_m4_payload(payload: bytes) -> tuple[int, bytes, tuple[int, int], tuple[int, int], int]:
    if len(payload) < SCALAR_LEN + LENGTH_LEN + 2 * POINT_LEN + TIMESTAMP_LEN:
        raise ValueError("invalid M4 payload")
    S = int.from_bytes(payload[:SCALAR_LEN], "big")
    pid_a, offset = _unpack_length_prefixed(payload, SCALAR_LEN)
    end_pa = offset + POINT_LEN
    end_ra = end_pa + POINT_LEN
    end_ta = end_ra + TIMESTAMP_LEN
    if end_ta != len(payload):
        raise ValueError("invalid M4 payload size")
    P_a = decode_point(payload[offset:end_pa])
    R_a = decode_point(payload[end_pa:end_ra])
    t_a = int.from_bytes(payload[end_ra:end_ta], "big")
    return S, pid_a, P_a, R_a, t_a


@dataclass(frozen=True)
class RegistrationBundle:
    rid: str
    pid: bytes
    P_i: tuple[int, int]
    R_i: tuple[int, int]
    x_i: int
    d_i: int
    delta_t: int

    @property
    def X_i(self) -> tuple[int, int]:
        return self.P_i


@dataclass(frozen=True)
class RequestMessage:
    M4: bytes
    T2: tuple[int, int]
    session_hint: str


@dataclass(frozen=True)
class ResponseMessage:
    M5: int
    T4: tuple[int, int]
    session_hint: str


class KGC:
    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.P = (curve.gx, curve.gy)
        self.s = secrets.randbelow(curve.n - 1) + 1
        self.Ppub = _point_scalar(curve, self.s, self.P)
        KGC._curve_to_public_ppub[id(curve)] = self.Ppub

    def process_partial_private_key_request(self, M2: bytes) -> bytes:
        payload = xor_bytes(M2, H2_mask(len(M2), _point_scalar(self.curve, self.s, TRA.public_Tpub_for(self.curve))))
        pid, P_i, h2 = _unpack_m2_payload(payload)
        _ensure_point(self.curve, P_i, "P_i")
        expected_h2 = H1_scalar(self.curve.n, pid, P_i)
        if h2 != expected_h2:
            raise ValueError("invalid M2 integrity check")

        r_i = secrets.randbelow(self.curve.n - 1) + 1
        R_i = _point_scalar(self.curve, r_i, self.P)
        h_i = H4_scalar(self.curve.n, pid, P_i, R_i)
        d_i = (r_i + self.s * h_i) % self.curve.n
        return xor_bytes(_pack_m3_payload(pid, R_i, d_i), H2_mask(len(_pack_m3_payload(pid, R_i, d_i)), _point_scalar(self.curve, self.s, P_i)))


class TRA:
    _curve_to_public_tpub: dict[int, tuple[int, int]] = {}

    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.P = (curve.gx, curve.gy)
        self.t = secrets.randbelow(curve.n - 1) + 1
        self.Tpub = _point_scalar(curve, self.t, self.P)
        self.registry: dict[bytes, tuple[str, tuple[int, int]]] = {}
        self._curve_to_public_tpub[id(curve)] = self.Tpub

    @classmethod
    def public_Tpub_for(cls, curve: Curve):
        tpub = cls._curve_to_public_tpub.get(id(curve))
        if tpub is None:
            raise RuntimeError("TRA public key unavailable for this curve")
        return tpub

    def process_pseudonym_request(self, M1: bytes, P_i, delta_t: int) -> tuple[bytes, bytes]:
        payload = xor_bytes(M1, H2_mask(len(M1), _point_scalar(self.curve, self.t, P_i)))
        rid, P_from_m1, h1 = _unpack_m1_payload(payload)
        _ensure_point(self.curve, P_i, "P_i")
        if P_from_m1 != P_i:
            raise ValueError("P_i mismatch in M1")
        expected_h1 = H1_scalar(self.curve.n, rid, P_i)
        if h1 != expected_h1:
            raise ValueError("invalid M1 integrity check")

        rid_bytes = rid.encode("utf-8")
        pid1 = xor_bytes(rid_bytes, H3_mask(len(rid_bytes), _point_scalar(self.curve, self.t, P_i), delta_t))
        pid = encode_pid(pid1, delta_t)
        h2 = H1_scalar(self.curve.n, pid, P_i)
        M2_payload = _pack_m2_payload(pid, P_i, h2)
        M2 = xor_bytes(M2_payload, H2_mask(len(M2_payload), _point_scalar(self.curve, self.t, KGC.public_Ppub_for(self.curve))))
        self.registry[pid] = (rid, P_i)
        return pid, M2

    def recover_identity(self, pid: bytes, P_i: tuple[int, int] | None = None) -> str | None:
        if P_i is None:
            entry = self.registry.get(pid)
            return None if entry is None else entry[0]
        pid1, delta_t = decode_pid(pid)
        rid_bytes = xor_bytes(pid1, H3_mask(len(pid1), _point_scalar(self.curve, self.t, P_i), delta_t))
        return rid_bytes.decode("utf-8")


KGC._curve_to_public_ppub = {}


def _kgc_public_ppub_for(curve: Curve):
    ppub = KGC._curve_to_public_ppub.get(id(curve))
    if ppub is None:
        raise RuntimeError("KGC public key unavailable for this curve")
    return ppub


KGC.public_Ppub_for = staticmethod(_kgc_public_ppub_for)


class Device:
    def __init__(self, rid: str, kgc: KGC, tra: TRA, *, pseudonym_validity: int = 3600, max_time_skew: int = 300):
        self.rid = rid
        self.curve = kgc.curve
        self.P = kgc.P
        self.kgc = kgc
        self.tra = tra
        self.max_time_skew = max_time_skew

        self.x_i = secrets.randbelow(self.curve.n - 1) + 1
        self.P_i = _point_scalar(self.curve, self.x_i, self.P)
        self.pid: bytes
        self.R_i: tuple[int, int]
        self.d_i: int
        self.delta_t: int
        self._register(pseudonym_validity)

    def _register(self, pseudonym_validity: int):
        h1 = H1_scalar(self.curve.n, self.rid, self.P_i)
        M1_payload = _pack_m1_payload(self.rid, self.P_i, h1)
        M1 = xor_bytes(M1_payload, H2_mask(len(M1_payload), _point_scalar(self.curve, self.x_i, self.tra.Tpub)))

        pid, M2 = self.tra.process_pseudonym_request(M1, self.P_i, pseudonym_validity)
        M3 = self.kgc.process_partial_private_key_request(M2)

        payload = xor_bytes(M3, H2_mask(len(M3), _point_scalar(self.curve, self.x_i, self.kgc.Ppub)))
        pid_from_m3, R_i, d_i = _unpack_m3_payload(payload)
        _ensure_point(self.curve, R_i, "R_i")

        rid_from_pid = self.tra.recover_identity(pid_from_m3, self.P_i)
        if rid_from_pid != self.rid:
            raise ValueError("PID validation failed")

        h_i = H4_scalar(self.curve.n, pid_from_m3, self.P_i, R_i)
        left = _point_scalar(self.curve, d_i, self.P)
        right = point_add(self.curve, R_i, _point_scalar(self.curve, h_i, self.kgc.Ppub))
        if left != right:
            raise ValueError("partial private key verification failed")

        _, delta_t = decode_pid(pid_from_m3)
        self.pid = pid_from_m3
        self.R_i = R_i
        self.d_i = d_i % self.curve.n
        self.delta_t = delta_t

    def registration_bundle(self) -> RegistrationBundle:
        return RegistrationBundle(
            rid=self.rid,
            pid=self.pid,
            P_i=self.P_i,
            R_i=self.R_i,
            x_i=self.x_i,
            d_i=self.d_i,
            delta_t=self.delta_t,
        )

    def _peer_h4(self, pid: bytes, P_i, R_i) -> int:
        return H4_scalar(self.curve.n, pid, P_i, R_i)

    def create_request(self, peer, timestamp: int) -> tuple[RequestMessage, dict]:
        a = secrets.randbelow(self.curve.n - 1) + 1
        factor = (a + self.x_i) % self.curve.n
        T1 = _point_scalar(self.curve, factor, self.P)
        h_b = self._peer_h4(peer.pid, peer.P_i, peer.R_i)
        peer_term = point_add(
            self.curve,
            peer.P_i,
            point_add(self.curve, peer.R_i, _point_scalar(self.curve, h_b, self.kgc.Ppub)),
        )
        T2 = _point_scalar(self.curve, factor, peer_term)
        h5 = H5_scalar(
            self.curve.n,
            self.pid,
            peer.pid,
            T1,
            T2,
            self.P_i,
            self.R_i,
            peer.P_i,
            peer.R_i,
            self.kgc.Ppub,
            timestamp,
        )
        h6 = H6_scalar(self.curve.n, T1, T2, h5)
        S = ((self.x_i * h6 + self.d_i) % self.curve.n) * h5 % self.curve.n
        S = S * inv_mod(factor, self.curve.n) % self.curve.n
        payload = _pack_m4_payload(S, self.pid, self.P_i, self.R_i, timestamp)
        M4 = xor_bytes(payload, H2_mask(len(payload), T1))
        request = RequestMessage(M4=M4, T2=T2, session_hint=f"{self.rid}->{peer.rid}@{timestamp}")
        state = {
            "a": a,
            "h5": h5,
            "timestamp": timestamp,
        }
        return request, state

    def verify_request(self, request: RequestMessage, current_time: int) -> dict:
        _ensure_point(self.curve, request.T2, "T2")
        inverse = inv_mod((self.x_i + self.d_i) % self.curve.n, self.curve.n)
        T1 = _point_scalar(self.curve, inverse, request.T2)
        S, pid_a, P_a, R_a, t_a = _unpack_m4_payload(xor_bytes(request.M4, H2_mask(len(request.M4), T1)))
        _ensure_point(self.curve, P_a, "P_a")
        _ensure_point(self.curve, R_a, "R_a")

        if current_time < t_a or current_time - t_a >= self.max_time_skew:
            raise ValueError("request timestamp outside freshness window")

        h5 = H5_scalar(
            self.curve.n,
            pid_a,
            self.pid,
            T1,
            request.T2,
            P_a,
            R_a,
            self.P_i,
            self.R_i,
            self.kgc.Ppub,
            t_a,
        )
        h6 = H6_scalar(self.curve.n, T1, request.T2, h5)
        h_a = self._peer_h4(pid_a, P_a, R_a)

        left = _point_scalar(self.curve, S * inv_mod(h5, self.curve.n), T1)
        right = point_add(
            self.curve,
            _point_scalar(self.curve, h6, P_a),
            point_add(self.curve, R_a, _point_scalar(self.curve, h_a, self.kgc.Ppub)),
        )
        if left != right:
            raise ValueError("request verification failed")

        return {
            "pid_a": pid_a,
            "P_a": P_a,
            "R_a": R_a,
            "T1": T1,
            "h5": h5,
            "timestamp": t_a,
        }

    def create_response(self, peer, request: RequestMessage, request_state: dict, timestamp: int) -> tuple[ResponseMessage, dict]:
        verified = self.verify_request(request, timestamp)
        b = secrets.randbelow(self.curve.n - 1) + 1
        factor = (b + self.x_i) % self.curve.n
        T3 = _point_scalar(self.curve, factor, verified["T1"])
        T4 = _point_scalar(self.curve, factor, verified["P_a"])
        session_key = H7_key(T3, verified["h5"])
        M5 = H1_scalar(self.curve.n, session_key, T4)
        response = ResponseMessage(M5=M5, T4=T4, session_hint=request.session_hint)
        return response, {"b": b, "session_key": session_key}

    def finalize_session_as_initiator(self, peer, request_state: dict, response: ResponseMessage, timestamp: int) -> bytes:
        _ensure_point(self.curve, response.T4, "T4")
        factor = (self.x_i + request_state["a"]) % self.curve.n
        T3 = _point_scalar(self.curve, factor * inv_mod(self.x_i, self.curve.n), response.T4)
        session_key = H7_key(T3, request_state["h5"])
        M5 = H1_scalar(self.curve.n, session_key, response.T4)
        if M5 != response.M5:
            raise ValueError("response verification failed")
        return session_key


def run_demo():
    kgc = KGC()
    tra = TRA()
    alice = Device("alice-sensor-01", kgc, tra)
    bob = Device("bob-gateway-02", kgc, tra)

    request, req_state = alice.create_request(bob.registration_bundle(), timestamp=1)
    response, resp_state = bob.create_response(alice.registration_bundle(), request, req_state, timestamp=2)
    initiator_sk = alice.finalize_session_as_initiator(bob.registration_bundle(), req_state, response, timestamp=2)

    return {
        "same_session_key": initiator_sk == resp_state["session_key"],
        "alice_pid": alice.pid.hex()[:48] + "...",
        "bob_pid": bob.pid.hex()[:48] + "...",
        "trace_alice": tra.recover_identity(alice.pid, alice.P_i),
        "trace_bob": tra.recover_identity(bob.pid, bob.P_i),
        "session_key_sha256": hashlib.sha256(initiator_sk).hexdigest(),
    }
