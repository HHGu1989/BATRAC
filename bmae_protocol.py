#!/usr/bin/env python3
"""Reproduction of the BMAE protocol (Yu et al., JISA 2025) in pure Python.

Paper: "A high-security batch message authentication protocol assisted by edge
servers in industrial Internet of Things" (DOI: 10.1016/j.jisa.2025.104075)

This module focuses on the protocol equations and message flow:
- KGC initializes public parameters (we reuse ECC from ecc.py; no pairings).
- ES registration (ID-based public key derivation) and ES long-term secret sk.
- SD registration with ES via a shared key S1 = H4(x_i * T_pub).
- ES issues partial private key d_i = r_i + sk * h_i1 and pseudonym seeds.
- SD encrypts+signs messages; ES batch-verifies aggregate signatures and forwards.

This is a research / reproduction artifact, not a production cryptosystem.
It uses SHA-256 as the underlying hash and a stream-XOR "Enc" for simplicity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import INFINITY, SECP256R1, Curve, is_on_curve, point_add, point_neg, scalar_mult
from protocol import encode_point, int_to_bytes

DEFAULT_AUTH_WINDOW = 300
DEFAULT_PACKET_WINDOW = 300


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def _norm_part(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part, 32)
    if isinstance(part, tuple):
        return encode_point(part)
    raise TypeError(f"unsupported hash part type: {type(part)!r}")


def H_scalar(modulus: int, domain_sep: bytes, *parts: Any) -> int:
    """Hash-to-scalar with explicit domain separation."""
    blob = b"".join([domain_sep, *(_norm_part(p) for p in parts)])
    return int.from_bytes(_sha256(blob), "big") % modulus


def H_bytes(domain_sep: bytes, *parts: Any, length: int = 32) -> bytes:
    """Hash-to-bytes (counter mode) for key material / stream keystream."""
    out = b""
    counter = 0
    while len(out) < length:
        blob = b"".join([domain_sep, int_to_bytes(counter, 4), *(_norm_part(p) for p in parts)])
        out += _sha256(blob)
        counter += 1
    return out[:length]


def xor_stream(key: bytes, data: bytes) -> bytes:
    """XOR a keystream derived from key with data."""
    stream = H_bytes(b"ENC", key, length=len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


def encode_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode_json(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def encode_acl(sd_id: str, expire_time: int) -> str:
    return json.dumps({"expire_time": expire_time, "sd_id": sd_id}, separators=(",", ":"), sort_keys=True)


def decode_acl(acl_i: str) -> dict:
    return json.loads(acl_i)


def _auth_transcript(N_e: int, F_e: tuple[int, int], N_s: int, F_s: tuple[int, int]) -> bytes:
    return b"".join(
        [
            int_to_bytes(N_e, 32),
            encode_point(F_e),
            int_to_bytes(N_s, 32),
            encode_point(F_s),
        ]
    )


def _auth_key(shared_point: tuple[int, int]) -> bytes:
    return H_bytes(b"H2_AUTH", shared_point, length=32)


def _fresh_enough(packet_ts: int, current_time: int, window: int) -> bool:
    return packet_ts <= current_time and current_time - packet_ts <= window


def _valid_scalar_component(value: int, modulus: int) -> bool:
    return 2 <= value < modulus


def _scalar_with_mask(curve: Curve) -> tuple[int, int]:
    while True:
        nonce = secrets.randbelow(curve.n - 2) + 2
        mask = secrets.randbelow(curve.n - 2) + 2
        scalar = (nonce + mask) % curve.n
        if _valid_scalar_component(scalar, curve.n):
            return nonce, mask


def pid_hash(seed: bytes) -> bytes:
    """H3(·) for hash-chain based pseudonym generation (bytes output)."""
    return _sha256(b"H3_PID", seed)


def pid_chain(seed: bytes, steps: int) -> bytes:
    out = seed
    for _ in range(steps):
        out = pid_hash(out)
    return out


def derive_pid(seed1: bytes, seed2: bytes, c: int, j: int) -> bytes:
    """Equation (1) in the paper: PID_{i,j} = H3(S1_j xor S2_{C-j+1})."""
    if j < 1 or j > c:
        raise ValueError("j must be in [1, C]")
    s1_j = pid_chain(seed1, j)
    s2 = pid_chain(seed2, c - j + 1)
    mixed = bytes(a ^ b for a, b in zip(s1_j, s2))
    return pid_hash(mixed)


@dataclass(frozen=True)
class SDPublicKey:
    X_i: tuple[int, int]
    R_i: tuple[int, int]


@dataclass(frozen=True)
class SDPrivateKey:
    x_i: int
    d_i: int


@dataclass(frozen=True)
class SDKeyMaterial:
    acl_i: str
    public_key: SDPublicKey
    private_key: SDPrivateKey
    seed1: bytes
    seed2: bytes
    chain_len: int
    expire_time: int


@dataclass(frozen=True)
class MutualAuthChallenge:
    es_id: str
    N_e: int
    F_e: tuple[int, int]


@dataclass(frozen=True)
class MutualAuthResponse:
    sd_id: str
    N_s: int
    F_s: tuple[int, int]
    mvc_s: bytes


@dataclass(frozen=True)
class MutualAuthAck:
    es_id: str
    mvc_e: bytes
    authenticated_until: int


@dataclass(frozen=True)
class SDRegistrationRequest:
    sd_id: str
    X_i: tuple[int, int]
    ts: int
    payload_ct: bytes


@dataclass(frozen=True)
class SDRegistrationResponse:
    ct: bytes


@dataclass(frozen=True)
class Signature:
    U_i: tuple[int, int]
    sigma_i: int


@dataclass(frozen=True)
class MessagePacket:
    sender_pid: bytes
    sender_acl: str
    sender_pk: SDPublicKey
    sig: Signature
    V: tuple[int, int]
    ciphertext: bytes
    ts: int
    dest_id: str


@dataclass(frozen=True)
class DeliveredMessage:
    sender_pid: bytes
    plaintext: bytes
    ts: int


class KGC:
    """KGC only provides public parameters and ID->public key mapping (H1)."""

    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.P = (curve.gx, curve.gy)

    def H1_to_point(self, identity: str) -> tuple[int, int]:
        k = H_scalar(self.curve.n, b"H1", identity)
        # Avoid the identity mapping to INFINITY.
        if k == 0:
            k = 1
        return scalar_mult(self.curve, k, self.P)


class EdgeServer:
    def __init__(self, es_id: str, kgc: KGC, chain_len: int = 64, auth_window: int = DEFAULT_AUTH_WINDOW, packet_window: int = DEFAULT_PACKET_WINDOW):
        self.es_id = es_id
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P
        self.chain_len = chain_len
        self.auth_window = auth_window
        self.packet_window = packet_window

        # ID-based public key (Q_ES) is derived from identity.
        self.Q_es = kgc.H1_to_point(es_id)

        # Long-term ES secret and corresponding public parameter T_pub = sk * P (Section 5.3).
        self.sk = secrets.randbelow(self.curve.n - 1) + 1
        self.T_pub = scalar_mult(self.curve, self.sk, self.P)

        # ES "private key" in the paper is S_u = sk * Q_es; it isn't used in the
        # core batch authentication equations, but we keep it for completeness.
        self.S_es = scalar_mult(self.curve, self.sk, self.Q_es)

        # sd_id -> SDKeyMaterial (incl. seeds to validate current pseudonym if needed)
        self._sd_registry: dict[str, SDKeyMaterial] = {}
        self._pending_auth: dict[str, tuple[int, MutualAuthChallenge]] = {}
        self._authenticated_until: dict[str, int] = {}

    def start_mutual_auth(self, sd_id: str) -> MutualAuthChallenge:
        n_e, y_e = _scalar_with_mask(self.curve)
        challenge = MutualAuthChallenge(
            es_id=self.es_id,
            N_e=(n_e + y_e) % self.curve.n,
            F_e=point_neg(self.curve, scalar_mult(self.curve, y_e, self.P)),
        )
        self._pending_auth[sd_id] = (n_e, challenge)
        return challenge

    def finish_mutual_auth(self, response: MutualAuthResponse, current_time: int) -> MutualAuthAck:
        pending = self._pending_auth.pop(response.sd_id, None)
        if pending is None:
            raise ValueError("no pending mutual-auth challenge for this SD")
        n_e, challenge = pending
        if not _valid_scalar_component(response.N_s, self.curve.n):
            raise ValueError("invalid N_s in mutual-auth response")
        if not is_on_curve(self.curve, response.F_s):
            raise ValueError("invalid F_s in mutual-auth response")

        shared = scalar_mult(
            self.curve,
            n_e,
            point_add(self.curve, response.F_s, scalar_mult(self.curve, response.N_s, self.P)),
        )
        key = _auth_key(shared)
        transcript = _auth_transcript(challenge.N_e, challenge.F_e, response.N_s, response.F_s)
        mvc_e = hmac.new(key, transcript, hashlib.sha256).digest()
        if response.mvc_s != mvc_e:
            raise ValueError("mutual-auth MVC mismatch")

        authenticated_until = current_time + self.auth_window
        self._authenticated_until[response.sd_id] = authenticated_until
        return MutualAuthAck(es_id=self.es_id, mvc_e=mvc_e, authenticated_until=authenticated_until)

    def _require_authenticated(self, sd_id: str, timestamp: int):
        auth_until = self._authenticated_until.get(sd_id)
        if auth_until is None or timestamp > auth_until:
            raise ValueError("SD has not completed a valid mutual-auth exchange")

    def _S1_key(self, X_i: tuple[int, int]) -> bytes:
        shared = scalar_mult(self.curve, self.sk, X_i)
        return H_bytes(b"H4_S1", shared, length=32)

    def _h_i1(self, acl_i: str, R_i: tuple[int, int], X_i: tuple[int, int]) -> int:
        # h_i1 = H2(T_pub; ACL_i, R_i, X_i)
        return H_scalar(self.curve.n, b"H2_h1", self.T_pub, acl_i, R_i, X_i)

    def _sig_hashes(self, pid: bytes, pk: SDPublicKey, U_i: tuple[int, int]) -> tuple[int, int, int]:
        # h_i2 = H2(PID_i; PK_i, U_i), h_i3 = H3(...), h_i4 = H4(...)
        h2 = H_scalar(self.curve.n, b"H2_h2", pid, pk.X_i, pk.R_i, U_i)
        h3 = H_scalar(self.curve.n, b"H3_h3", pid, pk.X_i, pk.R_i, U_i)
        h4 = H_scalar(self.curve.n, b"H4_h4", pid, pk.X_i, pk.R_i, U_i)
        return h2, h3, h4

    def _material_for_packet(self, pkt: "MessagePacket") -> SDKeyMaterial | None:
        for material in self._sd_registry.values():
            if material.acl_i != pkt.sender_acl:
                continue
            if material.public_key == pkt.sender_pk:
                return material
        return None

    def _pid_belongs_to_material(self, material: SDKeyMaterial, pid: bytes) -> bool:
        for idx in range(1, material.chain_len + 1):
            if derive_pid(material.seed1, material.seed2, material.chain_len, idx) == pid:
                return True
        return False

    def register_sd(self, request: SDRegistrationRequest) -> SDRegistrationResponse:
        if not is_on_curve(self.curve, request.X_i):
            raise ValueError("invalid X_i")
        self._require_authenticated(request.sd_id, request.ts)

        s1 = self._S1_key(request.X_i)
        payload = decode_json(xor_stream(s1, request.payload_ct))
        if payload.get("sd_id") != request.sd_id:
            raise ValueError("registration payload sd_id mismatch")
        if payload.get("ts") != request.ts:
            raise ValueError("registration payload timestamp mismatch")
        if payload.get("X_i") != encode_point(request.X_i).hex():
            raise ValueError("registration payload X_i mismatch")

        expire_time = request.ts + self.chain_len + self.packet_window
        acl_i = encode_acl(request.sd_id, expire_time)

        # Partial key generation (Section 5.3, Step 4).
        r_i = secrets.randbelow(self.curve.n - 1) + 1
        R_i = scalar_mult(self.curve, r_i, self.P)
        h1 = self._h_i1(acl_i, R_i, request.X_i)
        d_i = (r_i + self.sk * h1) % self.curve.n

        # Pseudonym seeds (Equation (1)).
        seed1 = secrets.token_bytes(32)
        seed2 = secrets.token_bytes(32)

        material = SDKeyMaterial(
            acl_i=acl_i,
            public_key=SDPublicKey(X_i=request.X_i, R_i=R_i),
            private_key=SDPrivateKey(x_i=0, d_i=d_i),  # x_i is unknown to ES; placeholder.
            seed1=seed1,
            seed2=seed2,
            chain_len=self.chain_len,
            expire_time=expire_time,
        )
        self._sd_registry[request.sd_id] = material

        # Send encrypted keying material to SD (Section 5.3, Step 5/6).
        package = {
            "acl_i": acl_i,
            "X_i": encode_point(request.X_i).hex(),
            "R_i": encode_point(R_i).hex(),
            "d_i": int_to_bytes(d_i, 32).hex(),
            "seed1": seed1.hex(),
            "seed2": seed2.hex(),
            "chain_len": self.chain_len,
            "expire_time": expire_time,
        }
        ct = xor_stream(s1, encode_json(package))
        return SDRegistrationResponse(ct=ct)

    def verify_batch(self, packets: list[MessagePacket], current_time: int | None = None) -> bool:
        if not packets:
            return True

        sigma_sum = 0
        rhs = INFINITY
        for pkt in packets:
            pk = pkt.sender_pk
            if not is_on_curve(self.curve, pk.X_i) or not is_on_curve(self.curve, pk.R_i):
                return False
            if not is_on_curve(self.curve, pkt.sig.U_i):
                return False
            material = self._material_for_packet(pkt)
            if material is None:
                return False
            if not self._pid_belongs_to_material(material, pkt.sender_pid):
                return False
            acl_info = decode_acl(pkt.sender_acl)
            if acl_info.get("expire_time") != material.expire_time:
                return False
            if current_time is not None:
                if not _fresh_enough(pkt.ts, current_time, self.packet_window):
                    return False
                if pkt.ts > material.expire_time or current_time > material.expire_time:
                    return False

            h1 = self._h_i1(pkt.sender_acl, pk.R_i, pk.X_i)
            h2, h3, h4 = self._sig_hashes(pkt.sender_pid, pk, pkt.sig.U_i)

            sigma_sum = (sigma_sum + pkt.sig.sigma_i) % self.curve.n

            term_u = scalar_mult(self.curve, h4, pkt.sig.U_i)
            term_d = scalar_mult(
                self.curve,
                h3,
                point_add(self.curve, pk.R_i, scalar_mult(self.curve, h1, self.T_pub)),
            )
            term_x = scalar_mult(self.curve, h2, pk.X_i)
            rhs = point_add(self.curve, rhs, point_add(self.curve, term_u, point_add(self.curve, term_d, term_x)))

        lhs = scalar_mult(self.curve, sigma_sum, self.P)
        return lhs == rhs

    def identify_invalid_indices(self, packets: list[MessagePacket], current_time: int | None = None) -> list[int]:
        """Binary-search style invalid signature identification (Section 5.6).

        Returns indices of packets that fail batch verification.
        """
        invalid: list[int] = []

        def rec(offset: int, segment: list[MessagePacket]):
            if not segment:
                return
            if self.verify_batch(segment, current_time=current_time):
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


class SmartDevice:
    def __init__(self, sd_id: str, kgc: KGC, packet_window: int = DEFAULT_PACKET_WINDOW):
        self.sd_id = sd_id
        self.kgc = kgc
        self.curve = kgc.curve
        self.P = kgc.P
        self.packet_window = packet_window

        self.x_i = secrets.randbelow(self.curve.n - 1) + 1
        self.X_i = scalar_mult(self.curve, self.x_i, self.P)

        self.key_material: SDKeyMaterial | None = None
        self._pid_index = 1
        self._peer_pubkeys: dict[str, tuple[int, int]] = {}
        self._authenticated_es: dict[str, int] = {}

    def learn_peer_pubkey(self, peer_id: str, X_peer: tuple[int, int]):
        self._peer_pubkeys[peer_id] = X_peer

    def _S1_key(self, T_pub: tuple[int, int]) -> bytes:
        shared = scalar_mult(self.curve, self.x_i, T_pub)
        return H_bytes(b"H4_S1", shared, length=32)

    def build_mutual_auth_response(self, challenge: MutualAuthChallenge) -> tuple[MutualAuthResponse, dict]:
        if not _valid_scalar_component(challenge.N_e, self.curve.n):
            raise ValueError("invalid N_e in mutual-auth challenge")
        if not is_on_curve(self.curve, challenge.F_e):
            raise ValueError("invalid F_e in mutual-auth challenge")

        n_s, y_s = _scalar_with_mask(self.curve)
        response = MutualAuthResponse(
            sd_id=self.sd_id,
            N_s=(n_s + y_s) % self.curve.n,
            F_s=point_neg(self.curve, scalar_mult(self.curve, y_s, self.P)),
            mvc_s=b"",
        )
        shared = scalar_mult(
            self.curve,
            n_s,
            point_add(self.curve, challenge.F_e, scalar_mult(self.curve, challenge.N_e, self.P)),
        )
        key = _auth_key(shared)
        transcript = _auth_transcript(challenge.N_e, challenge.F_e, response.N_s, response.F_s)
        mvc_s = hmac.new(key, transcript, hashlib.sha256).digest()
        return MutualAuthResponse(sd_id=self.sd_id, N_s=response.N_s, F_s=response.F_s, mvc_s=mvc_s), {
            "es_id": challenge.es_id,
            "mvc_expected": mvc_s,
        }

    def finalize_mutual_auth(self, ack: MutualAuthAck, state: dict):
        if ack.mvc_e != state["mvc_expected"]:
            raise ValueError("mutual-auth confirmation failed")
        self._authenticated_es[ack.es_id] = ack.authenticated_until

    def mutual_authenticate(self, es: EdgeServer, current_time: int):
        challenge = es.start_mutual_auth(self.sd_id)
        response, state = self.build_mutual_auth_response(challenge)
        ack = es.finish_mutual_auth(response, current_time)
        self.finalize_mutual_auth(ack, state)

    def _require_mutual_auth(self, es_id: str, timestamp: int):
        authenticated_until = self._authenticated_es.get(es_id)
        if authenticated_until is None or timestamp > authenticated_until:
            raise RuntimeError("mutual authentication with ES is required before registration")

    def create_registration_request(self, es: EdgeServer, timestamp: int) -> SDRegistrationRequest:
        self._require_mutual_auth(es.es_id, timestamp)
        s1 = self._S1_key(es.T_pub)
        payload = {
            "sd_id": self.sd_id,
            "X_i": encode_point(self.X_i).hex(),
            "ts": timestamp,
        }
        ct = xor_stream(s1, encode_json(payload))
        return SDRegistrationRequest(sd_id=self.sd_id, X_i=self.X_i, ts=timestamp, payload_ct=ct)

    def finalize_registration(self, es: EdgeServer, response: SDRegistrationResponse):
        s1 = self._S1_key(es.T_pub)
        package = decode_json(xor_stream(s1, response.ct))
        acl_i = package["acl_i"]
        X_i = bytes.fromhex(package["X_i"])
        if X_i != encode_point(self.X_i):
            raise ValueError("received X_i mismatch")

        R_i = self._decode_point_hex(package["R_i"])
        d_i = int.from_bytes(bytes.fromhex(package["d_i"]), "big") % self.curve.n
        seed1 = bytes.fromhex(package["seed1"])
        seed2 = bytes.fromhex(package["seed2"])
        chain_len = int(package["chain_len"])
        expire_time = int(package["expire_time"])

        # Verify partial key: d_i P = R_i + h_i1 T_pub (Section 5.3 Step 6).
        h1 = H_scalar(self.curve.n, b"H2_h1", es.T_pub, acl_i, R_i, self.X_i)
        left = scalar_mult(self.curve, d_i, self.P)
        right = point_add(self.curve, R_i, scalar_mult(self.curve, h1, es.T_pub))
        if left != right:
            raise ValueError("partial private key verification failed")

        self.key_material = SDKeyMaterial(
            acl_i=acl_i,
            public_key=SDPublicKey(X_i=self.X_i, R_i=R_i),
            private_key=SDPrivateKey(x_i=self.x_i, d_i=d_i),
            seed1=seed1,
            seed2=seed2,
            chain_len=chain_len,
            expire_time=expire_time,
        )

    def current_pid(self) -> bytes:
        if self.key_material is None:
            raise RuntimeError("device not registered")
        if self._pid_index > self.key_material.chain_len:
            raise RuntimeError("pseudonym chain exhausted; re-registration required")
        return derive_pid(self.key_material.seed1, self.key_material.seed2, self.key_material.chain_len, self._pid_index)

    def advance_pid(self):
        if self.key_material is None:
            raise RuntimeError("device not registered")
        self._pid_index += 1

    def _decode_point_hex(self, data_hex: str) -> tuple[int, int]:
        raw = bytes.fromhex(data_hex)
        if len(raw) != 65 or raw[0] != 4:
            raise ValueError("invalid point encoding")
        return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"))

    def _S2_key(self, V: tuple[int, int], dest_X: tuple[int, int]) -> bytes:
        # Sender uses v * X_j; receiver uses x_j * V. Both are equal.
        # Here we derive using the point v*X_j (sender side).
        return H_bytes(b"H5_S2", V, dest_X, length=32)

    def encrypt_and_sign(self, dest_id: str, message: bytes, timestamp: int) -> MessagePacket:
        if self.key_material is None:
            raise RuntimeError("device not registered")
        if dest_id not in self._peer_pubkeys:
            raise KeyError(f"unknown destination public key: {dest_id}")
        if timestamp > self.key_material.expire_time:
            raise ValueError("current key material has expired")

        dest_X = self._peer_pubkeys[dest_id]

        # Encryption (Section 5.4): choose v, compute V=vP, S2=H5(v*Xj).
        v = secrets.randbelow(self.curve.n - 1) + 1
        V = scalar_mult(self.curve, v, self.P)
        shared = scalar_mult(self.curve, v, dest_X)
        s2 = H_bytes(b"H5_S2", shared, length=32)
        digest = hashlib.sha256(message).digest()
        plaintext = message + digest
        ciphertext = xor_stream(s2, plaintext)

        # Signature (Section 5.4): choose u, U=uP; sigma = h4*u + h3*d + h2*x.
        u = secrets.randbelow(self.curve.n - 1) + 1
        U = scalar_mult(self.curve, u, self.P)
        pid = self.current_pid()
        pk = self.key_material.public_key
        h2 = H_scalar(self.curve.n, b"H2_h2", pid, pk.X_i, pk.R_i, U)
        h3 = H_scalar(self.curve.n, b"H3_h3", pid, pk.X_i, pk.R_i, U)
        h4 = H_scalar(self.curve.n, b"H4_h4", pid, pk.X_i, pk.R_i, U)
        sigma = (h4 * u + h3 * self.key_material.private_key.d_i + h2 * self.x_i) % self.curve.n

        sig = Signature(U_i=U, sigma_i=sigma)
        return MessagePacket(
            sender_pid=pid,
            sender_acl=self.key_material.acl_i,
            sender_pk=pk,
            sig=sig,
            V=V,
            ciphertext=ciphertext,
            ts=timestamp,
            dest_id=dest_id,
        )

    def receive_forwarded(self, packet: MessagePacket, current_time: int | None = None) -> DeliveredMessage:
        if self.key_material is None:
            raise RuntimeError("device not registered")
        if current_time is None:
            current_time = packet.ts
        if not _fresh_enough(packet.ts, current_time, self.packet_window):
            raise ValueError("packet timestamp outside freshness window")
        if current_time > self.key_material.expire_time or packet.ts > self.key_material.expire_time:
            raise ValueError("packet was received after key material expiry")
        # Receiver derives S2' = H5(x_j * V).
        shared = scalar_mult(self.curve, self.x_i, packet.V)
        s2 = H_bytes(b"H5_S2", shared, length=32)
        plaintext = xor_stream(s2, packet.ciphertext)
        if len(plaintext) < 32:
            raise ValueError("ciphertext too short")
        msg, digest = plaintext[:-32], plaintext[-32:]
        if hashlib.sha256(msg).digest() != digest:
            raise ValueError("message integrity check failed")
        return DeliveredMessage(sender_pid=packet.sender_pid, plaintext=msg, ts=packet.ts)


def run_bmae_smoke(devices: int = 6, messages: int = 12, seed: int = 20250306) -> dict:
    """Single-threaded smoke demo: register N devices to one ES and batch-verify messages."""
    rng = secrets.SystemRandom()
    kgc = KGC()
    es = EdgeServer("edge-01", kgc)
    sds = [SmartDevice(f"sd-{i:02d}", kgc) for i in range(1, devices + 1)]

    for sd in sds:
        sd.mutual_authenticate(es, current_time=1)
        req = sd.create_registration_request(es, timestamp=1)
        resp = es.register_sd(req)
        sd.finalize_registration(es, resp)

    # Distribute pubkeys (X_i only is needed for S2).
    for sd in sds:
        for other in sds:
            if other.sd_id != sd.sd_id:
                sd.learn_peer_pubkey(other.sd_id, other.X_i)

    # Create messages and verify them in one batch.
    pkts: list[MessagePacket] = []
    sd_ids = [sd.sd_id for sd in sds]
    for idx in range(messages):
        sender = sds[idx % len(sds)]
        dest = rng.choice([x for x in sd_ids if x != sender.sd_id])
        pkt = sender.encrypt_and_sign(dest, f"hello-{idx}".encode("utf-8"), timestamp=100 + idx)
        pkts.append(pkt)

    current_time = max(pkt.ts for pkt in pkts) + 1 if pkts else 0
    verified = es.verify_batch(pkts, current_time=current_time)
    delivered = 0
    if verified:
        by_id = {sd.sd_id: sd for sd in sds}
        for pkt in pkts:
            by_id[pkt.dest_id].receive_forwarded(pkt, current_time=current_time)
            delivered += 1

    return {
        "devices": devices,
        "messages": messages,
        "batch_verified": verified,
        "delivered": delivered,
        "curve": es.curve.name,
    }
