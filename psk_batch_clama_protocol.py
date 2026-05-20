#!/usr/bin/env python3
"""PSK-protected batch certificateless authentication for IoT.

This module implements the protocol described in the user-provided LaTeX:
- registration protected by a pre-shared key with RA/KGC
- certificateless full-key generation
- batched authentication toward an edge gateway
- per-device session-key agreement after a successful batch verification

It is designed as a third scheme alongside PPT-CLAMA and BMAE for study and
comparative experimentation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from ecc import Curve, SECP256R1, is_on_curve, point_add, scalar_mult
from protocol import decode_point, encode_point, int_to_bytes, inv_mod, xor_bytes


POINT_LEN = 65
SCALAR_LEN = 32
LENGTH_LEN = 2
TIMESTAMP_LEN = 8
DEFAULT_KEY_LEN = 32


def _norm_part(part: Any) -> bytes:
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return int_to_bytes(part, SCALAR_LEN)
    if isinstance(part, tuple):
        return encode_point(part)
    raise TypeError(f"unsupported hash part type: {type(part)!r}")


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


def H1_key(length: int, shared_point: tuple[int, int], psk: bytes) -> bytes:
    return _hash_bytes(b"H1", shared_point, psk, length=length)


def H2_mac(key: bytes, payload: bytes) -> bytes:
    return hmac.new(key, payload, hashlib.sha256).digest()


def H3_pid(length: int, shared_point: tuple[int, int], issue_ts: int) -> bytes:
    return _hash_bytes(b"H3", shared_point, issue_ts, length=length)


def H4_scalar(modulus: int, pid: bytes, P_i: tuple[int, int], R_i: tuple[int, int]) -> int:
    value = int.from_bytes(_hash_bytes(b"H4", pid, P_i, R_i, length=SCALAR_LEN), "big") % modulus
    return value or 1


def H5_scalar(
    modulus: int,
    pid_i: bytes,
    pid_eg: bytes,
    P_i: tuple[int, int],
    R_i: tuple[int, int],
    P_eg: tuple[int, int],
    R_eg: tuple[int, int],
    T_i: tuple[int, int],
    tau_i: int,
) -> int:
    value = int.from_bytes(
        _hash_bytes(b"H5", pid_i, pid_eg, P_i, R_i, P_eg, R_eg, T_i, tau_i, length=SCALAR_LEN),
        "big",
    ) % modulus
    return value or 1


def H6_key(U_i: tuple[int, int], nu_i: int, length: int = DEFAULT_KEY_LEN) -> bytes:
    return _hash_bytes(b"H6", U_i, nu_i, length=length)


def _ensure_point(curve: Curve, point, label: str):
    if not is_on_curve(curve, point):
        raise ValueError(f"{label} is not on the curve")


def _pack_len(blob: bytes) -> bytes:
    return int_to_bytes(len(blob), LENGTH_LEN) + blob


def _unpack_len(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    if offset + LENGTH_LEN > len(data):
        raise ValueError("truncated length-prefixed field")
    size = int.from_bytes(data[offset:offset + LENGTH_LEN], "big")
    start = offset + LENGTH_LEN
    end = start + size
    if end > len(data):
        raise ValueError("truncated length-prefixed payload")
    return data[start:end], end


def _pack_device_to_ra(rid: str, P_i: tuple[int, int]) -> bytes:
    return _pack_len(rid.encode("utf-8")) + encode_point(P_i)


def _unpack_device_to_ra(payload: bytes) -> tuple[str, tuple[int, int]]:
    rid_bytes, offset = _unpack_len(payload, 0)
    end = offset + POINT_LEN
    if end != len(payload):
        raise ValueError("invalid device->RA payload")
    return rid_bytes.decode("utf-8"), decode_point(payload[offset:end])


def _pack_ra_to_kgc(pid: bytes, P_i: tuple[int, int], issue_ts: int, validity: int) -> bytes:
    return _pack_len(pid) + encode_point(P_i) + int_to_bytes(issue_ts, TIMESTAMP_LEN) + int_to_bytes(validity, TIMESTAMP_LEN)


def _unpack_ra_to_kgc(payload: bytes) -> tuple[bytes, tuple[int, int], int, int]:
    pid, offset = _unpack_len(payload, 0)
    end_p = offset + POINT_LEN
    end_issue = end_p + TIMESTAMP_LEN
    end_validity = end_issue + TIMESTAMP_LEN
    if end_validity != len(payload):
        raise ValueError("invalid RA->KGC payload")
    return (
        pid,
        decode_point(payload[offset:end_p]),
        int.from_bytes(payload[end_p:end_issue], "big"),
        int.from_bytes(payload[end_issue:end_validity], "big"),
    )


def _pack_kgc_to_device(pid: bytes, issue_ts: int, validity: int, R_i: tuple[int, int], d_i: int) -> bytes:
    return (
        _pack_len(pid)
        + int_to_bytes(issue_ts, TIMESTAMP_LEN)
        + int_to_bytes(validity, TIMESTAMP_LEN)
        + encode_point(R_i)
        + int_to_bytes(d_i, SCALAR_LEN)
    )


def _unpack_kgc_to_device(payload: bytes) -> tuple[bytes, int, int, tuple[int, int], int]:
    pid, offset = _unpack_len(payload, 0)
    end_issue = offset + TIMESTAMP_LEN
    end_validity = end_issue + TIMESTAMP_LEN
    end_R = end_validity + POINT_LEN
    end_d = end_R + SCALAR_LEN
    if end_d != len(payload):
        raise ValueError("invalid KGC->device payload")
    return (
        pid,
        int.from_bytes(payload[offset:end_issue], "big"),
        int.from_bytes(payload[end_issue:end_validity], "big"),
        decode_point(payload[end_validity:end_R]),
        int.from_bytes(payload[end_R:end_d], "big"),
    )


@dataclass(frozen=True)
class PublicCredential:
    rid: str
    pid: bytes
    issue_ts: int
    validity: int
    P_i: tuple[int, int]
    R_i: tuple[int, int]

    @property
    def valid_until(self) -> int:
        return self.issue_ts + self.validity

    @property
    def X_i(self) -> tuple[int, int]:
        return self.P_i


@dataclass(frozen=True)
class FullCredential(PublicCredential):
    x_i: int
    d_i: int


@dataclass(frozen=True)
class RegistrationBundle:
    public: PublicCredential
    private_x: int
    private_d: int


@dataclass(frozen=True)
class DeviceRegistrationRequest:
    P_i: tuple[int, int]
    issue_ts: int
    validity: int
    ciphertext: bytes
    mac: bytes


@dataclass(frozen=True)
class DeviceRegistrationTicket:
    pid: bytes
    issue_ts: int
    validity: int


@dataclass(frozen=True)
class DeviceRegistrationResponse:
    ticket: DeviceRegistrationTicket
    ciphertext: bytes
    mac: bytes


@dataclass(frozen=True)
class BatchAuthRequest:
    sender_pid: bytes
    P_i: tuple[int, int]
    R_i: tuple[int, int]
    T_i: tuple[int, int]
    tau_i: int
    S_i: int


@dataclass(frozen=True)
class BatchAuthResponse:
    sender_pid: bytes
    tau_i: int
    V_i: tuple[int, int]
    mac_eg_di: bytes


class KGC:
    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.G = (curve.gx, curve.gy)
        self.s = secrets.randbelow(curve.n - 1) + 1
        self.P_KGC = scalar_mult(curve, self.s, self.G)

    def handle_registration_forward(self, ciphertext: bytes, mac: bytes, ra_public: tuple[int, int], psk: bytes) -> tuple[bytes, bytes]:
        key = H1_key(len(ciphertext), scalar_mult(self.curve, self.s, ra_public), psk)
        payload = xor_bytes(ciphertext, key)
        if H2_mac(key, payload) != mac:
            raise ValueError("invalid RA->KGC MAC")
        pid, P_i, issue_ts, validity = _unpack_ra_to_kgc(payload)
        _ensure_point(self.curve, P_i, "P_i")

        r_i = secrets.randbelow(self.curve.n - 1) + 1
        R_i = scalar_mult(self.curve, r_i, self.G)
        mu_i = H4_scalar(self.curve.n, pid, P_i, R_i)
        d_i = (r_i + self.s * mu_i) % self.curve.n

        response_payload = _pack_kgc_to_device(pid, issue_ts, validity, R_i, d_i)
        response_key = H1_key(len(response_payload), scalar_mult(self.curve, self.s, P_i), psk)
        response_ct = xor_bytes(response_payload, response_key)
        response_mac = H2_mac(response_key, response_payload)
        return response_ct, response_mac


class RA:
    def __init__(self, curve: Curve = SECP256R1):
        self.curve = curve
        self.G = (curve.gx, curve.gy)
        self.t = secrets.randbelow(curve.n - 1) + 1
        self.P_RA = scalar_mult(curve, self.t, self.G)

    def process_device_registration_request(
        self,
        request: DeviceRegistrationRequest,
        psk: bytes,
        kgc_public: tuple[int, int],
    ) -> tuple[DeviceRegistrationTicket, bytes, bytes]:
        _ensure_point(self.curve, request.P_i, "P_i")
        key = H1_key(len(request.ciphertext), scalar_mult(self.curve, self.t, request.P_i), psk)
        payload = xor_bytes(request.ciphertext, key)
        if H2_mac(key, payload) != request.mac:
            raise ValueError("invalid device->RA MAC")
        rid, P_from_req = _unpack_device_to_ra(payload)
        if P_from_req != request.P_i:
            raise ValueError("P_i mismatch in device->RA registration")

        rid_bytes = rid.encode("utf-8")
        pid = xor_bytes(H3_pid(len(rid_bytes), scalar_mult(self.curve, self.t, request.P_i), request.issue_ts), rid_bytes)
        ticket = DeviceRegistrationTicket(pid=pid, issue_ts=request.issue_ts, validity=request.validity)

        forward_payload = _pack_ra_to_kgc(ticket.pid, request.P_i, ticket.issue_ts, ticket.validity)
        forward_key = H1_key(len(forward_payload), scalar_mult(self.curve, self.t, kgc_public), psk)
        forward_ct = xor_bytes(forward_payload, forward_key)
        forward_mac = H2_mac(forward_key, forward_payload)
        return ticket, forward_ct, forward_mac

    def handle_device_registration(
        self,
        request: DeviceRegistrationRequest,
        psk: bytes,
        kgc: KGC,
    ) -> DeviceRegistrationResponse:
        ticket, forward_ct, forward_mac = self.process_device_registration_request(request, psk, kgc.P_KGC)
        response_ct, response_mac = kgc.handle_registration_forward(forward_ct, forward_mac, self.P_RA, psk)
        return DeviceRegistrationResponse(ticket=ticket, ciphertext=response_ct, mac=response_mac)

    def trace_identity(self, pid: bytes, P_i: tuple[int, int], issue_ts: int) -> str:
        rid_bytes = xor_bytes(pid, H3_pid(len(pid), scalar_mult(self.curve, self.t, P_i), issue_ts))
        return rid_bytes.decode("utf-8")


class Device:
    def __init__(
        self,
        rid: str,
        kgc: KGC,
        ra: RA,
        psk: bytes,
        *,
        issue_ts: int = 1,
        validity: int = 3600,
        freshness_window: int = 300,
        auto_register: bool = True,
    ):
        self.rid = rid
        self.kgc = kgc
        self.ra = ra
        self.curve = kgc.curve
        self.G = kgc.G
        self.psk = psk
        self.freshness_window = freshness_window

        self.x_i = secrets.randbelow(self.curve.n - 1) + 1
        self.P_i = scalar_mult(self.curve, self.x_i, self.G)
        self.pid: bytes | None = None
        self.issue_ts: int | None = None
        self.validity: int | None = None
        self.R_i: tuple[int, int] | None = None
        self.d_i: int | None = None
        self._registered = False
        if auto_register:
            self.register(issue_ts, validity)

    def build_registration_request(self, issue_ts: int, validity: int) -> DeviceRegistrationRequest:
        payload = _pack_device_to_ra(self.rid, self.P_i)
        key = H1_key(len(payload), scalar_mult(self.curve, self.x_i, self.ra.P_RA), self.psk)
        ciphertext = xor_bytes(payload, key)
        mac = H2_mac(key, payload)
        return DeviceRegistrationRequest(P_i=self.P_i, issue_ts=issue_ts, validity=validity, ciphertext=ciphertext, mac=mac)

    def finalize_registration(self, response: DeviceRegistrationResponse):
        response_key = H1_key(len(response.ciphertext), scalar_mult(self.curve, self.x_i, self.kgc.P_KGC), self.psk)
        response_payload = xor_bytes(response.ciphertext, response_key)
        if H2_mac(response_key, response_payload) != response.mac:
            raise ValueError("invalid KGC->device MAC")
        pid_recv, issue_recv, validity_recv, R_i, d_i = _unpack_kgc_to_device(response_payload)
        _ensure_point(self.curve, R_i, "R_i")
        if (
            pid_recv != response.ticket.pid
            or issue_recv != response.ticket.issue_ts
            or validity_recv != response.ticket.validity
        ):
            raise ValueError("registration response mismatch")

        self.pid = response.ticket.pid
        self.issue_ts = response.ticket.issue_ts
        self.validity = response.ticket.validity
        self.R_i = R_i
        self.d_i = d_i % self.curve.n
        self._registered = True

    def register(self, issue_ts: int, validity: int):
        request = self.build_registration_request(issue_ts, validity)
        response = self.ra.handle_device_registration(request, self.psk, self.kgc)
        self.finalize_registration(response)

    def _require_registered(self):
        if not self._registered or self.pid is None or self.issue_ts is None or self.validity is None or self.R_i is None or self.d_i is None:
            raise RuntimeError("device is not registered")

    def public_credential(self) -> PublicCredential:
        self._require_registered()
        return PublicCredential(
            rid=self.rid,
            pid=self.pid,
            issue_ts=self.issue_ts,
            validity=self.validity,
            P_i=self.P_i,
            R_i=self.R_i,
        )

    def registration_bundle(self) -> RegistrationBundle:
        self._require_registered()
        return RegistrationBundle(public=self.public_credential(), private_x=self.x_i, private_d=self.d_i)

    def create_auth_request(self, gateway: "EdgeGateway", tau_i: int) -> tuple[BatchAuthRequest, dict]:
        self._require_registered()
        a_i = secrets.randbelow(self.curve.n - 1) + 1
        T_i = scalar_mult(self.curve, a_i, self.G)
        nu_i = H5_scalar(
            self.curve.n,
            self.pid,
            gateway.pid,
            self.P_i,
            self.R_i,
            gateway.P_i,
            gateway.R_i,
            T_i,
            tau_i,
        )
        S_i = (a_i + nu_i * ((self.x_i + self.d_i) % self.curve.n)) % self.curve.n
        request = BatchAuthRequest(
            sender_pid=self.pid,
            P_i=self.P_i,
            R_i=self.R_i,
            T_i=T_i,
            tau_i=tau_i,
            S_i=S_i,
        )
        return request, {"a_i": a_i, "nu_i": nu_i, "tau_i": tau_i}

    def finalize_key_agreement(self, response: BatchAuthResponse, state: dict) -> bytes:
        self._require_registered()
        _ensure_point(self.curve, response.V_i, "V_i")
        scalar = ((self.x_i + state["a_i"]) % self.curve.n) * inv_mod(self.x_i, self.curve.n) % self.curve.n
        U_i = scalar_mult(self.curve, scalar, response.V_i)
        session_key = H6_key(U_i, state["nu_i"])
        expected_mac = H2_mac(session_key, encode_point(response.V_i))
        if expected_mac != response.mac_eg_di:
            raise ValueError("gateway response MAC verification failed")
        return session_key


class EdgeGateway(Device):
    def __init__(
        self,
        rid: str,
        kgc: KGC,
        ra: RA,
        psk: bytes,
        *,
        issue_ts: int = 0,
        validity: int = 7200,
        freshness_window: int = 300,
        weight_bits: int = 80,
    ):
        super().__init__(rid, kgc, ra, psk, issue_ts=issue_ts, validity=validity, freshness_window=freshness_window)
        self.weight_bits = weight_bits
        self._registry: dict[bytes, PublicCredential] = {}

    def register_known_device(self, credential: PublicCredential):
        self._registry[credential.pid] = credential

    def _get_registered(self, request: BatchAuthRequest) -> PublicCredential | None:
        credential = self._registry.get(request.sender_pid)
        if credential is None:
            return None
        if credential.P_i != request.P_i or credential.R_i != request.R_i:
            return None
        return credential

    def _is_fresh(self, tau_i: int, current_time: int) -> bool:
        return tau_i <= current_time and current_time - tau_i <= self.freshness_window

    def verify_batch(self, requests: list[BatchAuthRequest], current_time: int) -> bool:
        if not requests:
            return True

        lhs_scalar = 0
        rhs = None
        for request in requests:
            _ensure_point(self.curve, request.P_i, "P_i")
            _ensure_point(self.curve, request.R_i, "R_i")
            _ensure_point(self.curve, request.T_i, "T_i")
            if not self._is_fresh(request.tau_i, current_time):
                return False
            credential = self._get_registered(request)
            if credential is None:
                return False
            if current_time > credential.valid_until or request.tau_i > credential.valid_until:
                return False

            mu_i = H4_scalar(self.curve.n, request.sender_pid, request.P_i, request.R_i)
            nu_i = H5_scalar(
                self.curve.n,
                request.sender_pid,
                self.pid,
                request.P_i,
                request.R_i,
                self.P_i,
                self.R_i,
                request.T_i,
                request.tau_i,
            )
            weight = secrets.randbelow(1 << self.weight_bits) + 1
            lhs_scalar = (lhs_scalar + weight * request.S_i) % self.curve.n

            weighted_T = scalar_mult(self.curve, weight, request.T_i)
            binding_term = point_add(
                self.curve,
                request.P_i,
                point_add(self.curve, request.R_i, scalar_mult(self.curve, mu_i, self.kgc.P_KGC)),
            )
            weighted_binding = scalar_mult(self.curve, (weight * nu_i) % self.curve.n, binding_term)
            contribution = point_add(self.curve, weighted_T, weighted_binding)
            rhs = contribution if rhs is None else point_add(self.curve, rhs, contribution)

        lhs = scalar_mult(self.curve, lhs_scalar, self.G)
        return lhs == rhs

    def identify_invalid_indices(self, requests: list[BatchAuthRequest], current_time: int) -> list[int]:
        invalid: list[int] = []

        def rec(offset: int, segment: list[BatchAuthRequest]):
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

        rec(0, requests)
        invalid.sort()
        return invalid

    def respond_to_request(self, request: BatchAuthRequest) -> tuple[BatchAuthResponse, bytes]:
        b_i = secrets.randbelow(self.curve.n - 1) + 1
        factor = (b_i + self.x_i) % self.curve.n
        T_plus_P = point_add(self.curve, request.T_i, request.P_i)
        U_i = scalar_mult(self.curve, factor, T_plus_P)
        V_i = scalar_mult(self.curve, factor, request.P_i)
        nu_i = H5_scalar(
            self.curve.n,
            request.sender_pid,
            self.pid,
            request.P_i,
            request.R_i,
            self.P_i,
            self.R_i,
            request.T_i,
            request.tau_i,
        )
        session_key = H6_key(U_i, nu_i)
        mac_eg_di = H2_mac(session_key, encode_point(V_i))
        return BatchAuthResponse(sender_pid=request.sender_pid, tau_i=request.tau_i, V_i=V_i, mac_eg_di=mac_eg_di), session_key

    def batch_verify_and_respond(self, requests: list[BatchAuthRequest], current_time: int) -> tuple[bool, list[int], list[BatchAuthResponse], dict[tuple[bytes, int], bytes]]:
        verified = self.verify_batch(requests, current_time)
        if verified:
            valid_requests = list(requests)
            invalid_indices: list[int] = []
        else:
            invalid_indices = self.identify_invalid_indices(requests, current_time)
            invalid_set = set(invalid_indices)
            valid_requests = [request for idx, request in enumerate(requests) if idx not in invalid_set]

        responses: list[BatchAuthResponse] = []
        keys: dict[tuple[bytes, int], bytes] = {}
        for request in valid_requests:
            response, session_key = self.respond_to_request(request)
            responses.append(response)
            keys[(request.sender_pid, request.tau_i)] = session_key
        return verified, invalid_indices, responses, keys


def run_psk_batch_clama_smoke(devices: int = 6, messages: int = 12, tamper_index: int | None = None) -> dict:
    kgc = KGC()
    ra = RA(kgc.curve)
    psk = b"shared-registration-psk"
    gateway = EdgeGateway("edge-gateway-01", kgc, ra, psk)

    clients = [Device(f"dev-{i:02d}", kgc, ra, psk, issue_ts=1 + i) for i in range(1, devices + 1)]
    by_pid: dict[bytes, Device] = {}
    requests: list[BatchAuthRequest] = []
    states: list[dict] = []

    for client in clients:
        gateway.register_known_device(client.public_credential())
        by_pid[client.pid] = client

    for idx in range(messages):
        client = clients[idx % len(clients)]
        request, state = client.create_auth_request(gateway, tau_i=100 + idx)
        requests.append(request)
        states.append({"pid": client.pid, **state})

    if tamper_index is not None and 0 <= tamper_index < len(requests):
        tampered = requests[tamper_index]
        requests[tamper_index] = BatchAuthRequest(
            sender_pid=tampered.sender_pid,
            P_i=tampered.P_i,
            R_i=tampered.R_i,
            T_i=tampered.T_i,
            tau_i=tampered.tau_i,
            S_i=(tampered.S_i + 1) % gateway.curve.n,
        )

    current_time = max(request.tau_i for request in requests) + 1 if requests else 0
    verified, invalid_indices, responses, gateway_keys = gateway.batch_verify_and_respond(requests, current_time)

    response_by_key = {(response.sender_pid, response.tau_i): response for response in responses}
    confirmed = 0
    for state in states:
        response = response_by_key.get((state["pid"], state["tau_i"]))
        if response is None:
            continue
        client = by_pid[state["pid"]]
        derived = client.finalize_key_agreement(response, state)
        if derived == gateway_keys[(state["pid"], state["tau_i"])]:
            confirmed += 1

    return {
        "devices": devices,
        "messages": messages,
        "batch_verified": verified,
        "invalid_indices": invalid_indices,
        "responses": len(responses),
        "confirmed_session_keys": confirmed,
        "curve": gateway.curve.name,
        "scheme": "PSK-BAT-CLAMA",
    }
