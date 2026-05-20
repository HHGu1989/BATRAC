#!/usr/bin/env python3
"""Threaded actor-style execution model for PSK-BAT-CLAMA."""

from __future__ import annotations

import hashlib
import queue
import random
import threading
import time
from dataclasses import dataclass

from psk_batch_clama_protocol import (
    BatchAuthRequest,
    BatchAuthResponse,
    Device,
    DeviceRegistrationRequest,
    DeviceRegistrationResponse,
    EdgeGateway,
    KGC,
    PublicCredential,
    RA,
)
from ecc import Curve, SECP256R1


DEFAULT_PSK = b"shared-registration-psk"
DEFAULT_RPC_TIMEOUT_S = 300.0


class ActorThread(threading.Thread):
    def __init__(self, name: str):
        super().__init__(name=name, daemon=True)
        self.inbox: queue.Queue[dict] = queue.Queue()
        self._running = True

    def send(self, message: dict):
        self.inbox.put(message)

    def stop(self):
        self._running = False
        self.inbox.put({"type": "_stop"})

    def run(self):
        while self._running:
            message = self.inbox.get()
            if message["type"] == "_stop":
                return
            self.handle_message(message)

    def handle_message(self, message: dict):
        raise NotImplementedError


class KGCActor(ActorThread):
    def __init__(self, curve: Curve = SECP256R1):
        super().__init__("KGC")
        self.kgc = KGC(curve)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "get":
            message["reply_to"].put({"kgc": self.kgc})
        elif kind == "handle_registration_forward":
            ct, mac = self.kgc.handle_registration_forward(
                message["ciphertext"],
                message["mac"],
                message["ra_public"],
                message["psk"],
            )
            message["reply_to"].put({"ciphertext": ct, "mac": mac})


class RAActor(ActorThread):
    def __init__(self, kgc_actor: KGCActor, kgc: KGC, psk: bytes):
        super().__init__("RA")
        self.ra = RA(kgc.curve)
        self.kgc_actor = kgc_actor
        self.kgc_public = kgc.P_KGC
        self.psk = psk

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "get":
            message["reply_to"].put({"ra": self.ra})
        elif kind == "process_registration_request":
            request: DeviceRegistrationRequest = message["request"]
            ticket, forward_ct, forward_mac = self.ra.process_device_registration_request(
                request,
                self.psk,
                self.kgc_public,
            )
            kgc_reply = self.rpc(
                self.kgc_actor,
                {
                    "type": "handle_registration_forward",
                    "ciphertext": forward_ct,
                    "mac": forward_mac,
                    "ra_public": self.ra.P_RA,
                    "psk": self.psk,
                },
            )
            response = DeviceRegistrationResponse(
                ticket=ticket,
                ciphertext=kgc_reply["ciphertext"],
                mac=kgc_reply["mac"],
            )
            message["reply_to"].put({"response": response})
        elif kind == "trace":
            rid = self.ra.trace_identity(message["pid"], message["P_i"], message["issue_ts"])
            message["reply_to"].put({"rid": rid})


class GatewayActor(ActorThread):
    def __init__(self, gateway_id: str, kgc: KGC, ra: RA, psk: bytes):
        super().__init__(f"EG[{gateway_id}]")
        self.gateway = EdgeGateway(gateway_id, kgc, ra, psk)
        self.device_actors: dict[str, DeviceActor] = {}
        self.pid_to_rid: dict[bytes, str] = {}
        self.pending: list[BatchAuthRequest] = []

    def set_routes(self, device_actors: dict[str, "DeviceActor"]):
        self.device_actors = device_actors

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "get_public":
            message["reply_to"].put({"credential": self.gateway.public_credential()})
        elif kind == "register_credential":
            credential: PublicCredential = message["credential"]
            self.gateway.register_known_device(credential)
            self.pid_to_rid[credential.pid] = credential.rid
            message["reply_to"].put({"ok": True})
        elif kind == "submit_request":
            request: BatchAuthRequest = message["request"]
            self.pending.append(request)
            if message.get("reply_to") is not None:
                message["reply_to"].put({"queued": True, "pending": len(self.pending)})
        elif kind == "process_batch":
            batch_size = message.get("batch_size")
            if batch_size is None or batch_size <= 0:
                batch = list(self.pending)
                self.pending.clear()
            else:
                batch = self.pending[:batch_size]
                self.pending = self.pending[batch_size:]

            current_time = message.get("current_time")
            if current_time is None and batch:
                current_time = max(request.tau_i for request in batch) + 1

            verified, invalid_indices, responses, _ = self.gateway.batch_verify_and_respond(batch, current_time)
            responded = 0
            for response in responses:
                rid = self.pid_to_rid.get(response.sender_pid)
                if rid is None or rid not in self.device_actors:
                    continue
                self.device_actors[rid].send({"type": "receive_response", "response": response})
                responded += 1

            message["reply_to"].put(
                {
                    "batch_size": len(batch),
                    "verified": verified,
                    "invalid_indices": invalid_indices,
                    "responses": responded,
                    "current_time": current_time,
                    "pending_remaining": len(self.pending),
                }
            )
        elif kind == "tamper_pending":
            index = int(message["index"])
            if 0 <= index < len(self.pending):
                request = self.pending[index]
                self.pending[index] = BatchAuthRequest(
                    sender_pid=request.sender_pid,
                    P_i=request.P_i,
                    R_i=request.R_i,
                    T_i=request.T_i,
                    tau_i=request.tau_i,
                    S_i=(request.S_i + 1) % self.gateway.curve.n,
                )
                message["reply_to"].put({"ok": True})
            else:
                message["reply_to"].put({"ok": False})


class DeviceActor(ActorThread):
    def __init__(self, rid: str, kgc: KGC, ra: RA, ra_actor: RAActor, gateway_actor: GatewayActor, psk: bytes):
        super().__init__(f"Device[{rid}]")
        self.device = Device(rid, kgc, ra, psk, auto_register=False)
        self.ra_actor = ra_actor
        self.gateway_actor = gateway_actor
        self.gateway_view: PublicCredential | None = None
        self.pending_sessions: dict[tuple[bytes, int], dict] = {}
        self.confirmed_session_hashes: list[str] = []
        self.key_agreement_ns = 0

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            self._handle_register(
                timestamp=message["timestamp"],
                validity=message.get("validity", 3600),
                reply_to=message["reply_to"],
            )
        elif kind == "send_auth":
            self._handle_send_auth(message["timestamp"], message["reply_to"])
        elif kind == "receive_response":
            self._handle_receive_response(message["response"])
        elif kind == "get_stats":
            message["reply_to"].put(
                {
                    "confirmed": len(self.confirmed_session_hashes),
                    "key_agreement_ms": round(self.key_agreement_ns / 1_000_000.0, 3),
                }
            )
        elif kind == "get_public":
            message["reply_to"].put({"credential": self.device.public_credential()})

    def _handle_register(self, timestamp: int, validity: int, reply_to: queue.Queue[dict]):
        if self.gateway_view is None:
            self.gateway_view = self.rpc(self.gateway_actor, {"type": "get_public"})["credential"]
        request = self.device.build_registration_request(timestamp, validity)
        response: DeviceRegistrationResponse = self.rpc(
            self.ra_actor,
            {"type": "process_registration_request", "request": request},
        )["response"]
        self.device.finalize_registration(response)
        self.rpc(
            self.gateway_actor,
            {"type": "register_credential", "credential": self.device.public_credential()},
        )
        reply_to.put({"ok": True})

    def _handle_send_auth(self, timestamp: int, reply_to: queue.Queue[dict]):
        if self.gateway_view is None:
            self.gateway_view = self.rpc(self.gateway_actor, {"type": "get_public"})["credential"]
        start_ns = time.perf_counter_ns()
        request, state = self.device.create_auth_request(self.gateway_view, timestamp)
        key = (request.sender_pid, request.tau_i)
        self.pending_sessions[key] = {**state, "start_ns": start_ns}
        self.rpc(self.gateway_actor, {"type": "submit_request", "request": request})
        reply_to.put({"queued": True})

    def _handle_receive_response(self, response: BatchAuthResponse):
        key = (response.sender_pid, response.tau_i)
        state = self.pending_sessions.pop(key)
        t0 = time.perf_counter_ns()
        session_key = self.device.finalize_key_agreement(response, state)
        self.key_agreement_ns += time.perf_counter_ns() - t0
        self.confirmed_session_hashes.append(hashlib.sha256(session_key).hexdigest())


class ThreadedPSKBatchCLAMASimulation:
    def __init__(self, device_ids: list[str], gateway_id: str = "edge-gateway-01", psk: bytes = DEFAULT_PSK, curve: Curve = SECP256R1):
        self.device_ids = list(device_ids)
        self.gateway_id = gateway_id
        self.psk = psk
        self.kgc_actor = KGCActor(curve)
        self.kgc: KGC | None = None
        self.ra_actor: RAActor | None = None
        self.gateway_actor: GatewayActor | None = None
        self.device_actors: dict[str, DeviceActor] = {}

    def start(self):
        self.kgc_actor.start()
        self.kgc = self._rpc(self.kgc_actor, {"type": "get"})["kgc"]
        self.ra_actor = RAActor(self.kgc_actor, self.kgc, self.psk)
        self.ra_actor.start()
        ra = self._rpc(self.ra_actor, {"type": "get"})["ra"]
        self.gateway_actor = GatewayActor(self.gateway_id, self.kgc, ra, self.psk)
        self.gateway_actor.start()
        self.device_actors = {
            rid: DeviceActor(rid, self.kgc, ra, self.ra_actor, self.gateway_actor, self.psk)
            for rid in self.device_ids
        }
        self.gateway_actor.set_routes(self.device_actors)
        for actor in self.device_actors.values():
            actor.start()

    def stop(self):
        for actor in self.device_actors.values():
            actor.stop()
        if self.gateway_actor is not None:
            self.gateway_actor.stop()
        if self.ra_actor is not None:
            self.ra_actor.stop()
        self.kgc_actor.stop()
        for actor in self.device_actors.values():
            actor.join(timeout=1.0)
        if self.gateway_actor is not None:
            self.gateway_actor.join(timeout=1.0)
        if self.ra_actor is not None:
            self.ra_actor.join(timeout=1.0)
        self.kgc_actor.join(timeout=1.0)

    def _rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def register_all(self, start_timestamp: int = 1, validity: int = 3600):
        reply_queues: list[queue.Queue[dict]] = []
        for idx, rid in enumerate(self.device_ids):
            reply_q: queue.Queue[dict] = queue.Queue()
            reply_queues.append(reply_q)
            self.device_actors[rid].send(
                {
                    "type": "register",
                    "timestamp": start_timestamp + idx,
                    "validity": validity,
                    "reply_to": reply_q,
                }
            )
        for q in reply_queues:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def submit_auth_requests(self, senders: list[str], start_timestamp: int = 100) -> int:
        reply_queues: list[queue.Queue[dict]] = []
        for idx, rid in enumerate(senders):
            reply_q: queue.Queue[dict] = queue.Queue()
            reply_queues.append(reply_q)
            self.device_actors[rid].send(
                {
                    "type": "send_auth",
                    "timestamp": start_timestamp + idx,
                    "reply_to": reply_q,
                }
            )
        for q in reply_queues:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)
        return len(senders)

    def process_until_empty(self, batch_size: int = 0) -> list[dict]:
        assert self.gateway_actor is not None
        results = []
        while True:
            result = self._rpc(self.gateway_actor, {"type": "process_batch", "batch_size": batch_size})
            results.append(result)
            if result["pending_remaining"] == 0:
                break
        return results

    def tamper_pending(self, index: int) -> bool:
        assert self.gateway_actor is not None
        return bool(self._rpc(self.gateway_actor, {"type": "tamper_pending", "index": index}).get("ok"))

    def confirmed_counts(self) -> dict[str, int]:
        return {
            rid: int(self._rpc(actor, {"type": "get_stats"})["confirmed"])
            for rid, actor in self.device_actors.items()
        }

    def key_agreement_costs(self) -> dict[str, float]:
        return {
            rid: float(self._rpc(actor, {"type": "get_stats"})["key_agreement_ms"])
            for rid, actor in self.device_actors.items()
        }


def make_random_senders(device_ids: list[str], messages: int, seed: int = 20250306) -> list[str]:
    rng = random.Random(seed)
    if not device_ids:
        return []
    return [rng.choice(device_ids) for _ in range(messages)]


def run_threaded_psk_batch_clama_demo(
    devices: int = 8,
    messages: int = 16,
    batch_size: int = 0,
    tamper_index: int | None = None,
    curve: Curve = SECP256R1,
) -> dict:
    device_ids = [f"dev-{i:02d}" for i in range(1, devices + 1)]
    simulation = ThreadedPSKBatchCLAMASimulation(device_ids, curve=curve)
    simulation.start()
    try:
        t0 = time.perf_counter()
        simulation.register_all()
        t1 = time.perf_counter()
        senders = make_random_senders(device_ids, messages)
        simulation.submit_auth_requests(senders)
        t2 = time.perf_counter()
        if tamper_index is not None:
            simulation.tamper_pending(tamper_index)
        batches = simulation.process_until_empty(batch_size=batch_size)
        t3 = time.perf_counter()
        confirmed = simulation.confirmed_counts()
        key_agreement = simulation.key_agreement_costs()
        return {
            "devices": devices,
            "messages": messages,
            "curve": simulation.kgc.curve.name,
            "batch_size": batch_size,
            "tamper_index": tamper_index,
            "senders": senders,
            "batches": batches,
            "confirmed_total": sum(confirmed.values()),
            "confirmed_by_device": confirmed,
            "register_ms": round((t1 - t0) * 1000.0, 3),
            "request_submit_ms": round((t2 - t1) * 1000.0, 3),
            "batch_process_ms": round((t3 - t2) * 1000.0, 3),
            "key_agreement_ms_total": round(sum(key_agreement.values()), 3),
            "mode": "threaded-psk-bat-clama",
        }
    finally:
        simulation.stop()
