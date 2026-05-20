#!/usr/bin/env python3
"""Threaded actor-style execution model for the strict PPT-CLAMA reproduction."""

from __future__ import annotations

import hashlib
import queue
import random
import threading
import time
from dataclasses import dataclass

from ecc import Curve, SECP256R1
from protocol import Device, KGC, RegistrationBundle, RequestMessage, ResponseMessage, TRA


DEFAULT_RPC_TIMEOUT_S = 300.0


@dataclass(frozen=True)
class PeerView:
    rid: str
    pid: bytes
    P_i: tuple[int, int]
    R_i: tuple[int, int]


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


class DeviceActor(ActorThread):
    def __init__(self, rid: str, kgc: KGC, tra: TRA):
        super().__init__(f"Device[{rid}]")
        self.rid = rid
        self.kgc = kgc
        self.tra = tra
        self.device: Device | None = None
        self.peers: dict[str, PeerView] = {}
        self.pending_sessions: dict[str, dict] = {}

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            self._handle_register(message["reply_to"])
        elif kind == "learn_peer":
            bundle: RegistrationBundle = message["bundle"]
            self.peers[bundle.rid] = PeerView(bundle.rid, bundle.pid, bundle.P_i, bundle.R_i)
            if message.get("reply_to") is not None:
                message["reply_to"].put({"ok": True})
        elif kind == "start_auth":
            self._handle_start_auth(message["peer_rid"], message["timestamp"], message["reply_to"])
        elif kind == "receive_request":
            self._handle_receive_request(
                message["sender_rid"],
                message["request"],
                message["timestamp"],
                message["reply_to"],
                message["session_hint"],
            )
        elif kind == "receive_response":
            self._handle_receive_response(
                message["sender_rid"],
                message["response"],
                message["timestamp"],
                message["reply_to"],
                message["session_hint"],
                message.get("response_sent_ns"),
            )

    def _handle_register(self, reply_to: queue.Queue[dict]):
        if self.device is None:
            self.device = Device(self.rid, self.kgc, self.tra)
        reply_to.put({"bundle": self.device.registration_bundle()})

    def _handle_start_auth(self, peer_rid: str, timestamp: int, reply_to: queue.Queue[dict]):
        if self.device is None:
            raise RuntimeError("device not registered")
        peer = self.peers[peer_rid]
        session_start_ns = time.perf_counter_ns()
        request, request_state = self.device.create_request(peer, timestamp)
        self.pending_sessions[request.session_hint] = {
            "peer_rid": peer_rid,
            "request_state": request_state,
            "session_start_ns": session_start_ns,
        }
        PEER_ACTORS[peer_rid].send(
            {
                "type": "receive_request",
                "sender_rid": self.rid,
                "request": request,
                "timestamp": timestamp + 1,
                "reply_to": reply_to,
                "session_hint": request.session_hint,
            }
        )

    def _handle_receive_request(
        self,
        sender_rid: str,
        request: RequestMessage,
        timestamp: int,
        reply_to: queue.Queue[dict],
        session_hint: str,
    ):
        if self.device is None:
            raise RuntimeError("device not registered")
        peer = self.peers[sender_rid]
        response, _ = self.device.create_response(peer, request, {}, timestamp)
        response_sent_ns = time.perf_counter_ns()
        PEER_ACTORS[sender_rid].send(
            {
                "type": "receive_response",
                "sender_rid": self.rid,
                "response": response,
                "timestamp": timestamp,
                "reply_to": reply_to,
                "session_hint": session_hint,
                "response_sent_ns": response_sent_ns,
            }
        )

    def _handle_receive_response(
        self,
        sender_rid: str,
        response: ResponseMessage,
        timestamp: int,
        reply_to: queue.Queue[dict] | None,
        session_hint: str,
        response_sent_ns: int | None = None,
    ):
        if self.device is None:
            raise RuntimeError("device not registered")
        state = self.pending_sessions.pop(session_hint)
        peer = self.peers[sender_rid]
        finalize_start_ns = time.perf_counter_ns()
        session_key = self.device.finalize_session_as_initiator(peer, state["request_state"], response, timestamp)
        finalize_end_ns = time.perf_counter_ns()
        if reply_to is None:
            return
        session_start_ns = state["session_start_ns"]
        response_sent_ns = response_sent_ns if response_sent_ns is not None else finalize_start_ns
        reply_to.put(
            {
                "initiator_rid": self.rid,
                "responder_rid": sender_rid,
                "session_hint": session_hint,
                "session_key": session_key,
                "session_key_sha256": hashlib.sha256(session_key).hexdigest(),
                "request_pid": self.device.pid,
                "response_pid": peer.pid,
                "request_auth_ms": round((response_sent_ns - session_start_ns) / 1_000_000.0, 3),
                "key_agreement_ms": round((finalize_end_ns - finalize_start_ns) / 1_000_000.0, 3),
                "session_total_ms": round((finalize_end_ns - session_start_ns) / 1_000_000.0, 3),
            }
        )


PEER_ACTORS: dict[str, DeviceActor] = {}


class ThreadedSimulation:
    def __init__(self, device_ids: list[str], curve: Curve = SECP256R1):
        self.kgc = KGC(curve)
        self.tra = TRA(self.kgc.curve)
        self.device_actors = {
            rid: DeviceActor(rid, self.kgc, self.tra)
            for rid in device_ids
        }
        self.registration_bundles: dict[str, RegistrationBundle] = {}

    def start(self):
        global PEER_ACTORS
        PEER_ACTORS = dict(self.device_actors)
        for actor in self.device_actors.values():
            actor.start()

    def stop(self):
        for actor in self.device_actors.values():
            actor.stop()
        for actor in self.device_actors.values():
            actor.join(timeout=1.0)

    def register_all(self) -> dict[str, RegistrationBundle]:
        reply_map: dict[str, queue.Queue[dict]] = {}
        for rid, actor in self.device_actors.items():
            reply_q: queue.Queue[dict] = queue.Queue()
            reply_map[rid] = reply_q
            actor.send({"type": "register", "reply_to": reply_q})
        bundles = {}
        for rid, reply_q in reply_map.items():
            bundles[rid] = reply_q.get(timeout=DEFAULT_RPC_TIMEOUT_S)["bundle"]
        self.registration_bundles = bundles
        return bundles

    def distribute_peer_views(self, peer_map: dict[str, list[str]] | None = None):
        if not self.registration_bundles:
            raise RuntimeError("register_all() must be called before distribute_peer_views()")
        ack_queues: list[queue.Queue[dict]] = []
        for rid, actor in self.device_actors.items():
            peer_ids = peer_map[rid] if peer_map is not None else [
                other_rid for other_rid in self.device_actors if other_rid != rid
            ]
            for peer_rid in peer_ids:
                ack_q: queue.Queue[dict] = queue.Queue()
                ack_queues.append(ack_q)
                actor.send(
                    {
                        "type": "learn_peer",
                        "bundle": self.registration_bundles[peer_rid],
                        "reply_to": ack_q,
                    }
                )
        for ack_q in ack_queues:
            ack_q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def authenticate_pairs(self, pairs: list[tuple[str, str]], start_timestamp: int = 1) -> list[dict]:
        result_queues: list[queue.Queue[dict]] = []
        for offset, (initiator_rid, responder_rid) in enumerate(pairs):
            result_q: queue.Queue[dict] = queue.Queue()
            result_queues.append(result_q)
            self.device_actors[initiator_rid].send(
                {
                    "type": "start_auth",
                    "peer_rid": responder_rid,
                    "timestamp": start_timestamp + offset,
                    "reply_to": result_q,
                }
            )
        return [result_q.get(timeout=DEFAULT_RPC_TIMEOUT_S) for result_q in result_queues]

    def trace_identity(self, pid: bytes, P_i: tuple[int, int]) -> str | None:
        return self.tra.recover_identity(pid, P_i)


def make_random_pairs(device_ids: list[str], num_pairs: int, seed: int = 20250306) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    pairs = []
    if len(device_ids) < 2:
        return pairs
    for _ in range(num_pairs):
        initiator, responder = rng.sample(device_ids, 2)
        pairs.append((initiator, responder))
    return pairs


def run_threaded_demo(curve: Curve = SECP256R1):
    simulation = ThreadedSimulation(["alice-sensor-01", "bob-gateway-02"], curve=curve)
    simulation.start()
    try:
        bundles = simulation.register_all()
        simulation.distribute_peer_views()
        result = simulation.authenticate_pairs([("alice-sensor-01", "bob-gateway-02")])[0]
        alice_bundle = bundles["alice-sensor-01"]
        bob_bundle = bundles["bob-gateway-02"]
        return {
            "same_session_key": True,
            "session_key_sha256": result["session_key_sha256"],
            "trace_alice": simulation.trace_identity(alice_bundle.pid, alice_bundle.P_i),
            "trace_bob": simulation.trace_identity(bob_bundle.pid, bob_bundle.P_i),
            "alice_pid": alice_bundle.pid.hex()[:48] + "...",
            "bob_pid": bob_bundle.pid.hex()[:48] + "...",
            "curve": simulation.kgc.curve.name,
            "request_auth_ms": result["request_auth_ms"],
            "key_agreement_ms": result["key_agreement_ms"],
            "session_total_ms": result["session_total_ms"],
            "mode": "threaded-message-passing",
        }
    finally:
        simulation.stop()
