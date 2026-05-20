#!/usr/bin/env python3
"""Threaded actor-style execution model for the BMAE protocol reproduction."""

from __future__ import annotations

import hashlib
import queue
import random
import threading
import time
from dataclasses import dataclass

from bmae_protocol import (
    DeliveredMessage,
    EdgeServer,
    KGC,
    MessagePacket,
    MutualAuthChallenge,
    MutualAuthResponse,
    SDRegistrationRequest,
    SDRegistrationResponse,
    SmartDevice,
)
from ecc import Curve, SECP256R1


DEFAULT_RPC_TIMEOUT_S = 300.0


@dataclass(frozen=True)
class ESView:
    """Minimal ES view needed by SD registration/finalization logic."""

    es_id: str
    T_pub: tuple[int, int]


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
        if message["type"] == "get":
            message["reply_to"].put({"kgc": self.kgc})


class EdgeServerActor(ActorThread):
    def __init__(self, es_id: str, kgc: KGC):
        super().__init__(f"ES[{es_id}]")
        self.es = EdgeServer(es_id, kgc)
        self.sd_actors: dict[str, SmartDeviceActor] = {}
        self.pending: list[MessagePacket] = []

    def set_routes(self, sd_actors: dict[str, "SmartDeviceActor"]):
        self.sd_actors = sd_actors

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "get_t_pub":
            message["reply_to"].put({"T_pub": self.es.T_pub, "es_id": self.es.es_id})
        elif kind == "start_mutual_auth":
            challenge = self.es.start_mutual_auth(message["sd_id"])
            message["reply_to"].put({"challenge": challenge})
        elif kind == "finish_mutual_auth":
            ack = self.es.finish_mutual_auth(message["response"], message["current_time"])
            message["reply_to"].put({"ack": ack})
        elif kind == "register_sd":
            req: SDRegistrationRequest = message["request"]
            resp = self.es.register_sd(req)
            message["reply_to"].put({"response": resp})
        elif kind == "submit_packet":
            pkt: MessagePacket = message["packet"]
            self.pending.append(pkt)
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
                current_time = max(pkt.ts for pkt in batch) + 1

            verified = self.es.verify_batch(batch, current_time=current_time)
            invalid_indices: list[int] = []
            forwarded = 0
            if verified:
                forward_list = batch
            else:
                # Section 5.6: recursively split and forward valid segments while locating invalid ones.
                forward_list: list[MessagePacket] = []

                def rec(offset: int, segment: list[MessagePacket]):
                    nonlocal invalid_indices, forward_list
                    if not segment:
                        return
                    if self.es.verify_batch(segment, current_time=current_time):
                        forward_list.extend(segment)
                        return
                    if len(segment) == 1:
                        invalid_indices.append(offset)
                        return
                    mid = len(segment) // 2
                    rec(offset, segment[:mid])
                    rec(offset + mid, segment[mid:])

                rec(0, batch)
                invalid_indices.sort()

            for pkt in forward_list:
                if pkt.dest_id in self.sd_actors:
                    self.sd_actors[pkt.dest_id].send({"type": "deliver", "packet": pkt, "current_time": current_time})
                    forwarded += 1

            message["reply_to"].put(
                {
                    "batch_size": len(batch),
                    "verified": verified,
                    "invalid_indices": invalid_indices,
                    "forwarded": forwarded,
                    "current_time": current_time,
                    "pending_remaining": len(self.pending),
                }
            )
        elif kind == "tamper_pending":
            index = int(message["index"])
            if 0 <= index < len(self.pending):
                pkt = self.pending[index]
                # Create a tampered copy by flipping one bit in sigma.
                tampered_sig = type(pkt.sig)(U_i=pkt.sig.U_i, sigma_i=(pkt.sig.sigma_i ^ 1))
                self.pending[index] = type(pkt)(
                    sender_pid=pkt.sender_pid,
                    sender_acl=pkt.sender_acl,
                    sender_pk=pkt.sender_pk,
                    sig=tampered_sig,
                    V=pkt.V,
                    ciphertext=pkt.ciphertext,
                    ts=pkt.ts,
                    dest_id=pkt.dest_id,
                )
                message["reply_to"].put({"ok": True})
            else:
                message["reply_to"].put({"ok": False})


class SmartDeviceActor(ActorThread):
    def __init__(self, sd_id: str, kgc: KGC, es_actor: EdgeServerActor):
        super().__init__(f"SD[{sd_id}]")
        self.sd = SmartDevice(sd_id, kgc)
        self.es_actor = es_actor
        self.delivered: list[DeliveredMessage] = []
        self.delivery_processing_ns = 0

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            self._handle_register(message["timestamp"], message["reply_to"])
        elif kind == "learn_peer":
            self.sd.learn_peer_pubkey(message["peer_id"], message["peer_X"])
            if message.get("reply_to") is not None:
                message["reply_to"].put({"ok": True})
        elif kind == "send_message":
            pkt = self.sd.encrypt_and_sign(message["dest_id"], message["payload"], message["timestamp"])
            self.sd.advance_pid()
            # Ensure the packet is enqueued before acknowledging to the caller.
            self.rpc(self.es_actor, {"type": "submit_packet", "packet": pkt})
            if message.get("reply_to") is not None:
                message["reply_to"].put({"queued": True})
        elif kind == "deliver":
            pkt: MessagePacket = message["packet"]
            t0 = time.perf_counter_ns()
            delivered = self.sd.receive_forwarded(pkt, current_time=message.get("current_time"))
            self.delivery_processing_ns += time.perf_counter_ns() - t0
            self.delivered.append(delivered)
        elif kind == "get_stats":
            message["reply_to"].put(
                {
                    "delivered": len(self.delivered),
                    "delivery_processing_ms": round(self.delivery_processing_ns / 1_000_000.0, 3),
                }
            )

    def _handle_register(self, timestamp: int, reply_to: queue.Queue[dict]):
        es_reply = self.rpc(self.es_actor, {"type": "get_t_pub"})
        es_view = ESView(es_id=es_reply["es_id"], T_pub=es_reply["T_pub"])

        challenge: MutualAuthChallenge = self.rpc(
            self.es_actor, {"type": "start_mutual_auth", "sd_id": self.sd.sd_id}
        )["challenge"]
        response, state = self.sd.build_mutual_auth_response(challenge)
        ack = self.rpc(
            self.es_actor,
            {
                "type": "finish_mutual_auth",
                "response": response,
                "current_time": timestamp,
            },
        )["ack"]
        self.sd.finalize_mutual_auth(ack, state)

        # SmartDevice APIs expect an object with T_pub attribute. We provide ESView.
        req = self.sd.create_registration_request(es_view, timestamp=timestamp)  # type: ignore[arg-type]
        resp = self.rpc(self.es_actor, {"type": "register_sd", "request": req})["response"]
        self.sd.finalize_registration(es_view, resp)  # type: ignore[arg-type]
        reply_to.put({"ok": True})


class ThreadedBMAESimulation:
    def __init__(self, device_ids: list[str], es_id: str = "edge-01", curve: Curve = SECP256R1):
        self.kgc_actor = KGCActor(curve)
        self.kgc: KGC | None = None
        self.es_actor: EdgeServerActor | None = None
        self.sd_actors: dict[str, SmartDeviceActor] = {}
        self.device_ids = list(device_ids)
        self.es_id = es_id

    def start(self):
        self.kgc_actor.start()
        self.kgc = self._rpc(self.kgc_actor, {"type": "get"})["kgc"]
        self.es_actor = EdgeServerActor(self.es_id, self.kgc)
        self.es_actor.start()
        self.sd_actors = {rid: SmartDeviceActor(rid, self.kgc, self.es_actor) for rid in self.device_ids}
        self.es_actor.set_routes(self.sd_actors)
        for actor in self.sd_actors.values():
            actor.start()

    def stop(self):
        for actor in list(self.sd_actors.values()):
            actor.stop()
        if self.es_actor is not None:
            self.es_actor.stop()
        self.kgc_actor.stop()
        for actor in list(self.sd_actors.values()):
            actor.join(timeout=1.0)
        if self.es_actor is not None:
            self.es_actor.join(timeout=1.0)
        self.kgc_actor.join(timeout=1.0)

    def _rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def register_all(self, start_timestamp: int = 1):
        reply_queues: list[queue.Queue[dict]] = []
        for idx, rid in enumerate(self.device_ids):
            reply_q: queue.Queue[dict] = queue.Queue()
            reply_queues.append(reply_q)
            self.sd_actors[rid].send({"type": "register", "timestamp": start_timestamp + idx, "reply_to": reply_q})
        for q in reply_queues:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def distribute_pubkeys(self):
        # Each SD only needs X_i of peers (for H5(v * X_j)).
        pub = {rid: self.sd_actors[rid].sd.X_i for rid in self.device_ids}
        ack: list[queue.Queue[dict]] = []
        for rid, actor in self.sd_actors.items():
            for peer_id, peer_X in pub.items():
                if peer_id == rid:
                    continue
                q: queue.Queue[dict] = queue.Queue()
                ack.append(q)
                actor.send({"type": "learn_peer", "peer_id": peer_id, "peer_X": peer_X, "reply_to": q})
        for q in ack:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def submit_messages(self, pairs: list[tuple[str, str]], start_timestamp: int = 100) -> int:
        ack: list[queue.Queue[dict]] = []
        for idx, (src, dst) in enumerate(pairs):
            payload = f"msg-{idx} {src}->{dst}".encode("utf-8")
            q: queue.Queue[dict] = queue.Queue()
            ack.append(q)
            self.sd_actors[src].send(
                {
                    "type": "send_message",
                    "dest_id": dst,
                    "payload": payload,
                    "timestamp": start_timestamp + idx,
                    "reply_to": q,
                }
            )
        for q in ack:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)
        return len(pairs)

    def process_until_empty(self, batch_size: int = 0) -> list[dict]:
        assert self.es_actor is not None
        results = []
        while True:
            r = self._rpc(self.es_actor, {"type": "process_batch", "batch_size": batch_size})
            results.append(r)
            if r["pending_remaining"] == 0:
                break
        return results

    def tamper_pending(self, index: int) -> bool:
        assert self.es_actor is not None
        return bool(self._rpc(self.es_actor, {"type": "tamper_pending", "index": index}).get("ok"))

    def delivered_counts(self) -> dict[str, int]:
        out = {}
        for rid, actor in self.sd_actors.items():
            out[rid] = int(self._rpc(actor, {"type": "get_stats"})["delivered"])
        return out

    def delivery_processing(self) -> dict[str, float]:
        out = {}
        for rid, actor in self.sd_actors.items():
            out[rid] = float(self._rpc(actor, {"type": "get_stats"})["delivery_processing_ms"])
        return out


def make_random_pairs(device_ids: list[str], num_pairs: int, seed: int = 20250306) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    pairs = []
    if len(device_ids) < 2:
        return pairs
    for _ in range(num_pairs):
        src, dst = rng.sample(device_ids, 2)
        pairs.append((src, dst))
    return pairs


def run_threaded_bmae_demo(
    devices: int = 8,
    messages: int = 16,
    batch_size: int = 0,
    tamper_index: int | None = None,
    curve: Curve = SECP256R1,
) -> dict:
    device_ids = [f"sd-{i:02d}" for i in range(1, devices + 1)]
    sim = ThreadedBMAESimulation(device_ids, curve=curve)
    sim.start()
    try:
        t0 = time.perf_counter()
        sim.register_all()
        t1 = time.perf_counter()
        sim.distribute_pubkeys()
        t2 = time.perf_counter()
        pairs = make_random_pairs(device_ids, messages)
        sim.submit_messages(pairs)
        t3 = time.perf_counter()
        if tamper_index is not None:
            sim.tamper_pending(tamper_index)
        batches = sim.process_until_empty(batch_size=batch_size)
        t4 = time.perf_counter()
        delivered = sim.delivered_counts()
        delivery_processing = sim.delivery_processing()
        return {
            "devices": devices,
            "messages": messages,
            "curve": sim.kgc.curve.name,
            "batch_size": batch_size,
            "tamper_index": tamper_index,
            "batches": batches,
            "delivered_total": sum(delivered.values()),
            "delivered_by_device": delivered,
            "register_ms": round((t1 - t0) * 1000.0, 3),
            "pubkey_distribution_ms": round((t2 - t1) * 1000.0, 3),
            "submit_ms": round((t3 - t2) * 1000.0, 3),
            "batch_process_ms": round((t4 - t3) * 1000.0, 3),
            "delivery_processing_ms_total": round(sum(delivery_processing.values()), 3),
            "mode": "threaded-bmae",
        }
    finally:
        sim.stop()
