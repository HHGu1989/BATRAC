#!/usr/bin/env python3
"""Threaded actor-style execution model for Cui et al. (TNSM 2023)."""

from __future__ import annotations

import queue
import random
import threading
import time
from typing import Any

from cui_edge_batch_protocol import CuiEdgeServer, CuiKDC, CuiMessagePacket, CuiNotification, CuiSmartDevice
from ecc import Curve, SECP256R1


DEFAULT_RPC_TIMEOUT_S = 180.0
DEFAULT_PHASE_TIMEOUT_S = 300.0


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
            msg = self.inbox.get()
            if msg["type"] == "_stop":
                return
            self.handle_message(msg)

    def handle_message(self, message: dict):
        raise NotImplementedError


class KDCActor(ActorThread):
    def __init__(self, curve: Curve = SECP256R1):
        super().__init__("KDC")
        self.kdc = CuiKDC(curve)

    def handle_message(self, message: dict):
        if message["type"] == "get":
            message["reply_to"].put({"kdc": self.kdc})
        elif message["type"] == "register_sd":
            materials, vk_latest, gsk = self.kdc.register_sd(message["sd_id"], start_time=message.get("start_time", 0))
            message["reply_to"].put({"materials": materials, "vk_latest": vk_latest, "gsk": gsk})


class EdgeServerActor(ActorThread):
    def __init__(self, es_id: str, kdc: CuiKDC):
        super().__init__(f"ES[{es_id}]")
        self.es = CuiEdgeServer(es_id, kdc)
        self.sd_actors: dict[str, SDActor] = {}
        self.pending: list[CuiMessagePacket] = []

    def set_routes(self, sd_actors: dict[str, "SDActor"]):
        self.sd_actors = sd_actors

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register_materials":
            self.es.register_materials(message["materials"])
            message["reply_to"].put({"ok": True})
        elif kind == "submit_packet":
            self.pending.append(message["packet"])
            message["reply_to"].put({"queued": True, "pending": len(self.pending)})
        elif kind == "tamper_pending":
            idx = int(message["index"])
            if 0 <= idx < len(self.pending):
                pkt = self.pending[idx]
                self.pending[idx] = CuiMessagePacket(
                    pkt.sender_pid, pkt.U_i, pkt.R_i, (pkt.delta_i + 1) % self.es.curve.n, pkt.ciphertext, pkt.ts, pkt.dest_id
                )
                message["reply_to"].put({"ok": True})
            else:
                message["reply_to"].put({"ok": False})
        elif kind == "process_batch":
            current_time = message.get("current_time")
            if current_time is None and self.pending:
                current_time = max(pkt.ts for pkt in self.pending) + 1
            batch = list(self.pending)
            self.pending.clear()
            verified = self.es.verify_batch(batch, current_time=current_time)
            invalid = [] if verified else self.es.identify_invalid_indices(batch, current_time=current_time)
            valid_packets = [pkt for idx, pkt in enumerate(batch) if idx not in set(invalid)]
            valid_hashes = [__import__("cui_edge_batch_protocol").packet_hash(pkt) for pkt in valid_packets]
            invalid_hashes = [__import__("cui_edge_batch_protocol").packet_hash(batch[idx]) for idx in invalid]
            notification = self.es.sign_notification(valid_hashes, invalid_hashes, current_time or 0)

            for pkt in valid_packets:
                if pkt.dest_id in self.sd_actors:
                    self.sd_actors[pkt.dest_id].send({"type": "deliver", "packet": pkt, "notification": notification})
            message["reply_to"].put(
                {
                    "batch_size": len(batch),
                    "verified": verified,
                    "invalid_indices": invalid,
                    "forwarded": len(valid_packets),
                    "pending_remaining": len(self.pending),
                }
            )


class SDActor(ActorThread):
    def __init__(
        self,
        sd_id: str,
        kdc: CuiKDC,
        kdc_actor: KDCActor,
        es_actor: EdgeServerActor,
        rpc_timeout_s: float = DEFAULT_RPC_TIMEOUT_S,
    ):
        super().__init__(f"SD[{sd_id}]")
        self.sd = CuiSmartDevice(sd_id, kdc)
        self.kdc_actor = kdc_actor
        self.es_actor = es_actor
        self.delivered = 0
        self.delivery_processing_ns = 0
        self.rpc_timeout_s = rpc_timeout_s

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        try:
            return reply_to.get(timeout=self.rpc_timeout_s)
        except queue.Empty as exc:
            raise TimeoutError(
                f"{self.name} timed out waiting for {actor.name} to handle {payload.get('type')!r} "
                f"after {self.rpc_timeout_s:.1f}s"
            ) from exc

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            reply = self.rpc(self.kdc_actor, {"type": "register_sd", "sd_id": self.sd.sd_id, "start_time": message["timestamp"]})
            self.sd.load_registration(reply["materials"], reply["vk_latest"], reply["gsk"])
            self.rpc(self.es_actor, {"type": "register_materials", "materials": reply["materials"]})
            message["reply_to"].put({"ok": True})
        elif kind == "send_message":
            material = self.sd.next_material()
            pkt = self.sd.encrypt_and_sign(material, message["dest_id"], message["payload"], message["timestamp"])
            self.rpc(self.es_actor, {"type": "submit_packet", "packet": pkt})
            message["reply_to"].put({"queued": True})
        elif kind == "deliver":
            t0 = time.perf_counter_ns()
            delivered = self.sd.verify_notification_and_recover(message["notification"], message["packet"])
            self.delivery_processing_ns += time.perf_counter_ns() - t0
            if delivered is not None:
                self.delivered += 1
        elif kind == "get_stats":
            message["reply_to"].put(
                {
                    "delivered": self.delivered,
                    "delivery_processing_ms": round(self.delivery_processing_ns / 1_000_000.0, 3),
                }
            )


class ThreadedCuiSimulation:
    def __init__(
        self,
        device_ids: list[str],
        es_id: str = "edge-01",
        curve: Curve = SECP256R1,
        rpc_timeout_s: float = DEFAULT_RPC_TIMEOUT_S,
        phase_timeout_s: float = DEFAULT_PHASE_TIMEOUT_S,
    ):
        self.kdc_actor = KDCActor(curve)
        self.kdc = None
        self.es_actor: EdgeServerActor | None = None
        self.sd_actors: dict[str, SDActor] = {}
        self.device_ids = list(device_ids)
        self.es_id = es_id
        self.rpc_timeout_s = rpc_timeout_s
        self.phase_timeout_s = phase_timeout_s

    def start(self):
        self.kdc_actor.start()
        self.kdc = self._rpc(self.kdc_actor, {"type": "get"})["kdc"]
        self.es_actor = EdgeServerActor(self.es_id, self.kdc)
        self.es_actor.start()
        self.sd_actors = {
            rid: SDActor(rid, self.kdc, self.kdc_actor, self.es_actor, rpc_timeout_s=self.rpc_timeout_s)
            for rid in self.device_ids
        }
        self.es_actor.set_routes(self.sd_actors)
        for actor in self.sd_actors.values():
            actor.start()

    def stop(self):
        for actor in self.sd_actors.values():
            actor.stop()
        if self.es_actor is not None:
            self.es_actor.stop()
        self.kdc_actor.stop()
        for actor in self.sd_actors.values():
            actor.join(timeout=1.0)
        if self.es_actor is not None:
            self.es_actor.join(timeout=1.0)
        self.kdc_actor.join(timeout=1.0)

    def _rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        try:
            return reply_to.get(timeout=self.rpc_timeout_s)
        except queue.Empty as exc:
            raise TimeoutError(
                f"simulation timed out waiting for {actor.name} to handle {payload.get('type')!r} "
                f"after {self.rpc_timeout_s:.1f}s"
            ) from exc

    def register_all(self, start_timestamp: int = 1):
        qs = []
        for idx, rid in enumerate(self.device_ids):
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            self.sd_actors[rid].send({"type": "register", "timestamp": start_timestamp + idx, "reply_to": q})
        for q in qs:
            try:
                q.get(timeout=self.phase_timeout_s)
            except queue.Empty as exc:
                raise TimeoutError(
                    f"register_all timed out after {self.phase_timeout_s:.1f}s while waiting for device registration"
                ) from exc

    def submit_messages(self, pairs: list[tuple[str, str]], start_timestamp: int = 100) -> int:
        qs = []
        for idx, (src, dst) in enumerate(pairs):
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            payload = f"cui-msg-{idx} {src}->{dst}".encode("utf-8")
            self.sd_actors[src].send({"type": "send_message", "dest_id": dst, "payload": payload, "timestamp": start_timestamp + idx, "reply_to": q})
        for q in qs:
            try:
                q.get(timeout=self.phase_timeout_s)
            except queue.Empty as exc:
                raise TimeoutError(
                    f"submit_messages timed out after {self.phase_timeout_s:.1f}s while waiting for packet submission"
                ) from exc
        return len(pairs)

    def process_until_empty(self) -> list[dict]:
        assert self.es_actor is not None
        out = []
        while True:
            r = self._rpc(self.es_actor, {"type": "process_batch"})
            out.append(r)
            if r["pending_remaining"] == 0:
                break
        return out

    def tamper_pending(self, index: int) -> bool:
        assert self.es_actor is not None
        return bool(self._rpc(self.es_actor, {"type": "tamper_pending", "index": index}).get("ok"))

    def delivered_counts(self) -> dict[str, int]:
        return {rid: int(self._rpc(actor, {"type": "get_stats"})["delivered"]) for rid, actor in self.sd_actors.items()}

    def delivery_processing(self) -> dict[str, float]:
        return {rid: float(self._rpc(actor, {"type": "get_stats"})["delivery_processing_ms"]) for rid, actor in self.sd_actors.items()}


def make_random_pairs(device_ids: list[str], num_pairs: int, seed: int = 20250306) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    pairs = []
    if len(device_ids) < 2:
        return pairs
    for _ in range(num_pairs):
        src, dst = rng.sample(device_ids, 2)
        pairs.append((src, dst))
    return pairs


def run_threaded_cui_demo(
    devices: int = 8,
    messages: int = 16,
    tamper_index: int | None = None,
    curve: Curve = SECP256R1,
) -> dict:
    device_ids = [f"cui-sd-{i:02d}" for i in range(1, devices + 1)]
    sim = ThreadedCuiSimulation(device_ids, curve=curve)
    sim.start()
    try:
        t0 = time.perf_counter()
        sim.register_all()
        t1 = time.perf_counter()
        pairs = make_random_pairs(device_ids, messages)
        sim.submit_messages(pairs)
        t2 = time.perf_counter()
        if tamper_index is not None:
            sim.tamper_pending(tamper_index)
        batches = sim.process_until_empty()
        t3 = time.perf_counter()
        delivered = sim.delivered_counts()
        delivery_processing = sim.delivery_processing()
        return {
            "devices": devices,
            "messages": messages,
            "curve": curve.name,
            "pairs": pairs,
            "batches": batches,
            "delivered_total": sum(delivered.values()),
            "delivered_by_device": delivered,
            "register_ms": round((t1 - t0) * 1000.0, 3),
            "submit_ms": round((t2 - t1) * 1000.0, 3),
            "batch_process_ms": round((t3 - t2) * 1000.0, 3),
            "delivery_processing_ms_total": round(sum(delivery_processing.values()), 3),
            "mode": "threaded-cui-edge-batch",
        }
    finally:
        sim.stop()
