#!/usr/bin/env python3
"""Threaded actor-style execution model for Ma et al. (JSA 2025)."""

from __future__ import annotations

import queue
import random
import threading
import time

from ecc import Curve, SECP256R1
from ma_edge_protocol import MaCredential, MaDevice, MaEdgeServer, MaKGC, MaMessagePacket


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
            msg = self.inbox.get()
            if msg["type"] == "_stop":
                return
            self.handle_message(msg)

    def handle_message(self, message: dict):
        raise NotImplementedError


class KGCActor(ActorThread):
    def __init__(self, curve: Curve = SECP256R1):
        super().__init__("KGC")
        self.kgc = MaKGC(curve)

    def handle_message(self, message: dict):
        if message["type"] == "get":
            message["reply_to"].put({"kgc": self.kgc})
        elif message["type"] == "register":
            cred = self.kgc.register_sd(message["rid"])
            message["reply_to"].put({"credential": cred})
        elif message["type"] == "update":
            cred = self.kgc.update_sd(message["rid"])
            message["reply_to"].put({"credential": cred})


class ESActor(ActorThread):
    def __init__(self, kgc: MaKGC):
        super().__init__("ES")
        self.es = MaEdgeServer(kgc)
        self.pending: list[MaMessagePacket] = []

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "submit":
            self.pending.append(message["packet"])
            message["reply_to"].put({"queued": True})
        elif kind == "tamper_pending":
            idx = int(message["index"])
            if 0 <= idx < len(self.pending):
                p = self.pending[idx]
                self.pending[idx] = MaMessagePacket(p.sender_pid1, p.sender_pid2, p.R_i, (p.s_i + 1) % self.es.curve.n, p.message, p.ts)
                message["reply_to"].put({"ok": True})
            else:
                message["reply_to"].put({"ok": False})
        elif kind == "process":
            current_time = message.get("current_time")
            if current_time is None and self.pending:
                current_time = max(p.ts for p in self.pending) + 1
            batch = list(self.pending)
            self.pending.clear()
            verified = self.es.verify_batch(batch, current_time=current_time)
            invalid = [] if verified else self.es.identify_invalid_indices(batch, current_time=current_time)
            message["reply_to"].put(
                {
                    "batch_size": len(batch),
                    "verified": verified,
                    "invalid_indices": invalid,
                    "accepted": len(batch) - len(invalid),
                    "pending_remaining": len(self.pending),
                }
            )


class SDActor(ActorThread):
    def __init__(self, rid: str, kgc_actor: KGCActor, es_actor: ESActor):
        super().__init__(f"SD[{rid}]")
        self.rid = rid
        self.kgc_actor = kgc_actor
        self.es_actor = es_actor
        self.device: MaDevice | None = None
        self.update_ns = 0

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        q: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": q})
        return q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            if self.device is None:
                kgc = self.rpc(self.kgc_actor, {"type": "get"})["kgc"]
                self.device = MaDevice(self.rid, kgc)
            cred = self.rpc(self.kgc_actor, {"type": "register", "rid": self.rid})["credential"]
            self.device.load_credential(cred)
            message["reply_to"].put({"ok": True})
        elif kind == "send":
            pkt = self.device.sign(message["payload"], message["timestamp"])
            self.rpc(self.es_actor, {"type": "submit", "packet": pkt})
            # parallel-ish update path measured on sender side
            t0 = time.perf_counter_ns()
            cred = self.rpc(self.kgc_actor, {"type": "update", "rid": self.rid})["credential"]
            self.device.load_credential(cred)
            self.update_ns += time.perf_counter_ns() - t0
            message["reply_to"].put({"queued": True})
        elif kind == "get_stats":
            message["reply_to"].put({"update_ms": round(self.update_ns / 1_000_000.0, 3)})


class ThreadedMaSimulation:
    def __init__(self, device_ids: list[str], curve: Curve = SECP256R1):
        self.kgc_actor = KGCActor(curve)
        self.kgc = None
        self.es_actor: ESActor | None = None
        self.sd_actors: dict[str, SDActor] = {}
        self.device_ids = list(device_ids)

    def start(self):
        self.kgc_actor.start()
        self.kgc = self._rpc(self.kgc_actor, {"type": "get"})["kgc"]
        self.es_actor = ESActor(self.kgc)
        self.es_actor.start()
        self.sd_actors = {rid: SDActor(rid, self.kgc_actor, self.es_actor) for rid in self.device_ids}
        for actor in self.sd_actors.values():
            actor.start()

    def stop(self):
        for actor in self.sd_actors.values():
            actor.stop()
        if self.es_actor is not None:
            self.es_actor.stop()
        self.kgc_actor.stop()
        for actor in self.sd_actors.values():
            actor.join(timeout=1.0)
        if self.es_actor is not None:
            self.es_actor.join(timeout=1.0)
        self.kgc_actor.join(timeout=1.0)

    def _rpc(self, actor: ActorThread, payload: dict) -> dict:
        q: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": q})
        return q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def register_all(self):
        qs = []
        for rid in self.device_ids:
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            self.sd_actors[rid].send({"type": "register", "reply_to": q})
        for q in qs:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def submit_messages(self, senders: list[str], start_timestamp: int = 100):
        qs = []
        for idx, rid in enumerate(senders):
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            self.sd_actors[rid].send(
                {"type": "send", "payload": f"ma-msg-{idx}-{rid}".encode(), "timestamp": start_timestamp + idx, "reply_to": q}
            )
        for q in qs:
            q.get(timeout=DEFAULT_RPC_TIMEOUT_S)

    def process_batch(self):
        assert self.es_actor is not None
        return self._rpc(self.es_actor, {"type": "process"})

    def tamper_pending(self, index: int) -> bool:
        assert self.es_actor is not None
        return bool(self._rpc(self.es_actor, {"type": "tamper_pending", "index": index}).get("ok"))

    def update_costs(self) -> dict[str, float]:
        return {rid: float(self._rpc(actor, {"type": "get_stats"})["update_ms"]) for rid, actor in self.sd_actors.items()}


def make_random_senders(device_ids: list[str], messages: int, seed: int = 20250306) -> list[str]:
    rng = random.Random(seed)
    return [rng.choice(device_ids) for _ in range(messages)]


def run_threaded_ma_demo(
    devices: int = 8,
    messages: int = 16,
    tamper_index: int | None = None,
    curve: Curve = SECP256R1,
) -> dict:
    device_ids = [f"ma-sd-{i:02d}" for i in range(1, devices + 1)]
    sim = ThreadedMaSimulation(device_ids, curve=curve)
    sim.start()
    try:
        t0 = time.perf_counter()
        sim.register_all()
        t1 = time.perf_counter()
        senders = make_random_senders(device_ids, messages)
        sim.submit_messages(senders)
        t2 = time.perf_counter()
        if tamper_index is not None:
            sim.tamper_pending(tamper_index)
        batch = sim.process_batch()
        t3 = time.perf_counter()
        updates = sim.update_costs()
        return {
            "devices": devices,
            "messages": messages,
            "curve": curve.name,
            "senders": senders,
            "batch": batch,
            "accepted_total": batch["accepted"],
            "register_ms": round((t1 - t0) * 1000.0, 3),
            "submit_update_ms": round((t2 - t1) * 1000.0, 3),
            "batch_process_ms": round((t3 - t2) * 1000.0, 3),
            "update_ms_total": round(sum(updates.values()), 3),
            "mode": "threaded-ma-edge-update",
        }
    finally:
        sim.stop()
