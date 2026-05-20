#!/usr/bin/env python3
"""Threaded actor-style execution model for the ECroA protocol."""

from __future__ import annotations

import hashlib
import queue
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

from ecc import Curve, SECP256R1
from ecroa_protocol import (
    BlockchainLedger,
    DTCredential,
    DigitalTwin,
    MEC,
    SignedPacket,
    aggregate_domain_packets,
    verify_domain_batch,
    verify_single_packet,
)


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


class BlockchainActor(ActorThread):
    def __init__(self):
        super().__init__("Blockchain")
        self.ledger = BlockchainLedger()

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "publish_domain":
            self.ledger.publish_domain(message["record"])
            message["reply_to"].put({"ok": True})
        elif kind == "register_dt":
            self.ledger.register_dt(message["credential"])
            message["reply_to"].put({"ok": True})
        elif kind == "query_domain":
            record = self.ledger.get_domain(message["domain_id"])
            message["reply_to"].put({"record": record})
        elif kind == "trace":
            rid = self.ledger.trace_identity(message["domain_id"], message["id1"], message["id2"])
            message["reply_to"].put({"rid": rid})


class MECActor(ActorThread):
    def __init__(self, domain_id: str, blockchain: BlockchainActor, curve: Curve = SECP256R1):
        super().__init__(f"MEC[{domain_id}]")
        self.mec = MEC(domain_id, curve)
        self.blockchain = blockchain
        self.cache: dict[str, object] = {}

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=10.0)

    def bootstrap(self):
        self.rpc(self.blockchain, {"type": "publish_domain", "record": self.mec.domain_record()})
        self.cache[self.mec.domain_id] = self.mec.domain_record()

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register_dt":
            rid = message["rid"]
            credential = self.mec.register_dt(rid)
            self.rpc(self.blockchain, {"type": "register_dt", "credential": credential})
            message["reply_to"].put({"credential": credential})
        elif kind == "query_domain":
            domain_id = message["domain_id"]
            if domain_id not in self.cache:
                self.cache[domain_id] = self.rpc(self.blockchain, {"type": "query_domain", "domain_id": domain_id})["record"]
            message["reply_to"].put({"record": self.cache[domain_id]})
        elif kind == "trace":
            rid = self.rpc(
                self.blockchain,
                {"type": "trace", "domain_id": message["domain_id"], "id1": message["id1"], "id2": message["id2"]},
            )["rid"]
            message["reply_to"].put({"rid": rid})


class DigitalTwinActor(ActorThread):
    def __init__(self, rid: str, home_domain: str, mec_actor: MECActor, verifier_actor: "VerifierActor" | None = None, curve: Curve = SECP256R1):
        super().__init__(f"DT[{rid}]")
        self.rid = rid
        self.home_domain = home_domain
        self.mec_actor = mec_actor
        self.verifier_actor = verifier_actor
        self.curve = curve
        self.credential: DTCredential | None = None
        self.dt: DigitalTwin | None = None

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=10.0)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "register":
            self.credential = self.rpc(self.mec_actor, {"type": "register_dt", "rid": self.rid})["credential"]
            self.dt = DigitalTwin(self.rid, self.credential, self.curve)
            message["reply_to"].put({"ok": True})
        elif kind == "send_packet":
            if self.dt is None or self.verifier_actor is None:
                raise RuntimeError("DT not ready")
            packet = self.dt.sign_message(message["payload"], message["target_dt"])
            self.rpc(self.verifier_actor, {"type": "submit_packet", "packet": packet})
            message["reply_to"].put({"ok": True})
        elif kind == "get_public":
            message["reply_to"].put({"credential": self.credential})


@dataclass(frozen=True)
class DomainBatchResult:
    source_domain: str
    batch_size: int
    verified: bool
    invalid_indices: list[int]


class VerifierActor(ActorThread):
    def __init__(self, rid: str, domain_id: str, mec_actor: MECActor, curve: Curve = SECP256R1):
        super().__init__(f"Verifier[{rid}]")
        self.rid = rid
        self.domain_id = domain_id
        self.mec_actor = mec_actor
        self.curve = curve
        self.pending: list[SignedPacket] = []
        self.accepted: list[SignedPacket] = []
        self.query_ns = 0

    def rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=10.0)

    def handle_message(self, message: dict):
        kind = message["type"]
        if kind == "submit_packet":
            self.pending.append(message["packet"])
            if message.get("reply_to") is not None:
                message["reply_to"].put({"queued": True, "pending": len(self.pending)})
        elif kind == "tamper_pending":
            idx = int(message["index"])
            if 0 <= idx < len(self.pending):
                pkt = self.pending[idx]
                self.pending[idx] = SignedPacket(
                    sender_rid=pkt.sender_rid,
                    sender_domain=pkt.sender_domain,
                    id1=pkt.id1,
                    id2=pkt.id2,
                    message=pkt.message,
                    sigma=(pkt.sigma + 1) % self.curve.n,
                    target_dt=pkt.target_dt,
                )
                message["reply_to"].put({"ok": True})
            else:
                message["reply_to"].put({"ok": False})
        elif kind == "process_batch":
            grouped: dict[str, list[SignedPacket]] = defaultdict(list)
            for pkt in self.pending:
                grouped[pkt.sender_domain].append(pkt)
            self.pending.clear()

            results: list[DomainBatchResult] = []
            accepted = 0
            for domain_id, packets in grouped.items():
                t0 = time.perf_counter_ns()
                record = self.rpc(self.mec_actor, {"type": "query_domain", "domain_id": domain_id})["record"]
                self.query_ns += time.perf_counter_ns() - t0
                ok = verify_domain_batch(packets, record, self.curve.n)
                invalid_indices: list[int] = []
                if ok:
                    self.accepted.extend(packets)
                    accepted += len(packets)
                else:
                    for i, pkt in enumerate(packets):
                        if verify_single_packet(pkt, record, self.curve.n):
                            self.accepted.append(pkt)
                            accepted += 1
                        else:
                            invalid_indices.append(i)
                results.append(DomainBatchResult(domain_id, len(packets), ok, invalid_indices))

            message["reply_to"].put(
                {
                    "verified_domains": [r.__dict__ for r in results],
                    "accepted": accepted,
                    "pending_remaining": len(self.pending),
                    "query_ms_total": round(self.query_ns / 1_000_000.0, 3),
                }
            )
        elif kind == "get_stats":
            message["reply_to"].put(
                {
                    "accepted": len(self.accepted),
                    "query_ms_total": round(self.query_ns / 1_000_000.0, 3),
                }
            )


class ThreadedECroASimulation:
    def __init__(self, device_ids: list[str], domains: int = 3, curve: Curve = SECP256R1):
        self.device_ids = list(device_ids)
        self.domains = max(2, domains)
        self.curve = curve
        self.blockchain = BlockchainActor()
        self.mec_actors: dict[str, MECActor] = {}
        self.dt_actors: dict[str, DigitalTwinActor] = {}
        self.verifier: VerifierActor | None = None
        self._home_domain: dict[str, str] = {}

    def start(self):
        self.blockchain.start()
        for idx in range(self.domains):
            domain_id = f"domain-{idx+1:02d}"
            actor = MECActor(domain_id, self.blockchain, self.curve)
            actor.start()
            actor.bootstrap()
            self.mec_actors[domain_id] = actor
        self.verifier = VerifierActor("dt-verifier-01", "domain-01", self.mec_actors["domain-01"], self.curve)
        self.verifier.start()

        domain_cycle = list(self.mec_actors.keys())
        for idx, rid in enumerate(self.device_ids):
            home = domain_cycle[idx % len(domain_cycle)]
            self._home_domain[rid] = home
            actor = DigitalTwinActor(rid, home, self.mec_actors[home], self.verifier, self.curve)
            actor.start()
            self.dt_actors[rid] = actor

    def stop(self):
        for actor in self.dt_actors.values():
            actor.stop()
        if self.verifier is not None:
            self.verifier.stop()
        for actor in self.mec_actors.values():
            actor.stop()
        self.blockchain.stop()
        for actor in self.dt_actors.values():
            actor.join(timeout=1.0)
        if self.verifier is not None:
            self.verifier.join(timeout=1.0)
        for actor in self.mec_actors.values():
            actor.join(timeout=1.0)
        self.blockchain.join(timeout=1.0)

    def _rpc(self, actor: ActorThread, payload: dict) -> dict:
        reply_to: queue.Queue[dict] = queue.Queue()
        actor.send({**payload, "reply_to": reply_to})
        return reply_to.get(timeout=10.0)

    def register_all(self):
        qs = []
        for actor in self.dt_actors.values():
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            actor.send({"type": "register", "reply_to": q})
        for q in qs:
            q.get(timeout=10.0)

    def submit_messages(self, senders: list[str]) -> int:
        qs = []
        for idx, rid in enumerate(senders):
            q: queue.Queue[dict] = queue.Queue()
            qs.append(q)
            payload = f"ecroa-msg-{idx}:{rid}->dt-verifier-01".encode("utf-8")
            self.dt_actors[rid].send({"type": "send_packet", "payload": payload, "target_dt": "dt-verifier-01", "reply_to": q})
        for q in qs:
            q.get(timeout=10.0)
        return len(senders)

    def process_until_empty(self) -> dict:
        assert self.verifier is not None
        return self._rpc(self.verifier, {"type": "process_batch"})

    def tamper_pending(self, index: int) -> bool:
        assert self.verifier is not None
        return bool(self._rpc(self.verifier, {"type": "tamper_pending", "index": index}).get("ok"))

    def stats(self) -> dict:
        assert self.verifier is not None
        return self._rpc(self.verifier, {"type": "get_stats"})


def make_random_senders(device_ids: list[str], messages: int, seed: int = 20250306) -> list[str]:
    rng = random.Random(seed)
    return [rng.choice(device_ids) for _ in range(messages)]


def run_threaded_ecroa_demo(
    devices: int = 8,
    messages: int = 16,
    domains: int | None = None,
    tamper_index: int | None = None,
    curve: Curve = SECP256R1,
) -> dict:
    device_ids = [f"dt-{i:02d}" for i in range(1, devices + 1)]
    simulation = ThreadedECroASimulation(device_ids, domains=domains or max(2, min(4, devices // 2 or 2)), curve=curve)
    simulation.start()
    try:
        t0 = time.perf_counter()
        simulation.register_all()
        t1 = time.perf_counter()
        senders = make_random_senders(device_ids, messages)
        simulation.submit_messages(senders)
        t2 = time.perf_counter()
        if tamper_index is not None:
            simulation.tamper_pending(tamper_index)
        batch_result = simulation.process_until_empty()
        t3 = time.perf_counter()
        stats = simulation.stats()
        return {
            "devices": devices,
            "messages": messages,
            "domains": simulation.domains,
            "curve": curve.name,
            "senders": senders,
            "verified_domains": batch_result["verified_domains"],
            "accepted_total": stats["accepted"],
            "register_ms": round((t1 - t0) * 1000.0, 3),
            "sign_submit_ms": round((t2 - t1) * 1000.0, 3),
            "batch_process_ms": round((t3 - t2) * 1000.0, 3),
            "query_ms_total": batch_result["query_ms_total"],
            "tamper_index": tamper_index,
            "mode": "threaded-ecroa",
        }
    finally:
        simulation.stop()

