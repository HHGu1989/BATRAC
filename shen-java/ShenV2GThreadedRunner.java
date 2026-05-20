import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;

public class ShenV2GThreadedRunner {
    static final int RID_LEN = 16;

    static final class CryptoContext {
        final Pairing pairing;
        final Field<?> g1;
        final Field<?> zr;
        final Field<?> gt;
        final Element P;

        CryptoContext(String securityModel) {
            int rbits;
            int qbits;
            switch (securityModel) {
                case "80" -> {
                    rbits = 160;
                    qbits = 512;
                }
                case "112" -> {
                    rbits = 224;
                    qbits = 1024;
                }
                case "128" -> {
                    rbits = 256;
                    qbits = 1536;
                }
                default -> throw new IllegalArgumentException("unsupported security model: " + securityModel);
            }
            TypeACurveGenerator generator = new TypeACurveGenerator(rbits, qbits);
            PairingParameters params = generator.generate();
            this.pairing = PairingFactory.getPairing(params);
            this.g1 = pairing.getG1();
            this.zr = pairing.getZr();
            this.gt = pairing.getGT();
            this.P = g1.newRandomElement().getImmutable();
        }
    }

    static final class Envelope {
        final String type;
        final Map<String, Object> payload;
        final CompletableFuture<Object> reply;

        Envelope(String type, Map<String, Object> payload, CompletableFuture<Object> reply) {
            this.type = type;
            this.payload = payload;
            this.reply = reply;
        }
    }

    abstract static class ActorThread extends Thread {
        final BlockingQueue<Envelope> inbox = new LinkedBlockingQueue<>();
        volatile boolean running = true;

        ActorThread(String name) {
            super(name);
            setDaemon(true);
        }

        void send(Envelope env) {
            inbox.offer(env);
        }

        void shutdown() {
            running = false;
            inbox.offer(new Envelope("_stop", Map.of(), new CompletableFuture<>()));
        }

        @Override
        public void run() {
            try {
                while (running) {
                    Envelope env = inbox.take();
                    if (Objects.equals(env.type, "_stop")) {
                        return;
                    }
                    handle(env);
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }

        protected abstract void handle(Envelope env);
    }

    static final class RegistrationRecord {
        final String rid;
        final byte[] pid;
        final byte[] lambda;
        final Element qid;
        final Element did;
        final Element x;
        final Element uid;

        RegistrationRecord(String rid, byte[] pid, byte[] lambda, Element qid, Element did, Element x, Element uid) {
            this.rid = rid;
            this.pid = pid.clone();
            this.lambda = lambda.clone();
            this.qid = qid.getImmutable();
            this.did = did.getImmutable();
            this.x = x.getImmutable();
            this.uid = uid.getImmutable();
        }
    }

    static final class SignaturePacket {
        final String rid;
        final byte[] pid;
        final byte[] message;
        final Element qid;
        final Element uid;
        final Element tau;
        final Element r;
        final Element rScalar;
        final long ts;

        SignaturePacket(String rid, byte[] pid, byte[] message, Element qid, Element uid, Element tau, Element r, Element rScalar, long ts) {
            this.rid = rid;
            this.pid = pid.clone();
            this.message = message.clone();
            this.qid = qid.getImmutable();
            this.uid = uid.getImmutable();
            this.tau = tau.getImmutable();
            this.r = r.getImmutable();
            this.rScalar = rScalar.getImmutable();
            this.ts = ts;
        }
    }

    static final class TAActor extends ActorThread {
        final CryptoContext ctx;
        final Element s;
        final Element ppub;
        final Map<String, RegistrationRecord> byRid = new LinkedHashMap<>();
        final Map<String, String> pidToRid = new LinkedHashMap<>();
        long trackingNs = 0L;

        TAActor(CryptoContext ctx) {
            super("TA");
            this.ctx = ctx;
            this.s = ctx.zr.newRandomElement().getImmutable();
            this.ppub = ctx.P.duplicate().mulZn(s).getImmutable();
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "register_ev" -> {
                        String rid = (String) env.payload.get("rid");
                        RegistrationRecord r = register(rid);
                        env.reply.complete(r);
                    }
                    case "verify_batch" -> {
                        @SuppressWarnings("unchecked")
                        List<SignaturePacket> packets = (List<SignaturePacket>) env.payload.get("packets");
                        Map<String, Object> res = verifyBatch(packets);
                        env.reply.complete(res);
                    }
                    case "trace" -> {
                        String pidKey = (String) env.payload.get("pidKey");
                        long t0 = System.nanoTime();
                        String rid = pidToRid.get(pidKey);
                        trackingNs += System.nanoTime() - t0;
                        env.reply.complete(rid);
                    }
                    case "get_stats" -> {
                        env.reply.complete(Map.of("tracking_ms_total", roundMs(trackingNs)));
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private RegistrationRecord register(String rid) throws Exception {
            byte[] ridBytes = fixedRid(rid);
            byte[] lambda = randomBytes(16, new Random(rid.hashCode() ^ 20260409));
            byte[] pid = h3(lambda, ridBytes);
            Element qid = hashToG1(pid);
            Element did = qid.duplicate().mulZn(s).getImmutable();
            Element x = ctx.zr.newRandomElement().getImmutable();
            Element uid = ctx.P.duplicate().mulZn(x).getImmutable();
            RegistrationRecord rec = new RegistrationRecord(rid, pid, lambda, qid, did, x, uid);
            byRid.put(rid, rec);
            pidToRid.put(encodePid(pid), rid);
            return rec;
        }

        private Map<String, Object> verifyBatch(List<SignaturePacket> packets) throws Exception {
            boolean verified = verifyAggregate(packets);
            List<Integer> invalid = new ArrayList<>();
            int accepted = 0;
            if (verified) {
                accepted = packets.size();
            } else {
                locateInvalid(packets, 0, invalid);
                accepted = packets.size() - invalid.size();
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("verified", verified);
            out.put("invalid_indices", invalid);
            out.put("accepted", accepted);
            return out;
        }

        private void locateInvalid(List<SignaturePacket> packets, int offset, List<Integer> invalid) throws Exception {
            if (packets.isEmpty()) return;
            if (verifyAggregate(packets)) return;
            if (packets.size() == 1) {
                invalid.add(offset);
                long t0 = System.nanoTime();
                pidToRid.get(encodePid(packets.get(0).pid));
                trackingNs += System.nanoTime() - t0;
                return;
            }
            int mid = packets.size() / 2;
            locateInvalid(packets.subList(0, mid), offset, invalid);
            locateInvalid(packets.subList(mid, packets.size()), offset + mid, invalid);
        }

        private boolean verifyAggregate(List<SignaturePacket> packets) throws Exception {
            Element tauAgg = ctx.g1.newZeroElement();
            Element qidAgg = ctx.g1.newZeroElement();
            Element h1Agg = ctx.g1.newZeroElement();
            Element h2Agg = ctx.g1.newZeroElement();
            for (SignaturePacket p : packets) {
                Element h1 = h1(p.pid, p.message, p.uid, p.ts);
                Element h2 = h2(p.pid, p.message, p.r, p.ts);
                tauAgg.add(p.tau);
                qidAgg.add(p.qid);
                h1Agg.add(h1.duplicate().mulZn(extractScalarFromUid(p.uid)));
                h2Agg.add(h2.duplicate().mulZn(p.rScalar));
            }
            Element left = ctx.pairing.pairing(tauAgg.getImmutable(), ctx.P).getImmutable();
            Element term1 = ctx.pairing.pairing(qidAgg.getImmutable(), ppub).getImmutable();
            Element term2 = ctx.pairing.pairing(h1Agg.getImmutable(), ctx.P).getImmutable();
            Element term3 = ctx.pairing.pairing(h2Agg.getImmutable(), ctx.P).getImmutable();
            Element right = term1.duplicate().mul(term2).mul(term3).getImmutable();
            return left.isEqual(right);
        }

        private Element extractScalarFromUid(Element uid) {
            // uid = xP; use the x value stored in the registration map by reverse match.
            for (RegistrationRecord rec : byRid.values()) {
                if (rec.uid.isEqual(uid)) return rec.x;
            }
            throw new IllegalStateException("UID not found in registry");
        }

        private Element h1(byte[] pid, byte[] m, Element uid, long t) throws Exception {
            return hashToG1(pid, m, uid.toBytes(), longToBytes(t));
        }

        private Element h2(byte[] pid, byte[] m, Element r, long t) throws Exception {
            return hashToG1(pid, m, r.toBytes(), longToBytes(t));
        }
    }

    static final class EVActor extends ActorThread {
        final String rid;
        final TAActor ta;
        final LAAggregatorActor la;
        final CryptoContext ctx;
        RegistrationRecord record;

        EVActor(String rid, TAActor ta, LAAggregatorActor la, CryptoContext ctx) {
            super("EV[" + rid + "]");
            this.rid = rid;
            this.ta = ta;
            this.la = la;
            this.ctx = ctx;
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "register" -> {
                        this.record = (RegistrationRecord) rpc(ta, "register_ev", Map.of("rid", rid));
                        env.reply.complete(Boolean.TRUE);
                    }
                    case "send_packet" -> {
                        byte[] msg = (byte[]) env.payload.get("payload");
                        long ts = (long) env.payload.get("timestamp");
                        SignaturePacket packet = sign(msg, ts);
                        rpc(la, "submit_packet", Map.of("packet", packet));
                        env.reply.complete(Boolean.TRUE);
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private SignaturePacket sign(byte[] m, long ts) throws Exception {
            Element rScalar = ctx.zr.newRandomElement().getImmutable();
            Element rPoint = ctx.P.duplicate().mulZn(rScalar).getImmutable();
            Element h1 = hashToG1(record.pid, m, record.uid.toBytes(), longToBytes(ts));
            Element h2 = hashToG1(record.pid, m, rPoint.toBytes(), longToBytes(ts));
            Element tau = record.did.duplicate().add(h1.duplicate().mulZn(record.x)).add(h2.duplicate().mulZn(rScalar)).getImmutable();
            return new SignaturePacket(rid, record.pid, m, record.qid, record.uid, tau, rPoint, rScalar, ts);
        }
    }

    static final class LAAggregatorActor extends ActorThread {
        final TAActor ta;
        final List<SignaturePacket> pending = new ArrayList<>();

        LAAggregatorActor(TAActor ta) {
            super("LA");
            this.ta = ta;
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "submit_packet" -> {
                        pending.add((SignaturePacket) env.payload.get("packet"));
                        env.reply.complete(Boolean.TRUE);
                    }
                    case "tamper_pending" -> {
                        int idx = (int) env.payload.get("index");
                        if (idx >= 0 && idx < pending.size()) {
                            SignaturePacket p = pending.get(idx);
                            Element badTau = p.tau.duplicate().add(ctx().P).getImmutable();
                            pending.set(idx, new SignaturePacket(p.rid, p.pid, p.message, p.qid, p.uid, badTau, p.r, p.rScalar, p.ts));
                            env.reply.complete(Boolean.TRUE);
                        } else {
                            env.reply.complete(Boolean.FALSE);
                        }
                    }
                    case "process_batch" -> {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> res = (Map<String, Object>) rpc(ta, "verify_batch", Map.of("packets", new ArrayList<>(pending)));
                        pending.clear();
                        env.reply.complete(res);
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private CryptoContext ctx() {
            return ta.ctx;
        }
    }

    static Object rpc(ActorThread actor, String type, Map<String, Object> payload) throws Exception {
        CompletableFuture<Object> future = new CompletableFuture<>();
        actor.send(new Envelope(type, payload, future));
        return future.get();
    }

    static Element hashToG1(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return CTX.g1.newElement().setFromHash(digest, 0, digest.length).getImmutable();
    }

    static byte[] h3(byte[] lambda, byte[] rid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(lambda);
        md.update(rid);
        return Arrays.copyOf(md.digest(), 16);
    }

    static byte[] randomBytes(int len, Random rng) {
        byte[] out = new byte[len];
        rng.nextBytes(out);
        return out;
    }

    static byte[] fixedRid(String rid) {
        byte[] in = rid.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[RID_LEN];
        System.arraycopy(in, 0, out, 0, Math.min(RID_LEN, in.length));
        return out;
    }

    static byte[] xor(byte[] a, byte[] b) {
        int n = Math.max(a.length, b.length);
        byte[] left = new byte[n];
        byte[] right = new byte[n];
        System.arraycopy(a, 0, left, n - a.length, a.length);
        System.arraycopy(b, 0, right, n - b.length, b.length);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) (left[i] ^ right[i]);
        return out;
    }

    static byte[] longToBytes(long v) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xffL);
            v >>>= 8;
        }
        return out;
    }

    static String encodePid(byte[] pid) {
        return Base64.getEncoder().encodeToString(pid);
    }

    static double roundMs(long ns) {
        return Math.round((ns / 1_000_000.0) * 1000.0) / 1000.0;
    }

    static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static CryptoContext CTX;

    public static void main(String[] args) throws Exception {
        int devices = 8;
        int messages = 16;
        String securityModel = "128";
        Integer tamperIndex = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--devices" -> devices = Integer.parseInt(args[++i]);
                case "--messages" -> messages = Integer.parseInt(args[++i]);
                case "--security-model" -> securityModel = args[++i];
                case "--tamper-index" -> {
                    int idx = Integer.parseInt(args[++i]);
                    tamperIndex = idx >= 0 ? idx : null;
                }
                default -> throw new IllegalArgumentException("unknown arg: " + args[i]);
            }
        }

        long wallStart = System.nanoTime();
        CTX = new CryptoContext(securityModel);
        TAActor ta = new TAActor(CTX);
        LAAggregatorActor la = new LAAggregatorActor(ta);
        ta.start();
        la.start();

        Map<String, EVActor> evs = new LinkedHashMap<>();
        for (int i = 0; i < devices; i++) {
            String rid = String.format("ev-%02d", i + 1);
            EVActor ev = new EVActor(rid, ta, la, CTX);
            ev.start();
            evs.put(rid, ev);
        }

        long t0 = System.nanoTime();
        List<CompletableFuture<Object>> regFutures = new ArrayList<>();
        for (EVActor ev : evs.values()) {
            CompletableFuture<Object> f = new CompletableFuture<>();
            ev.send(new Envelope("register", Map.of(), f));
            regFutures.add(f);
        }
        for (CompletableFuture<Object> f : regFutures) f.get();
        long t1 = System.nanoTime();

        Random rng = new Random(20250306L);
        List<String> senderList = new ArrayList<>();
        List<CompletableFuture<Object>> sendFutures = new ArrayList<>();
        List<String> ids = new ArrayList<>(evs.keySet());
        for (int i = 0; i < messages; i++) {
            String sender = ids.get(rng.nextInt(ids.size()));
            senderList.add(sender);
            byte[] payload = ("shen-msg-" + i + ":" + sender + "->la").getBytes(StandardCharsets.UTF_8);
            CompletableFuture<Object> f = new CompletableFuture<>();
            evs.get(sender).send(new Envelope("send_packet", Map.of("payload", payload, "timestamp", (long) (100 + i)), f));
            sendFutures.add(f);
        }
        for (CompletableFuture<Object> f : sendFutures) f.get();
        long t2 = System.nanoTime();

        if (tamperIndex != null) {
            rpc(la, "tamper_pending", Map.of("index", tamperIndex));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> batchResult = (Map<String, Object>) rpc(la, "process_batch", Map.of());
        long t3 = System.nanoTime();
        @SuppressWarnings("unchecked")
        Map<String, Object> stats = (Map<String, Object>) rpc(ta, "get_stats", Map.of());
        long wallEnd = System.nanoTime();

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"devices\":").append(devices).append(",");
        sb.append("\"messages\":").append(messages).append(",");
        sb.append("\"security_model\":\"").append(jsonEscape(securityModel)).append("\",");
        sb.append("\"curve\":\"type-a-pairing\",");
        sb.append("\"mode\":\"threaded-shen-v2g-jpbc\",");
        sb.append("\"register_ms\":").append(roundMs(t1 - t0)).append(",");
        sb.append("\"sign_submit_ms\":").append(roundMs(t2 - t1)).append(",");
        sb.append("\"batch_process_ms\":").append(roundMs(t3 - t2)).append(",");
        sb.append("\"tracking_ms_total\":").append(stats.get("tracking_ms_total")).append(",");
        sb.append("\"accepted_total\":").append(batchResult.get("accepted")).append(",");
        sb.append("\"tamper_index\":").append(tamperIndex == null ? "null" : tamperIndex).append(",");
        sb.append("\"senders\":[");
        for (int i = 0; i < senderList.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(jsonEscape(senderList.get(i))).append("\"");
        }
        sb.append("],");
        @SuppressWarnings("unchecked")
        List<Integer> invalid = (List<Integer>) batchResult.get("invalid_indices");
        sb.append("\"invalid_indices\":[");
        for (int i = 0; i < invalid.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(invalid.get(i));
        }
        sb.append("],");
        sb.append("\"verified\":").append(batchResult.get("verified")).append(",");
        sb.append("\"wall_ms\":").append(roundMs(wallEnd - wallStart));
        sb.append("}");
        System.out.println(sb);

        for (EVActor ev : evs.values()) ev.shutdown();
        la.shutdown();
        ta.shutdown();
    }
}
