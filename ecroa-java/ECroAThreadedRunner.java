import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;

public class ECroAThreadedRunner {
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

    static final class DomainRecord {
        final String domainId;
        final Element ppub1;
        final Element ppub2;

        DomainRecord(String domainId, Element ppub1, Element ppub2) {
            this.domainId = domainId;
            this.ppub1 = ppub1.getImmutable();
            this.ppub2 = ppub2.getImmutable();
        }
    }

    static final class DTCredential {
        final String rid;
        final String domainId;
        final Element id1;
        final byte[] id2;
        final Element sk1;
        final Element sk2;

        DTCredential(String rid, String domainId, Element id1, byte[] id2, Element sk1, Element sk2) {
            this.rid = rid;
            this.domainId = domainId;
            this.id1 = id1.getImmutable();
            this.id2 = id2.clone();
            this.sk1 = sk1.getImmutable();
            this.sk2 = sk2.getImmutable();
        }
    }

    static final class SignedPacket {
        final String senderRid;
        final String senderDomain;
        final Element id1;
        final byte[] id2;
        final byte[] message;
        final Element sigma;
        final String targetDt;

        SignedPacket(String senderRid, String senderDomain, Element id1, byte[] id2, byte[] message, Element sigma, String targetDt) {
            this.senderRid = senderRid;
            this.senderDomain = senderDomain;
            this.id1 = id1.getImmutable();
            this.id2 = id2.clone();
            this.message = message.clone();
            this.sigma = sigma.getImmutable();
            this.targetDt = targetDt;
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

    static final class BlockchainActor extends ActorThread {
        final Map<String, DomainRecord> domains = new HashMap<>();
        final Map<String, String> registry = new HashMap<>();

        BlockchainActor() {
            super("Blockchain");
        }

        @Override
        protected void handle(Envelope env) {
            switch (env.type) {
                case "publish_domain" -> {
                    DomainRecord record = (DomainRecord) env.payload.get("record");
                    domains.put(record.domainId, record);
                    env.reply.complete(Boolean.TRUE);
                }
                case "query_domain" -> {
                    env.reply.complete(domains.get((String) env.payload.get("domainId")));
                }
                case "register_dt" -> {
                    DTCredential c = (DTCredential) env.payload.get("credential");
                    registry.put(c.domainId + "|" + encodeElement(c.id1) + "|" + Base64.getEncoder().encodeToString(c.id2), c.rid);
                    env.reply.complete(Boolean.TRUE);
                }
                case "trace" -> {
                    String key = env.payload.get("domainId") + "|" + env.payload.get("id1Enc") + "|" + env.payload.get("id2Enc");
                    env.reply.complete(registry.get(key));
                }
                default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
            }
        }
    }

    static final class MECActor extends ActorThread {
        final CryptoContext ctx;
        final BlockchainActor blockchain;
        final String domainId;
        final Element s1;
        final Element s2;
        final Element ppub1;
        final Element ppub2;
        final Map<String, DomainRecord> cache = new HashMap<>();

        MECActor(String domainId, CryptoContext ctx, BlockchainActor blockchain) {
            super("MEC[" + domainId + "]");
            this.domainId = domainId;
            this.ctx = ctx;
            this.blockchain = blockchain;
            this.s1 = ctx.zr.newRandomElement().getImmutable();
            this.s2 = ctx.zr.newRandomElement().getImmutable();
            this.ppub1 = ctx.P.duplicate().mulZn(s1).getImmutable();
            this.ppub2 = ctx.P.duplicate().mulZn(s2).getImmutable();
        }

        void bootstrap() throws Exception {
            rpc(blockchain, "publish_domain", Map.of("record", new DomainRecord(domainId, ppub1, ppub2)));
            cache.put(domainId, new DomainRecord(domainId, ppub1, ppub2));
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "register_dt" -> {
                        String rid = (String) env.payload.get("rid");
                        DTCredential c = registerDt(rid);
                        rpc(blockchain, "register_dt", Map.of("credential", c));
                        env.reply.complete(c);
                    }
                    case "query_domain" -> {
                        String id = (String) env.payload.get("domainId");
                        if (!cache.containsKey(id)) {
                            cache.put(id, (DomainRecord) rpc(blockchain, "query_domain", Map.of("domainId", id)));
                        }
                        env.reply.complete(cache.get(id));
                    }
                    case "trace" -> {
                        String rid = (String) rpc(
                            blockchain,
                            "trace",
                            Map.of(
                                "domainId", env.payload.get("domainId"),
                                "id1Enc", env.payload.get("id1Enc"),
                                "id2Enc", env.payload.get("id2Enc")
                            )
                        );
                        env.reply.complete(rid);
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private DTCredential registerDt(String rid) throws Exception {
            byte[] ridBytes = fixedRid(rid);
            Element r = ctx.zr.newRandomElement().getImmutable();
            Element id1 = ctx.P.duplicate().mulZn(r).getImmutable();
            Element rp1 = ppub1.duplicate().mulZn(r).getImmutable();
            byte[] mask = hashBytes("ID2", rp1.toBytes(), ridBytes, ridBytes.length);
            byte[] id2 = xor(ridBytes, mask);
            Element hId = hashToG1(id1.toBytes(), id2);
            Element sk1 = id1.duplicate().mulZn(s1).getImmutable();
            Element sk2 = hId.duplicate().mulZn(s2).getImmutable();
            return new DTCredential(rid, domainId, id1, id2, sk1, sk2);
        }
    }

    static final class DTActor extends ActorThread {
        final String rid;
        final String homeDomain;
        final MECActor mec;
        final VerifierActor verifier;
        final CryptoContext ctx;
        DTCredential credential;

        DTActor(String rid, String homeDomain, MECActor mec, VerifierActor verifier, CryptoContext ctx) {
            super("DT[" + rid + "]");
            this.rid = rid;
            this.homeDomain = homeDomain;
            this.mec = mec;
            this.verifier = verifier;
            this.ctx = ctx;
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "register" -> {
                        this.credential = (DTCredential) rpc(mec, "register_dt", Map.of("rid", rid));
                        env.reply.complete(Boolean.TRUE);
                    }
                    case "send_packet" -> {
                        byte[] msg = (byte[]) env.payload.get("payload");
                        String target = (String) env.payload.get("target");
                        SignedPacket p = sign(msg, target);
                        rpc(verifier, "submit_packet", Map.of("packet", p));
                        env.reply.complete(Boolean.TRUE);
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private SignedPacket sign(byte[] msg, String target) throws Exception {
            Element hm = hashToZr(msg);
            Element sigma = credential.sk1.duplicate().add(credential.sk2.duplicate().mulZn(hm)).getImmutable();
            return new SignedPacket(rid, homeDomain, credential.id1, credential.id2, msg, sigma, target);
        }
    }

    static final class VerifierActor extends ActorThread {
        final String rid;
        final String domainId;
        final MECActor mec;
        final CryptoContext ctx;
        final List<SignedPacket> pending = new ArrayList<>();
        final List<SignedPacket> accepted = new ArrayList<>();
        long queryNs = 0L;

        VerifierActor(String rid, String domainId, MECActor mec, CryptoContext ctx) {
            super("Verifier[" + rid + "]");
            this.rid = rid;
            this.domainId = domainId;
            this.mec = mec;
            this.ctx = ctx;
        }

        @Override
        protected void handle(Envelope env) {
            try {
                switch (env.type) {
                    case "submit_packet" -> {
                        pending.add((SignedPacket) env.payload.get("packet"));
                        env.reply.complete(Boolean.TRUE);
                    }
                    case "tamper_pending" -> {
                        int index = (int) env.payload.get("index");
                        if (index >= 0 && index < pending.size()) {
                            SignedPacket p = pending.get(index);
                            Element badSigma = p.sigma.duplicate().add(ctx.P).getImmutable();
                            pending.set(index, new SignedPacket(p.senderRid, p.senderDomain, p.id1, p.id2, p.message, badSigma, p.targetDt));
                            env.reply.complete(Boolean.TRUE);
                        } else {
                            env.reply.complete(Boolean.FALSE);
                        }
                    }
                    case "process_batch" -> {
                        Map<String, List<SignedPacket>> grouped = new LinkedHashMap<>();
                        for (SignedPacket p : pending) {
                            grouped.computeIfAbsent(p.senderDomain, k -> new ArrayList<>()).add(p);
                        }
                        pending.clear();
                        List<Map<String, Object>> result = new ArrayList<>();
                        int acceptedCount = 0;
                        for (Map.Entry<String, List<SignedPacket>> e : grouped.entrySet()) {
                            long t0 = System.nanoTime();
                            DomainRecord record = (DomainRecord) rpc(mec, "query_domain", Map.of("domainId", e.getKey()));
                            queryNs += System.nanoTime() - t0;
                            boolean ok = verifyBatch(e.getValue(), record);
                            List<Integer> invalid = new ArrayList<>();
                            if (ok) {
                                accepted.addAll(e.getValue());
                                acceptedCount += e.getValue().size();
                            } else {
                                for (int i = 0; i < e.getValue().size(); i++) {
                                    SignedPacket p = e.getValue().get(i);
                                    if (verifySingle(p, record)) {
                                        accepted.add(p);
                                        acceptedCount += 1;
                                    } else {
                                        invalid.add(i);
                                    }
                                }
                            }
                            Map<String, Object> domainRes = new LinkedHashMap<>();
                            domainRes.put("source_domain", e.getKey());
                            domainRes.put("batch_size", e.getValue().size());
                            domainRes.put("verified", ok);
                            domainRes.put("invalid_indices", invalid);
                            result.add(domainRes);
                        }
                        Map<String, Object> payload = new LinkedHashMap<>();
                        payload.put("verified_domains", result);
                        payload.put("accepted", acceptedCount);
                        payload.put("pending_remaining", pending.size());
                        payload.put("query_ms_total", roundMs(queryNs));
                        env.reply.complete(payload);
                    }
                    case "get_stats" -> {
                        Map<String, Object> payload = new LinkedHashMap<>();
                        payload.put("accepted", accepted.size());
                        payload.put("query_ms_total", roundMs(queryNs));
                        env.reply.complete(payload);
                    }
                    default -> env.reply.completeExceptionally(new IllegalArgumentException("unknown message: " + env.type));
                }
            } catch (Exception e) {
                env.reply.completeExceptionally(e);
            }
        }

        private boolean verifySingle(SignedPacket p, DomainRecord record) throws Exception {
            Element hM = hashToZr(p.message);
            Element hId = hashToG1(p.id1.toBytes(), p.id2);
            Element left = ctx.pairing.pairing(p.sigma, ctx.P).getImmutable();
            Element term1 = ctx.pairing.pairing(p.id1, record.ppub1).getImmutable();
            Element scaled = hId.duplicate().mulZn(hM).getImmutable();
            Element term2 = ctx.pairing.pairing(scaled, record.ppub2).getImmutable();
            Element right = term1.duplicate().mul(term2).getImmutable();
            return left.isEqual(right);
        }

        private boolean verifyBatch(List<SignedPacket> packets, DomainRecord record) throws Exception {
            Element aggSigma = ctx.g1.newZeroElement();
            Element sumId1 = ctx.g1.newZeroElement();
            Element sumScaled = ctx.g1.newZeroElement();
            for (SignedPacket p : packets) {
                aggSigma.add(p.sigma);
                sumId1.add(p.id1);
                Element hM = hashToZr(p.message);
                Element hId = hashToG1(p.id1.toBytes(), p.id2);
                sumScaled.add(hId.mulZn(hM));
            }
            Element left = ctx.pairing.pairing(aggSigma.getImmutable(), ctx.P).getImmutable();
            Element term1 = ctx.pairing.pairing(sumId1.getImmutable(), record.ppub1).getImmutable();
            Element term2 = ctx.pairing.pairing(sumScaled.getImmutable(), record.ppub2).getImmutable();
            Element right = term1.duplicate().mul(term2).getImmutable();
            return left.isEqual(right);
        }
    }

    static Object rpc(ActorThread actor, String type, Map<String, Object> payload) throws Exception {
        CompletableFuture<Object> future = new CompletableFuture<>();
        actor.send(new Envelope(type, payload, future));
        return future.get();
    }

    static Element hashToZr(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return CTX.zr.newElementFromHash(digest, 0, digest.length).getImmutable();
    }

    static Element hashToG1(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return CTX.g1.newElement().setFromHash(digest, 0, digest.length).getImmutable();
    }

    static byte[] hashBytes(String tag, byte[] seed, byte[] extra, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(tag.getBytes(StandardCharsets.UTF_8));
        md.update(seed);
        md.update(extra);
        byte[] digest = md.digest();
        if (len <= digest.length) {
            byte[] out = new byte[len];
            System.arraycopy(digest, 0, out, 0, len);
            return out;
        }
        byte[] out = new byte[len];
        int copied = 0;
        int counter = 0;
        while (copied < len) {
            md.reset();
            md.update(tag.getBytes(StandardCharsets.UTF_8));
            md.update(seed);
            md.update(extra);
            md.update(intToBytes(counter++, 4));
            byte[] block = md.digest();
            int take = Math.min(block.length, len - copied);
            System.arraycopy(block, 0, out, copied, take);
            copied += take;
        }
        return out;
    }

    static String encodeElement(Element e) {
        return Base64.getEncoder().encodeToString(e.toBytes());
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

    static byte[] intToBytes(int value, int len) {
        byte[] out = new byte[len];
        for (int i = len - 1; i >= 0; i--) {
            out[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return out;
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
        int domains = 3;
        String securityModel = "128";
        Integer tamperIndex = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--devices" -> devices = Integer.parseInt(args[++i]);
                case "--messages" -> messages = Integer.parseInt(args[++i]);
                case "--domains" -> domains = Integer.parseInt(args[++i]);
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
        BlockchainActor blockchain = new BlockchainActor();
        blockchain.start();

        Map<String, MECActor> mecs = new LinkedHashMap<>();
        for (int i = 0; i < domains; i++) {
            String domainId = String.format("domain-%02d", i + 1);
            MECActor mec = new MECActor(domainId, CTX, blockchain);
            mec.start();
            mec.bootstrap();
            mecs.put(domainId, mec);
        }

        VerifierActor verifier = new VerifierActor("dt-verifier-01", "domain-01", mecs.get("domain-01"), CTX);
        verifier.start();

        List<String> domainNames = new ArrayList<>(mecs.keySet());
        Map<String, DTActor> dts = new LinkedHashMap<>();
        for (int i = 0; i < devices; i++) {
            String rid = String.format("dt-%02d", i + 1);
            String domain = domainNames.get(i % domainNames.size());
            DTActor dt = new DTActor(rid, domain, mecs.get(domain), verifier, CTX);
            dt.start();
            dts.put(rid, dt);
        }

        long t0 = System.nanoTime();
        List<CompletableFuture<Object>> regFutures = new ArrayList<>();
        for (DTActor dt : dts.values()) {
            CompletableFuture<Object> f = new CompletableFuture<>();
            dt.send(new Envelope("register", Map.of(), f));
            regFutures.add(f);
        }
        for (CompletableFuture<Object> f : regFutures) f.get();
        long t1 = System.nanoTime();

        Random rng = new Random(20250306L);
        List<String> senderList = new ArrayList<>();
        List<CompletableFuture<Object>> sendFutures = new ArrayList<>();
        List<String> ids = new ArrayList<>(dts.keySet());
        for (int i = 0; i < messages; i++) {
            String sender = ids.get(rng.nextInt(ids.size()));
            senderList.add(sender);
            byte[] payload = ("ecroa-msg-" + i + ":" + sender + "->dt-verifier-01").getBytes(StandardCharsets.UTF_8);
            CompletableFuture<Object> f = new CompletableFuture<>();
            dts.get(sender).send(new Envelope("send_packet", Map.of("payload", payload, "target", "dt-verifier-01"), f));
            sendFutures.add(f);
        }
        for (CompletableFuture<Object> f : sendFutures) f.get();
        long t2 = System.nanoTime();

        if (tamperIndex != null) {
            rpc(verifier, "tamper_pending", Map.of("index", tamperIndex));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> batchResult = (Map<String, Object>) rpc(verifier, "process_batch", Map.of());
        long t3 = System.nanoTime();
        @SuppressWarnings("unchecked")
        Map<String, Object> stats = (Map<String, Object>) rpc(verifier, "get_stats", Map.of());
        long wallEnd = System.nanoTime();

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"devices\":").append(devices).append(",");
        sb.append("\"messages\":").append(messages).append(",");
        sb.append("\"domains\":").append(domains).append(",");
        sb.append("\"security_model\":\"").append(jsonEscape(securityModel)).append("\",");
        sb.append("\"curve\":\"type-a-pairing\",");
        sb.append("\"mode\":\"threaded-ecroa-jpbc\",");
        sb.append("\"register_ms\":").append(roundMs(t1 - t0)).append(",");
        sb.append("\"sign_submit_ms\":").append(roundMs(t2 - t1)).append(",");
        sb.append("\"batch_process_ms\":").append(roundMs(t3 - t2)).append(",");
        sb.append("\"query_ms_total\":").append(batchResult.get("query_ms_total")).append(",");
        sb.append("\"accepted_total\":").append(stats.get("accepted")).append(",");
        sb.append("\"tamper_index\":").append(tamperIndex == null ? "null" : tamperIndex).append(",");
        sb.append("\"senders\":[");
        for (int i = 0; i < senderList.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(jsonEscape(senderList.get(i))).append("\"");
        }
        sb.append("],");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> verifiedDomains = (List<Map<String, Object>>) batchResult.get("verified_domains");
        sb.append("\"verified_domains\":[");
        for (int i = 0; i < verifiedDomains.size(); i++) {
            if (i > 0) sb.append(",");
            Map<String, Object> item = verifiedDomains.get(i);
            sb.append("{");
            sb.append("\"source_domain\":\"").append(jsonEscape(String.valueOf(item.get("source_domain")))).append("\",");
            sb.append("\"batch_size\":").append(item.get("batch_size")).append(",");
            sb.append("\"verified\":").append(item.get("verified")).append(",");
            @SuppressWarnings("unchecked")
            List<Integer> invalid = (List<Integer>) item.get("invalid_indices");
            sb.append("\"invalid_indices\":[");
            for (int j = 0; j < invalid.size(); j++) {
                if (j > 0) sb.append(",");
                sb.append(invalid.get(j));
            }
            sb.append("]}");
        }
        sb.append("],");
        sb.append("\"wall_ms\":").append(roundMs(wallEnd - wallStart));
        sb.append("}");
        System.out.println(sb);

        for (DTActor dt : dts.values()) dt.shutdown();
        verifier.shutdown();
        for (MECActor mec : mecs.values()) mec.shutdown();
        blockchain.shutdown();
    }
}
