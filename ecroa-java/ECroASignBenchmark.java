import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class ECroASignBenchmark {
    static volatile int SINK = 0;
    static final int RID_LEN = 16;

    static final class CryptoContext {
        final Pairing pairing;
        final Field<?> g1;
        final Field<?> zr;
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
            this.P = g1.newRandomElement().getImmutable();
        }
    }

    static byte[] fixedRid(String rid) {
        byte[] in = rid.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[RID_LEN];
        System.arraycopy(in, 0, out, 0, Math.min(RID_LEN, in.length));
        return out;
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
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
            md.update((byte) counter++);
            byte[] block = md.digest();
            int take = Math.min(block.length, len - copied);
            System.arraycopy(block, 0, out, copied, take);
            copied += take;
        }
        return out;
    }

    static Element hashToZr(CryptoContext ctx, byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return ctx.zr.newElementFromHash(digest, 0, digest.length).getImmutable();
    }

    static Element hashToG1(CryptoContext ctx, byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return ctx.g1.newElement().setFromHash(digest, 0, digest.length).getImmutable();
    }

    static double round6(double value) {
        return Math.round(value * 1_000_000.0) / 1_000_000.0;
    }

    static double mean(List<Double> values) {
        double sum = 0.0;
        for (double value : values) sum += value;
        return sum / values.size();
    }

    static double stdev(List<Double> values, double mean) {
        if (values.size() <= 1) return 0.0;
        double sum = 0.0;
        for (double value : values) {
            double diff = value - mean;
            sum += diff * diff;
        }
        return Math.sqrt(sum / (values.size() - 1));
    }

    public static void main(String[] args) throws Exception {
        String securityModel = "128";
        int repeats = 20;
        int warmups = 5;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--security-model" -> securityModel = args[++i];
                case "--repeats" -> repeats = Integer.parseInt(args[++i]);
                case "--warmups" -> warmups = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("unknown arg: " + args[i]);
            }
        }

        CryptoContext ctx = new CryptoContext(securityModel);
        Element s1 = ctx.zr.newRandomElement().getImmutable();
        Element s2 = ctx.zr.newRandomElement().getImmutable();
        Element ppub1 = ctx.P.duplicate().mulZn(s1).getImmutable();

        byte[] ridBytes = fixedRid("ecroa-device");
        Element r = ctx.zr.newRandomElement().getImmutable();
        Element id1 = ctx.P.duplicate().mulZn(r).getImmutable();
        Element rp1 = ppub1.duplicate().mulZn(r).getImmutable();
        byte[] id2 = xor(ridBytes, hashBytes("ID2", rp1.toBytes(), ridBytes, ridBytes.length));
        Element hId = hashToG1(ctx, id1.toBytes(), id2);
        Element sk1 = hId.duplicate().mulZn(s1).getImmutable();
        Element sk2 = hId.duplicate().mulZn(s2).getImmutable();

        for (int i = 0; i < warmups; i++) {
            byte[] msg = ("warmup-" + i).getBytes(StandardCharsets.UTF_8);
            Element hm = hashToZr(ctx, msg);
            Element sigma = sk1.duplicate().add(sk2.duplicate().mulZn(hm)).getImmutable();
            SINK ^= sigma.toBytes()[0];
        }

        List<Double> samples = new ArrayList<>();
        for (int i = 0; i < repeats; i++) {
            byte[] msg = ("msg-" + i).getBytes(StandardCharsets.UTF_8);
            long t0 = System.nanoTime();
            Element hm = hashToZr(ctx, msg);
            Element sigma = sk1.duplicate().add(sk2.duplicate().mulZn(hm)).getImmutable();
            SINK ^= sigma.toBytes()[0];
            samples.add((System.nanoTime() - t0) / 1_000_000.0);
        }

        double mean = round6(mean(samples));
        double stddev = round6(stdev(samples, mean(samples)));
        System.out.println(
            "{\"scheme\":\"ECroA\",\"security_model\":\"" + securityModel + "\",\"mean_ms\":" + mean + ",\"stddev_ms\":" + stddev + "}"
        );
    }
}
