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
import java.util.List;
import java.util.Random;

public class ShenV2GSignBenchmark {
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

    static byte[] randomBytes(int len, Random rng) {
        byte[] out = new byte[len];
        rng.nextBytes(out);
        return out;
    }

    static byte[] h3(byte[] lambda, byte[] rid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(lambda);
        md.update(rid);
        return Arrays.copyOf(md.digest(), 16);
    }

    static Element hashToG1(CryptoContext ctx, byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) md.update(part);
        byte[] digest = md.digest();
        return ctx.g1.newElement().setFromHash(digest, 0, digest.length).getImmutable();
    }

    static byte[] longToBytes(long value) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return out;
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
        Element s = ctx.zr.newRandomElement().getImmutable();
        byte[] ridBytes = fixedRid("shen-ev");
        byte[] lambda = randomBytes(16, new Random(20260412));
        byte[] pid = h3(lambda, ridBytes);
        Element qid = hashToG1(ctx, pid);
        Element did = qid.duplicate().mulZn(s).getImmutable();
        Element x = ctx.zr.newRandomElement().getImmutable();
        Element uid = ctx.P.duplicate().mulZn(x).getImmutable();

        for (int i = 0; i < warmups; i++) {
            byte[] msg = ("warmup-" + i).getBytes(StandardCharsets.UTF_8);
            long ts = 100 + i;
            Element rScalar = ctx.zr.newRandomElement().getImmutable();
            Element rPoint = ctx.P.duplicate().mulZn(rScalar).getImmutable();
            Element h1 = hashToG1(ctx, pid, msg, uid.toBytes(), longToBytes(ts));
            Element h2 = hashToG1(ctx, pid, msg, rPoint.toBytes(), longToBytes(ts));
            Element tau = did.duplicate().add(h1.duplicate().mulZn(x)).add(h2.duplicate().mulZn(rScalar)).getImmutable();
            SINK ^= tau.toBytes()[0];
        }

        List<Double> samples = new ArrayList<>();
        for (int i = 0; i < repeats; i++) {
            byte[] msg = ("msg-" + i).getBytes(StandardCharsets.UTF_8);
            long ts = 1000 + i;
            long t0 = System.nanoTime();
            Element rScalar = ctx.zr.newRandomElement().getImmutable();
            Element rPoint = ctx.P.duplicate().mulZn(rScalar).getImmutable();
            Element h1 = hashToG1(ctx, pid, msg, uid.toBytes(), longToBytes(ts));
            Element h2 = hashToG1(ctx, pid, msg, rPoint.toBytes(), longToBytes(ts));
            Element tau = did.duplicate().add(h1.duplicate().mulZn(x)).add(h2.duplicate().mulZn(rScalar)).getImmutable();
            SINK ^= tau.toBytes()[0];
            samples.add((System.nanoTime() - t0) / 1_000_000.0);
        }

        double mean = round6(mean(samples));
        double stddev = round6(stdev(samples, mean(samples)));
        System.out.println(
            "{\"scheme\":\"Shen-V2G\",\"security_model\":\"" + securityModel + "\",\"mean_ms\":" + mean + ",\"stddev_ms\":" + stddev + "}"
        );
    }
}
