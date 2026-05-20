import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ShenV2GOnlineBenchmark {
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
        int devices = 8;
        int repeats = 20;
        String securityModel = "128";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--devices" -> devices = Integer.parseInt(args[++i]);
                case "--security-model" -> securityModel = args[++i];
                case "--repeats" -> repeats = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("unknown arg: " + args[i]);
            }
        }

        ShenV2GThreadedRunner.CTX = new ShenV2GThreadedRunner.CryptoContext(securityModel);
        ShenV2GThreadedRunner.TAActor ta = new ShenV2GThreadedRunner.TAActor(ShenV2GThreadedRunner.CTX);
        ShenV2GThreadedRunner.LAAggregatorActor la = new ShenV2GThreadedRunner.LAAggregatorActor(ta);
        ta.start();
        la.start();

        Map<String, ShenV2GThreadedRunner.EVActor> evs = new LinkedHashMap<>();
        for (int i = 0; i < devices; i++) {
            String rid = String.format("ev-%02d", i + 1);
            ShenV2GThreadedRunner.EVActor ev = new ShenV2GThreadedRunner.EVActor(rid, ta, la, ShenV2GThreadedRunner.CTX);
            ev.start();
            evs.put(rid, ev);
        }

        List<CompletableFuture<Object>> regFutures = new ArrayList<>();
        for (ShenV2GThreadedRunner.EVActor ev : evs.values()) {
            CompletableFuture<Object> f = new CompletableFuture<>();
            ev.send(new ShenV2GThreadedRunner.Envelope("register", Map.of(), f));
            regFutures.add(f);
        }
        for (CompletableFuture<Object> f : regFutures) f.get();

        List<String> ids = new ArrayList<>(evs.keySet());
        List<Double> samples = new ArrayList<>();
        for (int rep = 0; rep < repeats; rep++) {
            long t0 = System.nanoTime();
            List<CompletableFuture<Object>> sendFutures = new ArrayList<>();
            for (int i = 0; i < ids.size(); i++) {
                String sender = ids.get(i);
                byte[] payload = ("shen-bench-" + rep + "-" + sender).getBytes(StandardCharsets.UTF_8);
                CompletableFuture<Object> f = new CompletableFuture<>();
                evs.get(sender).send(new ShenV2GThreadedRunner.Envelope("send_packet", Map.of("payload", payload, "timestamp", 100L + i), f));
                sendFutures.add(f);
            }
            for (CompletableFuture<Object> f : sendFutures) f.get();
            ShenV2GThreadedRunner.rpc(la, "process_batch", Map.of());
            long t1 = System.nanoTime();
            samples.add((t1 - t0) / 1_000_000.0);
        }

        double m = mean(samples);
        double s = stdev(samples, m);
        System.out.println(
            "{\"scheme\":\"Shen-V2G\",\"devices\":" + devices +
            ",\"security_model\":\"" + securityModel +
            "\",\"mean_ms\":" + round6(m) +
            ",\"stddev_ms\":" + round6(s) +
            ",\"workload_note\":\"" + "one authentication packet per device in each round" + "\"}"
        );
    }
}
