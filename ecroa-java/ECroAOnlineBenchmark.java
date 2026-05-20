import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ECroAOnlineBenchmark {
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
        int domains = 4;
        int repeats = 20;
        String securityModel = "128";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--devices" -> devices = Integer.parseInt(args[++i]);
                case "--domains" -> domains = Integer.parseInt(args[++i]);
                case "--security-model" -> securityModel = args[++i];
                case "--repeats" -> repeats = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("unknown arg: " + args[i]);
            }
        }

        ECroAThreadedRunner.CTX = new ECroAThreadedRunner.CryptoContext(securityModel);
        ECroAThreadedRunner.BlockchainActor blockchain = new ECroAThreadedRunner.BlockchainActor();
        blockchain.start();

        Map<String, ECroAThreadedRunner.MECActor> mecs = new LinkedHashMap<>();
        for (int i = 0; i < domains; i++) {
            String domainId = String.format("domain-%02d", i + 1);
            ECroAThreadedRunner.MECActor mec = new ECroAThreadedRunner.MECActor(domainId, ECroAThreadedRunner.CTX, blockchain);
            mec.start();
            mec.bootstrap();
            mecs.put(domainId, mec);
        }

        ECroAThreadedRunner.VerifierActor verifier =
            new ECroAThreadedRunner.VerifierActor("dt-verifier-01", "domain-01", mecs.get("domain-01"), ECroAThreadedRunner.CTX);
        verifier.start();

        List<String> domainNames = new ArrayList<>(mecs.keySet());
        Map<String, ECroAThreadedRunner.DTActor> dts = new LinkedHashMap<>();
        for (int i = 0; i < devices; i++) {
            String rid = String.format("dt-%02d", i + 1);
            String domain = domainNames.get(i % domainNames.size());
            ECroAThreadedRunner.DTActor dt = new ECroAThreadedRunner.DTActor(rid, domain, mecs.get(domain), verifier, ECroAThreadedRunner.CTX);
            dt.start();
            dts.put(rid, dt);
        }

        List<CompletableFuture<Object>> regFutures = new ArrayList<>();
        for (ECroAThreadedRunner.DTActor dt : dts.values()) {
            CompletableFuture<Object> f = new CompletableFuture<>();
            dt.send(new ECroAThreadedRunner.Envelope("register", Map.of(), f));
            regFutures.add(f);
        }
        for (CompletableFuture<Object> f : regFutures) f.get();

        List<String> ids = new ArrayList<>(dts.keySet());
        List<Double> samples = new ArrayList<>();
        for (int rep = 0; rep < repeats; rep++) {
            long t0 = System.nanoTime();
            List<CompletableFuture<Object>> sendFutures = new ArrayList<>();
            for (int i = 0; i < ids.size(); i++) {
                String sender = ids.get(i);
                byte[] payload = ("ecroa-bench-" + rep + "-" + sender).getBytes(StandardCharsets.UTF_8);
                CompletableFuture<Object> f = new CompletableFuture<>();
                dts.get(sender).send(new ECroAThreadedRunner.Envelope("send_packet", Map.of("payload", payload, "target", "dt-verifier-01"), f));
                sendFutures.add(f);
            }
            for (CompletableFuture<Object> f : sendFutures) f.get();
            ECroAThreadedRunner.rpc(verifier, "process_batch", Map.of());
            long t1 = System.nanoTime();
            samples.add((t1 - t0) / 1_000_000.0);
        }

        double m = mean(samples);
        double s = stdev(samples, m);
        System.out.println(
            "{\"scheme\":\"ECroA\",\"devices\":" + devices +
            ",\"security_model\":\"" + securityModel +
            "\",\"mean_ms\":" + round6(m) +
            ",\"stddev_ms\":" + round6(s) +
            ",\"workload_note\":\"" + "one authentication packet per device in each round" + "\"}"
        );
    }
}
