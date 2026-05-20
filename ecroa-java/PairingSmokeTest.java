import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class PairingSmokeTest {
    public static void main(String[] args) {
        TypeACurveGenerator pg = new TypeACurveGenerator(160, 512);
        PairingParameters params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(params);

        Element P = pairing.getG1().newRandomElement().getImmutable();
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element aP = P.duplicate().mulZn(a).getImmutable();
        Element bP = P.duplicate().mulZn(b).getImmutable();
        Element left = pairing.pairing(aP, bP).getImmutable();
        Element right = pairing.pairing(P, P).powZn(a.duplicate().mul(b)).getImmutable();

        System.out.println("{\"pairing_ok\":" + left.isEqual(right) + ",\"g1_len\":" + P.toBytes().length + "}");
    }
}
