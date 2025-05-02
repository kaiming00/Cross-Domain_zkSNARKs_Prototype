package PPIM.Curve;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyElement;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyField;
import it.unisa.dia.gas.plaf.jpbc.field.quadratic.QuadraticField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class JPBCDemo {

    public static void main(String[] args) {
        //1024 bit
        BigInteger p = new BigInteger("9E868E40DA0144AA8D3F063C9B02B16C75C2898E29DA9F821C385B87D175A083" +
                "17EDD3E54E494CA3B29D22989DD3389DB7656B7F05448CCDCB04BB84D6663345" +
                "457C55C0B560EB2A9D195B5B6C501CDBF1587E2F9C02440D34BD725BBD470A56" +
                "F25731074B842092DD501E8D268CA18E82DDD4695515E0C2C8D3F809DBDB5CA3",16);
        BigInteger p_dot = new BigInteger("4F4347206D00A255469F831E4D8158B63AE144C714ED4FC10E1C2DC3E8BAD041" +
                "8BF6E9F2A724A651D94E914C4EE99C4EDBB2B5BF82A24666E5825DC26B3319A2" +
                "A2BE2AE05AB075954E8CADADB6280E6DF8AC3F17CE0122069A5EB92DDEA3852B" +
                "792B9883A5C210496EA80F46934650C7416EEA34AA8AF0616469FC04EDEDAE51",16);
        BigInteger q = new BigInteger("8A43FEE1B146464BA1EA3242787F49B38BF28EB76581076A8AC23AF418151264" +
                "63E28484BB73F06660AFDC0AA7D169117EBFB9BC72E3CEC9376CBF5514B57F3E" +
                "0995785047A4440E2CCA0F39518A80DA14CAFF67CFEE314FAA203A1748CC1856" +
                "72D572E887D06D97E9FD930E0F66FB0AE3CBD8E029090D3FB7DBD13C59C21E2F",16);
        BigInteger q_dot = new BigInteger("4521FF70D8A32325D0F519213C3FA4D9C5F9475BB2C083B545611D7A0C0A8932" +
                "31F142425DB9F8333057EE0553E8B488BF5FDCDE3971E7649BB65FAA8A5ABF9F" +
                "04CABC2823D222071665079CA8C5406D0A657FB3E7F718A7D5101D0BA4660C2B" +
                "396AB97443E836CBF4FEC98707B37D8571E5EC701484869FDBEDE89E2CE10F17",16);

        BigInteger N = p.multiply(q);
        Field Z_n2 = new ZrField(N.pow(2));

        //generate g
        Element g_dot = Z_n2.newRandomElement().getImmutable();
        Element g = g_dot.pow(N.multiply(BigInteger.valueOf(2L))).getImmutable();

        TypeFCurveGenerator fg = new TypeFCurveGenerator(256);
        PairingParameters pp = fg.generate();
        Pairing pairing = PairingFactory.getPairing(pp);

        Field G1 = pairing.getG1();
        Field G2 = pairing.getG2();
        Field GT = pairing.getGT();
        Field Z_phat = pairing.getZr();

        //get two generator from G1, one from G2
        Element g_hat = G1.newRandomElement().getImmutable();
        Element h_hat = G1.newRandomElement().getImmutable();
        Element g_solid = G2.newRandomElement().getImmutable();

        //generate tao from Z_phat
        Element tao = Z_phat.newRandomElement().getImmutable();

        //generate private key y, public key Y
        Element y = Z_phat.newRandomElement().getImmutable();
        Element Y = g_solid.powZn(y).getImmutable();

        //choose a sigma
        //the choose of q_hat is not finished!
        Element sigma = ElementUtils.randomIn(pairing, Z_phat.newRandomElement()).getImmutable().div(tao.mul(-1));

        //generate Cred
        Element Cred = g_hat.powZn(y.add(sigma).pow(BigInteger.valueOf(-1L))).getImmutable();

        //verify
        Element front = pairing.pairing(Cred, g_solid.powZn(sigma).mul(Y));
        Element tail = pairing.pairing(g_hat,g_solid);

        //generate {y1,y2,y3} & {Y1,Y2,Y3}
        Element y1 = Z_phat.newRandomElement().getImmutable();
        Element y2 = Z_phat.newRandomElement().getImmutable();
        Element y3 = Z_phat.newRandomElement().getImmutable();

        Element Y1 = g.powZn(y1).getImmutable();
        Element Y2 = g.powZn(y2).getImmutable();
        Element Y3 = g.powZn(y3).getImmutable();

        //generate secret shadow of y1
        //the number of VS is N=2
        int Vs_N = 2;
        int Vs_t = Vs_N/2+1;
        PolyElement fx = new PolyElement(new PolyField<>(Z_phat));
        fx.ensureSize(Vs_t);
        //a0 = y1,a1 = random in Z_phat
        fx.getCoefficient(0).set(y1);
        for (int i=1;i<Vs_t;i++){
            do {
                fx.getCoefficient(i).setToRandom();
            } while(!fx.isIrriducible());
        }
        System.out.println("fx is :\n"+fx.toString());
        //generate si, gsi for y1
        ArrayList<Element> s = new ArrayList<>();
        ArrayList<Element> gsi = new ArrayList<>();
//        System.out.println("g is : \n"+g);
        for (int i = 1; i<Vs_N+1;i++){
            Element sum = Z_phat.newElement().setToZero();
            for (int j=0;j<Vs_t;j++){
                sum = sum.duplicate().add(fx.getCoefficient(j).getImmutable().mul((int) Math.pow(i,j)));
            }
            s.add(sum);
            gsi.add(g.powZn(sum));
        }
        System.out.println("s is : \n"+s);
        System.out.println("gsi is : \n"+gsi);
        //generate Dk
        ArrayList<Element> Dk = new ArrayList<>();
        for (int i = 1; i<Vs_t;i++){
            Dk.add(fx.getCoefficient(i).getImmutable());
        }
        System.out.println("Dk is : \n"+Dk);

        //verify shadow
        for (int i=0;i<gsi.size();i++){
            Element mulResult = Z_n2.newElement().setToOne();
            for (int k=0;k<Dk.size();k++){
                mulResult = mulResult.mulZn(g.powZn(Dk.get(k).mul(BigInteger.valueOf((long)Math.pow(i+1, k+1)))));
            }
            mulResult = mulResult.mulZn(Y1);
            System.out.println(mulResult);
            System.out.println(gsi.get(i));
            if (gsi.get(i).isEqual(mulResult)){
                System.out.println("equal");
            }
        }
    }
}
