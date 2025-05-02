package PPIM.Parameters;

import Utils.TransformUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Map;

public class PublicParametersGenerator {
    public static final BigInteger p = new BigInteger("9E868E40DA0144AA8D3F063C9B02B16C75C2898E29DA9F821C385B87D175A083" +
            "17EDD3E54E494CA3B29D22989DD3389DB7656B7F05448CCDCB04BB84D6663345" +
            "457C55C0B560EB2A9D195B5B6C501CDBF1587E2F9C02440D34BD725BBD470A56" +
            "F25731074B842092DD501E8D268CA18E82DDD4695515E0C2C8D3F809DBDB5CA3",16);
    public static final BigInteger p_dot = new BigInteger("4F4347206D00A255469F831E4D8158B63AE144C714ED4FC10E1C2DC3E8BAD041" +
            "8BF6E9F2A724A651D94E914C4EE99C4EDBB2B5BF82A24666E5825DC26B3319A2" +
            "A2BE2AE05AB075954E8CADADB6280E6DF8AC3F17CE0122069A5EB92DDEA3852B" +
            "792B9883A5C210496EA80F46934650C7416EEA34AA8AF0616469FC04EDEDAE51",16);
    public static final BigInteger q = new BigInteger("8A43FEE1B146464BA1EA3242787F49B38BF28EB76581076A8AC23AF418151264" +
            "63E28484BB73F06660AFDC0AA7D169117EBFB9BC72E3CEC9376CBF5514B57F3E" +
            "0995785047A4440E2CCA0F39518A80DA14CAFF67CFEE314FAA203A1748CC1856" +
            "72D572E887D06D97E9FD930E0F66FB0AE3CBD8E029090D3FB7DBD13C59C21E2F",16);
    public static final BigInteger q_dot = new BigInteger("4521FF70D8A32325D0F519213C3FA4D9C5F9475BB2C083B545611D7A0C0A8932" +
            "31F142425DB9F8333057EE0553E8B488BF5FDCDE3971E7649BB65FAA8A5ABF9F" +
            "04CABC2823D222071665079CA8C5406D0A657FB3E7F718A7D5101D0BA4660C2B" +
            "396AB97443E836CBF4FEC98707B37D8571E5EC701484869FDBEDE89E2CE10F17",16);
    public int l = 1024;
    public int l_hat = 256;
    public BigInteger N;

    //can be computed
    public Field Z_n2;
    public Element g_dot;
    public Element g;

    //can be generated from pairingParameters
    public PairingParameters pairingParameters;
    public Pairing pairing;
    public Field G1;
    public Field G2;
    public Field GT;
    public Field Z_phat;

    public Element g_hat;
    public Element h_hat;
    public Element g_solid;
    public Element tao;
    public Element y;
    public Element Y;

    public PublicParametersGenerator(){
        this.N = p.multiply(q);
        this.Z_n2 = new ZrField(N.pow(2));
        this.g_dot = this.Z_n2.newRandomElement().getImmutable();
        this.g = this.g_dot.pow(this.N.multiply(BigInteger.valueOf(2L))).getImmutable();
        TypeFCurveGenerator fg = new TypeFCurveGenerator(this.l_hat);
        this.pairingParameters = fg.generate();
        this.pairing = PairingFactory.getPairing(this.pairingParameters);
        this.G1 = this.pairing.getG1();
        this.G2 = this.pairing.getG2();
        this.GT = this.pairing.getGT();
        this.Z_phat = this.pairing.getZr();
        this.g_hat = this.G1.newRandomElement().getImmutable();
        do {
            this.h_hat = this.G1.newRandomElement().getImmutable();
        }while (this.h_hat.isEqual(this.g_hat));
        this.g_solid = this.G2.newRandomElement().getImmutable();
        this.tao = this.Z_phat.newRandomElement().getImmutable();

        this.y = this.Z_phat.newRandomElement().getImmutable();
        this.Y = this.g_solid.pow(y.toBigInteger()).getImmutable();
//        this.Y = this.g_solid.powZn(y).getImmutable();
    }

    public PublicParametersGenerator(Map<String,String> getMap){
        //BigInteger
        this.N = new BigInteger(getMap.get("N"));
        this.Z_n2 = new ZrField(N.pow(2));
        //Element
        this.g_dot = this.Z_n2.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("g_dot"))
        ).getImmutable();
        this.g = this.g_dot.pow(this.N.multiply(BigInteger.valueOf(2L))).getImmutable();
        //Get the pairing
        try {
            OutputStream outputStream = new FileOutputStream("f.properties");
            outputStream.write(getMap.get("pairingParameters").getBytes());
            outputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.pairing = PairingFactory.getPairing("f.properties");
        this.G1 = this.pairing.getG1();
        this.G2 = this.pairing.getG2();
        this.GT = this.pairing.getGT();
        this.Z_phat = this.pairing.getZr();

        //Element
        this.g_hat = this.G1.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("g_hat"))
        ).getImmutable();
        this.h_hat = this.G1.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("h_hat"))
        ).getImmutable();
        this.g_solid = this.G2.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("g_solid"))
        ).getImmutable();
        this.tao = this.Z_phat.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("tao"))
        ).getImmutable();
        this.Y = this.G2.newElementFromBytes(
                TransformUtils.hexStrToByteArray(getMap.get("Y"))
        ).getImmutable();
    }

    public Element randomSigma(){
        return ElementUtils.randomIn(this.pairing,
                this.Z_phat.newRandomElement().getImmutable().div(this.tao.mul(-1))).getImmutable();
    }

    public Element hashSigmaFromString(String str){
        return TransformUtils.hashFromStringToZpHat(this.Z_phat, this.tao, str).getImmutable();
    }

    public Element hashSigmaFromBytes(byte[] bytes){
        return TransformUtils.hashFromBytesToZpHat(this.Z_phat, this.tao, bytes).getImmutable();
    }

    public static Element getCred(Element g_hat, Element sigma, Element y){
        return g_hat.powZn(y.add(sigma).pow(BigInteger.valueOf(-1L))).getImmutable();
    }

    public Boolean verifySigmaAndCred(Element sigma, Element Cred){
        Element front = this.pairing.pairing(Cred, this.g_solid.pow(sigma.toBigInteger()).mul(this.Y)).getImmutable();
        Element tail = this.pairing.pairing(this.g_hat,this.g_solid).getImmutable();
        return front.isEqual(tail);
    }
}
