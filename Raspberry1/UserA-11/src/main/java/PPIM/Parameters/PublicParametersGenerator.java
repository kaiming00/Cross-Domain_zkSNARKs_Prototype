package PPIM.Parameters;

import Utils.TransformUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Map;

public class PublicParametersGenerator {
    public final BigInteger p = new BigInteger("9E868E40DA0144AA8D3F063C9B02B16C75C2898E29DA9F821C385B87D175A083" +
            "17EDD3E54E494CA3B29D22989DD3389DB7656B7F05448CCDCB04BB84D6663345" +
            "457C55C0B560EB2A9D195B5B6C501CDBF1587E2F9C02440D34BD725BBD470A56" +
            "F25731074B842092DD501E8D268CA18E82DDD4695515E0C2C8D3F809DBDB5CA3",16);

    public final BigInteger q = new BigInteger("8A43FEE1B146464BA1EA3242787F49B38BF28EB76581076A8AC23AF418151264" +
            "63E28484BB73F06660AFDC0AA7D169117EBFB9BC72E3CEC9376CBF5514B57F3E" +
            "0995785047A4440E2CCA0F39518A80DA14CAFF67CFEE314FAA203A1748CC1856" +
            "72D572E887D06D97E9FD930E0F66FB0AE3CBD8E029090D3FB7DBD13C59C21E2F",16);

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

    public Boolean verifySigmaAndCred(Element sigma, Element Cred, Element getY){
        Element front = this.pairing.pairing(Cred, this.g_solid.pow(sigma.toBigInteger()).mul(getY)).getImmutable();
        Element tail = this.pairing.pairing(this.g_hat,this.g_solid).getImmutable();
        return front.isEqual(tail);
    }
}
