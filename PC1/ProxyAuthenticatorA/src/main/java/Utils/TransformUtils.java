package Utils;

import PPIM.Parameters.PublicParametersGenerator;
import PPIM.zkSNARKs.Proof;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyElement;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class TransformUtils {

    public static Map<String, String> proofInfoToMap(String pId, Element u,
                                                     Element w, Element v, Proof pai,
                                                     Element Y1, Element Y2, Element Y3){
        Map<String, String> result = new HashMap<>();

        result.put("pId", pId);
        //Element, belongs to Z_n2
        result.put("u", TransformUtils.byteArrayToHexStr(u.toBytes()));
        result.put("w", TransformUtils.byteArrayToHexStr(w.toBytes()));
        result.put("v", TransformUtils.byteArrayToHexStr(v.toBytes()));

        result.put("A", TransformUtils.byteArrayToHexStr(pai.A.toBytes()));
        result.put("C", TransformUtils.byteArrayToHexStr(pai.C.toBytes()));
        result.put("B1", TransformUtils.byteArrayToHexStr(pai.B1.toBytes()));
        result.put("B2", TransformUtils.byteArrayToHexStr(pai.B2.toBytes()));
        result.put("B3", TransformUtils.byteArrayToHexStr(pai.B3.toBytes()));
        result.put("B4", TransformUtils.byteArrayToHexStr(pai.B4.toBytes()));
        result.put("u_above_dot", TransformUtils.byteArrayToHexStr(pai.u_above_dot.toBytes()));
        result.put("w_above_dot", TransformUtils.byteArrayToHexStr(pai.w_above_dot.toBytes()));
        result.put("v_above_dot", TransformUtils.byteArrayToHexStr(pai.v_above_dot.toBytes()));
        result.put("A_above_dot", TransformUtils.byteArrayToHexStr(pai.A_above_dot.toBytes()));
        result.put("C_above_dot", TransformUtils.byteArrayToHexStr(pai.C_above_dot.toBytes()));
        result.put("B_11_above_dot", TransformUtils.byteArrayToHexStr(pai.B_11_above_dot.toBytes()));
        result.put("B_12_above_dot", TransformUtils.byteArrayToHexStr(pai.B_12_above_dot.toBytes()));
        result.put("B_31_above_dot", TransformUtils.byteArrayToHexStr(pai.B_31_above_dot.toBytes()));
        result.put("B_32_above_dot", TransformUtils.byteArrayToHexStr(pai.B_32_above_dot.toBytes()));
        result.put("B_4_above_dot", TransformUtils.byteArrayToHexStr(pai.B_4_above_dot.toBytes()));
        result.put("D_above_dot", TransformUtils.byteArrayToHexStr(pai.D_above_dot.toBytes()));
        result.put("sigma_above_dot", TransformUtils.byteArrayToHexStr(pai.sigma_above_dot.toBytes()));
        result.put("r_above_double_dot", String.valueOf(pai.r_above_double_dot));
        result.put("epson_above_double_dot", String.valueOf(pai.epson_above_double_dot));
        result.put("sigma_above_double_dot", String.valueOf(pai.sigma_above_double_dot));
        result.put("gama_above_double_dot", String.valueOf(pai.gama_above_double_dot));
        result.put("d_above_double_dot", String.valueOf(pai.d_above_double_dot));
        result.put("beta1_above_double_dot", TransformUtils.byteArrayToHexStr(pai.beta1_above_double_dot.toBytes()));
        result.put("beta2_above_double_dot", TransformUtils.byteArrayToHexStr(pai.beta2_above_double_dot.toBytes()));
        result.put("beta3_above_double_dot", TransformUtils.byteArrayToHexStr(pai.beta3_above_double_dot.toBytes()));
        result.put("beta4_above_double_dot", TransformUtils.byteArrayToHexStr(pai.beta4_above_double_dot.toBytes()));
        result.put("theta1_above_double_dot", TransformUtils.byteArrayToHexStr(pai.theta1_above_double_dot.toBytes()));
        result.put("theta2_above_double_dot", TransformUtils.byteArrayToHexStr(pai.theta2_above_double_dot.toBytes()));
        result.put("theta3_above_double_dot", TransformUtils.byteArrayToHexStr(pai.theta3_above_double_dot.toBytes()));
        result.put("theta4_above_double_dot", TransformUtils.byteArrayToHexStr(pai.theta4_above_double_dot.toBytes()));
        result.put("g1_hat", TransformUtils.byteArrayToHexStr(pai.g1_hat.toBytes()));
        result.put("g2_hat", TransformUtils.byteArrayToHexStr(pai.g2_hat.toBytes()));
        result.put("g3_hat", TransformUtils.byteArrayToHexStr(pai.g3_hat.toBytes()));

        //Belong to Z_n2
        result.put("Y1", TransformUtils.byteArrayToHexStr(Y1.toBytes()));
        result.put("Y2", TransformUtils.byteArrayToHexStr(Y2.toBytes()));
        result.put("Y3", TransformUtils.byteArrayToHexStr(Y3.toBytes()));

        return result;
    }

    //change publicparameters to Map<string,string> type for data exchange
    public static Map<String, String> publicparametersToMap(PublicParametersGenerator publicParametersGenerator){
        Map<String, String> result = new HashMap<>();
        //BigInteger
        result.put("N", String.valueOf(publicParametersGenerator.N));
        //Element, belongs to Z_n2
        result.put("g_dot", TransformUtils.byteArrayToHexStr(publicParametersGenerator.g_dot.toBytes()));
        //PairingParameters structure
        result.put("pairingParameters", publicParametersGenerator.pairingParameters.toString());
        //Element, belongs to G1
        result.put("g_hat", TransformUtils.byteArrayToHexStr(publicParametersGenerator.g_hat.toBytes()));
        result.put("h_hat", TransformUtils.byteArrayToHexStr(publicParametersGenerator.h_hat.toBytes()));
        //Element, belongs to G2
        result.put("g_solid", TransformUtils.byteArrayToHexStr(publicParametersGenerator.g_solid.toBytes()));
        //Element, belong to Z_phat
        result.put("tao", TransformUtils.byteArrayToHexStr(publicParametersGenerator.tao.toBytes()));
        //public key of ProxyAuthenticatorA
        //Element, belong to G2
        result.put("Y", TransformUtils.byteArrayToHexStr(publicParametersGenerator.Y.toBytes()));
        return result;
    }

    //H: {0,1}* -> Z_phat, generate sigma
    public static Element hashFromStringToZpHat(Field Z_phat, Element tao, String str){
        return Z_phat.newElement().setFromHash(str.getBytes(), 0, str.length()).getImmutable().div(tao.mul(-1));
    }

    //H: {0,1}* -> Z_phat, generate sigma
    public static Element hashFromBytesToZpHat(Field Z_phat, Element tao, byte[] bytes){
        return Z_phat.newElement().setFromHash(bytes, 0, bytes.length).getImmutable().div(tao.mul(-1));
    }

    //H1: {0,1}* x {0,1}* -> {0,1}l , l=1024
    public static BigInteger H1FromStringToL(String str1, String str2){
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(str1.getBytes());
            out.write(messageDigest.digest());
            messageDigest.reset();
            messageDigest.update(str2.getBytes());
            out.write(messageDigest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        byte[] byteArray = out.toByteArray();
        BigInteger result = new BigInteger(1, byteArray);
        return result;
    }

    public static BigInteger H1FromBytesToL(byte[] bytes1, byte[] bytes2){
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(bytes1);
            out.write(messageDigest.digest());
            messageDigest.reset();
            messageDigest.update(bytes2);
            out.write(messageDigest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        byte[] byteArray = out.toByteArray();
        BigInteger result = new BigInteger(1, byteArray);
        return result;
    }

    //H2: {0,1}* -> {0,1}l_hat, l_hat = 256
    public static BigInteger H2FromStringToLHat(String str){
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes());
            out.write(messageDigest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        byte[] byteArray = out.toByteArray();
        BigInteger result = new BigInteger(1, byteArray);
        return result;
    }

    public static BigInteger randomBigInteger(BigInteger upperLimit){
        BigInteger randomNumber;
        Random random = new Random();
        do {
            randomNumber = new BigInteger(upperLimit.bitLength(), random);
        }while (randomNumber.compareTo(upperLimit)>=0);
        return randomNumber;
    }

    public static BigInteger H2FromBytesToLHat(byte[] bytes){
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes);
            out.write(messageDigest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        byte[] byteArray = out.toByteArray();
        BigInteger result = new BigInteger(1, byteArray);
        return result;
    }

    public static BigInteger generateCH(byte[] g_hat, byte[] g, byte[] A, byte[] A_above_dot){
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(g_hat);
            out.write(g);
            out.write(A);
            out.write(A_above_dot);
        } catch (IOException e) {
            e.printStackTrace();
        }
        BigInteger ch = TransformUtils.H2FromBytesToLHat(out.toByteArray());
        return ch;
    }

    /*
     * @Author Chen Xing
     * @Purpose UserA's operation; Generate y1,y2,y3 Y1,Y2,Y3
     * @Operations
     * 1. for TestDemo.java to test
     */
    public static PolyElement generatePolynominalForyi(int N, Field Z_phat, Element yi){
        int t = N/2+1;
        PolyElement fx = new PolyElement(new PolyField<>(Z_phat));
        fx.ensureSize(t);
        //a0 = yi,ai = random in Z_phat
        fx.getCoefficient(0).set(yi);
        for (int i=1;i<t;i++){
            do {
                fx.getCoefficient(i).setToRandom();
            } while(!fx.isIrriducible());
        }
        return fx;
    }

    public static ArrayList<BigInteger> generateSiForyi(PolyElement fx, int N){
        int t = N/2+1;
        ArrayList<BigInteger> s = new ArrayList<>();
        for (int i = 1; i<N+1; i++){
            BigInteger sum = BigInteger.ZERO;
            for (int j = 0; j<t;j++){
                sum = sum.add(fx.getCoefficient(j).toBigInteger().multiply(BigInteger.valueOf((long) Math.pow(i,j))));
            }
            s.add(sum);
        }
        return s;
    }

    public static ArrayList<Element> generateGsiForyi(PolyElement fx, int N, Element g){
        int t = N/2+1;
        ArrayList<Element> gsi = new ArrayList<>();
        for (int i = 1; i<N+1; i++){
            BigInteger sum = BigInteger.ZERO;
            for (int j = 0; j<t;j++){
                sum = sum.add(fx.getCoefficient(j).toBigInteger().multiply(BigInteger.valueOf((long) Math.pow(i,j))));
            }
            gsi.add(g.pow(sum).getImmutable());
        }
        return gsi;
    }

    public static ArrayList<Element> generateDkForyi(PolyElement fx,Element g, int N){
        int t = N/2+1;
        ArrayList<Element> Dk = new ArrayList<>();
        for (int i = 1; i<t; i++){
            Dk.add(g.powZn(fx.getCoefficient(i).duplicate()).getImmutable());
        }
        return Dk;
    }

    //i = 0~t-1;
    public static Boolean verifyShadow(Field Z_n2, Element gs, ArrayList<Element> Dk, Element Yi, int i, int N){
        int t = N/2+1;
        Element mulResult = Z_n2.newElement().setToOne().getImmutable();
        for (int k=0;k<Dk.size();k++){
            mulResult = mulResult.duplicate().mul(Dk.get(k).duplicate().pow(BigInteger.valueOf((long)Math.pow(i+1, k+1))));
        }
        mulResult = mulResult.duplicate().mul(Yi);
        return gs.isEqual(mulResult);
    }

    //generate r and encrypt the identity sigma as (u, w, v)
    public static BigInteger generateR(BigInteger N){
        BigInteger r = TransformUtils.randomBigInteger(N.divide(BigInteger.valueOf(4L)));
        return r;
    }
    public static Element generateU(Element g, BigInteger r){
        return g.pow(r).getImmutable();
    }
    public static Element generateW(Element Y1, BigInteger r, Element sigma, BigInteger N, Field Z_phat){
        Field Z_n2 = new ZrField(N.pow(2));
        Element nN = Z_n2.newElement(N);
        return Y1.pow(r).mul(nN.add(Z_n2.newOneElement()).pow(sigma.toBigInteger())).getImmutable();
    }
    public static Element generateV(Element Y2, Element Y3, Element u, Element w, BigInteger r){
        return Y2.mul(Y3.pow(TransformUtils.H1FromBytesToL(u.toBytes(), w.toBytes()))).pow(r).getImmutable();
    }


    /*
     * @Author Chen Xing
     * @Purpose VS's verification operations
     * @Operations
     * 1.
     */
    public static Boolean checkProof(Element c, PublicParametersGenerator publicParametersGenerator, Element Y1, Element Y2, Element Y3, BigInteger ch, Element u, Element w, Element v, Proof proof){
        Boolean f1 = proof.u_above_dot.isEqual(
                u.pow(ch.multiply(BigInteger.TWO)).mul(
                        publicParametersGenerator.g.pow(proof.r_above_double_dot.multiply(BigInteger.TWO))
                )
        );

        Field Z_n2 = new ZrField(publicParametersGenerator.N.pow(2));
        Element nN = Z_n2.newElement(publicParametersGenerator.N).getImmutable();
        Boolean f2 = proof.w_above_dot.isEqual(
                w.pow(ch.multiply(BigInteger.TWO)).mul(
                        Y1.pow(proof.r_above_double_dot.multiply(BigInteger.TWO))
                ).mul(
                        nN.add(Z_n2.newOneElement()).pow(proof.sigma_above_double_dot.multiply(BigInteger.TWO))
                )
        );

        Boolean f3 = proof.v_above_dot.isEqual(
                v.pow(ch.multiply(BigInteger.TWO)).mul(
                        Y2.mul(Y3.pow(TransformUtils.H1FromBytesToL(u.toBytes(),w.toBytes())))
                                .pow(proof.r_above_double_dot.multiply(BigInteger.TWO))
                )
        );

        Boolean f4 = proof.A_above_dot.isEqual(
                proof.A.pow(ch).mul(
                        publicParametersGenerator.g_hat.powZn(publicParametersGenerator.Z_phat.newElement(proof.sigma_above_double_dot))
                ).mul(
                        publicParametersGenerator.h_hat.powZn(publicParametersGenerator.Z_phat.newElement(proof.epson_above_double_dot))
                )
        );

        Boolean f6 = !proof.B4.isEqual(publicParametersGenerator.Z_phat.newOneElement());

        Boolean f7 = proof.B_11_above_dot.isEqual(
                proof.B1.pow(ch).mul(
                        publicParametersGenerator.g_hat.powZn(proof.beta1_above_double_dot)
                ).mul(
                        publicParametersGenerator.h_hat.powZn(proof.beta2_above_double_dot)
                )
        );

        Boolean f8 = proof.B_12_above_dot.isEqual(
                proof.B1.pow(proof.sigma_above_double_dot.multiply(BigInteger.valueOf(-1L))).mul(
                        publicParametersGenerator.g_hat.powZn(proof.theta1_above_double_dot)
                ).mul(
                        publicParametersGenerator.h_hat.powZn(proof.theta2_above_double_dot)
                )
        );

        Boolean f9 = proof.B_31_above_dot.isEqual(
                proof.B3.pow(ch).mul(
                        proof.g1_hat.powZn(proof.beta3_above_double_dot)
                ).mul(
                        proof.g2_hat.powZn(proof.beta4_above_double_dot)
                )
        );

        Boolean f10 = proof.B_32_above_dot.isEqual(
                proof.B3.pow(proof.d_above_double_dot.multiply(BigInteger.valueOf(-1L)))
                        .mul(
                                proof.g1_hat.powZn(proof.theta3_above_double_dot)
                        ).mul(
                        proof.g2_hat.powZn(proof.theta4_above_double_dot)
                )
        );

        Boolean f11 = proof.B_4_above_dot.isEqual(
                proof.B4.pow(ch).mul(
                        proof.g3_hat.powZn(proof.theta3_above_double_dot)
                )
        );

        Boolean f12 = proof.D_above_dot.isEqual(
                publicParametersGenerator.pairing.pairing(
                        proof.B2,publicParametersGenerator.g_solid
                ).pow(publicParametersGenerator.tao.toBigInteger()).div(
                        publicParametersGenerator.pairing.pairing(
                                c, publicParametersGenerator.g_solid
                        )
                ).pow(ch).mul(
                        publicParametersGenerator.pairing.pairing(
                                publicParametersGenerator.g_hat,
                                publicParametersGenerator.g_solid
                        ).pow(proof.d_above_double_dot.multiply(BigInteger.valueOf(-1L)))
                ).mul(
                        publicParametersGenerator.pairing.pairing(
                                publicParametersGenerator.h_hat,
                                publicParametersGenerator.g_solid
                        ).pow(proof.theta1_above_double_dot.toBigInteger())
                ).mul(
                        publicParametersGenerator.pairing.pairing(
                                publicParametersGenerator.h_hat,
                                publicParametersGenerator.g_solid
                        ).pow(publicParametersGenerator.tao.toBigInteger().multiply(proof.beta1_above_double_dot.toBigInteger()))
                ).mul(
                        publicParametersGenerator.pairing.pairing(
                                proof.B2, publicParametersGenerator.g_solid
                        ).pow(proof.sigma_above_double_dot.multiply(BigInteger.valueOf(-1L)))
                )
        );

        return  f1 && f2 && f3 && f4 && f6 && f7 && f8 && f9 && f10 && f11 && f12;
    }


    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStrToByteArray(String str)
    {
        if (str == null) {
            return null;
        }
        if (str.length() == 0) {
            return new byte[0];
        }
        byte[] byteArray = new byte[str.length() / 2];
        for (int i = 0; i < byteArray.length; i++){
            String subStr = str.substring(2 * i, 2 * i + 2);
            byteArray[i] = ((byte)Integer.parseInt(subStr, 16));
        }
        return byteArray;
    }


}
