package Utils;

import Parameters.PublicParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class TransformUtils {

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

    //test
    public static void main(String[] args) {
        String tt = "test for the BytesToHexString546 function.fasfasfadsf";
//        System.out.println(TransformUtils.BytesToHexString(tt.getBytes()));
        BigInteger result = H2FromStringToLHat(tt);
        System.out.println(result);
        System.out.println(result.bitLength());
    }
}
