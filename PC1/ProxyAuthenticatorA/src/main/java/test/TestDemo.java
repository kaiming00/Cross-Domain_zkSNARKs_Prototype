package test;

import PPIM.Parameters.PublicParametersGenerator;
import PPIM.zkSNARKs.Proof;
import PPIM.zkSNARKs.ProofGenerator;
import Utils.TransformUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyElement;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFPairing;

import javax.print.DocFlavor;
import java.awt.*;
import java.awt.image.AreaAveragingScaleFilter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


public class TestDemo {
    public static void main(String[] args) {

        //Generate the public parameters
        PublicParametersGenerator publicParametersGenerator = new PublicParametersGenerator();
        Field Z_phat = publicParametersGenerator.Z_phat;
        Element g = publicParametersGenerator.g;

        //step1: get the identity info from UserA, generate the certificate
        //send back to UserA
        String certificate = "This is a PKI certificate from CA!";

        //step2: get the cross domain visit request from UserA
        //generate the sigma of UserA according to its certificate
        String signatureA = "Use domain A's signature way to do it.";
        Element sigma = publicParametersGenerator.hashSigmaFromString(certificate);
        //send {sigma, certificate, identity info, signatureA} to KGC in domain B

        //create Cred
        Element Cred = publicParametersGenerator.getCred(publicParametersGenerator.g_hat,sigma,publicParametersGenerator.y);

        //test the validation
//        System.out.println(publicParametersGenerator.verifySigmaAndCred(sigma, Cred));

        //generate {y1,y2,y3} & {Y1,Y2,Y3}
        ArrayList<Element> yi = new ArrayList<>();
        Element y1 = Z_phat.newRandomElement().getImmutable();
        yi.add(y1);
        Element y2 = Z_phat.newRandomElement().getImmutable();
        yi.add(y2);
        Element y3 = Z_phat.newRandomElement().getImmutable();
        yi.add(y3);

        ArrayList<Element> Yi = new ArrayList<>();
        Element Y1 = g.powZn(y1).getImmutable();
        Yi.add(Y1);
        Element Y2 = g.powZn(y2).getImmutable();
        Yi.add(Y2);
        Element Y3 = g.powZn(y3).getImmutable();
        Yi.add(Y3);

        //generate secret shadow of yi
        //the number of VS is N=2
        int vsN = 2;
        ArrayList<PolyElement> fxs = new ArrayList<>();
        ArrayList<ArrayList<BigInteger>> ss = new ArrayList<>();
        ArrayList<ArrayList<Element>> gsis = new ArrayList<>();
        ArrayList<ArrayList<Element>> Dks = new ArrayList<>();
//        for (int tt = 0;tt<10;tt++){
//            System.out.println(tt);
        for (int i=0;i<3;i++) {
            //generate polynominal for yi
            fxs.add(TransformUtils.generatePolynominalForyi(vsN, Z_phat, yi.get(i)));
            //generate si for yi
            ss.add(TransformUtils.generateSiForyi(fxs.get(i), vsN));
            //generate gsi for yi
            gsis.add(TransformUtils.generateGsiForyi(fxs.get(i), vsN, g));
            //generate Dk for yi
            Dks.add(TransformUtils.generateDkForyi(fxs.get(i), g, vsN));
            for (int j = 0; j < gsis.get(i).size(); j++) {
                System.out.println("shadow verify for y"+(j+1));
                System.out.println(TransformUtils.verifyShadow(publicParametersGenerator.Z_n2,
                        gsis.get(i).get(j), Dks.get(i), Yi.get(i), j, vsN));

            }

        }
//        }

        // Test zkSNARKs
        // assume revocation list Sinv is empty
        Element c = publicParametersGenerator.g_hat;
        // customer calculate the witness (a,d)
        // At the  beginning, the revocation list is empty
        // therefore c = g_hat, d = 1, a = [g_hat.pow(-d)].pow(1/(sigma+tao))
        BigInteger d = BigInteger.ONE;
        Element a = publicParametersGenerator.g_hat.pow(d.multiply(BigInteger.valueOf(-1L))).powZn(sigma.add(publicParametersGenerator.tao).mul(-1));
//        System.out.println("a is : "+a);
//        System.out.println("d is : "+d);

        //generate r,u,v,w
        BigInteger r = TransformUtils.generateR(publicParametersGenerator.N);
        Element u = TransformUtils.generateU(g,r);
        Element w = TransformUtils.generateW(Y1, r, sigma, publicParametersGenerator.N,Z_phat);
        Element v = TransformUtils.generateV(Y2,Y3,u,w,r);


        ProofGenerator proofGenerator = new ProofGenerator(publicParametersGenerator.pairing);
        Proof pai = proofGenerator.generateProof(r,
                sigma, Cred, a,d , Y1, Y2, Y3,
                u,w,v, publicParametersGenerator);

        BigInteger ch = TransformUtils.generateCH(publicParametersGenerator.g_hat.toBytes(),
                g.toBytes(), pai.A.toBytes(), pai.A_above_dot.toBytes());
        //verify the proof
        TransformUtils.checkProof(c, publicParametersGenerator,Y1,Y2,Y3,ch,u,w,v,pai);

        //Test Field example
        System.out.println("Test field : "+g.getField().equals(publicParametersGenerator.Z_n2));

        // identity recovery
        ArrayList<Element> recovered_yi = new ArrayList<>();
        int vst = vsN/2+1;
        for (int i=0;i<3;i++){
            BigInteger sum = BigInteger.ZERO;
            BigInteger mulR;
            for (int j=1; j<vst+1;j++){
                mulR = BigInteger.ONE;
                for (int k=1;k<vst+1;k++){
                    if (k!=j){
                        mulR = mulR.multiply(BigInteger.valueOf(k/(k-j)));
                    }
                }
                sum = sum.add(ss.get(i).get(j-1).multiply(mulR));
//                sum = sum.add(ss.get(i).get(j-1).mul(mulR));
            }
            recovered_yi.add(Z_phat.newElement(sum));
        }

        for (int i=0;i<yi.size();i++){
//            System.out.println("yi is : "+yi.get(i));
//            System.out.println("recovered_yi is : "+recovered_yi.get(i));
            System.out.println(yi.get(i).isEqual(recovered_yi.get(i)));
        }

        // check ciphertext
        BigInteger v_2 = v.pow(BigInteger.TWO).toBigInteger();
        BigInteger u_2x = u.pow(recovered_yi.get(1).toBigInteger().add(TransformUtils.H1FromBytesToL(u.toBytes(),w.toBytes()).multiply(recovered_yi.get(2).toBigInteger())).multiply(BigInteger.TWO)).toBigInteger();
//        System.out.println(v_2);
//        System.out.println(u_2x);
        System.out.println("v2 == u_2x is : "+v_2.equals(u_2x));

        BigInteger m_dot = w.div(u.powZn(recovered_yi.get(0))).toBigInteger().mod(publicParametersGenerator.N.pow(2));
//        System.out.println(m_dot);
        BigInteger recovered_sigma = m_dot.subtract(BigInteger.ONE).divide(publicParametersGenerator.N);
//        System.out.println(recovered_sigma);
//        System.out.println(sigma);
        System.out.println(recovered_sigma.equals(sigma.toBigInteger()));



        String YY = TransformUtils.byteArrayToHexStr(publicParametersGenerator.Y.toBytes());
        Element YT = publicParametersGenerator.G2.newElementFromBytes(TransformUtils.hexStrToByteArray(YY));
        System.out.println(YT.isEqual(publicParametersGenerator.Y));

    }
}
