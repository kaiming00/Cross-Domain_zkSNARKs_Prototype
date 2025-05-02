package PPIM.zkSNARKs;

import PPIM.Parameters.PublicParametersGenerator;
import Utils.TransformUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;

import java.math.BigInteger;

public class ProofGenerator {

    private Pairing pairing;
    public ProofGenerator(Pairing pairing){
        this.pairing = pairing;
    }

    public Proof generateProof(BigInteger r, Element sigma,
                               Element Cred, Element a, BigInteger d, Element Y1, Element Y2, Element Y3,
                               Element u, Element w, Element v, PublicParametersGenerator publicParametersGenerator){
        Element epson = pairing.getZr().newRandomElement().getImmutable();
        Element gama = pairing.getZr().newRandomElement().getImmutable();
        Element A = publicParametersGenerator.g_hat.powZn(sigma).mul(publicParametersGenerator.h_hat.powZn(epson)).getImmutable();
//        Element C = Cred.powZn(gama).getImmutable();
        Element C = Cred.pow(gama.toBigInteger()).getImmutable();

        Element beta1 = pairing.getZr().newRandomElement().getImmutable();
        Element beta2 = pairing.getZr().newRandomElement().getImmutable();
        Element beta3 = pairing.getZr().newRandomElement().getImmutable();
        Element beta4 = pairing.getZr().newRandomElement().getImmutable();

        Element theta1 = sigma.mul(beta1).getImmutable();
        Element theta2 = sigma.mul(beta2).getImmutable();
        Element theta3 = beta3.mul(d).getImmutable();
        Element theta4 = beta4.mul(d).getImmutable();

        Element B1 = publicParametersGenerator.g_hat.powZn(beta1).mul(publicParametersGenerator.h_hat.powZn(beta2)).getImmutable();
        Element B2 = a.mul(publicParametersGenerator.h_hat.powZn(beta1)).getImmutable();

        Element g1_hat = pairing.getG1().newRandomElement().getImmutable();
        Element g2_hat = pairing.getG1().newRandomElement().getImmutable();
        Element g3_hat = pairing.getG1().newRandomElement().getImmutable();

        Element B3 = g1_hat.powZn(beta3).mul(g2_hat.powZn(beta4)).getImmutable();
        Element B4 = g3_hat.powZn(theta3).getImmutable();

        Element r_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element epson_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element sigma_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element gama_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element d_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element beta1_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element beta2_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element beta3_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element beta4_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element theta1_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element theta2_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element theta3_above_dot = pairing.getZr().newRandomElement().getImmutable();
        Element theta4_above_dot = pairing.getZr().newRandomElement().getImmutable();

        Element u_above_dot = publicParametersGenerator.g.pow(r_above_dot.toBigInteger().multiply(BigInteger.TWO)).getImmutable();

        Field Z_n2 = new ZrField(publicParametersGenerator.N.pow(2));
        Element nN = Z_n2.newElement(publicParametersGenerator.N).getImmutable();
        Element w_above_dot = Y1.pow(r_above_dot.toBigInteger().multiply(BigInteger.TWO)).mul(nN.add(Z_n2.newOneElement()).pow(sigma_above_dot.toBigInteger().multiply(BigInteger.TWO))).getImmutable();
        Element v_above_dot = Y2.mul(Y3.pow(TransformUtils.H1FromBytesToL(u.toBytes(),w.toBytes()))).pow(r_above_dot.toBigInteger().multiply(BigInteger.TWO)).getImmutable();

        Element A_above_dot = publicParametersGenerator.g_hat.powZn(sigma_above_dot).mul(publicParametersGenerator.h_hat.powZn(epson_above_dot)).getImmutable();
        Element C_above_dot = pairing.pairing(C, publicParametersGenerator.g_solid).pow(sigma_above_dot.mul(-1).toBigInteger()).mul(pairing.pairing(publicParametersGenerator.g_hat,publicParametersGenerator.g_solid).pow(gama_above_dot.toBigInteger())).getImmutable();
        Element B_11_above_dot = publicParametersGenerator.g_hat.powZn(beta1_above_dot).mul(publicParametersGenerator.h_hat.powZn(beta2_above_dot)).getImmutable();
        Element B_12_above_dot = B1.powZn(sigma_above_dot.mul(-1)).mul(publicParametersGenerator.g_hat.powZn(theta1_above_dot)).mul(publicParametersGenerator.h_hat.powZn(theta2_above_dot)).getImmutable();
        Element B_31_above_dot = g1_hat.powZn(beta3_above_dot).mul(g2_hat.powZn(beta4_above_dot)).getImmutable();
        Element B_32_above_dot = B3.powZn(d_above_dot.mul(-1)).mul(g1_hat.powZn(theta3_above_dot)).mul(g2_hat.powZn(theta4_above_dot)).getImmutable();
        Element B_4_above_dot = g3_hat.powZn(theta3_above_dot).getImmutable();
//
        Element D_above_dot = pairing.pairing(publicParametersGenerator.g_hat, publicParametersGenerator.g_solid).powZn(d_above_dot.mul(-1)).
                mul(pairing.pairing(publicParametersGenerator.h_hat,publicParametersGenerator.g_solid).powZn(theta1_above_dot)).
                mul(pairing.pairing(publicParametersGenerator.h_hat,publicParametersGenerator.g_solid).powZn(publicParametersGenerator.tao.mul(beta1_above_dot))).
                mul(pairing.pairing(B2, publicParametersGenerator.g_solid).powZn(sigma_above_dot.mul(-1))).getImmutable();


        //create challenge ch
        BigInteger ch = TransformUtils.generateCH(publicParametersGenerator.g_hat.toBytes(), publicParametersGenerator.g.toBytes(), A.toBytes(), A_above_dot.toBytes());

        BigInteger r_above_double_dot = r_above_dot.toBigInteger().subtract(r.multiply(ch));
        BigInteger epson_above_double_dot = epson_above_dot.toBigInteger().subtract(epson.toBigInteger().multiply(ch));
        BigInteger sigma_above_double_dot = sigma_above_dot.toBigInteger().subtract(sigma.toBigInteger().multiply(ch));
        BigInteger gama_above_double_dot = gama_above_dot.toBigInteger().subtract(gama.toBigInteger().multiply(ch));

        BigInteger d_above_double_dot = d_above_dot.toBigInteger().subtract(d.multiply(ch));
        Element beta1_above_double_dot = beta1_above_dot.sub(beta1.mul(ch)).getImmutable();
        Element beta2_above_double_dot = beta2_above_dot.sub(beta2.mul(ch)).getImmutable();
        Element beta3_above_double_dot = beta3_above_dot.sub(beta3.mul(ch)).getImmutable();
        Element beta4_above_double_dot = beta4_above_dot.sub(beta4.mul(ch)).getImmutable();
        Element theta1_above_double_dot = theta1_above_dot.sub(theta1.mul(ch)).getImmutable();
        Element theta2_above_double_dot = theta2_above_dot.sub(theta2.mul(ch)).getImmutable();
        Element theta3_above_double_dot = theta3_above_dot.sub(theta3.mul(ch)).getImmutable();
        Element theta4_above_double_dot = theta4_above_dot.sub(theta4.mul(ch)).getImmutable();

        return new Proof(A, C, B1, B2, B3,
                B4, u_above_dot, w_above_dot,
                v_above_dot, A_above_dot, C_above_dot,
                B_11_above_dot, B_12_above_dot, B_31_above_dot,
                B_32_above_dot, B_4_above_dot, D_above_dot, sigma_above_dot,
                r_above_double_dot, epson_above_double_dot, sigma_above_double_dot,
                gama_above_double_dot, d_above_double_dot, beta1_above_double_dot,
                beta2_above_double_dot, beta3_above_double_dot, beta4_above_double_dot,
                theta1_above_double_dot, theta2_above_double_dot, theta3_above_double_dot,
                theta4_above_double_dot, g1_hat, g2_hat, g3_hat);
    }
}
