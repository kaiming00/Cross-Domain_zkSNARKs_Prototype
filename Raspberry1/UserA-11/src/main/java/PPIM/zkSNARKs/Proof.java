package PPIM.zkSNARKs;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

public class Proof {
    public Element A;
    public Element C;
    public Element B1;
    public Element B2;
    public Element B3;
    public Element B4;
    public Element u_above_dot;
    public Element w_above_dot;
    public Element v_above_dot;
    public Element A_above_dot;
    public Element C_above_dot;
    public Element B_11_above_dot;
    public Element B_12_above_dot;
    public Element B_31_above_dot;
    public Element B_32_above_dot;
    public Element B_4_above_dot;
    public Element D_above_dot;
    public Element sigma_above_dot;
    public BigInteger r_above_double_dot;
    public BigInteger epson_above_double_dot;
    public BigInteger sigma_above_double_dot;
    public BigInteger gama_above_double_dot;
    public BigInteger d_above_double_dot;
    public Element beta1_above_double_dot;
    public Element beta2_above_double_dot;
    public Element beta3_above_double_dot;
    public Element beta4_above_double_dot;
    public Element theta1_above_double_dot;
    public Element theta2_above_double_dot;
    public Element theta3_above_double_dot;
    public Element theta4_above_double_dot;
    public Element g1_hat;
    public Element g2_hat;
    public Element g3_hat;

    public Proof(Element a, Element c, Element b1, Element b2, Element b3,
                 Element b4, Element u_above_dot, Element w_above_dot,
                 Element v_above_dot, Element a_above_dot, Element c_above_dot,
                 Element b_11_above_dot, Element b_12_above_dot, Element b_31_above_dot,
                 Element b_32_above_dot, Element b_4_above_dot, Element d_above_dot, Element sigma_above_dot,
                 BigInteger r_above_double_dot, BigInteger epson_above_double_dot, BigInteger sigma_above_double_dot,
                 BigInteger gama_above_double_dot, BigInteger d_above_double_dot, Element beta1_above_double_dot,
                 Element beta2_above_double_dot, Element beta3_above_double_dot, Element beta4_above_double_dot,
                 Element theta1_above_double_dot, Element theta2_above_double_dot, Element theta3_above_double_dot,
                 Element theta4_above_double_dot, Element g1_hat, Element g2_hat, Element g3_hat) {
        A = a;
        C = c;
        B1 = b1;
        B2 = b2;
        B3 = b3;
        B4 = b4;
        this.u_above_dot = u_above_dot;
        this.w_above_dot = w_above_dot;
        this.v_above_dot = v_above_dot;
        A_above_dot = a_above_dot;
        C_above_dot = c_above_dot;
        B_11_above_dot = b_11_above_dot;
        B_12_above_dot = b_12_above_dot;
        B_31_above_dot = b_31_above_dot;
        B_32_above_dot = b_32_above_dot;
        B_4_above_dot = b_4_above_dot;
        D_above_dot = d_above_dot;
        this.sigma_above_dot = sigma_above_dot;
        this.r_above_double_dot = r_above_double_dot;
        this.epson_above_double_dot = epson_above_double_dot;
        this.sigma_above_double_dot = sigma_above_double_dot;
        this.gama_above_double_dot = gama_above_double_dot;
        this.d_above_double_dot = d_above_double_dot;
        this.beta1_above_double_dot = beta1_above_double_dot;
        this.beta2_above_double_dot = beta2_above_double_dot;
        this.beta3_above_double_dot = beta3_above_double_dot;
        this.beta4_above_double_dot = beta4_above_double_dot;
        this.theta1_above_double_dot = theta1_above_double_dot;
        this.theta2_above_double_dot = theta2_above_double_dot;
        this.theta3_above_double_dot = theta3_above_double_dot;
        this.theta4_above_double_dot = theta4_above_double_dot;
        this.g1_hat = g1_hat;
        this.g2_hat = g2_hat;
        this.g3_hat = g3_hat;
    }

//    public Proof(Map<String, String> getMap, PublicParametersGenerator publicParametersGenerator){
//        A = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("A"))
//        ).getImmutable();
//        C = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("C"))
//        ).getImmutable();
//        B1 = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B1"))
//        ).getImmutable();
//        B2 = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B2"))
//        ).getImmutable();
//        B3 = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B3"))
//        ).getImmutable();
//        B4 = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B4"))
//        ).getImmutable();
//        this.u_above_dot = publicParametersGenerator.Z_n2.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("u_above_dot"))
//        ).getImmutable();
//        this.w_above_dot = publicParametersGenerator.Z_n2.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("w_above_dot"))
//        ).getImmutable();
//        this.v_above_dot = publicParametersGenerator.Z_n2.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("v_above_dot"))
//        ).getImmutable();
//        A_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("A_above_dot"))
//        ).getImmutable();
//        C_above_dot = publicParametersGenerator.GT.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("C_above_dot"))
//        ).getImmutable();
//        B_11_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B_11_above_dot"))
//        ).getImmutable();
//        B_12_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B_12_above_dot"))
//        ).getImmutable();
//        B_31_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B_31_above_dot"))
//        ).getImmutable();
//        B_32_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B_32_above_dot"))
//        ).getImmutable();
//        B_4_above_dot = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("B_4_above_dot"))
//        ).getImmutable();
//        D_above_dot = publicParametersGenerator.GT.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("D_above_dot"))
//        ).getImmutable();
//        this.sigma_above_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("sigma_above_dot"))
//        ).getImmutable();
//        this.r_above_double_dot = new BigInteger(getMap.get("r_above_double_dot"));
//        this.epson_above_double_dot = new BigInteger(getMap.get("epson_above_double_dot"));
//        this.sigma_above_double_dot = new BigInteger(getMap.get("sigma_above_double_dot"));
//        this.gama_above_double_dot = new BigInteger(getMap.get("gama_above_double_dot"));
//        this.d_above_double_dot = new BigInteger(getMap.get("d_above_double_dot"));
//        this.beta1_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("beta1_above_double_dot"))
//        ).getImmutable();
//        this.beta2_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("beta2_above_double_dot"))
//        ).getImmutable();
//        this.beta3_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("beta3_above_double_dot"))
//        ).getImmutable();
//        this.beta4_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("beta4_above_double_dot"))
//        ).getImmutable();
//        this.theta1_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("theta1_above_double_dot"))
//        ).getImmutable();
//        this.theta2_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("theta2_above_double_dot"))
//        ).getImmutable();
//        this.theta3_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("theta3_above_double_dot"))
//        ).getImmutable();
//        this.theta4_above_double_dot = publicParametersGenerator.Z_phat.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("theta4_above_double_dot"))
//        ).getImmutable();
//        this.g1_hat = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("g1_hat"))
//        ).getImmutable();
//        this.g2_hat = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("g2_hat"))
//        ).getImmutable();
//        this.g3_hat = publicParametersGenerator.G1.newElementFromBytes(
//                TransformUtils.hexStrToByteArray(getMap.get("g3_hat"))
//        ).getImmutable();
//    }
}
