package HttpServer;

import PPIM.Parameters.PublicParametersGenerator;
import PPIM.zkSNARKs.Proof;
import PPIM.zkSNARKs.ProofGenerator;
import Utils.TransformUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;

public class Server {

    private static final CloseableHttpClient httpClient = HttpClients.createDefault();

    public static PublicParametersGenerator publicParametersGenerator = new PublicParametersGenerator();
    public static final String proxyAuthenticatorBUrl = "http://192.168.10.4:9010";
    public static final String verificationServer1Url = "http://localhost:8200";
    public static final String verificationServer2Url = "http://192.168.10.4:9200";

    public static Map<String,String> userInfo = new HashMap<>();
    public static Map<String,String> crossInfo = new HashMap<>();
    public static KeyPair keyPair;
    public static PublicKey signPkB;

    public static String verificationResult1 = null;
    public static String verificationResult2 = null;

    public static String certificate = "";

    public static int kss = 0;
    public static long prepareTime = 0;
    public static long idHideTime = 0;

    public static void main(String[] args) throws NoSuchAlgorithmException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        keyPair = kpGen.generateKeyPair();


        //step1: generate the public parameters

        HttpServer server = null;
        try {
            server = HttpServer.create(new InetSocketAddress(8010), 0);
            server.createContext("/publicParameters", new PublicParametersHandler());
            server.createContext("/innerVerify", new InnerVerifyAHandler());
            server.createContext("/crossVerify", new CrossVerifyAHandler());
            server.createContext("/identityHide", new IdentityHideHandler());

            server.setExecutor(Executors.newCachedThreadPool());

            server.start();
            System.out.println("ProxyAuthenticator in domain A is on!");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String sendGet(String url) {
        HttpGet httpGet = new HttpGet(url);
        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpGet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        String result = null;
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                result = EntityUtils.toString(entity);
            }
        } catch (ParseException | IOException e) {
            e.printStackTrace();
        } finally {
            try {
                response.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    public static String sendPost(String url, String jsonStr){
        String result =null;
        CloseableHttpResponse response = null;

        StringEntity stringEntity = new StringEntity(jsonStr, ContentType.parse("application/json"));

        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(stringEntity);

        try {
            response = httpClient.execute(httpPost);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            HttpEntity entity = response.getEntity();
            if (entity!=null){
                result = EntityUtils.toString(entity);
            }
        }catch (ParseException | IOException e){
            e.printStackTrace();
        }finally {
            try {
                response.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * @Author Chen Xing
     * @Purpose Inner-domain verify to deviceA (ProxyAuthenticator as a PKI's CA)
     * @Operations
     * 1. get the identity info send by device A.
     * 2. verify the identity of device A and give the certificate.
     * 3. respond to device A.
     */
    private static class InnerVerifyAHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> recievedMap = new HashMap<>();
            recievedMap = gson.fromJson(request, HashMap.class);

            //verify the identity and then give the certificate to userA
            boolean state = true;
            Map<String, String> sendMap = new HashMap<>();

            certificate = recievedMap.get("info")+System.currentTimeMillis();
            userInfo.put(recievedMap.get("name"), certificate);
            sendMap.put("certificate",certificate);

            sendMap.put("state",String.valueOf(state));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    /**
     * @Author Chen Xing
     * @Purpose Cross-domain verify to deviceA (Device A of Domain A want to visit Domain B)
     * @Operations
     * 1. do Hash(certificate) = sigma .
     * 2. sign the message(sigma|certificate|evidence of identity) with private key of domain A .
     * 3. send the message and signature to ProxyAuthenticator B in Domain B.
     */
    private static class CrossVerifyAHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            long stime = System.currentTimeMillis();

            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> recievedMap = new HashMap<>();
            recievedMap = gson.fromJson(request, HashMap.class);

            String recievedCertificate = recievedMap.get("certificate");

            //verify the validity of the certificate of UserA
            //compared with the local certificate stored by ProxyAuthenticatorA
            boolean verify = false;
            if (recievedCertificate.equals(userInfo.get(recievedMap.get("name")))){
                verify = true;
            }

            Map<String, String> sendMap = new HashMap<>();
            if (verify){
                //do Hash(certificate) = sigma
                Element sigma = publicParametersGenerator.hashSigmaFromString(recievedCertificate);

                //sign the message(sigma|certificate|evidence of identity) with private key of domain A . y
                try {
                    Signature s = Signature.getInstance("SHA1withRSA");
                    s.initSign(keyPair.getPrivate());
                    s.update(TransformUtils.H1FromStringToL(sigma.toString(),recievedCertificate+"evidence of identity").toByteArray());
                    byte[] signature = s.sign();

                    //Element, belong to Z_phat
                    sendMap.put("sigma", TransformUtils.byteArrayToHexStr(sigma.toBytes()));
                    sendMap.put("certificate", recievedCertificate);
                    sendMap.put("evidence", "evidence of identity");
                    sendMap.put("signature", TransformUtils.byteArrayToHexStr(signature));
                    String sendStrJson = gson.toJson(sendMap);
                    //send user A's info to proxyAuthenticator B
                    //get the (sigma, Cred, Y of pAB, SignatureB) from proxyAuthenticator B
                    String getStrJson = sendPost(proxyAuthenticatorBUrl+"/verifyRealIdentity", sendStrJson);
                    recievedMap = gson.fromJson(getStrJson,HashMap.class);

                    crossInfo.put(recievedCertificate,getStrJson);
                    sendMap = new HashMap<>();
                    sendMap.put("state",recievedMap.get("state"));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }
            }
            //send back the verification result from pB to User A
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();

            long etime = System.currentTimeMillis();
            prepareTime = etime-stime;
        }
    }

    private static class PublicParametersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Gson gson = new GsonBuilder().create();
            String request = IOUtils.toString(exchange.getRequestBody());
            //get public key from proxyAuthenticatorB
            Map<String, String> getMap = gson.fromJson(request, HashMap.class);
            if (getMap.containsKey("pk")){
                //get the public key of domainB for signature validation
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(
                        TransformUtils.hexStrToByteArray(getMap.get("pk"))
                );
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    signPkB = keyFactory.generatePublic(pubKeySpec);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    e.printStackTrace();
                }
            }

            Map<String,String> sendMap = TransformUtils.publicparametersToMap(publicParametersGenerator);
            sendMap.put("pk", TransformUtils.byteArrayToHexStr(keyPair.getPublic().getEncoded()));

            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private static class IdentityHideHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            FileOutputStream out = new FileOutputStream("./LOG/ASA.csv",true);
            PrintStream ps = new PrintStream(out);

            Gson gson = new GsonBuilder().create();
            String request = IOUtils.toString(exchange.getRequestBody());
            //get public key from proxyAuthenticatorB
            Map<String, String> getMap = gson.fromJson(request, HashMap.class);
            String recievedCertificate = getMap.get("certificate");
            String pId = getMap.get("pId");

            long stime = System.currentTimeMillis();
            //verify the validity of the certificate of UserA
            //compared with the local certificate stored by ProxyAuthenticatorA
            boolean verify = false;
            if (recievedCertificate.equals(userInfo.get(getMap.get("name")))){
                verify = true;
            }
            Map<String, String> sendMap = new HashMap<>();
            Element orignY = publicParametersGenerator.Y;
            boolean accessToB = false;
            if (verify){
                String userLicenseInfo = crossInfo.get(recievedCertificate);
                Map<String,String> userLicenseMap = gson.fromJson(userLicenseInfo, HashMap.class);


                Element sigma = publicParametersGenerator.Z_phat.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(userLicenseMap.get("sigma"))
                ).getImmutable();
                Element Cred = publicParametersGenerator.G1.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(userLicenseMap.get("Cred"))
                ).getImmutable();
                Element YB = publicParametersGenerator.G2.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(userLicenseMap.get("YB"))
                ).getImmutable();

                publicParametersGenerator.Y = YB;

                // distribute the secret key
                ArrayList<Element> yi = new ArrayList<>();
                ArrayList<Element> Yi = new ArrayList<>();
                //generate {y1,y2,y3} & {Y1,Y2,Y3}
                Element y1 = publicParametersGenerator.Z_phat.newRandomElement().getImmutable();
                yi.add(y1);
                Element y2 = publicParametersGenerator.Z_phat.newRandomElement().getImmutable();
                yi.add(y2);
                Element y3 = publicParametersGenerator.Z_phat.newRandomElement().getImmutable();
                yi.add(y3);

                Element Y1 = publicParametersGenerator.g.powZn(y1).getImmutable();
                Yi.add(Y1);
                Element Y2 = publicParametersGenerator.g.powZn(y2).getImmutable();
                Yi.add(Y2);
                Element Y3 = publicParametersGenerator.g.powZn(y3).getImmutable();
                Yi.add(Y3);

                ArrayList<PolyElement> fxs = new ArrayList<>();
                ArrayList<ArrayList<BigInteger>> ss = new ArrayList<>();
                ArrayList<ArrayList<Element>> Dks = new ArrayList<>();

                //generate secret shadow of yi
                //the number of VS is vsN = 2 (N=2)
                int vsN = 2;
                for (int i=0;i<3;i++) {
                    //generate polynominal for yi
                    fxs.add(TransformUtils.generatePolynominalForyi(vsN, publicParametersGenerator.Z_phat, yi.get(i)));
                    //generate si for yi
                    ss.add(TransformUtils.generateSiForyi(fxs.get(i), vsN));
                    //generate Dk for yi
                    Dks.add(TransformUtils.generateDkForyi(fxs.get(i), publicParametersGenerator.g, vsN));
                }

                // customer calculate the witness (a,d)
                // At the  beginning, the revocation list is empty
                // therefore c = g_hat, d = 1, a = [g_hat.pow(-d)].pow(1/(sigma+tao))
                Element c = publicParametersGenerator.g_hat.getImmutable();
                BigInteger d = BigInteger.ONE;
                Element a = publicParametersGenerator.g_hat.pow(d.multiply(BigInteger.valueOf(-1L))).powZn(sigma.add(publicParametersGenerator.tao).mul(-1)).getImmutable();

                //generate r,u,v,w
                BigInteger r = TransformUtils.generateR(publicParametersGenerator.N);
                Element u = TransformUtils.generateU(publicParametersGenerator.g,r).getImmutable();
                Element w = TransformUtils.generateW(Y1, r, sigma, publicParametersGenerator.N,publicParametersGenerator.Z_phat).getImmutable();
                Element v = TransformUtils.generateV(Y2,Y3,u,w,r).getImmutable();

                ProofGenerator proofGenerator = new ProofGenerator(publicParametersGenerator.pairing);
                Proof pai = proofGenerator.generateProof(r,
                        sigma, Cred, a,d , Y1, Y2, Y3,
                        u,w,v, publicParametersGenerator);

                sendMap = TransformUtils.proofInfoToMap(pId,
                        u,w,v,pai,Y1,Y2,Y3);

                String sendStrJson = gson.toJson(sendMap);
                String getStrJson = sendPost("http://localhost:8200/updateIdentityInfo",sendStrJson);

                getMap = gson.fromJson(getStrJson,HashMap.class);

                accessToB = Boolean.valueOf(getMap.get("state"));

                if (!accessToB){
                    System.out.println("Blockchain update false!");
                }

                Map<String,String> sendMap1 = new HashMap<>();
                Map<String,String> sendMap2 = new HashMap<>();
                sendMap1.put("pId", pId);
                sendMap2.put("pId", pId);
                sendMap1.put("vsN", String.valueOf(vsN));
                sendMap2.put("vsN", String.valueOf(vsN));
                for (int i=0;i<3;i++){
                    for (int j=0;j<Dks.get(i).size();j++){
                        sendMap1.put("D"+i+"_"+j, TransformUtils.byteArrayToHexStr(Dks.get(i).get(j).toBytes()));
                        sendMap2.put("D"+i+"_"+j, TransformUtils.byteArrayToHexStr(Dks.get(i).get(j).toBytes()));
                    }
                    for (int j=0;j<ss.get(i).size();j++){
                        if (j==0){
                            //si for vs1
                            sendMap1.put("s"+i, String.valueOf(ss.get(i).get(j)));
                        }else{
                            //si for vs2
                            sendMap2.put("s"+i, String.valueOf(ss.get(i).get(j)));
                        }
                    }
                }

                String[] sendStrJsons = {
                        gson.toJson(sendMap1),
                        gson.toJson(sendMap2)
                };
                String[] urlToPost = {
                        verificationServer1Url+"/verify",
                        verificationServer2Url+"/verify"
                };
                PostThread[] threads = new PostThread[urlToPost.length];
                for (int i=0; i<threads.length; i++){
                    StringEntity stringEntity = new StringEntity(sendStrJsons[i], ContentType.parse("application/json"));
                    HttpPost httpPost = new HttpPost(urlToPost[i]);
                    httpPost.setEntity(stringEntity);
                    threads[i] = new PostThread(httpClient, httpPost, i+1);
                }
                for (int j=0;j<threads.length;j++){
                    threads[j].start();
                }
                for (int k=0;k<threads.length;k++){
                    try {
                        threads[k].join();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                Map<String, String> getMap1 = gson.fromJson(verificationResult1,HashMap.class);
                ps.println("Vs1 : "+getMap1.get("state"));
                Map<String, String> getMap2 = gson.fromJson(verificationResult2,HashMap.class);
                ps.println("Vs2 : "+getMap2.get("state"));


                // verification result true >= 1/2 , asccessToB = true
                accessToB = Boolean.valueOf(getMap1.get("state"))
                        || Boolean.valueOf(getMap2.get("state"));
            }

            sendMap = new HashMap<>();
            sendMap.put("state", String.valueOf(accessToB));
            publicParametersGenerator.Y = orignY;

            long etime = System.currentTimeMillis();
            idHideTime = etime-stime;

            ps.println(kss+",Prepare,"+prepareTime);
            ps.println(kss+",Hide,"+idHideTime);
            kss++;
            ps.close();
            out.close();
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    public static class PostThread extends Thread{
        private final HttpPost httpPost;
        private final CloseableHttpClient httpClient;
        private int flag;

        public PostThread(CloseableHttpClient httpClient, HttpPost httpPost, int flag){
            this.httpPost = httpPost;
            this.httpClient = httpClient;
            this.flag = flag;
        }

        @Override
        public void run() {
            super.run();
            try {
                CloseableHttpResponse response = httpClient.execute(httpPost);
                HttpEntity entity = response.getEntity();
                if (entity!=null){
                    if (flag == 1)
                        verificationResult1 = EntityUtils.toString(entity);
                    else
                        verificationResult2 = EntityUtils.toString(entity);
                }
                response.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
