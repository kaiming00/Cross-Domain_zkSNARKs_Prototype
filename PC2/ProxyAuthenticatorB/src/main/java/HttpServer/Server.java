package HttpServer;

import Parameters.PublicParametersGenerator;
import Parameters.SelfKeypair;
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
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
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
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public class Server {
    private static final CloseableHttpClient httpClient = HttpClients.createDefault();
    public static PublicParametersGenerator parametersA;
    public static final String proxyAuthenticatorAUrl = "http://192.168.10.3:8010";
    public static final String blockchainApplication2 = "http://localhost:9200";
    public static SelfKeypair selfKeypair;
    public static PublicKey signPkA;
    public static KeyPair keyPair;

    public static Map<String,String> userInfo = new HashMap<>();
    public static int kss =0;
    public static long prepareTime = 0;
    public static long authenticTime = 0;


    public static void main(String[] args) throws NoSuchAlgorithmException {
        Gson gson = new GsonBuilder().create();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        keyPair = kpGen.generateKeyPair();

        /*
        Get the public parameters & public key from proxyAuthenticatorA
         */
        Map<String,String> sendMap = new HashMap<>();
        sendMap.put("pk", TransformUtils.byteArrayToHexStr(keyPair.getPublic().getEncoded()));
        String sendStrJson = gson.toJson(sendMap);
        String keyStrJson = sendPost(proxyAuthenticatorAUrl+"/publicParameters",sendStrJson);
        Map<String, String> getMap = gson.fromJson(keyStrJson, HashMap.class);
        parametersA = new PublicParametersGenerator(getMap);

        selfKeypair = new SelfKeypair(parametersA.Z_phat,parametersA.g_solid);

        //get the public key of domainA for signature validation
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(
                TransformUtils.hexStrToByteArray(getMap.get("pk"))
        );
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            signPkA = keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }



        HttpServer server = null;
        try {
            server = HttpServer.create(new InetSocketAddress(9010), 0);
            server.createContext("/publicParametersB", new PublicParametersBHandler());
            server.createContext("/verifyRealIdentity", new VerifyRealIdentityHandler());
            server.createContext("/checkCrossAccessRequest", new CheckCrossAccessRequestHandler());

            server.setExecutor(Executors.newCachedThreadPool());

            server.start();
            System.out.println("ProxyAuthenticator in domain B is on!");


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
     * @Purpose verify the real identity of device A
     * @Operations
     * 1. get the info from ProxyAuthenticator A {sigma, certificate, evidence of identity, signature A}
     * 2. verify the signature A and Hash(certificate) == sigma
     * 3. if pass, create the credential (Cred)
     * 4. Sign, then send back to device A {sigma, Credential, SignatureB}
     */
    private static class VerifyRealIdentityHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

//            System.out.println("(Time cost test) ***************** AS B ID Negotiation (IN) start!");
            long stime = System.currentTimeMillis();
//            ps.println("ASB_IN_start, "+stime);

            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> recievedMap = new HashMap<>();
            recievedMap = gson.fromJson(request, HashMap.class);

            Element sigmaOfUser = parametersA.Z_phat.newElementFromBytes(TransformUtils.hexStrToByteArray(recievedMap.get("sigma"))).getImmutable();
            boolean v1 = sigmaOfUser.isEqual(
                    parametersA.hashSigmaFromString(recievedMap.get("certificate"))
            );

            //check the signature
            boolean v3 = false;
            try {
                Signature v = Signature.getInstance("SHA1withRSA");
                v.initVerify(signPkA);
                v.update(
                        TransformUtils.H1FromStringToL(sigmaOfUser.toString(),
                                recievedMap.get("certificate")+recievedMap.get("evidence")).toByteArray()
                );
                v3 = v.verify(
                        TransformUtils.hexStrToByteArray(recievedMap.get("signature"))
                );
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }

            boolean verify = v1 && v3;
            Map<String, String> sendMap = new HashMap<>();

            // Access verification, send (sigma, Cred, Y of pAB, SignatureB) to UserA
            /*
             * Actually, the process should be send directly to UserA, but to simplify the implementation through http
             * the process is changed to send (sigma, Cred, Y of pAB, SignatureB) to proxyAuthenticator A
             * and then pA add (pkB), then pass to UserA
             */
            if (verify){
                sendMap.put("sigma", TransformUtils.byteArrayToHexStr(sigmaOfUser.toBytes()));
                //Element, belong to G1
                Element Cred = PublicParametersGenerator.getCred(parametersA.g_hat,sigmaOfUser,selfKeypair.y).getImmutable();

                /*
                    store the {ID, info of ID, sigma, Cred} in local database.
                 */


                sendMap.put("Cred", TransformUtils.byteArrayToHexStr(
                        Cred.toBytes()
                ));

                //Element, belong to G2
                sendMap.put("YB", TransformUtils.byteArrayToHexStr(
                        selfKeypair.Y.toBytes()
                ));
                try {
                    Signature s = Signature.getInstance("SHA1withRSA");
                    s.initSign(keyPair.getPrivate());
                    s.update(TransformUtils.H1FromStringToL(
                            sigmaOfUser.toString(),
                            Cred.toString()+selfKeypair.Y.toString()
                            ).toByteArray()
                    );
                    byte[] signature = s.sign();
                    sendMap.put("signature", TransformUtils.byteArrayToHexStr(signature));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }
            }

            //send back the certificate verification result to ProxyAuthenticator A
            sendMap.put("state", String.valueOf(verify));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();

            long etime = System.currentTimeMillis();
            prepareTime = etime-stime;
        }
    }

    /**
     * @Author Chen Xing
     * @Purpose verify the rights for the device A's pseudonym to access the domain B
     * @Operations
     * 1. Verify the signature of the message {IDUserPK, Signature}
     * 2. Search the info of device A in blockchain with (IDUserPK)
     * 3. Check the state info of the device A, and create the response
     * 4. Use KeyUserPK encrypt the response
     * 5. send back to device A
     */
    private static class CheckCrossAccessRequestHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            FileOutputStream out = new FileOutputStream("./LOG/ASB.csv",true);

            PrintStream ps = new PrintStream(out);
            long stime = System.currentTimeMillis();

            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> getMap = new HashMap<>();
            getMap = gson.fromJson(request, HashMap.class);

            //check the signature
            boolean verify = false;

            PublicKey IDUserPk = null;
            //get the public key of domainA for signature validation
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(
                    TransformUtils.hexStrToByteArray(getMap.get("IDUserPk"))
            );
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                IDUserPk = keyFactory.generatePublic(pubKeySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }

            try {
                Signature v = Signature.getInstance("SHA1withRSA");
                v.initVerify(IDUserPk);
                v.update(
                        (getMap.get("pId")+getMap.get("Message")).getBytes()
                );
                verify = v.verify(
                        TransformUtils.hexStrToByteArray(getMap.get("signature"))
                );

            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }

            if (verify){
                // check the state in blockchain
                String getStrJson = sendPost(blockchainApplication2+"/queryIdentityInfo", request);
                getMap = gson.fromJson(getStrJson, HashMap.class);

                //getMap.get("verify")出错
                int result = Integer.valueOf(getMap.get("verify"));

                System.out.println("query number: "+result);
                if (result>=1){
                    verify = true;
                }else{
                    verify = false;
                }
            }

            Map<String,String> sendMap = new HashMap<>();

            //send back the certificate verification result to ProxyAuthenticator A
            sendMap.put("state", String.valueOf(verify));
            ps.println(kss+","+String.valueOf(verify));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();

            long etime = System.currentTimeMillis();
            authenticTime = etime-stime;
            ps.println(kss+",Prepare,"+prepareTime);
            ps.println(kss+",AU,"+authenticTime);
            kss++;
            ps.close();
            out.close();
        }
    }

    private static class PublicParametersBHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Gson gson = new GsonBuilder().create();
            Map<String,String> sendMap = new HashMap<>();
            sendMap.put("pk", TransformUtils.byteArrayToHexStr(keyPair.getPublic().getEncoded()));

            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

}
