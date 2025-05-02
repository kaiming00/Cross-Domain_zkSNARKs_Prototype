package HttpServer;

import PPIM.Parameters.PublicParametersGenerator;
import PPIM.zkSNARKs.Proof;
import Utils.TransformUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import it.unisa.dia.gas.jpbc.Element;
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

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private static final CloseableHttpClient httpClient = HttpClients.createDefault();
    public static final String proxyAuthenticatorAUrl = "http://localhost:8010";
    public static final String proxyAuthenticatorBUrl = "http://localhost:9010";
    public static final String blockchainApplication1 = "http://192.168.23.132:3000";
    public static PublicParametersGenerator parametersA;
    public static PublicKey signPkB;
    public static PublicKey signPkA;

    public static void main(String[] args) {
        Gson gson = new GsonBuilder().create();

        Map<String,String> sendMap = new HashMap<>();
        sendMap.put("state", String.valueOf(true));
        String sendStrJson = gson.toJson(sendMap);
        String getStrJson = sendPost(proxyAuthenticatorAUrl+"/publicParameters",sendStrJson);
        Map<String,String> getMap = gson.fromJson(getStrJson, HashMap.class);
        parametersA = new PublicParametersGenerator(getMap);

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

        getStrJson = sendGet(proxyAuthenticatorBUrl+"/publicParametersB");
        getMap = gson.fromJson(getStrJson,HashMap.class);

        //get the public key of domainB for signature validation
        pubKeySpec = new X509EncodedKeySpec(
                TransformUtils.hexStrToByteArray(getMap.get("pk"))
        );
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            signPkB = keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        HttpServer server = null;
        try {
            server = HttpServer.create(new InetSocketAddress(9200), 0);
            server.createContext("/verify", new VerifyHandler());
            server.start();
            System.out.println("VS2 in domain B is on!");
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

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> getMap = new HashMap<>();
            getMap = gson.fromJson(request, HashMap.class);

            boolean verify = true;

            //get the info from blockchain
            String getStrJson = sendPost(blockchainApplication1+"/queryIdentityInfo", request);
            Map<String, String> getMap2 = gson.fromJson(getStrJson, HashMap.class);

            Element Y1 = parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("Y1"))).getImmutable();
            Element Y2 = parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("Y2"))).getImmutable();
            Element Y3 = parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("Y3"))).getImmutable();

            int vsN = Integer.valueOf(getMap.get("vsN"));
            int vsT = vsN/2+1;

            //verify the shadow of y1
            Element gs1 = parametersA.g.pow(
                    new BigInteger(getMap.get("s0"))
            ).getImmutable();
            Element mulResult1 = parametersA.Z_n2.newElement().setToOne().getImmutable();
            for (int k=0;k<vsT-1;k++){
                Element temp = parametersA.Z_n2.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(getMap.get("D0"+"_"+k))
                ).getImmutable();
                mulResult1 = mulResult1.duplicate().mul(temp.pow(BigInteger.valueOf((long)Math.pow(2, k+1))));
            }
            mulResult1 = mulResult1.duplicate().mul(Y1);


            //verify the shadow of y2
            Element gs2 = parametersA.g.pow(
                    new BigInteger(getMap.get("s1"))
            ).getImmutable();
            Element mulResult2 = parametersA.Z_n2.newElement().setToOne().getImmutable();
            for (int k=0;k<vsT-1;k++){
                Element temp = parametersA.Z_n2.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(getMap.get("D1"+"_"+k))
                ).getImmutable();
                mulResult2 = mulResult2.duplicate().mul(temp.pow(BigInteger.valueOf((long)Math.pow(2, k+1))));
            }
            mulResult2 = mulResult2.duplicate().mul(Y2);



            //verify the shadow of y3
            Element gs3 = parametersA.g.pow(
                    new BigInteger(getMap.get("s2"))
            ).getImmutable();
            Element mulResult3 = parametersA.Z_n2.newElement().setToOne().getImmutable();
            for (int k=0;k<vsT-1;k++){
                Element temp = parametersA.Z_n2.newElementFromBytes(
                        TransformUtils.hexStrToByteArray(getMap.get("D2"+"_"+k))
                ).getImmutable();
                mulResult3 = mulResult3.duplicate().mul(temp.pow(BigInteger.valueOf((long)Math.pow(2, k+1))));
            }
            mulResult3 = mulResult3.duplicate().mul(Y3);



            verify = gs1.isEqual(mulResult1) && gs2.isEqual(mulResult2) && gs3.isEqual(mulResult3);

            if (verify) {
                //check the proof of User/Device A
                Proof proof = new Proof(getMap2, parametersA);
                //assume the revoke list is empty, c is the original value
                Element c = parametersA.g_hat.getImmutable();

                verify = TransformUtils.checkProof(c, parametersA,
                        Y1, Y2, Y3,
                        parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("u"))).getImmutable(),
                        parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("w"))).getImmutable(),
                        parametersA.Z_n2.newElementFromBytes(TransformUtils.hexStrToByteArray(getMap2.get("v"))).getImmutable(),
                        proof);

                if (verify){
                    //update the proof verify
                    getStrJson = sendPost(blockchainApplication1+"/updateState", request);
                    getMap = gson.fromJson(getStrJson,HashMap.class);
                    verify = Boolean.valueOf(getMap.get("state"));
                }
            }

            Map<String,String> sendMap = new HashMap<>();
            sendMap.put("state", String.valueOf(verify));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
