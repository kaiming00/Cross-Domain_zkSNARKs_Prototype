package HttpServer;


import Utils.TransformUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.http.HttpEntity;
import org.apache.http.ParseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.*;

import java.security.*;

import java.util.HashMap;
import java.util.Map;

public class Server {
    private static final CloseableHttpClient httpClient = HttpClients.createDefault();

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        PrintStream ps = new PrintStream(new FileOutputStream("./LOG/EntityA.csv",true));

        for (int ks=0;ks<202;ks++){
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(1024);
            KeyPair IDUserKeyPair = kpGen.generateKeyPair();

            long prepareTime = 0;
            long idHideTime = 0;
            long authenticTime =0;

            Map<String, String> sendMap = new HashMap<>();
            Gson gson = new GsonBuilder().create();

            //get the public parameters & public key from proxyAuthenticatorA
            /*
             *  step1: send identity info to inner domain CA & get the certificate
             */
            String identityInfo = "this is my information.";
            String name = String.valueOf(System.currentTimeMillis());
            sendMap.put("name",name);
            sendMap.put("info", identityInfo);
            String sendStrJson = gson.toJson(sendMap);
            String getStrJson = sendPost("http://192.168.20.2:8010/innerVerify", sendStrJson);
            Map<String, String> getMap = gson.fromJson(getStrJson, HashMap.class);

            if (!Boolean.parseBoolean(getMap.get("state"))){
                return;
            }

            String certificate = getMap.get("certificate");

        /*
        Ask for cross domain licensing
         */
            long stime = System.currentTimeMillis();
            sendMap = new HashMap<>();
            sendMap.put("name",name);
            sendMap.put("certificate", certificate);
            sendStrJson = gson.toJson(sendMap);
            getStrJson = sendPost("http://192.168.20.2:8010/crossVerify",sendStrJson);

            getMap = gson.fromJson(getStrJson,HashMap.class);
            boolean pAverifyResult = Boolean.parseBoolean(getMap.get("state"));
            System.out.println("Cross licensing result is : "+pAverifyResult);
            long etime = System.currentTimeMillis();
            prepareTime = etime-stime;

        /*
        Ask for identity hide
         */
            stime = System.currentTimeMillis();
            sendMap = new HashMap<>();
            String pId = "Fake name"+System.currentTimeMillis();
            sendMap.put("name",name);
            sendMap.put("pId",pId);
            sendMap.put("certificate", certificate);
            sendStrJson = gson.toJson(sendMap);
            getStrJson = sendPost("http://192.168.20.2:8010/identityHide",sendStrJson);

            getMap = gson.fromJson(getStrJson,HashMap.class);

            boolean pIdResult = Boolean.parseBoolean(getMap.get("state"));
            if (!pIdResult) {
                System.out.println("Fake name generate wrong!");
                return;
            }
            etime = System.currentTimeMillis();
            idHideTime = etime-stime;
        /*
        Cross domain Authentication
         */
            stime = System.currentTimeMillis();
            sendMap = new HashMap<>();
            String keyInfo = "new Message";
            sendMap.put("pId", pId);
            sendMap.put("Message", keyInfo);
            sendMap.put("IDUserPk",
                    TransformUtils.byteArrayToHexStr(IDUserKeyPair.getPublic().getEncoded()));
            try {
                Signature s = Signature.getInstance("SHA1withRSA");
                s.initSign(IDUserKeyPair.getPrivate());
                s.update(
                        (pId+keyInfo).getBytes()
                );
                byte[] signature = s.sign();
                sendMap.put("signature", TransformUtils.byteArrayToHexStr(signature));
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }
            sendStrJson = gson.toJson(sendMap);
            getStrJson = sendPost("http://192.168.30.2:9010/checkCrossAccessRequest", sendStrJson);
            getMap = gson.fromJson(getStrJson, HashMap.class);
            boolean accessToB = Boolean.valueOf(getMap.get("state"));

            if (!accessToB){
                System.out.println("access don't succeed!");
                return;
            }

            System.out.println("Got domain B permission!");
            etime =System.currentTimeMillis();
            authenticTime = etime-stime;
            ps.println(ks+",Prepare,"+prepareTime);
            ps.println(ks+",Hide,"+idHideTime);
            ps.println(ks+",AU,"+authenticTime);
        }



        ps.close();
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

}
