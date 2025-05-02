package BAS;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

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
import org.hyperledger.fabric.gateway.*;

public class BasServer {
    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "false");
    }

    private static final CloseableHttpClient httpClient = HttpClients.createDefault();
    public static final String proxyAuthenticatorAUrl = "http://192.168.10.3:8010";
    public static final String proxyAuthenticatorBUrl = "http://localhost:9010";
    public static PublicParametersGenerator parametersA;
    public static PublicKey signPkB;
    public static PublicKey signPkA;

    public static final String userId = "Org2User1";
    public static final String orgMspId = "Org2MSP";
    public static final String myChannel = "mychannel";
    public static final String myChaincodeName = "MyPaperContract";

    public static Gateway gateway;

    public static int kss =0;
    public static long idHideTime = 0;
    public static long authenticTime = 0;


    // helper function for getting connected to the gateway
    public static Gateway connect() throws Exception{
        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        // load a CCP
        Path networkConfigPath = Paths.get("connection-org2.yaml");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, userId).networkConfig(networkConfigPath).discovery(true);


        return builder.connect();
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


    public static void main(String[] args) throws Exception {

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

        // enrolls the admin and registers the user
        try {
            RegisterUser.main(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        HttpServer server = null;

        gateway = connect();

        // connect to the network and invoke the smart contract
        try {

            server = HttpServer.create(new InetSocketAddress(9200), 0);
            server.createContext("/verify", new VerifyHandler());
            server.createContext("/updateIdentityInfo", new UpdateIdentityInfoHandler());
            server.createContext("/queryIdentityInfo", new QueryIdentityInfoHandler());
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            System.out.println("VS2 in domain B is on!");

        }
        catch(Exception e){
            System.err.println(e);
        }

    }

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            long stime = System.currentTimeMillis();

            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> getMap = new HashMap<>();
            getMap = gson.fromJson(request, HashMap.class);

            boolean verify = true;

            //get the info from blockchain & do verification
            try {
                Network network = gateway.getNetwork(myChannel);

                Contract contract = network.getContract(myChaincodeName);

                byte[] queryInfo = contract.evaluateTransaction("QueryInfo", getMap.get("pId"));

                Map<String, String> getMap2 = gson.fromJson(new String(queryInfo), HashMap.class);

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
                    byte[] resultInfo = new byte[0];
                    if (verify){
                        //update the proof verify

                        resultInfo = contract.submitTransaction("UpdateState", getMap.get("pId"));
                    }
                    verify = verify && Boolean.parseBoolean(new String(resultInfo));
                }

            } catch (ContractException | TimeoutException | InterruptedException e) {
                e.printStackTrace();
            }
            Map<String,String> sendMap = new HashMap<>();
            sendMap.put("state", String.valueOf(verify));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();

            long etime = System.currentTimeMillis();
            idHideTime =etime-stime;
        }
    }

    private static class UpdateIdentityInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> getMap = new HashMap<>();
            getMap = gson.fromJson(request, HashMap.class);

            byte[] resultInfo = new byte[0];
            try {
                Network network = gateway.getNetwork(myChannel);

                Contract contract = network.getContract(myChaincodeName);

                getMap.put("verify","0");
                resultInfo = contract.submitTransaction("UpdateInfo", getMap.get("pId"), gson.toJson(getMap));
            } catch (ContractException | TimeoutException | InterruptedException e) {
                e.printStackTrace();
            }

            Map<String,String> sendMap = new HashMap<>();
            sendMap.put("state", new String(resultInfo));
            String response = gson.toJson(sendMap);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private static class QueryIdentityInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            FileOutputStream out = new FileOutputStream("./LOG/VS2.csv",true);

            PrintStream ps = new PrintStream(out);

            long stime = System.currentTimeMillis();

            String request = IOUtils.toString(exchange.getRequestBody());
            Gson gson = new GsonBuilder().create();
            Map<String, String> getMap = new HashMap<>();
            getMap = gson.fromJson(request, HashMap.class);

            byte[] queryInfo = new byte[0];
            try {
                Network network = gateway.getNetwork(myChannel);

                Contract contract = network.getContract(myChaincodeName);
                queryInfo = contract.evaluateTransaction("QueryInfo", getMap.get("pId"));
            } catch (ContractException e) {
                e.printStackTrace();
            }

            String response = new String(queryInfo);
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();

            long etime = System.currentTimeMillis();
            authenticTime = etime-stime;
            ps.println(kss+",Hide,"+idHideTime);
            ps.println(kss+",AU,"+authenticTime);
            kss++;
            ps.close();
            out.close();
        }
    }
}