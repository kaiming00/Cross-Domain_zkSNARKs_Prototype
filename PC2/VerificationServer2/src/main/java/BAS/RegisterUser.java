package BAS;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import org.hyperledger.fabric.gateway.Identities;
import org.hyperledger.fabric.gateway.Identity;


public class RegisterUser {

    public static final String userId = "Org2User1";
    public static final String orgMspId = "Org2MSP";

    public static void main(String[] args) throws Exception {

        // Load the certPEM file, keyPEM file
        String certPEM = Files.readString(Paths.get("../network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/signcerts/User1@org2.example.com-cert.pem"));
        String keyPEM = Files.readString(Paths.get("../network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore/priv_sk"));

        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

        // Check to see if we've already enrolled the user.
        if (wallet.get(userId) != null) {
            System.out.println("An identity for the user \""+userId+"\" already exists in the wallet");
            return;
        }

        // Register the user, enroll the user, and import the new identity into the wallet.
        X509Certificate x509Certificate = Identities.readX509Certificate(certPEM);
        PrivateKey privateKey = Identities.readPrivateKey(keyPEM);
        Identity user = Identities.newX509Identity(orgMspId,x509Certificate, privateKey);
        wallet.put(userId, user);
        System.out.println("Successfully enrolled user \""+userId+"\" and imported it into the wallet");
    }

}
