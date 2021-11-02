import java.math.BigInteger;


public class Main {
    public static void main(String[] args) {
        //RSA.Key[] keyPairA = RSA.generateKeyPair(128);
        //RSA.Key publicKeyA = keyPairA[0];
        //RSA.Key privateKeyA = keyPairA[1];

        RSA.Key[] keyPairB = RSA.generateKeyPair(128);
        RSA.Key publicKeyB = keyPairB[0];
        RSA.Key privateKeyB = keyPairB[1];

        System.out.println(publicKeyB.getBitLength());

        String message = "Hallo";
        System.out.println(message.getBytes().length * 8);

        BigInteger encryptedMessage = RSA.encrypt(message, publicKeyB);
        //BigInteger signature = RSA.sign(message, "SHA-256", privateKeyA);

        String decrypted = RSA.decrypt(encryptedMessage, privateKeyB);
        //String hashOfMessage = RSA.decrypt(signature, publicKeyA);

        System.out.println("encrypted: " + encryptedMessage);
        System.out.println("decrypted: " + decrypted);
        //System.out.println(hashOfMessage);
        System.out.println(RSA.hash(message, "SHA-256"));

    }

}