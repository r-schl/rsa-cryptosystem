import java.math.BigInteger;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {

        if (args[0].equals("-gen")) {
            int bitLength = Integer.parseInt(args[1]);
            RSA.Key[] keyPair = RSA.generateKeyPair(bitLength);
            System.out.println("Keys with the bitlength of " + keyPair[0].getBitLength() + " were geerated. ");
            System.out.println(keyPair[0]);
            System.out.println();
            System.out.println(keyPair[1]);
        }

        if (args[0].equals("-enc")) {
            BigInteger n = new BigInteger(args[2]);
            BigInteger e = new BigInteger(args[3]);
            RSA.Key key = new RSA.Key(n, e);

            BigInteger plaintext = new BigInteger(args[1].getBytes());
            BigInteger ciphertext = RSA.encrypt(plaintext, key);
            System.out.println();
            System.out.println("Ciphertext = " + ciphertext);
        }

        if (args[0].equals("-dec")) {

            BigInteger n = new BigInteger(args[2]);
            BigInteger d = new BigInteger(args[3]);
            RSA.Key key = new RSA.Key(n, d);

            BigInteger ciphertext = new BigInteger(args[1]);
            BigInteger plaintext = RSA.decrypt(ciphertext, key);
            String decryptedStr = new String(plaintext.toByteArray());

            System.out.println();
            System.out.println("Decrypted Message = \"" + decryptedStr + "\"");
        }
    }

}