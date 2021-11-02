import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class RSA {

    public static String hash(final String base, final String instance) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(instance);
            final byte[] hash = digest.digest(base.getBytes("UTF-8"));
            final StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                final String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static BigInteger sign(final String message, final String hashFunction, final RSA.Key signerPrivateKey) {
        return encrypt(hash(message, hashFunction), signerPrivateKey);
    }

    public static BigInteger encrypt(final String message, final RSA.Key key) {
        return modPow(new BigInteger(message.getBytes()), key);
    }

    public static String decrypt(final BigInteger encryptedMessage, final RSA.Key key) {
        return new String(modPow(encryptedMessage, key).toByteArray());
    }

    public static BigInteger modPow(final BigInteger m, final RSA.Key key) throws IllegalArgumentException {
        if (m.compareTo(key.getN()) != -1)
            throw new IllegalArgumentException("Integer m must be smaller than the modulus N");
        return m.modPow(key.getExponent(), key.getN());
    }

    /**
     * This method generates a key pair with a specified key bit length
     * 
     * @param bitLength The key bit length
     * @return An array that contains both keys
     */
    public static RSA.Key[] generateKeyPair(final int bitLength) {
        Random PRNG = new Random();
        // Generate two large random prime numbers p and q
        BigInteger p = getRandomPrime(bitLength / 2, PRNG);
        BigInteger q = getRandomPrime(bitLength / 2, PRNG);
        // Make sure p is not equal to q
        while (q.equals(p))
            q = getRandomPrime(bitLength / 2, PRNG);

        System.out.println("p = " + p);
        System.out.println("q = " + q);

        // Compute n as the product of p and q
        BigInteger n = p.multiply(q);
        System.out.println("n = p * q = " + n);
        // Compute phi
        BigInteger phi = computePhi(p, q);
        System.out.println("phi = " + phi);
        // Generate e
        BigInteger e = generateE(phi, n.bitLength(), PRNG);
        System.out.println("e = " + e);
        // Compute d
        BigInteger d = computeD(e, phi);
        System.out.println("d = " + d);

        return new RSA.Key[] { new RSA.Key(e, n), new RSA.Key(d, n) };
    }

    /**
     * This method returns a natural number d such that e * d mod phi = 1
     * 
     * @param e
     * @param phi
     * @return the modular inverse
     */
    private static BigInteger computeD(final BigInteger e, final BigInteger phi) {
        return e.modInverse(phi);
    }

    /**
     * This method finds an int e such that e is coprime to phi(n) and 1 < e <
     * phi(n)
     * 
     * @param phi
     * @param bitLength
     * @param PRNG
     * @return
     */
    private static BigInteger generateE(final BigInteger phi, final int bitLength, final Random PRNG) {
        BigInteger e;
        do {
            e = new BigInteger(bitLength, PRNG);
            // e = getRandomPrime(bitLength);
        } while (e.compareTo(phi) != -1 || !getGCD(e, phi).equals(BigInteger.ONE));
        return e;
    }

    /**
     * This method computes the Euler's totient function with phi(prime1 * prime2) =
     * (prime1 - 1) * (prime2 - 1)
     * 
     * @param prime1 First prime number
     * @param prime2 Second prime number
     * @return The Number Phi which is is the number of coprime natural numbers that
     *         are not larger than the product of both prime numbers (prime1 *
     *         prime2)
     */
    private static BigInteger computePhi(final BigInteger prime1, final BigInteger prime2) {
        return (prime1.subtract(BigInteger.ONE)).multiply(prime2.subtract(BigInteger.ONE));
    }

    /**
     * This method generates a random prime number with a specified byte length
     * 
     * @param bitLength The byte length of the prime number to be generated
     * @param PRNG      The Pseudorandom Number Generatur (PRNG) that is used to
     *                  generate the number
     * @return The generated prime number
     */
    private static BigInteger getRandomPrime(final int bitLength, final Random PRNG) {
        return BigInteger.probablePrime(bitLength, PRNG);
    }

    /**
     * This method return the greatest common divisor (GCD) of two numbers a and b
     * 
     * @param a First number
     * @param b Second number
     * @return The greatest common divisor of a and b
     */
    private static BigInteger getGCD(final BigInteger a, final BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return a;
        } else {
            return getGCD(b, a.mod(b));
        }
    }

    /**
     * This is a class for a RSA key. It can be either a public or a private key
     */
    static class Key {

        private final BigInteger exponent;
        private final BigInteger n;

        public Key(BigInteger exponent, BigInteger n) {
            this.exponent = exponent;
            this.n = n;
        }

        public BigInteger getExponent() {
            return this.exponent;
        }

        public BigInteger getN() {
            return this.n;
        }

        public long getBitLength() {
            return this.n.bitLength();
        }

        @Override
        public String toString() {
            return "RSA.Key(" + exponent + ", " + n + ")";
        }
    }
}
