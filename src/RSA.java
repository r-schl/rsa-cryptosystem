import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class RSA {

    /**
     * This method calculates the hash of a integer number
     * 
     * @param base         data to be hashed
     * @param hashInstance hash function to be used
     * @return hash (decimal representation)
     */
    public static BigInteger hash(BigInteger base, final String hashInstance) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(hashInstance);
            final byte[] hash = digest.digest(base.toByteArray());
            final StringBuilder hexStringBuilder = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                final String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1)
                    hexStringBuilder.append('0');
                hexStringBuilder.append(hex);
            }
            return new BigInteger(hexStringBuilder.toString().getBytes());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * This method calculates a signature for specified bytes.
     * 
     * @param plaintext        plaintext (decimal representation)
     * @param hashInstance     A hash function that should be used
     * @param signerPrivateKey The private key of the signer
     * @return The signature (decimal representation)
     */
    public static BigInteger sign(final BigInteger plaintext, final String hashInstance,
            final RSA.Key signerPrivateKey) {
        return encrypt(hash(plaintext, hashInstance), signerPrivateKey);
    }

    public static BigInteger encrypt(final BigInteger plaintext, final RSA.Key key) {
        // TODO: padding
        BigInteger m = plaintext;
        BigInteger c = modPow(m, key);
        return c;
    }

    public static BigInteger decrypt(final BigInteger ciphertext, final RSA.Key key) {
        // TODO: reverse padding
        BigInteger c = ciphertext;
        BigInteger m = modPow(c, key);
        return m;
    }

    /**
     * This method encrypts or decrypts a number (base) with a RSA key:
     * base ^ key.exponent mod key.n
     * 
     * @param base The number that should be encrypted or decrypted
     * @param key  The RSA key
     * @return
     * @throws IllegalArgumentException
     */
    private static BigInteger modPow(final BigInteger base, final RSA.Key key) throws IllegalArgumentException {
        if (base.compareTo(key.getN()) != -1)
            throw new IllegalArgumentException("Integer base must be smaller than the modulus N");
        return base.modPow(key.getExponent(), key.getN());
    }

    /**
     * This method generates interchangeable public and secret keys with a specified
     * key bit length
     * 
     * @param bitLength The key bit length
     * @return An array that contains both keys
     */
    public static RSA.Key[] generateKeyPair(final int bitLength) {

        Random PRNG;
        BigInteger p;
        BigInteger q;
        BigInteger n;

        do {
            PRNG = new Random();
            // Generate two large random prime numbers p and q.
            // Note that when multiplying two numbers p and q of the same bit length L, the
            // product has a bit length of 2L or 2L-1. So to achieve a given bit length for
            // n, both p and q must be about half as long as the given bit length.

            p = getRandomPrime((int) Math.floor((float) bitLength / 2), PRNG);
            q = getRandomPrime((int) Math.ceil((float) bitLength / 2), PRNG);
            // Make sure p is not equal to q.
            while (q.equals(p))
                q = getRandomPrime((int) Math.ceil((float) bitLength / 2), PRNG);

            // Compute n as the product of p and q.
            n = p.multiply(q);
            // If n does not have the specified length, calculate again.
        } while (n.bitLength() != bitLength);

        // Compute phi(n)
        // https://en.wikipedia.org/wiki/Euler%27s_totient_function
        BigInteger phi = computePhi(p, q);
        // Generate a random integer e such that e is coprime to phi(n) and 1 < e <
        // phi(n)
        BigInteger e = generateE(phi, n.bitLength(), PRNG);
        // Compute d such that e * d mod phi(n) = 1
        // https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
        BigInteger d = computeD(e, phi);

        return new RSA.Key[] { new RSA.Key(n, e), new RSA.Key(n, d) };
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
            // If e is greater than phi(n) or e and phi(n) are not coprime, calculate again.
        } while (e.compareTo(phi) != -1 || !isCoprime(e, phi));
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
     * This method checks if two numbers a and b are coprime, i.e. if the GCD(a,b)=1
     * 
     * @param a First number
     * @param b Second number
     * @return A boolean value (are a and b coprime?)
     */
    private static boolean isCoprime(final BigInteger a, final BigInteger b) {
        return a.gcd(b).compareTo(BigInteger.ONE) == 0;
    }

    /**
     * This is a class for a RSA key. It can be either a public or a private key
     */
    static class Key {

        private final BigInteger exponent;
        private final BigInteger n;

        public Key(BigInteger n, BigInteger exponent) {
            this.n = n;
            this.exponent = exponent;
        }

        public Key(int n, int exponent) {
            this.n = BigInteger.valueOf(n);
            this.exponent = BigInteger.valueOf(exponent);
        }

        public BigInteger getExponent() {
            return this.exponent;
        }

        public BigInteger getN() {
            return this.n;
        }

        /**
         * This method returns the position (start the count at 2^0) of the highest
         * set bit (=1), i.e. the length of the binary representation of the number.
         * e.g. bitlength(010101) = 5
         * Note that positive numbers always need bit length + 1 bits (otherwise they
         * are interpreted as negative numbers)
         * 
         * @return the bit length
         */
        public long getBitLength() {
            return this.n.bitLength();
        }

        @Override
        public String toString() {
            return "Modulus N = " + n + "\n\nExponent (E/D) = " + exponent;
        }
    }
}
