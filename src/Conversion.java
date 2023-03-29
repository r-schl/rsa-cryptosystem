import java.math.BigInteger;

public class Conversion {

    public static String bytesToStr(final byte[] bytes) {
        return new String(bytes);
    }

    public static String bytesToHexStr(final byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStrToBytes(final String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                    + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] strToBytes(final String str) {
        return str.getBytes();
    }

    public static BigInteger bytesToInt(final byte[] bytes) {
        return new BigInteger(bytes);
    }

    public static byte[] intToBytes(final BigInteger integer) {
        return integer.toByteArray();
    }

}
