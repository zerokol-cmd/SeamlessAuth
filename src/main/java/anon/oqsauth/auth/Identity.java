package anon.oqsauth.auth;

import java.util.Arrays;

public final class Identity {

    public final String algorithm;
    public final byte[] publicKey;
    public final byte[] secretKey;

    public Identity(String algorithm, byte[] publicKey, byte[] secretKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey == null ? null : publicKey.clone();
        this.secretKey = secretKey == null ? null : secretKey.clone();
    }

    public boolean publicEquals(Identity other) {
        return other != null && algorithm.equals(other.algorithm) && Arrays.equals(publicKey, other.publicKey);
    }

    public boolean publicEquals(String otherAlgorithm, byte[] otherPublic) {
        return algorithm.equals(otherAlgorithm) && Arrays.equals(publicKey, otherPublic);
    }
}
