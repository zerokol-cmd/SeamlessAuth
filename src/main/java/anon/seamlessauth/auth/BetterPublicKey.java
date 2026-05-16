package anon.seamlessauth.auth;

import java.security.PublicKey;

public class BetterPublicKey implements PublicKey {

    byte[] key;
    String algorithm;

    public BetterPublicKey(String algorithmName, byte[] key) {
        this.algorithm = algorithmName;
        if (key != null) this.key = key.clone();

    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (this.key == null) {
            return null;
        }
        return this.key.clone();
    }
}
