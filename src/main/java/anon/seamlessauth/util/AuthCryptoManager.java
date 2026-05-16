package anon.seamlessauth.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;

import org.openquantumsafe.Signature;
import org.openquantumsafe.Sigs;

import anon.seamlessauth.auth.BetterPublicKey;

public class AuthCryptoManager {

    /**
     * Checks if the algorithm is a Post-Quantum Signature supported by LibOQS
     */
    public static boolean isOQSSignature(String algorithm) {
        return Sigs.get_supported_sigs()
            .contains(algorithm);
    }

    /**
     * Bundles the challenge for the client.
     * Uses Encryption for RSA/EC, and raw Plaintext for LibOQS signatures.
     */
    public static byte[] generateMultiKeyChallenge(byte[] challenge, Map<String, BetterPublicKey> keys)
        throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(keys.size());

        for (Map.Entry<String, BetterPublicKey> entry : keys.entrySet()) {
            String algorithm = entry.getKey();
            BetterPublicKey bKey = entry.getValue();

            dos.writeUTF(algorithm);

            if (isOQSSignature(algorithm)) {
                // Post-Quantum Signature: We send the raw challenge.
                // The client will SIGN it. (Plaintext is safe, as only the client holds the private signing key).
                dos.writeInt(challenge.length);
                dos.write(challenge);
            } else {
                // Classic JCA: We encrypt the challenge. The client must DECRYPT it.
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                PublicKey standardKey = keyFactory.generatePublic(new X509EncodedKeySpec(bKey.getEncoded()));

                Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, standardKey);
                byte[] encryptedChallenge = cipher.doFinal(challenge);

                dos.writeInt(encryptedChallenge.length);
                dos.write(encryptedChallenge);
            }
        }

        return baos.toByteArray();
    }

    /**
     * Verifies the client's ChallengeResponse packet.
     * Handles both Decrypted Payload Matches (RSA) and Signature Verification (OQS).
     */
    public static boolean verifyChallengeResponse(byte[] originalChallenge, byte[] clientResponsePayload,
        Map<String, BetterPublicKey> keys) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(clientResponsePayload);
            DataInputStream dis = new DataInputStream(bais)) {

            // Read what algorithm the client successfully used
            String algorithm = dis.readUTF();
            int len = dis.readInt();
            byte[] responseData = new byte[len];
            dis.readFully(responseData);

            BetterPublicKey pubKey = keys.get(algorithm);
            if (pubKey == null) return false;

            if (isOQSSignature(algorithm)) {
                // Client sent an OQS Signature. Verify it using LibOQS.
                Signature verifier = new Signature(algorithm);
                boolean isValid = verifier.verify(originalChallenge, responseData, pubKey.getEncoded());
                verifier.dispose_sig(); // Clean up native memory
                return isValid;
            } else {
                // Client sent Decrypted Data (RSA). Check if it matches exactly.
                return Arrays.equals(originalChallenge, responseData);
            }
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean areKeyMapsEqual(Map<String, BetterPublicKey> keys1, Map<String, BetterPublicKey> keys2) {
        if (keys1 == null || keys2 == null) return keys1 == keys2;
        if (keys1.size() != keys2.size()) return false;

        for (Map.Entry<String, BetterPublicKey> entry : keys1.entrySet()) {
            BetterPublicKey k2 = keys2.get(entry.getKey());
            if (k2 == null || !Arrays.equals(
                entry.getValue()
                    .getEncoded(),
                k2.getEncoded())) {
                return false;
            }
        }
        return true;
    }
}
