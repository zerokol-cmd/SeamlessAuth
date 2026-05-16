package anon.seamlessauth.auth;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.openquantumsafe.Signature;

import anon.seamlessauth.Config;
import anon.seamlessauth.SeamlessAuth;
import cpw.mods.fml.common.FMLCommonHandler;

public class KeyManager {

    private final Map<String, BetterPublicKey> publicKeys = new HashMap<>();
    private final Map<String, Signature> activeOqsSigners = new HashMap<>();

    public KeyManager(String pubKeyPath, String prvKeyPath) {
        // Split the config string by the pipe character (escaped as \\|)
        String[] algorithms = Config.requiredKeyAlgorithms.split("\\|");

        for (String algorithm : algorithms) {
            algorithm = algorithm.trim();
            if (algorithm.isEmpty()) {
                continue;
            }

            // Create a safe file suffix (e.g., "ML-DSA-44" -> "mldsa44")
            String suffix = "_" + algorithm.toLowerCase()
                .replaceAll("[^a-z0-9]", "");

            // Dynamically call the loader for each algorithm in the config
            loadOrGenerateOQSKey(algorithm, pubKeyPath + suffix, prvKeyPath + suffix);
        }
    }

    private void loadOrGenerateOQSKey(String algorithm, String pubPath, String prvPath) {
        try {
            byte[] pubData = Files.readAllBytes(Paths.get(pubPath));
            byte[] prvData = Files.readAllBytes(Paths.get(prvPath));

            publicKeys.put(algorithm, new BetterPublicKey(algorithm, pubData));

            // Reconstruct OQS Signer
            Signature signer = new Signature(algorithm);
            // signer.import_secret_key(prvData); <-- Assuming your wrapper has this or similar!

            activeOqsSigners.put(algorithm, signer);
            SeamlessAuth.LOG.info("Successfully loaded stored OQS keys for " + algorithm);

        } catch (NoSuchFileException e) {
            SeamlessAuth.LOG.info("Generating new OQS " + algorithm + " key pair...");
            try {
                Signature signer = new Signature(algorithm);
                byte[] pubKey = signer.generate_keypair();
                byte[] prvKey = signer.export_secret_key();

                Files.write(Paths.get(pubPath), pubKey);
                Files.write(Paths.get(prvPath), prvKey);

                publicKeys.put(algorithm, new BetterPublicKey(algorithm, pubKey));
                activeOqsSigners.put(algorithm, signer);
            } catch (Exception ex) {
                SeamlessAuth.LOG.fatal("Failed to generate OQS keys for " + algorithm, ex);
                FMLCommonHandler.instance()
                    .exitJava(1, false);
            }
        } catch (Exception e) {
            SeamlessAuth.LOG.fatal("Failed to load OQS keys for " + algorithm, e);
            FMLCommonHandler.instance()
                .exitJava(1, false);
        }
    }

    public Map<String, BetterPublicKey> getPublicKeys() {
        return publicKeys;
    }

    public byte[] processChallenge(byte[] multiPayload) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(multiPayload);
            DataInputStream dis = new DataInputStream(bais)) {

            int keyCount = dis.readInt();

            for (int i = 0; i < keyCount; i++) {
                String algorithm = dis.readUTF();
                int length = dis.readInt();
                byte[] payloadData = new byte[length];
                dis.readFully(payloadData);

                if (activeOqsSigners.containsKey(algorithm)) {
                    Signature signer = activeOqsSigners.get(algorithm);
                    byte[] signatureBytes = signer.sign(payloadData);
                    return packResponse(algorithm, signatureBytes);
                }
            }
        }
        throw new Exception("No matching Post-Quantum signing key found to process the challenge.");
    }

    private byte[] packResponse(String algorithm, byte[] responseData) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(algorithm);
        dos.writeInt(responseData.length);
        dos.write(responseData);
        return baos.toByteArray();
    }
}
