package anon.oqsauth.auth;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

public final class SecureChannel {

    public static final int AEAD_KEY_LEN = 32;
    public static final int AEAD_NONCE_LEN = 12;
    public static final int AEAD_TAG_BITS = 128;
    public static final int CHAIN_LEN = 32;

    private static final String AEAD = "AES/GCM/NoPadding";
    private static final String HMAC = "HmacSHA256";
    private static final byte CHAIN_STEP_MSG = 0x01;
    private static final byte CHAIN_STEP_NEXT = 0x02;
    private static final byte[] INFO_ROOT = "oqs-auth-root".getBytes();
    private static final byte[] INFO_RATCHET = "oqs-auth-ratchet".getBytes();
    private static final byte[] INFO_SERVER_SEND = "oqs-auth-server".getBytes();
    private static final byte[] INFO_CLIENT_SEND = "oqs-auth-client".getBytes();

    private final String kemAlgorithm;
    private final boolean ratchetEnabled;

    private byte[] rootKey;
    private byte[] sendChain;
    private byte[] recvChain;
    private int sendCounter;
    private int recvCounter;

    private KeyEncapsulation localKem;
    private byte[] remotePub;

    private SecureChannel(String kemAlgorithm, boolean ratchetEnabled, byte[] sharedSecret, byte[] transcript,
        KeyEncapsulation localKem, byte[] remotePub, boolean isServer) {
        this.kemAlgorithm = kemAlgorithm;
        this.ratchetEnabled = ratchetEnabled;
        this.localKem = localKem;
        this.remotePub = remotePub == null ? null : remotePub.clone();

        byte[] prk = hkdfExtract(transcript, sharedSecret);
        this.rootKey = hkdfExpand(prk, INFO_ROOT, CHAIN_LEN);
        byte[] serverSend = hkdfExpand(this.rootKey, INFO_SERVER_SEND, CHAIN_LEN);
        byte[] clientSend = hkdfExpand(this.rootKey, INFO_CLIENT_SEND, CHAIN_LEN);
        this.sendChain = isServer ? serverSend : clientSend;
        this.recvChain = isServer ? clientSend : serverSend;
        wipe(prk);
    }

    public static SecureChannel forServer(String kemAlgorithm, boolean ratchetEnabled, byte[] sharedSecret,
        byte[] transcript, KeyEncapsulation serverKem) {
        return new SecureChannel(kemAlgorithm, ratchetEnabled, sharedSecret, transcript, serverKem, null, true);
    }

    public static SecureChannel forClient(String kemAlgorithm, boolean ratchetEnabled, byte[] sharedSecret,
        byte[] transcript, byte[] serverPub) {
        return new SecureChannel(kemAlgorithm, ratchetEnabled, sharedSecret, transcript, null, serverPub, false);
    }

    public boolean isRatchetEnabled() {
        return ratchetEnabled;
    }

    public synchronized Envelope encrypt(byte[] plaintext, boolean forceRatchet) throws GeneralSecurityException {
        byte[] kemCipher = null;
        byte[] newLocalPub = null;

        if (forceRatchet && ratchetEnabled && remotePub != null) {
            KeyEncapsulation outbound = new KeyEncapsulation(kemAlgorithm);
            try {
                @SuppressWarnings("unchecked")
                Pair<byte[], byte[]> encaps = outbound.encap_secret(remotePub);
                kemCipher = encaps.getLeft();
                byte[] sharedSecret = encaps.getRight();
                ratchetRoot(sharedSecret);
                wipe(sharedSecret);
            } finally {
                outbound.dispose_KEM();
            }

            KeyEncapsulation freshLocal = new KeyEncapsulation(kemAlgorithm);
            newLocalPub = freshLocal.generate_keypair()
                .clone();
            if (localKem != null) localKem.dispose_KEM();
            localKem = freshLocal;
        }

        byte[][] kn = deriveMessageKey(sendChain);
        sendChain = stepChain(sendChain);

        int counter = sendCounter++;
        byte[] ad = associatedData(counter, kemCipher, newLocalPub);
        byte[] ciphertext = aead(Cipher.ENCRYPT_MODE, kn[0], kn[1], ad, plaintext);
        wipe(kn[0]);
        wipe(kn[1]);

        return new Envelope(kemCipher, newLocalPub, counter, ciphertext);
    }

    public synchronized byte[] decrypt(Envelope envelope) throws GeneralSecurityException {
        if (envelope.kemCiphertext != null && envelope.newRemotePublic != null) {
            if (!ratchetEnabled || localKem == null) {
                throw new GeneralSecurityException("unexpected ratchet header");
            }
            byte[] sharedSecret = localKem.decap_secret(envelope.kemCiphertext);
            ratchetRoot(sharedSecret);
            wipe(sharedSecret);
            remotePub = envelope.newRemotePublic.clone();
        }

        byte[][] kn = deriveMessageKey(recvChain);
        recvChain = stepChain(recvChain);

        byte[] ad = associatedData(envelope.counter, envelope.kemCiphertext, envelope.newRemotePublic);
        byte[] plaintext = aead(Cipher.DECRYPT_MODE, kn[0], kn[1], ad, envelope.ciphertext);
        wipe(kn[0]);
        wipe(kn[1]);

        recvCounter = envelope.counter + 1;
        return plaintext;
    }

    public synchronized void dispose() {
        if (localKem != null) {
            localKem.dispose_KEM();
            localKem = null;
        }
        wipe(rootKey);
        wipe(sendChain);
        wipe(recvChain);
        rootKey = sendChain = recvChain = null;
    }

    private void ratchetRoot(byte[] sharedSecret) {
        byte[] prk = hkdfExtract(rootKey, sharedSecret);
        byte[] derived = hkdfExpand(prk, INFO_RATCHET, CHAIN_LEN * 2);
        wipe(rootKey);
        rootKey = Arrays.copyOfRange(derived, 0, CHAIN_LEN);
        byte[] newSend = Arrays.copyOfRange(derived, CHAIN_LEN, CHAIN_LEN * 2);
        wipe(sendChain);
        sendChain = newSend;
        sendCounter = 0;
        wipe(derived);
        wipe(prk);
        wipe(recvChain);
        recvChain = hkdfExpand(rootKey, INFO_RATCHET, CHAIN_LEN);
        recvCounter = 0;
    }

    private byte[][] deriveMessageKey(byte[] chain) {
        byte[] key = hmac(chain, new byte[] { CHAIN_STEP_MSG });
        byte[] nonce = Arrays.copyOfRange(hmac(chain, new byte[] { CHAIN_STEP_MSG, 0x10 }), 0, AEAD_NONCE_LEN);
        return new byte[][] { key, nonce };
    }

    private static byte[] stepChain(byte[] chain) {
        return hmac(chain, new byte[] { CHAIN_STEP_NEXT });
    }

    private static byte[] associatedData(int counter, byte[] kemCipher, byte[] newRemotePub) {
        int len = 4 + 4
            + (kemCipher == null ? 0 : kemCipher.length)
            + 4
            + (newRemotePub == null ? 0 : newRemotePub.length);
        byte[] out = new byte[len];
        writeInt(out, 0, counter);
        writeInt(out, 4, kemCipher == null ? 0 : kemCipher.length);
        if (kemCipher != null) System.arraycopy(kemCipher, 0, out, 8, kemCipher.length);
        int o = 8 + (kemCipher == null ? 0 : kemCipher.length);
        writeInt(out, o, newRemotePub == null ? 0 : newRemotePub.length);
        if (newRemotePub != null) System.arraycopy(newRemotePub, 0, out, o + 4, newRemotePub.length);
        return out;
    }

    private static byte[] aead(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input)
        throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AEAD);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AEAD_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        byte[] saltOrZero = salt == null || salt.length == 0 ? new byte[CHAIN_LEN] : salt;
        return hmac(saltOrZero, ikm == null ? new byte[0] : ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        int blocks = (length + CHAIN_LEN - 1) / CHAIN_LEN;
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for (int i = 1; i <= blocks; i++) {
            byte[] data = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, data, 0, previous.length);
            System.arraycopy(info, 0, data, previous.length, info.length);
            data[data.length - 1] = (byte) i;
            previous = hmac(prk, data);
            int take = Math.min(CHAIN_LEN, length - offset);
            System.arraycopy(previous, 0, out, offset, take);
            offset += take;
        }
        return out;
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("missing HmacSHA256", e);
        }
    }

    public static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = hkdfExtract(salt, ikm);
        try {
            return hkdfExpand(prk, info, length);
        } finally {
            wipe(prk);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) if (part != null) md.update(part);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("missing SHA-256", e);
        }
    }

    public static void wipe(byte[] data) {
        if (data != null) Arrays.fill(data, (byte) 0);
    }

    private static void writeInt(byte[] dst, int off, int value) {
        dst[off] = (byte) (value >>> 24);
        dst[off + 1] = (byte) (value >>> 16);
        dst[off + 2] = (byte) (value >>> 8);
        dst[off + 3] = (byte) value;
    }

    public static final class Envelope {

        public final byte[] kemCiphertext;
        public final byte[] newRemotePublic;
        public final int counter;
        public final byte[] ciphertext;

        public Envelope(byte[] kemCiphertext, byte[] newRemotePublic, int counter, byte[] ciphertext) {
            this.kemCiphertext = kemCiphertext;
            this.newRemotePublic = newRemotePublic;
            this.counter = counter;
            this.ciphertext = ciphertext;
        }
    }
}
