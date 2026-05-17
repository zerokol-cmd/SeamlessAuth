package anon.oqsauth.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Set;

import org.openquantumsafe.Signature;

public final class Keystore {

    private static final byte[] MAGIC = { 'O', 'A', 'K', 'S' };
    private static final byte VERSION = 1;

    private final Path path;
    private Identity identity;

    public Keystore(Path path) {
        this.path = path;
    }

    public Identity getIdentity() {
        return identity;
    }

    public Identity ensureIdentity(String algorithm) throws IOException {
        if (Files.exists(path)) {
            Identity loaded = read(path);
            if (loaded.algorithm.equals(algorithm)) {
                this.identity = loaded;
                return loaded;
            }
        }
        Identity created = generate(algorithm);
        write(path, created);
        this.identity = created;
        return created;
    }

    public byte[] sign(byte[] message) {
        if (identity == null) throw new IllegalStateException("keystore not initialized");
        Signature signer = new Signature(identity.algorithm, identity.secretKey);
        try {
            return signer.sign(message);
        } finally {
            signer.dispose_sig();
        }
    }

    public static boolean verify(String algorithm, byte[] publicKey, byte[] message, byte[] signature) {
        Signature verifier = new Signature(algorithm);
        try {
            return verifier.verify(message, signature, publicKey);
        } finally {
            verifier.dispose_sig();
        }
    }

    private static Identity generate(String algorithm) {
        Signature signer = new Signature(algorithm);
        try {
            byte[] publicKey = signer.generate_keypair();
            byte[] secretKey = signer.export_secret_key();
            return new Identity(algorithm, publicKey, secretKey);
        } finally {
            signer.dispose_sig();
        }
    }

    private static Identity read(Path path) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(Files.readAllBytes(path));
        byte[] magic = new byte[4];
        buf.get(magic);
        for (int i = 0; i < MAGIC.length; i++)
            if (magic[i] != MAGIC[i]) throw new IOException("invalid keystore magic");
        byte version = buf.get();
        if (version != VERSION) throw new IOException("unsupported keystore version: " + version);
        byte[] algoBytes = readBlob(buf, 256);
        String algorithm = new String(algoBytes, StandardCharsets.UTF_8);
        byte[] publicKey = readBlob(buf, 1 << 20);
        byte[] secretKey = readBlob(buf, 1 << 20);
        return new Identity(algorithm, publicKey, secretKey);
    }

    private static void write(Path path, Identity identity) throws IOException {
        byte[] algoBytes = identity.algorithm.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer
            .allocate(4 + 1 + 2 + algoBytes.length + 4 + identity.publicKey.length + 4 + identity.secretKey.length);
        buf.put(MAGIC);
        buf.put(VERSION);
        writeBlob(buf, algoBytes);
        writeIntBlob(buf, identity.publicKey);
        writeIntBlob(buf, identity.secretKey);
        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path tmp = path.resolveSibling(path.getFileName() + ".new");
        Files.write(
            tmp,
            buf.array(),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE);
        try {
            Set<PosixFilePermission> perms = EnumSet
                .of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(
                tmp,
                PosixFilePermissions.asFileAttribute(perms)
                    .value());
        } catch (UnsupportedOperationException ignored) {}
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static byte[] readBlob(ByteBuffer buf, int maxLen) throws IOException {
        int len;
        if (maxLen <= 0xFFFF) {
            len = buf.getShort() & 0xFFFF;
        } else {
            len = buf.getInt();
        }
        if (len < 0 || len > maxLen) throw new IOException("blob length out of range: " + len);
        byte[] out = new byte[len];
        buf.get(out);
        return out;
    }

    private static void writeBlob(ByteBuffer buf, byte[] data) {
        buf.putShort((short) data.length);
        buf.put(data);
    }

    private static void writeIntBlob(ByteBuffer buf, byte[] data) {
        buf.putInt(data.length);
        buf.put(data);
    }

    public static Path resolve(String configured) {
        String expanded = configured.startsWith("~/") ? System.getProperty("user.home") + configured.substring(1)
            : configured;
        return Paths.get(expanded);
    }
}
