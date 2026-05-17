package anon.oqsauth.auth;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.Logger;

public final class KeyDatabase {

    public static final class Entry {

        public final UUID uuid;
        public final Identity identity;

        public Entry(UUID uuid, Identity identity) {
            this.uuid = uuid;
            this.identity = identity;
        }
    }

    private final Path path;
    private final Logger log;
    private final Map<String, Entry> entries = new LinkedHashMap<>();

    public KeyDatabase(Path path, Logger log) {
        this.path = path;
        this.log = log;
        reload();
    }

    public synchronized Entry lookup(String username) {
        return entries.get(username);
    }

    public synchronized boolean register(String username, UUID uuid, String algorithm, byte[] publicKey) {
        Entry existing = entries.get(username);
        if (existing != null && existing.identity != null) return existing.identity.publicEquals(algorithm, publicKey);
        Identity identity = new Identity(algorithm, publicKey, null);
        UUID resolved = existing != null && existing.uuid != null ? existing.uuid : uuid;
        entries.put(username, new Entry(resolved, identity));
        rewrite();
        return true;
    }

    public synchronized void reload() {
        entries.clear();
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split(" ");
                if (parts.length < 2 || parts.length == 3) {
                    log.warn("invalid key database entry: {}", line);
                    continue;
                }
                String username = parts[0];
                UUID uuid;
                try {
                    uuid = UUID.fromString(parts[1]);
                } catch (IllegalArgumentException e) {
                    log.warn("invalid UUID for {}: {}", username, parts[1]);
                    continue;
                }
                Identity identity = null;
                if (parts.length == 4) {
                    try {
                        byte[] publicKey = Base64.getDecoder()
                            .decode(parts[3]);
                        identity = new Identity(parts[2], publicKey, null);
                    } catch (IllegalArgumentException e) {
                        log.warn("invalid base64 public key for {}", username);
                        continue;
                    }
                }
                entries.put(username, new Entry(uuid, identity));
            }
        } catch (NoSuchFileException e) {
            log.info("no existing key database at {}", path);
        } catch (IOException e) {
            throw new RuntimeException("failed to read key database " + path, e);
        }
    }

    private void rewrite() {
        Path parent = path.getParent();
        try {
            if (parent != null) Files.createDirectories(parent);
            Path tmp = path.resolveSibling(path.getFileName() + ".new");
            try (BufferedWriter writer = Files.newBufferedWriter(
                tmp,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE)) {
                for (Map.Entry<String, Entry> e : entries.entrySet()) {
                    Entry entry = e.getValue();
                    writer.append(e.getKey())
                        .append(' ')
                        .append(entry.uuid.toString());
                    if (entry.identity != null) {
                        writer.append(' ')
                            .append(entry.identity.algorithm)
                            .append(' ')
                            .append(
                                Base64.getEncoder()
                                    .encodeToString(entry.identity.publicKey));
                    }
                    writer.append('\n');
                }
            }
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            log.error("failed to rewrite key database", e);
        }
    }

    public static Path resolve(String configured) {
        String expanded = configured.startsWith("~/") ? System.getProperty("user.home") + configured.substring(1)
            : configured;
        return Paths.get(expanded);
    }
}
