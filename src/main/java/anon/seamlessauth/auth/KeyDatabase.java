package anon.seamlessauth.auth;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.google.common.base.Charsets;

import anon.seamlessauth.Config;
import anon.seamlessauth.SeamlessAuth;
import anon.seamlessauth.util.Pair;
import cpw.mods.fml.common.FMLCommonHandler;

public class KeyDatabase {

    public Map<String, Pair<UUID, Map<String, BetterPublicKey>>> authorized = new HashMap<>();

    public String path;

    public KeyDatabase(String databasePath) {
        path = databasePath;
        reloadKeys();
    }

    public void reloadKeys() {
        Map<String, Pair<UUID, Map<String, BetterPublicKey>>> working = new HashMap<>();

        try {
            List<String> lines = Files.readAllLines(Paths.get(path), Charsets.UTF_8);

            for (String line : lines) {
                int firstSpace = line.indexOf(' ');
                if (firstSpace == -1) {
                    SeamlessAuth.LOG.warn("invalid entry in key database");
                    continue;
                }

                String username = line.substring(0, firstSpace);
                int secondSpace = line.indexOf(' ', firstSpace + 1);

                String uuidStr;
                String serializedKeys = "";

                if (secondSpace == -1) {
                    uuidStr = line.substring(firstSpace + 1);
                } else {
                    uuidStr = line.substring(firstSpace + 1, secondSpace);
                    serializedKeys = line.substring(secondSpace + 1);
                }

                UUID uuid;
                try {
                    uuid = UUID.fromString(uuidStr);
                } catch (IllegalArgumentException e) {
                    SeamlessAuth.LOG.warn("invalid UUID in entry for: " + username);
                    continue;
                }

                if (secondSpace == -1 || serializedKeys.isEmpty()) {
                    working.put(username, new Pair<>(uuid, new HashMap<>()));
                    continue;
                }

                Map<String, BetterPublicKey> userKeys = new HashMap<>();
                boolean hasInvalidKey = false;

                // Manually parse the "algo:base64|algo2:base64|" format
                int start = 0;
                while (start < serializedKeys.length()) {
                    int pipePos = serializedKeys.indexOf('|', start);
                    if (pipePos == -1) {
                        pipePos = serializedKeys.length(); // handle remainder if no trailing pipe
                    }

                    if (pipePos > start) {
                        int colonPos = serializedKeys.indexOf(':', start);

                        // Colon must exist, and it must be BEFORE the current pipe
                        if (colonPos == -1 || colonPos >= pipePos || colonPos == start) {
                            SeamlessAuth.LOG.warn("invalid key mapping in entry for: " + username);
                            hasInvalidKey = true;
                            break;
                        }

                        String algorithmName = serializedKeys.substring(start, colonPos);
                        String base64Key = serializedKeys.substring(colonPos + 1, pipePos);

                        try {
                            byte[] decoded = Base64.getDecoder()
                                .decode(base64Key);
                            BetterPublicKey key = new BetterPublicKey(algorithmName, decoded);
                            userKeys.put(algorithmName, key);
                        } catch (IllegalArgumentException e) {
                            SeamlessAuth.LOG.warn("invalid base64 key in entry for: " + username);
                            hasInvalidKey = true;
                            break;
                        }
                    }
                    start = pipePos + 1;
                }

                if (!hasInvalidKey) {
                    working.put(username, new Pair<>(uuid, userKeys));
                }
            }
        } catch (NoSuchFileException e) {
            SeamlessAuth.LOG.info("no existing key database found");
            return;
        } catch (IOException e) {
            SeamlessAuth.LOG.fatal("failed to read key database", e);
            FMLCommonHandler.instance()
                .exitJava(1, false);
        }

        authorized = working;
    }

    public void addUser(String username, UUID uuid, Map<String, BetterPublicKey> keys) {
        authorized.put(username, new Pair<>(uuid, keys));

        StringBuilder stringBuilder = new StringBuilder();
        if (keys != null) {
            for (Map.Entry<String, BetterPublicKey> entry : keys.entrySet()) {
                String algorithmName = entry.getKey();
                BetterPublicKey key = entry.getValue();
                String base64Key = Base64.getEncoder()
                    .encodeToString(key.getEncoded());
                stringBuilder.append(algorithmName)
                    .append(':')
                    .append(base64Key)
                    .append('|');
            }
        }

        String serializedKeys = stringBuilder.toString();

        // Build output line string without trailing spaces
        String lineToWrite = serializedKeys.isEmpty() ? username + " " + uuid.toString() + "\n"
            : username + " " + uuid.toString() + " " + serializedKeys + "\n";

        try {
            Files.write(
                Paths.get(path),
                lineToWrite.getBytes(Charsets.UTF_8),
                StandardOpenOption.APPEND,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE);
        } catch (IOException e) {
            SeamlessAuth.LOG.warn("failed to write to key database", e);
        }
    }

    public void rewritePartialUser(String username, Map<String, BetterPublicKey> keys) {
        UUID uuid = authorized.get(username).first;
        authorized.put(username, new Pair<>(uuid, keys));
        rewriteKeyFile();
    }

    public void rewriteKeyFile() {
        String keyfilePath = Config.databasePath;
        Path tempOutput = Paths.get(keyfilePath + ".new");

        try (BufferedWriter writer = Files.newBufferedWriter(
            tempOutput,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE)) {

            authorized.forEach((name, pair) -> {
                StringBuilder stringBuilder = new StringBuilder();
                Map<String, BetterPublicKey> keys = pair.second;

                if (keys != null) {
                    for (Map.Entry<String, BetterPublicKey> entry : keys.entrySet()) {
                        String algorithmName = entry.getKey();
                        BetterPublicKey key = entry.getValue();
                        String base64Key = Base64.getEncoder()
                            .encodeToString(key.getEncoded());
                        stringBuilder.append(algorithmName)
                            .append(':')
                            .append(base64Key)
                            .append('|');
                    }
                }

                String serializedKeys = stringBuilder.toString();
                String line = serializedKeys.isEmpty() ? name + " " + pair.first.toString() + "\n"
                    : name + " " + pair.first.toString() + " " + serializedKeys + "\n";

                try {
                    writer.append(line);
                } catch (IOException e) {
                    SeamlessAuth.LOG.error("failed to append user line", e);
                }
            });

            tempOutput.toFile()
                .renameTo(new File(keyfilePath));
        } catch (IOException e) {
            SeamlessAuth.LOG.error("failed to rewrite key database", e);
        }
    }
}
