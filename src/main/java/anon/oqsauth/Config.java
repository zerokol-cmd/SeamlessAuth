package anon.oqsauth;

import java.io.File;

import net.minecraftforge.common.config.Configuration;

public final class Config {

    public static String keystorePath;
    public static String keyDatabasePath;
    public static String signatureAlgorithm;
    public static String kemAlgorithm;
    public static boolean requireLoginAuth;
    public static boolean implicitRegistration;
    public static boolean enableSessionEncryption;
    public static boolean enableSessionRatchet;
    public static boolean debugLogging;

    private static File lastRead;

    private Config() {}

    public static void load(File configFile) {
        if (configFile == null) {
            if (lastRead == null) return;
            configFile = lastRead;
        } else {
            lastRead = configFile;
        }

        Configuration cfg = new Configuration(configFile);

        keystorePath = cfg.getString(
            "keystorePath",
            "client",
            "oqsauth.keystore",
            "Path to the single client keystore file. An initial ~ expands to the user's home directory.");

        keyDatabasePath = cfg.getString(
            "keyDatabasePath",
            "server",
            "oqsauth.keys",
            "Path to the single server key database file. An initial ~ expands to the user's home directory.");

        signatureAlgorithm = cfg.getString(
            "signatureAlgorithm",
            "general",
            "ML-DSA-65",
            "Post-quantum signature algorithm. Must be supported by liboqs (e.g. ML-DSA-44, ML-DSA-65, Falcon-512).");

        kemAlgorithm = cfg.getString(
            "kemAlgorithm",
            "general",
            "ML-KEM-768",
            "Post-quantum KEM used for session-key establishment and double-ratchet rekey.");

        requireLoginAuth = cfg.getBoolean(
            "requireLoginAuth",
            "server",
            true,
            "When true, the server demands a signature-based login. When false, login is skipped.");

        implicitRegistration = cfg.getBoolean(
            "implicitRegistration",
            "server",
            true,
            "When true, the server pins the first key seen for an unknown username.");

        enableSessionEncryption = cfg.getBoolean(
            "enableSessionEncryption",
            "server",
            false,
            "When true, the server establishes an AES-256-GCM session key with the client during login.");

        enableSessionRatchet = cfg.getBoolean(
            "enableSessionRatchet",
            "server",
            false,
            "When true, the session supports KEM-based double-ratchet rekey. Requires enableSessionEncryption.");

        debugLogging = cfg
            .getBoolean("debugLogging", "general", false, "When true, extra information is printed to the log.");

        if (cfg.hasChanged()) cfg.save();
    }
}
