package anon.oqsauth.net;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import net.minecraft.network.NetworkManager;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.NetHandlerLoginServer;

import org.openquantumsafe.KeyEncapsulation;

import com.google.common.base.Charsets;
import com.mojang.authlib.GameProfile;

import anon.oqsauth.Config;
import anon.oqsauth.OqsAuth;
import anon.oqsauth.ServerProxy;
import anon.oqsauth.auth.KeyDatabase;
import anon.oqsauth.auth.Keystore;
import anon.oqsauth.auth.SecureChannel;
import io.netty.util.concurrent.GenericFutureListener;

public final class ServerLoginHandler extends NetHandlerLoginServer implements IServerLoginHandler {

    public static final Map<NetworkManager, SecureChannel> SESSIONS = new ConcurrentHashMap<>();

    private static final SecureRandom RNG = new SecureRandom();
    private static final int CHALLENGE_LEN = 64;

    private final boolean authRequired;
    private final boolean sessionEnc;
    private final boolean sessionRatchet;
    private final String sigAlgorithm;
    private final String kemAlgorithm;

    private byte[] challenge;
    private byte[] kemPublicKey;
    private KeyEncapsulation kem;

    public ServerLoginHandler(MinecraftServer server, NetworkManager network, GameProfile profile) {
        super(server, network);
        this.authRequired = Config.requireLoginAuth;
        this.sessionEnc = Config.enableSessionEncryption;
        this.sessionRatchet = sessionEnc && Config.enableSessionRatchet;
        this.sigAlgorithm = Config.signatureAlgorithm;
        this.kemAlgorithm = Config.kemAlgorithm;
        this.field_147337_i = resolveProfile(profile);
    }

    public ServerHello buildHello() {
        int flags = 0;
        if (authRequired) {
            flags |= ServerHello.FLAG_AUTH;
            challenge = new byte[CHALLENGE_LEN];
            RNG.nextBytes(challenge);
        }
        if (sessionEnc) {
            flags |= ServerHello.FLAG_SESSION_ENC;
            kem = new KeyEncapsulation(kemAlgorithm);
            kemPublicKey = kem.generate_keypair()
                .clone();
            if (sessionRatchet) flags |= ServerHello.FLAG_SESSION_RATCHET;
        }
        return new ServerHello(
            flags,
            authRequired ? sigAlgorithm : "",
            sessionEnc ? kemAlgorithm : "",
            challenge,
            kemPublicKey);
    }

    @Override
    public void handleClientAuthResponse(ClientAuthResponse packet) {
        try {
            byte[] transcript = transcript(packet.kemCiphertext);

            if (authRequired) {
                if (packet.publicKey.length == 0 || packet.signature.length == 0) {
                    func_147322_a("auth response missing signature");
                    return;
                }
                KeyDatabase.Entry existing = ServerProxy.keyDatabase.lookup(field_147337_i.getName());
                if (existing != null && existing.identity != null) {
                    if (!existing.identity.publicEquals(sigAlgorithm, packet.publicKey)) {
                        func_147322_a("public key does not match pinned identity");
                        return;
                    }
                } else if (!Config.implicitRegistration) {
                    func_147322_a("implicit registration disabled");
                    return;
                }
                if (!Keystore.verify(sigAlgorithm, packet.publicKey, transcript, packet.signature)) {
                    func_147322_a("signature verification failed");
                    return;
                }
                if (existing == null || existing.identity == null) {
                    ServerProxy.keyDatabase
                        .register(field_147337_i.getName(), field_147337_i.getId(), sigAlgorithm, packet.publicKey);
                }
            }

            if (sessionEnc) {
                if (packet.kemCiphertext.length == 0) {
                    func_147322_a("session ciphertext missing");
                    return;
                }
                byte[] sharedSecret = kem.decap_secret(packet.kemCiphertext);
                SecureChannel channel = SecureChannel
                    .forServer(kemAlgorithm, sessionRatchet, sharedSecret, transcript, kem);
                SecureChannel previous = SESSIONS.put(field_147333_a, channel);
                if (previous != null) previous.dispose();
                SecureChannel.wipe(sharedSecret);
                kem = null;
            } else {
                disposeKem();
            }

            field_147328_g = NetHandlerLoginServer.LoginState.READY_TO_ACCEPT;
        } catch (Exception e) {
            OqsAuth.LOG.error("failed to process client auth response", e);
            disposeKem();
            func_147322_a("authentication error");
        }
    }

    public void sendHello(ServerHello hello) {
        field_147333_a.scheduleOutboundPacket(hello, new GenericFutureListener[0]);
    }

    private byte[] transcript(byte[] kemCiphertext) {
        return SecureChannel.sha256(
            ("oqs-auth-v1").getBytes(Charsets.UTF_8),
            new byte[] { (byte) flagsForTranscript() },
            sigAlgorithm.getBytes(Charsets.UTF_8),
            kemAlgorithm.getBytes(Charsets.UTF_8),
            challenge == null ? new byte[0] : challenge,
            kemPublicKey == null ? new byte[0] : kemPublicKey,
            kemCiphertext == null ? new byte[0] : kemCiphertext,
            field_147337_i.getName()
                .getBytes(Charsets.UTF_8));
    }

    private int flagsForTranscript() {
        int f = 0;
        if (authRequired) f |= ServerHello.FLAG_AUTH;
        if (sessionEnc) f |= ServerHello.FLAG_SESSION_ENC;
        if (sessionRatchet) f |= ServerHello.FLAG_SESSION_RATCHET;
        return f;
    }

    private void disposeKem() {
        if (kem != null) {
            kem.dispose_KEM();
            kem = null;
        }
    }

    private GameProfile resolveProfile(GameProfile original) {
        KeyDatabase.Entry entry = ServerProxy.keyDatabase.lookup(original.getName());
        UUID uuid = entry != null && entry.uuid != null ? entry.uuid
            : UUID.nameUUIDFromBytes(("OfflinePlayer:" + original.getName()).getBytes(Charsets.UTF_8));
        return new GameProfile(uuid, original.getName());
    }
}
