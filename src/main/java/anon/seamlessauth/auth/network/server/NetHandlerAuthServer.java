package anon.seamlessauth.auth.network.server;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;

import net.minecraft.network.NetworkManager;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.NetHandlerLoginServer;

import com.google.common.base.Charsets;
import com.mojang.authlib.GameProfile;

import anon.seamlessauth.Config;
import anon.seamlessauth.SeamlessAuth;
import anon.seamlessauth.ServerProxy;
import anon.seamlessauth.auth.BetterPublicKey;
import anon.seamlessauth.auth.network.packet.ChallengeRequest;
import anon.seamlessauth.auth.network.packet.ChallengeResponse;
import anon.seamlessauth.auth.network.packet.KeyResponse;
import anon.seamlessauth.util.AuthCryptoManager;
import anon.seamlessauth.util.Pair;
import io.netty.util.concurrent.GenericFutureListener;

public class NetHandlerAuthServer extends NetHandlerLoginServer implements INetHandlerAuthServer {

    private static final SecureRandom challengeGenerator = new SecureRandom();

    private byte[] challenge = new byte[8192];

    public NetHandlerAuthServer(MinecraftServer p_i45298_1_, NetworkManager p_i45298_2_, GameProfile user) {
        super(p_i45298_1_, p_i45298_2_);
        field_147337_i = func_152506_a(user);
    }

    @Override
    protected GameProfile func_152506_a(GameProfile original) {
        Pair<UUID, Map<String, BetterPublicKey>> user = ServerProxy.keyDatabase.authorized.get(original.getName());

        UUID uuid;
        if (user == null) {
            uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + original.getName()).getBytes(Charsets.UTF_8));
        } else {
            uuid = user.first;
        }

        return new GameProfile(uuid, original.getName());
    }

    @Override
    public void handleKeyResponse(KeyResponse packetIn) {
        Map<String, BetterPublicKey> incomingKeys = packetIn.keys;
        Pair<UUID, Map<String, BetterPublicKey>> user = ServerProxy.keyDatabase.authorized
            .get(field_147337_i.getName());

        if (user == null) {
            if (Config.implicitRegistration) {
                ServerProxy.keyDatabase.addUser(field_147337_i.getName(), field_147337_i.getId(), incomingKeys);
            } else {
                func_147322_a("implicit registration is disabled");
                return; // Stop processing if disconnected
            }
        } else {
            if (user.second == null) {
                ServerProxy.keyDatabase.rewritePartialUser(field_147337_i.getName(), incomingKeys);
            } else if (!AuthCryptoManager.areKeyMapsEqual(incomingKeys, user.second)) {
                func_147322_a("mismatched key");
                return; // Stop processing if keys don't match
            }
        }

        // Generate the 64-byte random challenge
        NetHandlerAuthServer.challengeGenerator.nextBytes(challenge);
        byte[] multiEncryptedPayload;

        try {
            // Orchestrate the encryption using all available keys
            multiEncryptedPayload = AuthCryptoManager.generateMultiKeyChallenge(challenge, incomingKeys);
        } catch (Exception e) {
            SeamlessAuth.LOG.error("Failed to generate multi-key challenge payload:", e);

            func_147322_a("invalid key or encryption failure");
            return;
        }

        // Send the bundled multi-key encrypted challenge to the client
        field_147333_a
            .scheduleOutboundPacket(new ChallengeRequest(multiEncryptedPayload), new GenericFutureListener[0]);
    }

    @Override
    public void handleChallengeResponse(ChallengeResponse packetIn) {
        Pair<UUID, Map<String, BetterPublicKey>> user = ServerProxy.keyDatabase.authorized
            .get(field_147337_i.getName());

        if (user == null || !AuthCryptoManager.verifyChallengeResponse(challenge, packetIn.payload, user.second)) {
            func_147322_a("challenge failed or invalid signature");
            return;
        }

        field_147328_g = NetHandlerLoginServer.LoginState.READY_TO_ACCEPT;
    }
}
