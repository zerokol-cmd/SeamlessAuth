package anon.oqsauth.net;

import java.util.concurrent.atomic.AtomicReference;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiScreen;
import net.minecraft.client.network.NetHandlerLoginClient;
import net.minecraft.network.NetworkManager;
import net.minecraft.util.ChatComponentText;

import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

import com.google.common.base.Charsets;

import anon.oqsauth.ClientProxy;
import anon.oqsauth.OqsAuth;
import anon.oqsauth.auth.Identity;
import anon.oqsauth.auth.SecureChannel;
import io.netty.util.concurrent.GenericFutureListener;

public final class ClientLoginHandler extends NetHandlerLoginClient implements IClientLoginHandler {

    public static final AtomicReference<SecureChannel> SESSION = new AtomicReference<>();

    public ClientLoginHandler(NetworkManager network, Minecraft minecraft, GuiScreen parent) {
        super(network, minecraft, parent);
    }

    @Override
    public void handleServerHello(ServerHello hello) {
        try {
            byte[] kemCiphertext = new byte[0];
            byte[] sharedSecret = null;
            KeyEncapsulation kem = null;

            try {
                if (hello.sessionEncryption()) {
                    if (hello.kemAlgorithm.isEmpty() || hello.kemPublicKey.length == 0) {
                        OqsAuth.LOG.warn("server requested session encryption without KEM material");
                        field_147393_d.closeChannel(new ChatComponentText("invalid server hello"));
                        return;
                    }
                    kem = new KeyEncapsulation(hello.kemAlgorithm);
                    @SuppressWarnings("unchecked")
                    Pair<byte[], byte[]> encaps = kem.encap_secret(hello.kemPublicKey);
                    kemCiphertext = encaps.getLeft();
                    sharedSecret = encaps.getRight();
                }

                Identity identity = ClientProxy.keystore.getIdentity();
                byte[] transcript = transcript(hello, kemCiphertext, identity);

                byte[] signature = new byte[0];
                byte[] publicKey = new byte[0];
                if (hello.authRequired()) {
                    if (identity == null || !identity.algorithm.equals(hello.signatureAlgorithm)) {
                        OqsAuth.LOG.warn(
                            "server requested {} but local keystore holds {}",
                            hello.signatureAlgorithm,
                            identity == null ? "nothing" : identity.algorithm);
                        field_147393_d.closeChannel(new ChatComponentText("unsupported signature algorithm"));
                        return;
                    }
                    signature = ClientProxy.keystore.sign(transcript);
                    publicKey = identity.publicKey;
                }

                if (hello.sessionEncryption()) {
                    SecureChannel channel = SecureChannel.forClient(
                        hello.kemAlgorithm,
                        hello.sessionRatchet(),
                        sharedSecret,
                        transcript,
                        hello.kemPublicKey);
                    SecureChannel previous = SESSION.getAndSet(channel);
                    if (previous != null) previous.dispose();
                }

                field_147393_d.scheduleOutboundPacket(
                    new ClientAuthResponse(publicKey, signature, kemCiphertext),
                    new GenericFutureListener[0]);
            } finally {
                if (sharedSecret != null) SecureChannel.wipe(sharedSecret);
                if (kem != null) kem.dispose_KEM();
            }
        } catch (Exception e) {
            OqsAuth.LOG.error("failed to process server hello", e);
            field_147393_d.closeChannel(new ChatComponentText("authentication error"));
        }
    }

    private byte[] transcript(ServerHello hello, byte[] kemCiphertext, Identity identity) {
        String username = Minecraft.getMinecraft()
            .getSession()
            .func_148256_e()
            .getName();
        int flags = (hello.authRequired() ? ServerHello.FLAG_AUTH : 0)
            | (hello.sessionEncryption() ? ServerHello.FLAG_SESSION_ENC : 0)
            | (hello.sessionRatchet() ? ServerHello.FLAG_SESSION_RATCHET : 0);
        return SecureChannel.sha256(
            "oqs-auth-v1".getBytes(Charsets.UTF_8),
            new byte[] { (byte) flags },
            hello.signatureAlgorithm.getBytes(Charsets.UTF_8),
            hello.kemAlgorithm.getBytes(Charsets.UTF_8),
            hello.challenge,
            hello.kemPublicKey,
            kemCiphertext,
            username.getBytes(Charsets.UTF_8));
    }
}
