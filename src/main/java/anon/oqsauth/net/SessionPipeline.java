package anon.oqsauth.net;

import net.minecraft.network.NetworkManager;

import anon.oqsauth.OqsAuth;
import anon.oqsauth.auth.SecureChannel;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelPipeline;

public final class SessionPipeline {

    public static final String DECRYPT_HANDLER = "oqs-decrypt";
    public static final String ENCRYPT_HANDLER = "oqs-encrypt";

    private SessionPipeline() {}

    public static void install(final NetworkManager network, Channel netty) {
        final SecureChannel session = OqsAuth.proxy.findSession(network);
        if (session == null) return;
        ChannelPipeline pipeline = netty.pipeline();
        if (pipeline.get(DECRYPT_HANDLER) != null || pipeline.get(ENCRYPT_HANDLER) != null) return;
        pipeline.addBefore("splitter", DECRYPT_HANDLER, new DecryptingDecoder(session));
        pipeline.addBefore("prepender", ENCRYPT_HANDLER, new EncryptingEncoder(session));
        netty.closeFuture()
            .addListener(new ChannelFutureListener() {

                @Override
                public void operationComplete(ChannelFuture future) {
                    OqsAuth.proxy.removeSession(network);
                    session.dispose();
                }
            });
        OqsAuth.LOG.info("oqs-auth session encryption installed for {}", netty.remoteAddress());
    }
}
