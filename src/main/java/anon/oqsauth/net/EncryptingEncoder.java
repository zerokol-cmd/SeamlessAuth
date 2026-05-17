package anon.oqsauth.net;

import anon.oqsauth.auth.SecureChannel;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

public final class EncryptingEncoder extends MessageToByteEncoder<ByteBuf> {

    private final SecureChannel channel;

    public EncryptingEncoder(SecureChannel channel) {
        this.channel = channel;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, ByteBuf msg, ByteBuf out) throws Exception {
        byte[] plaintext = new byte[msg.readableBytes()];
        msg.readBytes(plaintext);
        byte[] frame = SecureChannel.encodeEnvelope(channel.encrypt(plaintext, false));
        out.writeInt(frame.length);
        out.writeBytes(frame);
    }
}
