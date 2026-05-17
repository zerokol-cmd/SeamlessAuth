package anon.oqsauth.net;

import java.util.List;

import anon.oqsauth.auth.SecureChannel;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

public final class DecryptingDecoder extends ByteToMessageDecoder {

    private static final int MAX_FRAME = 1 << 22;

    private final SecureChannel channel;

    public DecryptingDecoder(SecureChannel channel) {
        this.channel = channel;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        if (in.readableBytes() < 4) return;
        in.markReaderIndex();
        int frameLen = in.readInt();
        if (frameLen < 0 || frameLen > MAX_FRAME) {
            throw new IllegalStateException("oqs-auth frame length out of range: " + frameLen);
        }
        if (in.readableBytes() < frameLen) {
            in.resetReaderIndex();
            return;
        }
        byte[] frame = new byte[frameLen];
        in.readBytes(frame);
        byte[] plaintext = channel.decrypt(SecureChannel.decodeEnvelope(frame));
        ByteBuf decrypted = ctx.alloc()
            .buffer(plaintext.length);
        decrypted.writeBytes(plaintext);
        out.add(decrypted);
    }
}
