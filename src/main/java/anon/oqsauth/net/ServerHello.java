package anon.oqsauth.net;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import net.minecraft.client.network.NetHandlerLoginClient;
import net.minecraft.network.INetHandler;
import net.minecraft.network.Packet;
import net.minecraft.network.PacketBuffer;

public final class ServerHello extends Packet {

    public static final int FLAG_AUTH = 0x01;
    public static final int FLAG_SESSION_ENC = 0x02;
    public static final int FLAG_SESSION_RATCHET = 0x04;

    public int flags;
    public String signatureAlgorithm;
    public String kemAlgorithm;
    public byte[] challenge;
    public byte[] kemPublicKey;

    public ServerHello() {}

    public ServerHello(int flags, String signatureAlgorithm, String kemAlgorithm, byte[] challenge,
        byte[] kemPublicKey) {
        this.flags = flags;
        this.signatureAlgorithm = signatureAlgorithm == null ? "" : signatureAlgorithm;
        this.kemAlgorithm = kemAlgorithm == null ? "" : kemAlgorithm;
        this.challenge = challenge == null ? new byte[0] : challenge;
        this.kemPublicKey = kemPublicKey == null ? new byte[0] : kemPublicKey;
    }

    public boolean authRequired() {
        return (flags & FLAG_AUTH) != 0;
    }

    public boolean sessionEncryption() {
        return (flags & FLAG_SESSION_ENC) != 0;
    }

    public boolean sessionRatchet() {
        return (flags & FLAG_SESSION_RATCHET) != 0;
    }

    @Override
    public void readPacketData(PacketBuffer data) throws IOException {
        flags = data.readUnsignedByte();
        signatureAlgorithm = new String(readBlob(data), StandardCharsets.UTF_8);
        kemAlgorithm = new String(readBlob(data), StandardCharsets.UTF_8);
        challenge = readBlob(data);
        kemPublicKey = readBlob(data);
    }

    @Override
    public void writePacketData(PacketBuffer data) throws IOException {
        data.writeByte(flags);
        writeBlob(data, signatureAlgorithm.getBytes(StandardCharsets.UTF_8));
        writeBlob(data, kemAlgorithm.getBytes(StandardCharsets.UTF_8));
        writeBlob(data, challenge);
        writeBlob(data, kemPublicKey);
    }

    public void processPacket(IClientLoginHandler handler) {
        handler.handleServerHello(this);
    }

    @Override
    public void processPacket(INetHandler handler) {
        handler.onConnectionStateTransition(null, null);
        NetHandlerLoginClient vanilla = (NetHandlerLoginClient) handler;
        IClientLoginHandler ours = (IClientLoginHandler) vanilla.field_147393_d.getNetHandler();
        ours.handleServerHello(this);
    }

    @Override
    public boolean hasPriority() {
        return true;
    }
}
