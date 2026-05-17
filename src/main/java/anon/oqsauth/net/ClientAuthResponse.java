package anon.oqsauth.net;

import java.io.IOException;

import net.minecraft.network.INetHandler;
import net.minecraft.network.Packet;
import net.minecraft.network.PacketBuffer;

public final class ClientAuthResponse extends Packet {

    public byte[] publicKey;
    public byte[] signature;
    public byte[] kemCiphertext;

    public ClientAuthResponse() {}

    public ClientAuthResponse(byte[] publicKey, byte[] signature, byte[] kemCiphertext) {
        this.publicKey = publicKey == null ? new byte[0] : publicKey;
        this.signature = signature == null ? new byte[0] : signature;
        this.kemCiphertext = kemCiphertext == null ? new byte[0] : kemCiphertext;
    }

    @Override
    public void readPacketData(PacketBuffer data) throws IOException {
        publicKey = readBlob(data);
        signature = readBlob(data);
        kemCiphertext = readBlob(data);
    }

    @Override
    public void writePacketData(PacketBuffer data) throws IOException {
        writeBlob(data, publicKey);
        writeBlob(data, signature);
        writeBlob(data, kemCiphertext);
    }

    public void processPacket(IServerLoginHandler handler) {
        handler.handleClientAuthResponse(this);
    }

    @Override
    public void processPacket(INetHandler handler) {
        this.processPacket((IServerLoginHandler) handler);
    }

    @Override
    public boolean hasPriority() {
        return true;
    }
}
