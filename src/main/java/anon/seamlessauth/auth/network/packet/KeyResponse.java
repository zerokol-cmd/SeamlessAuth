package anon.seamlessauth.auth.network.packet;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.minecraft.network.INetHandler;
import net.minecraft.network.Packet;
import net.minecraft.network.PacketBuffer;

import com.google.common.base.Charsets;

import anon.seamlessauth.auth.BetterPublicKey;
import anon.seamlessauth.auth.network.server.INetHandlerAuthServer;

public class KeyResponse extends Packet {

    public Map<String, BetterPublicKey> keys;

    public KeyResponse() {
        this.keys = new HashMap<>();
    }

    public KeyResponse(Map<String, BetterPublicKey> userKeys) {
        this.keys = userKeys != null ? userKeys : new HashMap<>();
    }

    @Override
    public void readPacketData(PacketBuffer data) throws IOException {
        int keyCount = data.readInt();
        this.keys = new HashMap<>();

        for (int i = 0; i < keyCount; i++) {
            String algorithm = new String(readBlob(data), Charsets.UTF_8);

            byte[] keyBytes = readBlob(data);

            BetterPublicKey key = new BetterPublicKey(algorithm, keyBytes);
            this.keys.put(algorithm, key);
        }
    }

    @Override
    public void writePacketData(PacketBuffer data) throws IOException {
        if (this.keys == null || this.keys.isEmpty()) {
            data.writeInt(0);
            return;
        }

        data.writeInt(this.keys.size());

        for (Map.Entry<String, BetterPublicKey> entry : this.keys.entrySet()) {
            writeBlob(
                data,
                entry.getKey()
                    .getBytes(Charsets.UTF_8));

            writeBlob(
                data,
                entry.getValue()
                    .getEncoded());
        }
    }

    public void processPacket(INetHandlerAuthServer handler) {
        handler.handleKeyResponse(this);
    }

    @Override
    public void processPacket(INetHandler handler) {
        this.processPacket((INetHandlerAuthServer) handler);
    }

    @Override
    public boolean hasPriority() {
        return true;
    }
}
