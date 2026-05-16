package anon.seamlessauth.auth.network.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiScreen;
import net.minecraft.client.network.NetHandlerLoginClient;
import net.minecraft.network.NetworkManager;
import net.minecraft.util.ChatComponentText;

import anon.seamlessauth.ClientProxy;
import anon.seamlessauth.SeamlessAuth;
import anon.seamlessauth.auth.network.packet.ChallengeRequest;
import anon.seamlessauth.auth.network.packet.ChallengeResponse;
import anon.seamlessauth.auth.network.packet.KeyRequest;
import anon.seamlessauth.auth.network.packet.KeyResponse;
import io.netty.util.concurrent.GenericFutureListener;

public class NetHandlerAuthClient extends NetHandlerLoginClient implements INetHandlerAuthClient {

    public NetHandlerAuthClient(NetworkManager p_i45059_1_, Minecraft p_i45059_2_, GuiScreen p_i45059_3_) {
        super(p_i45059_1_, p_i45059_2_, p_i45059_3_);
    }

    @Override
    public void handleKeyRequest(KeyRequest packetIn) {
        // We now send the entire map of supported keys (RSA + Post-Quantum)
        field_147393_d.scheduleOutboundPacket(
            new KeyResponse(ClientProxy.keyManager.getPublicKeys()),
            new GenericFutureListener[0]);
    }

    @Override
    public void handleChallengeRequest(ChallengeRequest packetIn) {
        byte[] multiPayload = packetIn.payload;
        byte[] responsePayload;

        try {
            responsePayload = ClientProxy.keyManager.processChallenge(multiPayload);
        } catch (Exception e) {
            SeamlessAuth.LOG.warn("failed to process server challenge", e);
            field_147393_d.closeChannel(new ChatComponentText("failed to process authentication challenge!"));
            return;
        }

        SeamlessAuth.LOG.info("Challenge processed successfully, responding to server...");

        field_147393_d.scheduleOutboundPacket(new ChallengeResponse(responsePayload), new GenericFutureListener[0]);
    }
}
