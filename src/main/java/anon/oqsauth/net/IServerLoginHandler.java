package anon.oqsauth.net;

import net.minecraft.network.login.INetHandlerLoginServer;

public interface IServerLoginHandler extends INetHandlerLoginServer {

    void handleClientAuthResponse(ClientAuthResponse packet);
}
