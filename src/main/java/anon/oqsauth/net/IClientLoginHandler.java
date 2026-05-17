package anon.oqsauth.net;

import net.minecraft.network.login.INetHandlerLoginClient;

public interface IClientLoginHandler extends INetHandlerLoginClient {

    void handleServerHello(ServerHello packet);
}
