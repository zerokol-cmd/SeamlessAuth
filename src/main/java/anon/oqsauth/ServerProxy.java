package anon.oqsauth;

import net.minecraft.network.NetworkManager;

import anon.oqsauth.auth.KeyDatabase;
import anon.oqsauth.auth.SecureChannel;
import anon.oqsauth.net.ServerLoginHandler;
import cpw.mods.fml.common.event.FMLPreInitializationEvent;
import cpw.mods.fml.common.event.FMLServerStartingEvent;

public final class ServerProxy extends CommonProxy {

    public static KeyDatabase keyDatabase;

    @Override
    public void preInit(FMLPreInitializationEvent event) {
        super.preInit(event);

        keyDatabase = new KeyDatabase(KeyDatabase.resolve(Config.keyDatabasePath), OqsAuth.LOG);
    }

    @Override
    public void serverStarting(FMLServerStartingEvent event) {
        event.registerServerCommand(new ServerCommand());
    }

    @Override
    public SecureChannel findSession(NetworkManager network) {
        return ServerLoginHandler.SESSIONS.get(network);
    }

    @Override
    public void removeSession(NetworkManager network) {
        ServerLoginHandler.SESSIONS.remove(network);
    }
}
