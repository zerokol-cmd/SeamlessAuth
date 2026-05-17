package anon.oqsauth;

import anon.oqsauth.auth.KeyDatabase;
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
}
