package anon.oqsauth;

import net.minecraft.network.EnumConnectionState;

import anon.oqsauth.net.ClientAuthResponse;
import anon.oqsauth.net.ServerHello;
import cpw.mods.fml.common.event.FMLInitializationEvent;
import cpw.mods.fml.common.event.FMLPostInitializationEvent;
import cpw.mods.fml.common.event.FMLPreInitializationEvent;
import cpw.mods.fml.common.event.FMLServerStartingEvent;

public class CommonProxy {

    public void preInit(FMLPreInitializationEvent event) {
        OqsAuth.LOG.info("{} ({}) loading...", Tags.MODNAME, Tags.VERSION);
        Config.load(event.getSuggestedConfigurationFile());

        EnumConnectionState.LOGIN.func_150751_a(2, ClientAuthResponse.class);
        EnumConnectionState.LOGIN.func_150756_b(3, ServerHello.class);
    }

    public void init(FMLInitializationEvent event) {}

    public void postInit(FMLPostInitializationEvent event) {}

    public void serverStarting(FMLServerStartingEvent event) {}
}
