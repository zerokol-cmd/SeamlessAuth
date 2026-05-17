package anon.oqsauth;

import java.io.IOException;

import net.minecraftforge.client.ClientCommandHandler;

import anon.oqsauth.auth.Keystore;
import cpw.mods.fml.common.FMLCommonHandler;
import cpw.mods.fml.common.event.FMLInitializationEvent;
import cpw.mods.fml.common.event.FMLPreInitializationEvent;

public final class ClientProxy extends CommonProxy {

    public static Keystore keystore;

    @Override
    public void preInit(FMLPreInitializationEvent event) {
        super.preInit(event);

        keystore = new Keystore(Keystore.resolve(Config.keystorePath));
        try {
            keystore.ensureIdentity(Config.signatureAlgorithm);
            OqsAuth.LOG.info("client keystore ready ({})", Config.signatureAlgorithm);
        } catch (IOException e) {
            OqsAuth.LOG.fatal("failed to initialize client keystore", e);
            FMLCommonHandler.instance()
                .exitJava(1, false);
        }
    }

    @Override
    public void init(FMLInitializationEvent event) {
        ClientCommandHandler.instance.registerCommand(new ClientCommand());
    }
}
