package anon.oqsauth;

import java.io.IOException;

import net.minecraft.network.NetworkManager;
import net.minecraftforge.client.ClientCommandHandler;

import anon.oqsauth.auth.Keystore;
import anon.oqsauth.auth.SecureChannel;
import anon.oqsauth.net.ClientLoginHandler;
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

    @Override
    public SecureChannel findSession(NetworkManager network) {
        return ClientLoginHandler.SESSION.get();
    }

    @Override
    public void removeSession(NetworkManager network) {
        ClientLoginHandler.SESSION.set(null);
    }
}
