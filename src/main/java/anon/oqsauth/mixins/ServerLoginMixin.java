package anon.oqsauth.mixins;

import net.minecraft.network.NetworkManager;
import net.minecraft.network.login.client.C00PacketLoginStart;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.NetHandlerLoginServer;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import com.mojang.authlib.GameProfile;

import anon.oqsauth.OqsAuth;
import anon.oqsauth.net.ServerHello;
import anon.oqsauth.net.ServerLoginHandler;

@Mixin(NetHandlerLoginServer.class)
public abstract class ServerLoginMixin {

    @Shadow
    public abstract void func_147322_a(String reason);

    @Shadow
    private NetHandlerLoginServer.LoginState field_147328_g;
    @Shadow
    public MinecraftServer field_147327_f;
    @Shadow
    public NetworkManager field_147333_a;
    @Shadow
    public GameProfile field_147337_i;

    @Inject(at = @At("RETURN"), method = "processLoginStart(Lnet/minecraft/network/login/client/C00PacketLoginStart;)V")
    public void interceptLoginStart(C00PacketLoginStart packet, CallbackInfo ci) {
        if (field_147328_g != NetHandlerLoginServer.LoginState.READY_TO_ACCEPT || field_147333_a.isLocalChannel())
            return;

        OqsAuth.LOG.info("sending OQS ServerHello to {}", field_147337_i.getName());
        field_147328_g = NetHandlerLoginServer.LoginState.AUTHENTICATING;
        ServerLoginHandler handler = new ServerLoginHandler(field_147327_f, field_147333_a, field_147337_i);
        field_147333_a.setNetHandler(handler);
        ServerHello hello = handler.buildHello();
        handler.sendHello(hello);
    }
}
