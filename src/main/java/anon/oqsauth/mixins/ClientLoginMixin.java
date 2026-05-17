package anon.oqsauth.mixins;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiScreen;
import net.minecraft.client.network.NetHandlerLoginClient;
import net.minecraft.network.EnumConnectionState;
import net.minecraft.network.NetworkManager;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import anon.oqsauth.OqsAuth;
import anon.oqsauth.net.ClientLoginHandler;

@Mixin(NetHandlerLoginClient.class)
public abstract class ClientLoginMixin {

    @Shadow
    private NetworkManager field_147393_d;
    @Shadow
    private Minecraft field_147394_b;
    @Shadow
    private GuiScreen field_147395_c;

    @Inject(
        at = @At("HEAD"),
        method = "onConnectionStateTransition(Lnet/minecraft/network/EnumConnectionState;Lnet/minecraft/network/EnumConnectionState;)V")
    public void swapInOqsHandler(EnumConnectionState oldState, EnumConnectionState newState, CallbackInfo ci) {
        if (oldState != null || newState != null) return;
        OqsAuth.LOG.info("server hello received, switching to OQS auth handler");
        field_147393_d.setNetHandler(new ClientLoginHandler(field_147393_d, field_147394_b, field_147395_c));
    }
}
