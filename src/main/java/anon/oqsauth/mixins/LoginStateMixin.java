package anon.oqsauth.mixins;

import net.minecraft.network.EnumConnectionState;
import net.minecraft.network.Packet;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import anon.oqsauth.net.ClientAuthResponse;
import anon.oqsauth.net.ServerHello;

@Mixin(EnumConnectionState.class)
public class LoginStateMixin {

    @Inject(
        at = @At("HEAD"),
        method = "func_150752_a(Lnet/minecraft/network/Packet;)Lnet/minecraft/network/EnumConnectionState;",
        cancellable = true)
    private static void getFromPacket(Packet packet, CallbackInfoReturnable<EnumConnectionState> ci) {
        if (packet instanceof ServerHello || packet instanceof ClientAuthResponse) {
            ci.setReturnValue(EnumConnectionState.LOGIN);
        }
    }
}
