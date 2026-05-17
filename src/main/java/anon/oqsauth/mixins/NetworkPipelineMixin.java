package anon.oqsauth.mixins;

import net.minecraft.network.EnumConnectionState;
import net.minecraft.network.NetworkManager;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import anon.oqsauth.net.SessionPipeline;
import io.netty.channel.Channel;

@Mixin(NetworkManager.class)
public abstract class NetworkPipelineMixin {

    @Shadow
    private Channel channel;

    @Inject(at = @At("RETURN"), method = "setConnectionState(Lnet/minecraft/network/EnumConnectionState;)V")
    private void installOqsEncryption(EnumConnectionState newState, CallbackInfo ci) {
        if (newState != EnumConnectionState.PLAY) return;
        if (channel == null) return;
        SessionPipeline.install((NetworkManager) (Object) this, channel);
    }
}
