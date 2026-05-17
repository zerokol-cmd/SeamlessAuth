package anon.oqsauth;

import net.minecraft.command.CommandBase;
import net.minecraft.command.ICommandSender;
import net.minecraft.util.ChatComponentText;
import net.minecraft.util.EnumChatFormatting;

public final class ClientCommand extends CommandBase {

    @Override
    public int getRequiredPermissionLevel() {
        return 0;
    }

    @Override
    public String getCommandName() {
        return "oqsauth";
    }

    @Override
    public String getCommandUsage(ICommandSender sender) {
        return "/" + getCommandName() + " reload-config";
    }

    @Override
    public void processCommand(ICommandSender sender, String[] args) {
        if (args.length != 1 || !"reload-config".equals(args[0])) {
            sender.addChatMessage(new ChatComponentText(EnumChatFormatting.RED + "usage: " + getCommandUsage(sender)));
            return;
        }
        Config.load(null);
        sender.addChatMessage(new ChatComponentText("oqsauth config reloaded"));
    }
}
