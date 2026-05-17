package anon.oqsauth;

import net.minecraft.command.CommandBase;
import net.minecraft.command.ICommandSender;
import net.minecraft.util.ChatComponentText;

public final class ServerCommand extends CommandBase {

    @Override
    public int getRequiredPermissionLevel() {
        return 4;
    }

    @Override
    public String getCommandName() {
        return "oqsauth_server";
    }

    @Override
    public String getCommandUsage(ICommandSender sender) {
        return "/" + getCommandName() + " <reload-config|reload-keys>";
    }

    @Override
    public void processCommand(ICommandSender sender, String[] args) {
        if (args.length != 1) {
            sender.addChatMessage(new ChatComponentText("usage: " + getCommandUsage(sender)));
            return;
        }
        switch (args[0]) {
            case "reload-config":
                Config.load(null);
                sender.addChatMessage(new ChatComponentText("oqsauth config reloaded"));
                return;
            case "reload-keys":
                ServerProxy.keyDatabase.reload();
                sender.addChatMessage(new ChatComponentText("oqsauth keys reloaded"));
                return;
            default:
                sender.addChatMessage(new ChatComponentText("usage: " + getCommandUsage(sender)));
        }
    }
}
