package pl.piotradamczyk.ghidracord;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import net.arikia.dev.drpc.DiscordEventHandlers;
import net.arikia.dev.drpc.DiscordRPC;
import net.arikia.dev.drpc.DiscordRichPresence;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidracord",
	category = "Experimental",
	shortDescription = "Discord Rich Presence for Ghidra!",
	description = "Discord Rich Presence for Ghidra!"
)
//@formatter:on
public class GhidracordPlugin extends ProgramPlugin {

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public GhidracordPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        super.init();
        DiscordEventHandlers discordEventHandlers = new DiscordEventHandlers.Builder()
                .setReadyEventHandler((user) -> System.out.println("Connected to Discord account: "
                        + user.username + "#" + user.discriminator + "!")).build();
        DiscordRPC.discordInitialize("948701935735799878", discordEventHandlers, true);
        updatePresenceInfo();
    }

    @Override
    public void cleanup() {
        super.cleanup();
        DiscordRPC.discordShutdown();
    }

    private void updatePresenceInfo() {
        Program currentProgram = this.getCurrentProgram();
        if (currentProgram == null) {
            this.updateRichPresence(null, null);
            return;
        }

        String desc = switch (this.getTool().getName()) {
            case "CodeBrowser" -> "Examining \"";
            case "Debugger" -> "Debugging \"";
            case "Version Tracking" -> "Version Tracking \"";
            default -> "Examining \"";
        } + currentProgram.getName() + "\"";

        String status = null;
        if (this.getTool().getToolName().equals("CodeBrowser")) {// current function name
            Address currentAddress = this.currentLocation.getAddress();
            if (currentAddress != null) {
                FunctionManager functionManager = currentProgram.getFunctionManager();
                if (functionManager != null) {
                    Function currentFunc = functionManager.getFunctionContaining(currentAddress);
                    if (currentFunc != null) {
                        long offset = this.currentLocation.getAddress().getOffset();
                        status = currentFunc.getName() + " + 0x" + Long.toHexString(offset);
                    }
                }
            }
        }

        this.updateRichPresence(desc, status);
    }

    @Override
    protected void programOpened(Program program) {
        super.programOpened(program);

        updatePresenceInfo();
    }

    @Override
    protected void programClosed(Program program) {
        super.programClosed(program);

        updatePresenceInfo();
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        super.locationChanged(loc);

        updatePresenceInfo();
    }

    @Override
    protected void selectionChanged(ProgramSelection sel) {
        super.selectionChanged(sel);

        updatePresenceInfo();
    }

    @Override
    protected void highlightChanged(ProgramSelection hl) {
        super.highlightChanged(hl);

        updatePresenceInfo();
    }

    private void updateRichPresence(String programStatus, String subStatus) {
        String program = programStatus == null ? "Idle" : programStatus;
        String sub = subStatus == null ? "" : subStatus;
        DiscordRichPresence.Builder rich = new DiscordRichPresence.Builder(subStatus)
                .setBigImage("logo", "Ghidra")
                .setStartTimestamps(System.currentTimeMillis());
        this.setSmallIcon(rich);

        rich.setDetails(programStatus);

        DiscordRPC.discordUpdatePresence(rich.build());
    }

    private void setSmallIcon(DiscordRichPresence.Builder builder) {
        switch (this.getTool().getName()) {
            case "CodeBrowser":
                builder.setSmallImage("codebrowser", "CodeBrowser");
                return;
            case "Debugger":
                builder.setSmallImage("debugger", "Debugger");
                return;
            case "Version Tracking":
                builder.setSmallImage("version-tracking", "Version Tracking");
                return;
        }
    }
}
