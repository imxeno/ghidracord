package pl.piotradamczyk.ghidracord;

import ghidra.Ghidra;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
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
		super(tool, true, true);
	}

	@Override
	public void init() {
		super.init();
		DiscordEventHandlers discordEventHandlers = new DiscordEventHandlers.Builder()
				.setReadyEventHandler((user) -> System.out.println("Connected to Discord account: "
						+ user.username + "#" + user.discriminator + "!")).build();
		DiscordRPC.discordInitialize("948701935735799878", discordEventHandlers, true);
		this.updateRichPresence(this.getCurrentProgram());
	}

	@Override
	public void cleanup() {
		super.cleanup();
		DiscordRPC.discordShutdown();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if(event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent programOpenedPluginEvent = (ProgramOpenedPluginEvent) event;
			this.updateRichPresence(programOpenedPluginEvent.getProgram());
		} else if (event instanceof ProgramClosedPluginEvent) {
			this.updateRichPresence(null);
		}
	}

	private void updateRichPresence(Program program) {
		DiscordRichPresence.Builder rich = new DiscordRichPresence.Builder(this.getTool().getToolName())
				.setBigImage("logo", "Ghidra")
				.setStartTimestamps(System.currentTimeMillis());
		this.setSmallIcon(rich);
		if(program != null) {
			rich.setDetails("Examining \"" + program.getName() + "\"");
		} else {
			rich.setDetails("Idle");
		}
		DiscordRPC.discordUpdatePresence(rich.build());
	}

	private void setSmallIcon(DiscordRichPresence.Builder builder) {
		switch(this.getTool().getName()) {
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
