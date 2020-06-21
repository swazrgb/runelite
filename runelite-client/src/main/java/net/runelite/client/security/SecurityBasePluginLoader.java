package net.runelite.client.security;

import java.nio.file.Path;
import org.pf4j.BasePluginLoader;
import org.pf4j.PluginClassLoader;
import org.pf4j.PluginClasspath;
import org.pf4j.PluginDescriptor;
import org.pf4j.PluginManager;

public class SecurityBasePluginLoader extends BasePluginLoader
{
	public SecurityBasePluginLoader(PluginManager pluginManager, PluginClasspath pluginClasspath)
	{
		super(pluginManager, pluginClasspath);
	}

	protected PluginClassLoader createPluginClassLoader(Path pluginPath, PluginDescriptor pluginDescriptor) {
		return new SecurityPluginClassLoader(pluginManager, pluginDescriptor, getClass().getClassLoader());
	}
}
