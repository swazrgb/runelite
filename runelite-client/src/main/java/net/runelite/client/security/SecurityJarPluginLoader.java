package net.runelite.client.security;

import java.nio.file.Path;
import org.pf4j.JarPluginLoader;
import org.pf4j.PluginClassLoader;
import org.pf4j.PluginDescriptor;
import org.pf4j.PluginManager;

public class SecurityJarPluginLoader extends JarPluginLoader
{
	public SecurityJarPluginLoader(PluginManager pluginManager)
	{
		super(pluginManager);
	}

	@Override
	public ClassLoader loadPlugin(Path pluginPath, PluginDescriptor pluginDescriptor) {
		PluginClassLoader pluginClassLoader = new SecurityPluginClassLoader(pluginManager, pluginDescriptor, getClass().getClassLoader());
		pluginClassLoader.addFile(pluginPath.toFile());

		return pluginClassLoader;
	}
}
