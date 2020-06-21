package net.runelite.client.security;

import java.awt.AWTPermission;
import java.io.File;
import java.io.FilePermission;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.SocketPermission;
import java.net.URL;
import java.security.AccessController;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.PropertyPermission;
import lombok.extern.slf4j.Slf4j;
import net.runelite.client.RuneLite;
import org.pf4j.PluginDescriptor;

@Slf4j
public class OPRSPolicy extends Policy
{

	/**
	 * Janky workaround to clear the default Policy, which gets configured when Policy#getPolicy is invoked prior to
	 * our Policy#setPolicy, which unfortunately happens when ran from Gradle.
	 *
	 * @return whether the default policy was cleared. Will be false if the JVM is incompatible or an existing
	 * SecurityManager blocked this.
	 */
	public static boolean clearDefaultPolicy()
	{
		try
		{
			Field policyInfoField = Policy.class.getDeclaredField("policyInfo");
			policyInfoField.setAccessible(true);

			Object policyInfo = policyInfoField.get(null);
			Class<?> policyInfoClazz = policyInfo.getClass();

			Constructor<?> policyInfoConstructor = policyInfoClazz.getDeclaredConstructors()[0];
			policyInfoConstructor.setAccessible(true);

			policyInfoField.set(null, policyInfoConstructor.newInstance(null, false));
			return true;
		}
		catch (ReflectiveOperationException | SecurityException e)
		{
			log.warn("Could not clear default SecurityManager policy.", e);
			return false;
		}
	}

	/**
	 * Configures the JVM to use this Policy
	 */
	public static void useSecurity()
	{
		boolean clearedSecurityPolicy = clearDefaultPolicy();
		Policy.setPolicy(new OPRSPolicy());
		System.setSecurityManager(new OPRSSecurityManager());

		// Tests if we're experiencing the Policy#getPolicy bug - https://stackoverflow.com/a/53188052
		try
		{
			System.getProperty("user.home");
		}
		catch (SecurityException e)
		{
			throw new IllegalStateException(String.format(
				"SecurityManager could not be configured successfully. The default security policy %s cleared.",
				clearedSecurityPolicy ? "was" : "was not"
			), e);
		}
	}

//	private Collection<Permission> pluginPermissions = calculatePluginPermissions();

	@Override
	public PermissionCollection getPermissions(ProtectionDomain domain)
	{
		if (isPlugin(domain))
		{
			return pluginPermissions(((SecurityPluginClassLoader) domain.getClassLoader()).getPluginDescriptor());
		}
		else
		{
			return applicationPermissions();
		}
	}

	private boolean isBlessedPlugin(PluginDescriptor pluginDescriptor)
	{
		return isPlugin(pluginDescriptor, "gpu");
	}

	private boolean isPlugin(PluginDescriptor pluginDescriptor, String provider, String id)
	{
		return provider.equals(pluginDescriptor.getProvider()) && (id + "-plugin").equals(pluginDescriptor.getPluginId());
	}

	private boolean isPlugin(PluginDescriptor pluginDescriptor, String id)
	{
		return isPlugin(pluginDescriptor, "OpenOSRS", id);
	}

	private boolean isPlugin(ProtectionDomain domain)
	{
		if (!(domain.getClassLoader() instanceof SecurityPluginClassLoader))
		{
			return false;
		}

		SecurityPluginClassLoader classLoader = (SecurityPluginClassLoader) domain.getClassLoader();

		PluginDescriptor pluginDescriptor = classLoader.getPluginDescriptor();
		return !isBlessedPlugin(pluginDescriptor);
	}

	private PermissionCollection pluginPermissions(PluginDescriptor pluginDescriptor)
	{
		Permissions permissions = new Permissions();

		AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
			// Allow reading all properties
			permissions.add(new PropertyPermission("*", "read"));


			// TODO hacky workaround to grant access to resources. Improve?
			URL resource = getClass().getResource("/logback.xml");
			Permission p = SecurityPluginClassLoader.getPermissionForURL(resource);
			String path = p.getName().replaceAll("logback\\.xml$", "-");
			permissions.add(new FilePermission(path, "read"));

			permissions.add(new FilePermission(RuneLite.RUNELITE_DIR.getPath(), "read"));
			permissions.add(new FilePermission(RuneLite.RUNELITE_DIR.getPath() + File.separator + "-", "read,write,delete"));

			permissions.add(new AWTPermission("setWindowAlwaysOnTop"));

			if (isPlugin(pluginDescriptor, "newsfeed"))
			{
				permissions.add(new SocketPermission("pbs.twimg.com", "resolve,connect"));
			}

			return null;
		});


		return permissions;
	}

	private PermissionCollection applicationPermissions()
	{
		Permissions permissions = new Permissions();
		permissions.add(new AllPermission());
		return permissions;
	}
}
