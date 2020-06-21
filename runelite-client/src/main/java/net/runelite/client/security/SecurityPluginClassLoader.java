package net.runelite.client.security;

import java.io.File;
import java.io.FilePermission;
import java.net.JarURLConnection;
import java.net.SocketPermission;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.PrivilegedAction;
import lombok.Getter;
import org.pf4j.PluginClassLoader;
import org.pf4j.PluginDescriptor;
import org.pf4j.PluginManager;

public class SecurityPluginClassLoader extends PluginClassLoader
{
	private final AccessControlContext acc;
	@Getter
	private final PluginDescriptor pluginDescriptor;

	public SecurityPluginClassLoader(PluginManager pluginManager, PluginDescriptor pluginDescriptor, ClassLoader parent)
	{
		super(pluginManager, pluginDescriptor, parent);
		this.acc = AccessController.getContext();
		this.pluginDescriptor = pluginDescriptor;
	}

	public SecurityPluginClassLoader(PluginManager pluginManager, PluginDescriptor pluginDescriptor, ClassLoader parent, boolean parentFirst)
	{
		super(pluginManager, pluginDescriptor, parent, parentFirst);
		this.acc = AccessController.getContext();
		this.pluginDescriptor = pluginDescriptor;
	}

	static Permission getPermissionForURL(URL url) {
		Permission p;
		URLConnection urlConnection;

		try {
			urlConnection = url.openConnection();
			p = urlConnection.getPermission();
		} catch (java.io.IOException ioe) {
			p = null;
			urlConnection = null;
		}

		if (p instanceof FilePermission) {
			// if the permission has a separator char on the end,
			// it means the codebase is a directory, and we need
			// to add an additional permission to read recursively
			String path = p.getName();
			if (path.endsWith(File.separator)) {
				path += "-";
				p = new FilePermission(path, "read");
			}
		} else if ((p == null) && (url.getProtocol().equals("file"))) {
			throw new UnsupportedOperationException();
		} else {
			/**
			 * Not loading from a 'file:' URL so we want to give the class
			 * permission to connect to and accept from the remote host
			 * after we've made sure the host is the correct one and is valid.
			 */
			URL locUrl = url;
			if (urlConnection instanceof JarURLConnection) {
				locUrl = ((JarURLConnection)urlConnection).getJarFileURL();
			}
			String host = locUrl.getHost();
			if (host != null && (host.length() > 0))
				p = new SocketPermission(host, "connect,accept");
		}

		return p;
	}

	@Override
	protected PermissionCollection getPermissions(CodeSource codesource)
	{
		// The permission to access the codesource
		PermissionCollection permissions = super.getPermissions(codesource);

		// We also need to add the additional resources to this
		for (URL url : getURLs())
		{
			if (url.equals(codesource.getLocation()))
			{
				// This is already handled by super#getPermissions
				continue;
			}

			Permission p = getPermissionForURL(url);

			// make sure the person that created this class loader
			// would have this permission
			if (p != null) {
				final SecurityManager sm = System.getSecurityManager();
				if (sm != null) {
					final Permission fp = p;
					AccessController.doPrivileged(new PrivilegedAction<>() {
						public Void run() throws SecurityException {
							sm.checkPermission(fp);
							return null;
						}
					}, acc);
				}
				permissions.add(p);
			}
		}


		return permissions;
	}
}
