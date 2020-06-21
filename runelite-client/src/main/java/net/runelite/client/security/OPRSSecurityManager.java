package net.runelite.client.security;

import com.google.gson.Gson;
import com.google.inject.Injector;
import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

public class OPRSSecurityManager extends SecurityManager
{
	private final ProtectionDomain jvmProtectionDomain = Class.class.getProtectionDomain();
	private final List<BlessedInvocation> blessedInvocations = Collections.unmodifiableList(createBlessedInvocations());

	private List<BlessedInvocation> createBlessedInvocations()
	{
		ProtectionDomain guice = Injector.class.getProtectionDomain();
		ProtectionDomain gson = Gson.class.getProtectionDomain();

		return Arrays.asList(
			new BlessedInvocation(guice, "accessDeclaredMembers", "suppressAccessChecks"),
			new BlessedInvocation(gson, "accessDeclaredMembers", "suppressAccessChecks", "accessClassInPackage.sun.misc")
		);
	}

	@Override
	public void checkPermission(Permission perm)
	{
		try
		{
			super.checkPermission(perm);
		}
		catch (SecurityException e)
		{
			// First check if this permission can be blessed (performance)
			boolean canBless = false;
			outer:
			for (BlessedInvocation blessedInvocation : blessedInvocations)
			{
				for (String s : blessedInvocation.getPermission())
				{
					if (s.equals(perm.getName()))
					{
						canBless = true;
						break outer;
					}
				}
			}

			if (!canBless)
			{
				throw e;
			}

			Class<?>[] classContext = getClassContext();
			boolean blessed = AccessController.doPrivileged((PrivilegedAction<Boolean>) () -> {
				for (int i = 1; i < classContext.length; i++)
				{
					ProtectionDomain protectionDomain = classContext[i].getProtectionDomain();

					for (BlessedInvocation blessedInvocation : blessedInvocations)
					{
						if (!protectionDomain.equals(blessedInvocation.getProtectionDomain()))
						{
							continue;
						}

						for (String s : blessedInvocation.getPermission())
						{
							if (s.equals(perm.getName()))
							{
								return true;
							}
						}
					}

					if (!jvmProtectionDomain.equals(protectionDomain))
					{
						return false;
					}
				}

				return false;
			});

			if (!blessed)
			{
				throw e;
			}
		}
	}

	@Getter
	@EqualsAndHashCode
	@ToString
	private static class BlessedInvocation
	{
		private final ProtectionDomain protectionDomain;
		private final String[] permission;

		private BlessedInvocation(ProtectionDomain protectionDomain, String... permission)
		{
			this.protectionDomain = protectionDomain;
			this.permission = permission;
		}
	}

}
