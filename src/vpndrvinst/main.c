#include "Device.h"
#include "Dialog.h"

#include <stdio.h>

void ShowUsage()
{
	const char *message =
		"Usage: vpndrvinst <action> <instance>\n"
		"\n"
		"\"instvlan\": Installs a new virtual network interface\n"
		"\"uninstvlan\": Uninstalls an existing virtual network interface\n"
		"\"upgradevlan\": Updates the driver for an existing virtual network interface\n"
		"\"enablevlan\": Enables an existing virtual network interface\n"
		"\"disablevlan\": Disables an existing virtual network interface\n"
		"\n"
		"Example: vpndrvinst instvlan VPN21";

	ShowInformation("Usage", message);
}

int main(const int argc, const char **argv)
{
	if (argc < 3)
	{
		ShowUsage();
		return 0;
	}

	bool ok = true;

	const char* action = argv[1];
	if (strcmp(action, "instvlan") == 0)
	{
		ok = InstallDevice(argv[2]);
	}
	else if (strcmp(action, "uninstvlan") == 0)
	{
		ok = UninstallDevice(argv[2]);
	}
	else if (strcmp(action, "upgradevlan") == 0)
	{
		ok = UpgradeDevice(argv[2]);
	}
	else if (strcmp(action, "enablevlan") == 0)
	{
		ok = ToggleDevice(argv[2], true);
	}
	else if (strcmp(action, "disablevlan") == 0)
	{
		ok = ToggleDevice(argv[2], false);
	}
	else
	{
		ShowUsage();
	}

	return ok ? 0 : 1;
}
