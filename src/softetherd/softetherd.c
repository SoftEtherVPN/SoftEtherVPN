//  SoftEther VPN daemon for upstart and systemd.
//
//  Copyright 2014 Darik Horn <dajhorn@vanadac.com>
//
//  This file is part of SoftEther.
//
//  SoftEther is free software: you can redistribute it and/or modify it under
//  the terms of the GNU General Public License as published by the Free 
//  Software Foundation, either version 2 of the License, or (at your option)
//  any later version.
//
//  SoftEther is distributed in the hope that it will be useful, but WITHOUT ANY
//  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
//  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License along with
//  SoftEther.  If not, see <http://www.gnu.org/licenses/>.


#include <GlobalConst.h>

#define	VPN_EXE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

void DaemonUsage(char *name)
{
	UniPrint(_UU("UNIX_DAEMON_HELP"), name, name, name);
}


void DaemonStartProcess()
{
	// This environment variable is exported by upstart.
	char *upstart_job = getenv("UPSTART_JOB");

	InitCedar();
	StInit();
	StStartServer(false);

	// Notify upstart that softetherd is ready.
	if (upstart_job != NULL)
	{
		unsetenv("UPSTART_JOB");
		raise(SIGSTOP);
	}
}


void DaemonStopProcess()
{
	StStopServer();
	StFree();
	FreeCedar();
}


int main(int argc, char *argv[])
{
	// This environment variable is sourced and exported by the init process from /etc/default/softether.
	char *softether_mode = getenv("SOFTETHER_MODE");

	InitMayaqua(false, false, argc, argv);

	// Check for an explicit invocation. (eg: "/usr/sbin/softetherd vpnserver")
	if (argc >= 2)
	{
		if (StrCmpi(argv[1], "vpnbridge") == 0
		 || StrCmpi(argv[1], "vpnclient") == 0
		 || StrCmpi(argv[1], "vpnserver") == 0)
		{
			UnixExecService(argv[1], DaemonStartProcess, DaemonStopProcess);
			FreeMayaqua();
			return 0;
		}

		// Exit status codes 150..199 are reserved for the application by the LSB.
		fprintf(stderr, "Error: Unrecognized parameter: %s\n", argv[1]);
		fflush(stderr);
		FreeMayaqua();
		return 150;
	}

	// Alternatively, use the environment variable.
	if (softether_mode != NULL)
	{
		if (StrCmpi(softether_mode, "vpnbridge") == 0 
		 || StrCmpi(softether_mode, "vpnclient") == 0
		 || StrCmpi(softether_mode, "vpnserver") == 0)
		{
			UnixExecService(softether_mode, DaemonStartProcess, DaemonStopProcess);
			FreeMayaqua();
			return 0;
		}

		// Exit status codes 150..199 are reserved for the application by the LSB.
		fprintf(stderr, "Error: Unrecognized environment variable: SOFTETHER_MODE=%s\n", softether_mode);
		fflush(stderr);
		FreeMayaqua();
		return 151;
	}

	DaemonUsage(argv[0]);
	FreeMayaqua();
	return 3;
}
