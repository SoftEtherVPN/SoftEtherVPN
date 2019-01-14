// SoftEther VPN Source Code - Developer Edition Master Branch
// 16-bit Driver Install Utility for Windows 9x


// vpn16.c
// 16-bit Driver Install Utility for Windows 9x

// ----------------------------------------------------------------------------------
// A part of this file is from Microsoft Windows 98 DDK.
// Copyright (c) 1996, Microsoft Corporation. All Rights Reserved.
// 
// Windows 98 Driver Development Kit  License.txt:
// * SAMPLE CODE.  You may modify the sample source code ("Sample Code")
//  included with the SOFTWARE PRODUCT to design, develop and test your Application.
// ----------------------------------------------------------------------------------


#include <windows.h>
#include <setupx.h>
#include <winerror.h>
#include <regstr.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "vpn16.h"

void GetDirFromPath(char *dst, char *src)
{
	char str[MAX_PATH];
	int i,len;
	char c;
	char tmp[MAX_PATH];
	int wp;
	if (src)
	{
		strcpy(str, src);
	}
	else
	{
		strcpy(str, dst);
	}
	NukuEn(str, NULL);
	wp = 0;
	len = strlen(str);
	dst[0] = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		switch (c)
		{
		case '\\':
			tmp[wp] = 0;
			wp = 0;
			strcat(dst, tmp);
			strcat(dst, "\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	NukuEn(dst, NULL);
}

void NukuEn(char *dst, char *src)
{
	char str[MAX_PATH];
	int i;
	if (src)
	{
		strcpy(str, src);
	}
	else
	{
		strcpy(str, dst);
	}
	i = strlen(str);
	if (str[i - 1] == '\\')
	{
		str[i - 1] = 0;
	}
	strcpy(dst, str);
}

void Print(char *fmt, ...)
{
	char tmp[260];
	va_list args;
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	_vsnprintf(tmp, sizeof(tmp), fmt, args);

	MessageBox(NULL, tmp, "SoftEther VPN 16-bit Utility", MB_ICONEXCLAMATION);
	va_end(args);
}

BOOL IsFile(char *name)
{
	HFILE h;
	if (name == NULL)
	{
		return FALSE;
	}

	h = _lopen(name, OF_READ);
	if (h == HFILE_ERROR)
	{
		return FALSE;
	}
	_lclose(h);

	return TRUE;
}

void InstallMain(char *name)
{
	char sysdir[MAX_PATH];
	char windir[MAX_PATH];
	char infdir[MAX_PATH];
	char otherdir[MAX_PATH];
	char infname[MAX_PATH];
	char deviceid[MAX_PATH];
	char sysname[MAX_PATH];
	if (name == NULL)
	{
		return;
	}
	if (strlen(name) == 0 || strlen(name) >= 5)
	{
		return;
	}

	GetSystemDirectory(sysdir, sizeof(sysdir));

	GetDirFromPath(windir, sysdir);

	sprintf(infdir, "%s\\inf", windir);

	sprintf(otherdir, "%s\\other", infdir);

	sprintf(infname, "%s\\Neo_%s.inf", infdir, name);

	sprintf(sysname, "%s\\Neo_%s.sys", sysdir, name);

	sprintf(deviceid, "NeoAdapter_%s", name);

	if (IsFile(infname) == FALSE)
	{
		Print("Failed to open %s.", infname);
		return;
	}
	if (IsFile(sysname) == FALSE)
	{
		Print("Failed to open %s.", sysname);
		return;
	}

	if (DiInstallClass(infname, 0) != OK)
	{
		Print("Failed to register %s.\n", infname);
		return;
	}

	if (InstallNDIDevice("Net", deviceid, NULL, NULL) != OK)
	{
		return;
	}
}

void Test()
{
	char *inf = "c:\\windows\\inf\\other\\Neo_TEST.inf";

	if (DiInstallClass(inf, 0) == OK)
	{
		Print("DiInstallClass Ok.");
		if (InstallNDIDevice("Net", "NeoAdapter_TEST", NULL, NULL) == OK)
		{
			Print("InstallNDIDevice Ok.\n");
		}
		else
		{
			Print("InstallNDIDevice Failed.\n");
		}
	}
	else
	{
		Print("DiInstallClass Failed. ");
	}
}

RETERR InstallNDIDevice(const char* szClass,
						const char* szDeviceID, 
						const char* szDriverPath,
						const char* szRegPath)
{
	char *szClassNetProtocol    = "NetTrans"; 
	char *szClassNet            = "Net";
	char *szClassNetClient      = "NetClient";
	char *szClassNetService		= "NetService";
	char *szNull                = "";
	char *szClassNetInfFileName        = "Net.inf";
	char *szClassNetTransInfFileName   = "Nettrans.inf";
	char *szClassNetClientInfFileName  = "Netcli.inf";
	char *szClassNetServiceInfFileName = "Netservr.inf";
	char *szRegKeyNdi           = "Ndi";
	char *szRegKeyBindings      = "Bindings";
	char *szRegValDeviceID      = "DeviceID";
	char *szRegValDriverDesc	= "DriverDesc";
	char *szRegValCompatibleIDs = REGSTR_VAL_COMPATIBLEIDS;
	char *szRegPathNetwork      = "Enum\\Network\\";
	char *szRegPathFilter       = "Enum\\Filter\\";
	char *szRegPathTemp         = "\\Temp";
	char *szVServer				= "VSERVER";
	LPDEVICE_INFO lpdi = NULL;
	RETERR	      err  = OK;

	err = DiCreateDeviceInfo( &lpdi, NULL, 0, NULL, NULL, szClass, NULL );
	
	if (err == OK)
	{
		HKEY hKeyTmp;
		
		lpdi->hRegKey = HKEY_LOCAL_MACHINE;
		lstrcpy( lpdi->szRegSubkey, szRegPathNetwork );
		lstrcat( lpdi->szRegSubkey, lpdi->szClassName );
		lstrcat( lpdi->szRegSubkey, szRegPathTemp );

		err = DiCreateDevRegKey( lpdi, &hKeyTmp, NULL, NULL, DIREG_DEV );

		if (err == OK)
		{
			if (SURegSetValueEx(hKeyTmp, 
			                      szRegValCompatibleIDs, 
			                      0, 
			                      REG_SZ, 
			                      (unsigned char *) szDeviceID,
			                      lstrlen( szDeviceID ) + 1 ) == ERROR_SUCCESS )
			{
            if ( szDriverPath )
            {
               if ( lpdi->atDriverPath = GlobalAddAtom( szDriverPath ) )
                  lpdi->Flags |= DI_ENUMSINGLEINF;
				}

				err = DiBuildCompatDrvList( lpdi );
				
				SURegCloseKey( hKeyTmp );
				
				DiDeleteDevRegKey( lpdi, DIREG_DEV );
				lpdi->hRegKey = NULL;
				lstrcpy( lpdi->szRegSubkey, szNull );

				if ( err || !lpdi->lpCompatDrvList )
				{
					err = DiSelectDevice( lpdi );		
				}
				else
				{
					lpdi->lpSelectedDriver = lpdi->lpCompatDrvList;
				}
				
				if ( err == OK )
				{
					if ( szRegPath )
					{
						lpdi->hRegKey = HKEY_LOCAL_MACHINE;
						lstrcpy( lpdi->szRegSubkey, szRegPath );
						
						DiCreateDevRegKey( lpdi, &hKeyTmp, NULL, NULL, DIREG_DEV );
					}

					lpdi->Flags |= DI_NOVCP | DI_NOFILECOPY | DI_QUIETINSTALL;
               err = DiCallClassInstaller( DIF_INSTALLDEVICE, lpdi );
				}
            else
            {
               DiDestroyDeviceInfoList( lpdi );
            }
			}
			else
			{
				DiDeleteDevRegKey( lpdi, DIREG_DEV );
            DiDestroyDeviceInfoList( lpdi );
			}
		}
      else
      {
         DiDestroyDeviceInfoList( lpdi );
      }
	}

	return err;		                 
}

BOOL IsSafeChar(char c)
{
	UINT i, len;
	char *check_str =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		" ()-_#%&.";

	len = strlen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL IsSafeStr(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return FALSE;
	}

	len = strlen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeChar(str[i]) == FALSE)
		{
			return FALSE;
		}
	}
	if (str[0] == ' ')
	{
		return FALSE;
	}
	if (len != 0)
	{
		if (str[len - 1] == ' ')
		{
			return FALSE;
		}
	}
	return TRUE;
}

// WinMain
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR CmdLine32, int CmdShow)
{
	char CmdLine[MAX_PATH];
	UINT wp;
	wp = 0;
	while (TRUE)
	{
		CmdLine[wp++] = *CmdLine32;
		if (*CmdLine32 == 0)
		{
			break;
		}
		CmdLine32++;

	}
	if (strlen(CmdLine) == 0 || strlen(CmdLine) >= 5 || IsSafeStr(CmdLine) == FALSE)
	{
		Print("Please execute VPN Client Connection Manager.");
	}
	else
	{
		InstallMain(CmdLine);
	}
	return 0;
}


