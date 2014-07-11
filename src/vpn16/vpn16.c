// SoftEther VPN Source Code
// 16-bit Driver Install Utility for Windows 9x
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


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



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
