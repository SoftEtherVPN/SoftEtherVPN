// SoftEther VPN Source Code
// SeLow: SoftEther Lightweight Network Protocol
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


// SeLowUser.c
// SoftEther Lightweight Network Protocol User-mode Library

#include <GlobalConst.h>

#ifdef	WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Install the driver
bool SuInstallDriver(bool force)
{
	bool ret;
	void *wow;

	wow = MsDisableWow64FileSystemRedirection();

	ret = SuInstallDriverInner(force);

	MsRestoreWow64FileSystemRedirection(wow);

	return ret;
}
bool SuInstallDriverInner(bool force)
{
	wchar_t sys_fullpath[MAX_PATH];
	UINT current_sl_ver = 0;
	bool ret = false;
	wchar_t src_cat[MAX_PATH];
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dst_cat[MAX_PATH];
	wchar_t dst_inf[MAX_PATH];
	wchar_t dst_sys[MAX_PATH];
	wchar_t tmp_dir[MAX_PATH];
	char *cpu_type = MsIsX64() ? "x64" : "x86";

	if (SuIsSupportedOs(true) == false)
	{
		// Unsupported OS
		return false;
	}

	CombinePathW(tmp_dir, sizeof(tmp_dir), MsGetWindowsDirW(), L"Temp");
	MakeDirExW(tmp_dir);

	UniStrCat(tmp_dir, sizeof(tmp_dir), L"\\selowtmp");
	MakeDirExW(tmp_dir);

	// Confirm whether the driver is currently installed
	CombinePathW(sys_fullpath, sizeof(sys_fullpath), MsGetSystem32DirW(), L"drivers\\SeLow_%S.sys");
	UniFormat(sys_fullpath, sizeof(sys_fullpath), sys_fullpath, cpu_type);

	if (IsFileExistsW(sys_fullpath))
	{
		char *path;

		// Read the current version from the registry
		current_sl_ver = MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
			(MsIsWindows10() ? SL_REG_VER_VALUE_WIN10 : SL_REG_VER_VALUE),
			false, true);

		path = MsRegReadStrEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "ImagePath", false, true);

		if (IsEmptyStr(path))
		{
			current_sl_ver = 0;
		}

		Free(path);
	}

	if (force == false && current_sl_ver >= SL_VER)
	{
		// Newer version has already been installed
		Debug("Newer SeLow is Installed. %u >= %u\n", current_sl_ver, SL_VER);
		return true;
	}

	// Copy necessary files to a temporary directory
	UniFormat(src_sys, sizeof(src_sys), L"|DriverPackages\\%S\\%S\\SeLow_%S.sys",
		(MsIsWindows10() ? "SeLow_Win10" : "SeLow_Win8"),
		cpu_type, cpu_type);
	if (MsIsWindows8() == false)
	{
		// Windows Vista and Windows 7 uses SHA-1 catalog files
		UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win8\\%S\\inf.cat", cpu_type);
	}
	else
	{
		// Windows 8 or above uses SHA-256 catalog files
		UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win8\\%S\\inf2.cat", cpu_type);

		if (MsIsWindows10())
		{
			// Windows 10 uses WHQL catalog files
			UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win10\\%S\\SeLow_Win10_%S.cat", cpu_type, cpu_type);
		}
	}
	UniFormat(src_inf, sizeof(src_inf), L"|DriverPackages\\%S\\%S\\SeLow_%S.inf",
		(MsIsWindows10() ? "SeLow_Win10" : "SeLow_Win8"),
		cpu_type, cpu_type);

	UniFormat(dst_sys, sizeof(dst_cat), L"%s\\SeLow_%S.sys", tmp_dir, cpu_type);
	UniFormat(dst_cat, sizeof(dst_cat), L"%s\\SeLow_%S_%S.cat", tmp_dir,
		(MsIsWindows10() ? "Win10" : "Win8"),
		cpu_type);
	UniFormat(dst_inf, sizeof(dst_inf), L"%s\\SeLow_%S.inf", tmp_dir, cpu_type);

	if (FileCopyW(src_sys, dst_sys) &&
		FileCopyW(src_cat, dst_cat) &&
		FileCopyW(src_inf, dst_inf))
	{
		NO_WARNING *nw;

		nw = MsInitNoWarningEx(SL_USER_AUTO_PUSH_TIMER);

		// Call the installer
		if (InstallNdisProtocolDriver(dst_inf, L"SeLow", SL_USER_INSTALL_LOCK_TIMEOUT) == false)
		{
			Debug("InstallNdisProtocolDriver Error.\n");
		}
		else
		{
			Debug("InstallNdisProtocolDriver Ok.\n");

			// Copy manually because there are cases where .sys file is not copied successfully for some reason
			FileCopyW(src_sys, sys_fullpath);

			ret = true;

			// Write the version number into the registry
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
				(MsIsWindows10() ? SL_REG_VER_VALUE_WIN10 : SL_REG_VER_VALUE),
				SL_VER, false, true);

			// Set to automatic startup
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "Start", SERVICE_SYSTEM_START, false, true);
		}

		MsFreeNoWarning(nw);
	}
	else
	{
		Debug("Fail Copying Files.\n");
	}

	if (ret)
	{
		// If the service is installed this time, start and wait until the enumeration is completed
		SuFree(SuInitEx(180 * 1000));
	}

	return ret;
}

// Get whether the current OS is supported by SeLow
bool SuIsSupportedOs(bool on_install)
{
	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "EnableSeLow", false, true) != 0)
	{
		// Force enable
		return true;
	}

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "DisableSeLow", false, true) != 0)
	{
		// Force disable
		return false;
	}

	if (MsIsWindows10())
	{
		// Windows 10 or later are always supported.
		return true;
	}

	if (on_install)
	{
		// If Microsoft Routing and Remote Access service is running,
		// then return false.
		if (MsIsServiceRunning("RemoteAccess"))
		{
			return false;
		}
	}

	// If the Su driver is currently running,
	// then return true.
	if (MsIsServiceRunning(SL_PROTOCOL_NAME))
	{
		return true;
	}

	// Currently Windows 8.1 or later are supported
	if (MsIsWindows81() == false)
	{
		return false;
	}

	if (on_install == false)
	{
		// If Microsoft Routing and Remote Access service is running,
		// then return false.
		if (MsIsServiceRunning("RemoteAccess"))
		{
			return false;
		}
	}

	return true;
}

// Write the next packet to the driver
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size)
{
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}

	// First, examine whether the current buffer is full
	if ((SL_NUM_PACKET(a->PutBuffer) >= SL_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && SL_NUM_PACKET(a->PutBuffer) != 0))
	{
		// Write all current packets to the driver
		if (SuPutPacketsToDriver(a) == false)
		{
			return false;
		}

		SL_NUM_PACKET(a->PutBuffer) = 0;
	}

	// Add the next packet to the buffer
	if (buf != NULL)
	{
		UINT i = SL_NUM_PACKET(a->PutBuffer);
		SL_NUM_PACKET(a->PutBuffer)++;

		SL_SIZE_OF_PACKET(a->PutBuffer, i) = size;
		Copy(SL_ADDR_OF_PACKET(a->PutBuffer, i), buf, size);

		Free(buf);
	}

	return true;
}

// Write all current packets to the driver
bool SuPutPacketsToDriver(SU_ADAPTER *a)
{
	DWORD write_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}

	if (WriteFile(a->hFile, a->PutBuffer, SL_EXCHANGE_BUFFER_SIZE, &write_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (write_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Read the next packet from the driver
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size)
{
	// Validate arguments
	if (a == NULL || buf == NULL || size == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	while (true)
	{
		if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
		{
			// There are still packets that have been already read
			*size = SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
			*buf = Malloc(*size);
			Copy(*buf, SL_ADDR_OF_PACKET(a->GetBuffer, a->CurrentPacketCount), *size);

			// Increment the packet number
			a->CurrentPacketCount++;

			return true;
		}
		else
		{
			// Read the next packet from the driver
			if (SuGetPacketsFromDriver(a) == false)
			{
				return false;
			}

			if (SL_NUM_PACKET(a->GetBuffer) == 0)
			{
				// Packet is not received yet
				*buf = NULL;
				*size = 0;
				return true;
			}

			a->CurrentPacketCount = 0;
		}
	}
}

// Read the next packet from the driver
bool SuGetPacketsFromDriver(SU_ADAPTER *a)
{
	DWORD read_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	if (ReadFile(a->hFile, a->GetBuffer, SL_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (read_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Close the adapter
void SuCloseAdapter(SU_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hEvent != NULL)
	{
		CloseHandle(a->hEvent);
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}

	Free(a);
}

// Close the adapter handle
void SuCloseAdapterHandleInner(SU_ADAPTER *a)
{
	return;//////////// ****************
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}
}

// Open the adapter
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id)
{
	char filename[MAX_PATH];
	void *h;
	SU_ADAPTER *a;
	SL_IOCTL_EVENT_NAME t;
	UINT read_size;
	// Validate arguments
	if (u == NULL || adapter_id == NULL)
	{
		return NULL;
	}

	Format(filename, sizeof(filename), SL_ADAPTER_DEVICE_FILENAME_WIN32, adapter_id);

	h = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		Debug("Create File %s failed. %u\n", filename, GetLastError());
		return NULL;
	}
	else
	{
		Debug("Create File %s ok.\n", filename);
	}

	a = ZeroMalloc(sizeof(SU_ADAPTER));

	StrCpy(a->AdapterId, sizeof(a->AdapterId), adapter_id);
	StrCpy(a->DeviceName, sizeof(a->DeviceName), filename);

	a->hFile = h;

	Zero(&t, sizeof(t));

	// Get the event name
	if (DeviceIoControl(h, SL_IOCTL_GET_EVENT_NAME, &t, sizeof(t), &t, sizeof(t), &read_size, NULL) == false)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	Debug("Event Name: %s\n", t.EventNameWin32);

	// Get the event
	a->hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, t.EventNameWin32);

	if (a->hEvent == NULL)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	return a;
}

// Enumerate adapters
TOKEN_LIST *SuEnumAdapters(SU *u)
{
	UINT i;
	UINT ret_size;
	TOKEN_LIST *ret;
	// Validate arguments
	if (u == NULL)
	{
		return NullToken();
	}

	Zero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&ret_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		Debug("SuEnumAdapters: ReadFile error.\n");
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	ret->NumTokens = u->AdapterInfoList.NumAdapters;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	Debug("SuEnumAdapters: u->AdapterInfoList.NumAdapters = %u\n", u->AdapterInfoList.NumAdapters);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyUniToStr(u->AdapterInfoList.Adapters[i].AdapterId);

		UniPrint(L"%s %u %S\n",
			u->AdapterInfoList.Adapters[i].AdapterId,
			u->AdapterInfoList.Adapters[i].MtuSize,
			u->AdapterInfoList.Adapters[i].FriendlyName);
	}

	return ret;
}

// Create an adapters list
LIST *SuGetAdapterList(SU *u)
{
	LIST *ret;
	UINT read_size;
	UINT i;
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	ret = NewList(SuCmpAdaterList);

	// Enumerate adapters
	Zero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&read_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		SuFreeAdapterList(ret);
		return NULL;
	}

	for (i = 0;i < u->AdapterInfoList.NumAdapters;i++)
	{
		SL_ADAPTER_INFO *info = &u->AdapterInfoList.Adapters[i];
		SU_ADAPTER_LIST *a = SuAdapterInfoToAdapterList(info);

		if (a != NULL)
		{
			Add(ret, a);
		}
	}

	// Sort
	Sort(ret);

	return ret;
}

// Comparison function of the adapter list
int SuCmpAdaterList(void *p1, void *p2)
{
	int r;
	SU_ADAPTER_LIST *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(SU_ADAPTER_LIST **)p1;
	a2 = *(SU_ADAPTER_LIST **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	r = StrCmpi(a1->SortKey, a2->SortKey);
	if (r != 0)
	{
		return 0;
	}

	return StrCmpi(a1->Guid, a2->Guid);
}

// Release the adapter list
void SuFreeAdapterList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *a = LIST_DATA(o, i);

		Free(a);
	}

	ReleaseList(o);
}

// Create an adapter list item
SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info)
{
	SU_ADAPTER_LIST t;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (info == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.Info, info, sizeof(SL_ADAPTER_INFO));

	UniToStr(tmp, sizeof(tmp), info->AdapterId);
	if (IsEmptyStr(tmp) || IsEmptyStr(info->FriendlyName) || StartWith(tmp, SL_ADAPTER_ID_PREFIX) == false)
	{
		// Name is invalid
		return NULL;
	}

	// GUID (Part after "SELOW_A_" prefix)
	StrCpy(t.Guid, sizeof(t.Guid), tmp + StrLen(SL_ADAPTER_ID_PREFIX));

	// Name
	StrCpy(t.Name, sizeof(t.Name), tmp);

	// Key for sort
	if (GetClassRegKeyWin32(t.SortKey, sizeof(t.SortKey), tmp, sizeof(tmp), t.Guid) == false)
	{
		// Can not be found
		return NULL;
	}

	return Clone(&t, sizeof(t));
}

// Initialize the driver 
SU *SuInit()
{
	return SuInitEx(0);
}
SU *SuInitEx(UINT wait_for_bind_complete_tick)
{
	void *h;
	SU *u;
	UINT read_size;
	bool flag = false;
	UINT64 giveup_tick = 0;
	bool flag2 = false;

	if (SuIsSupportedOs(false) == false)
	{
		// Unsupported OS
		return NULL;
	}

LABEL_RETRY:

	// Open the device driver
	h = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		Debug("CreateFileA(%s) Failed.\n", SL_BASIC_DEVICE_FILENAME_WIN32);

		// Start the service if it fails to start the device driver
		if (flag == false)
		{
			if (MsStartService(SL_PROTOCOL_NAME) == false)
			{
				Debug("MsStartService(%s) Failed.\n", SL_PROTOCOL_NAME);

				if (MsIsWindows10())
				{
					if (flag2 == false)
					{
						flag2 = true;

						if (SuInstallDriver(true))
						{
							goto LABEL_RETRY;
						}
					}
				}
			}
			else
			{
				Debug("MsStartService(%s) Ok.\n", SL_PROTOCOL_NAME);
				flag = true;

				goto LABEL_RETRY;
			}
		}
		return NULL;
	}

	//Debug("CreateFileA(%s) Ok.\n", SL_BASIC_DEVICE_FILENAME_WIN32);

	u = ZeroMalloc(sizeof(SU));

	giveup_tick = Tick64() + (UINT64)wait_for_bind_complete_tick;

	if (wait_for_bind_complete_tick == 0)
	{
		if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
			u->AdapterInfoList.Signature != SL_SIGNATURE)
		{
			// Signature reception failure
			Debug("Bad Signature.\n");

			Free(u);
			CloseHandle(h);

			return NULL;
		}
	}
	else
	{
		while (giveup_tick >= Tick64())
		{
			// Wait until the enumeration is completed
			if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
				u->AdapterInfoList.Signature != SL_SIGNATURE)
			{
				// Signature reception failure
				Debug("Bad Signature.\n");

				Free(u);
				CloseHandle(h);

				return NULL;
			}

			if (u->AdapterInfoList.EnumCompleted)
			{
				// Complete enumeration
				Debug("Bind Completed! %u\n", u->AdapterInfoList.EnumCompleted);
				break;
			}

			// Incomplete enumeration
			Debug("Waiting for Bind Complete.\n");

			SleepThread(25);
		}
	}

	u->hFile = h;

	return u;
}

// Release the driver
void SuFree(SU *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	CloseHandle(u->hFile);

	Free(u);
}

#endif	// WIN32


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
