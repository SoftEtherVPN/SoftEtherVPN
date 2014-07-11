// SoftEther VPN Source Code
// Cedar Communication Module
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


// EtherLog.c
// EtherLogger program

#include "CedarPch.h"

static LOCK *el_lock = NULL;
static EL *el = NULL;

// RPC functional related macro
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(e, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
		free_rpc(&t);													\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(e, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
		ok = true;														\
	}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}

// RPC client disconnect
void EcDisconnect(RPC *rpc)
{
	// Validate arguments
	if (rpc == NULL)
	{
		return;
	}

	RpcFree(rpc);
}

// RPC client connect
UINT EcConnect(char *host, UINT port, char *password, RPC **rpc)
{
	SOCK *s;
	UCHAR password_hash[SHA1_SIZE];
	UCHAR rand[SHA1_SIZE];
	UCHAR response[SHA1_SIZE];
	bool retcode;
	// Validate arguments
	if (host == NULL)
	{
		host = "localhost";
	}
	if (port == 0)
	{
		port = EL_ADMIN_PORT;
	}
	if (password == NULL)
	{
		password = "";
	}
	if (rpc == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Connect to the server
	s = Connect(host, port);
	if (s == NULL)
	{
		// Connection failure
		return ERR_CONNECT_FAILED;
	}

	SetTimeout(s, 5000);

	// Hash the password
	Hash(password_hash, password, StrLen(password), true);

	// Receive the random number
	Zero(rand, sizeof(rand));
	RecvAll(s, rand, sizeof(rand), false);
	SecurePassword(response, password_hash, rand);

	// Send a response
	SendAll(s, response, sizeof(response), false);

	// Receive results
	retcode = false;
	if (RecvAll(s, &retcode, sizeof(retcode), false) == false)
	{
		// Disconnect
		ReleaseSock(s);
		return ERR_PROTOCOL_ERROR;
	}
	retcode = Endian32(retcode);

	if (retcode == false)
	{
		// Password incorrect
		ReleaseSock(s);
		return ERR_AUTH_FAILED;
	}

	// Successful connection
	SetTimeout(s, INFINITE);

	*rpc = StartRpcClient(s, NULL);

	ReleaseSock(s);

	return ERR_NO_ERROR;
}

// RPC server function
PACK *ElRpcServer(RPC *r, char *name, PACK *p)
{
	EL *e = (EL *)r->Param;
	PACK *ret;
	UINT err;
	bool ok;
	// Validate arguments
	if (r == NULL || name == NULL || p == NULL || e == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;
	ok = false;

	if (0) {}

	DECLARE_RPC("AddDevice", RPC_ADD_DEVICE, EtAddDevice, InRpcAddDevice, OutRpcAddDevice)
	DECLARE_RPC("DelDevice", RPC_DELETE_DEVICE, EtDelDevice, InRpcDeleteDevice, OutRpcDeleteDevice)
	DECLARE_RPC("SetDevice", RPC_ADD_DEVICE, EtSetDevice, InRpcAddDevice, OutRpcAddDevice)
	DECLARE_RPC("GetDevice", RPC_ADD_DEVICE, EtGetDevice, InRpcAddDevice, OutRpcAddDevice)
	DECLARE_RPC_EX("EnumDevice", RPC_ENUM_DEVICE, EtEnumDevice, InRpcEnumDevice, OutRpcEnumDevice, FreeRpcEnumDevice)
	DECLARE_RPC("SetPassword", RPC_SET_PASSWORD, EtSetPassword, InRpcSetPassword, OutRpcSetPassword)
	DECLARE_RPC_EX("EnumAllDevice", RPC_ENUM_DEVICE, EtEnumAllDevice, InRpcEnumDevice, OutRpcEnumDevice, FreeRpcEnumDevice)
	DECLARE_RPC("AddLicenseKey", RPC_TEST, EtAddLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC("DelLicenseKey", RPC_TEST, EtDelLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, EtEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
	DECLARE_RPC("GetLicenseStatus", RPC_EL_LICENSE_STATUS, EtGetLicenseStatus, InRpcElLicenseStatus, OutRpcElLicenseStatus)
	DECLARE_RPC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, EtGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
	DECLARE_RPC("RebootServer", RPC_TEST, EtRebootServer, InRpcTest, OutRpcTest)

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	PackAddInt(ret, "error", err);

	return ret;
}

DECLARE_SC("AddDevice", RPC_ADD_DEVICE, EcAddDevice, InRpcAddDevice, OutRpcAddDevice)
DECLARE_SC("DelDevice", RPC_DELETE_DEVICE, EcDelDevice, InRpcDeleteDevice, OutRpcDeleteDevice)
DECLARE_SC("SetDevice", RPC_ADD_DEVICE, EcSetDevice, InRpcAddDevice, OutRpcAddDevice)
DECLARE_SC("GetDevice", RPC_ADD_DEVICE, EcGetDevice, InRpcAddDevice, OutRpcAddDevice)
DECLARE_SC_EX("EnumDevice", RPC_ENUM_DEVICE, EcEnumDevice, InRpcEnumDevice, OutRpcEnumDevice, FreeRpcEnumDevice)
DECLARE_SC("SetPassword", RPC_SET_PASSWORD, EcSetPassword, InRpcSetPassword, OutRpcSetPassword)
DECLARE_SC_EX("EnumAllDevice", RPC_ENUM_DEVICE, EcEnumAllDevice, InRpcEnumDevice, OutRpcEnumDevice, FreeRpcEnumDevice)
DECLARE_SC("AddLicenseKey", RPC_TEST, EcAddLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC("DelLicenseKey", RPC_TEST, EcDelLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, EcEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
DECLARE_SC("GetLicenseStatus", RPC_EL_LICENSE_STATUS, EcGetLicenseStatus, InRpcElLicenseStatus, OutRpcElLicenseStatus)
DECLARE_SC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, EcGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
DECLARE_SC("RebootServer", RPC_TEST, EcRebootServer, InRpcTest, OutRpcTest)

// Thread to restart the server
void EiRebootServerThread(THREAD *thread, void *param)
{
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	if (el == NULL)
	{
		return;
	}

	// Stopping the server
	ElStop();

	// Starting the server
	ElStart();
}

// Restarting the server
void EiRebootServer()
{
	THREAD *t;

	t = NewThread(EiRebootServerThread, NULL);
	ReleaseThread(t);
}

// RPC to restart server
UINT EtRebootServer(EL *a, RPC_TEST *t)
{

	EiRebootServer();

	return ERR_NO_ERROR;
}

// Get support information for the local bridge
UINT EtGetBridgeSupport(EL *a, RPC_BRIDGE_SUPPORT *t)
{
	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = IsBridgeSupported();
	t->IsWinPcapNeeded = IsNeedWinPcap();

	return ERR_NO_ERROR;
}

// Update the status by checking the all licenses
void ElCheckLicense(EL_LICENSE_STATUS *st, LICENSE *e)
{
}

// Save by analyzing the status of the current license
void ElParseCurrentLicenseStatus(LICENSE_SYSTEM *s, EL_LICENSE_STATUS *st)
{
}

// Get a license status
UINT EtGetLicenseStatus(EL *e, RPC_EL_LICENSE_STATUS *t)
{
	UINT ret = ERR_NO_ERROR;
	LICENSE_SYSTEM *ls = e->LicenseSystem;

	if (ls == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	Zero(t, sizeof(RPC_EL_LICENSE_STATUS));

	// Get the current license status
	ElParseCurrentLicenseStatus(ls, e->LicenseStatus);

	t->Valid = e->LicenseStatus->Valid;
	t->SystemId = e->LicenseStatus->SystemId;
	t->SystemExpires = e->LicenseStatus->Expires;

	return ret;
}

// Enumerate the license keys
UINT EtEnumLicenseKey(EL *el, RPC_ENUM_LICENSE_KEY *t)
{
	return ERR_NOT_SUPPORTED;
}

// Add a license key
UINT EtAddLicenseKey(EL *e, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// Delete the license key
UINT EtDelLicenseKey(EL *e, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// Password setting
UINT EtSetPassword(EL *e, RPC_SET_PASSWORD *t)
{
	Copy(e->HashedPassword, t->HashedPassword, SHA1_SIZE);

	ElSaveConfig(e);

	return ERR_NO_ERROR;
}

// Add a device
UINT EtAddDevice(EL *e, RPC_ADD_DEVICE *t)
{
	if (ElAddCaptureDevice(e, t->DeviceName, &t->LogSetting, t->NoPromiscus) == false)
	{
		return ERR_CAPTURE_DEVICE_ADD_ERROR;
	}

	ElSaveConfig(e);

	return ERR_NO_ERROR;
}

// Remove the device
UINT EtDelDevice(EL *e, RPC_DELETE_DEVICE *t)
{
	if (ElDeleteCaptureDevice(e, t->DeviceName) == false)
	{
		return ERR_CAPTURE_NOT_FOUND;
	}

	ElSaveConfig(e);

	return ERR_NO_ERROR;
}

// Get the device
UINT EtGetDevice(EL *e, RPC_ADD_DEVICE *t)
{
	UINT ret = ERR_CAPTURE_NOT_FOUND;

	LockList(e->DeviceList);
	{
		EL_DEVICE *d, a;
		Zero(&a, sizeof(a));
		StrCpy(a.DeviceName, sizeof(a.DeviceName), t->DeviceName);

		d = Search(e->DeviceList, &a);

		if (d != NULL)
		{
			ret = ERR_NO_ERROR;

			Copy(&t->LogSetting, &d->LogSetting, sizeof(HUB_LOG));
			t->NoPromiscus = d->NoPromiscus;
		}
	}
	UnlockList(e->DeviceList);

	return ret;
}

// Device Setting
UINT EtSetDevice(EL *e, RPC_ADD_DEVICE *t)
{
	if (ElSetCaptureDeviceLogSetting(e, t->DeviceName, &t->LogSetting) == false)
	{
		return ERR_CAPTURE_NOT_FOUND;
	}

	ElSaveConfig(e);

	return ERR_NO_ERROR;
}

// Enumerate all devices
UINT EtEnumAllDevice(EL *e, RPC_ENUM_DEVICE *t)
{
	TOKEN_LIST *eth;
	UINT i;
	if (IsEthSupported() == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcEnumDevice(t);
	Zero(t, sizeof(RPC_ENUM_DEVICE));

	eth = GetEthList();

	t->NumItem = eth->NumTokens;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_DEVICE_ITEM) * t->NumItem);

	for (i = 0;i < eth->NumTokens;i++)
	{
		char *name = eth->Token[i];
		RPC_ENUM_DEVICE_ITEM *item = &t->Items[i];

		StrCpy(item->DeviceName, sizeof(item->DeviceName), name);
	}

	FreeToken(eth);

	return ERR_NO_ERROR;
}

// Device enumeration
UINT EtEnumDevice(EL *e, RPC_ENUM_DEVICE *t)
{
	bool is_beta_expired = ElIsBetaExpired();

	if (is_beta_expired)
	{
		// The beta version has expired
		return ERR_BETA_EXPIRES;
	}

	FreeRpcEnumDevice(t);
	Zero(t, sizeof(RPC_ENUM_DEVICE));

	LockList(e->DeviceList);
	{
		UINT i;

		t->NumItem = LIST_NUM(e->DeviceList);
		t->Items = ZeroMalloc(sizeof(RPC_ENUM_DEVICE_ITEM) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_ENUM_DEVICE_ITEM *d = &t->Items[i];
			EL_DEVICE *eld = LIST_DATA(e->DeviceList, i);

			StrCpy(d->DeviceName, sizeof(d->DeviceName), eld->DeviceName);
			d->Active = eld->Active && ((ELOG_IS_BETA || e->LicenseStatus->Valid) ? true : false);
		}
	}
	UnlockList(e->DeviceList);

	return ERR_NO_ERROR;
}

void InRpcAddDevice(RPC_ADD_DEVICE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADD_DEVICE));
	PackGetStr(p, "DeviceName", t->DeviceName, sizeof(t->DeviceName));
	t->NoPromiscus = PackGetInt(p, "NoPromiscus");
	t->LogSetting.PacketLogSwitchType = PackGetInt(p, "PacketLogSwitchType");

	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		t->LogSetting.PacketLogConfig[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
}

void OutRpcAddDevice(PACK *p, RPC_ADD_DEVICE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
	PackAddInt(p, "NoPromiscus", t->NoPromiscus);
	PackAddInt(p, "PacketLogSwitchType", t->LogSetting.PacketLogSwitchType);

	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", t->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
}

void InRpcDeleteDevice(RPC_DELETE_DEVICE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_DEVICE));
	PackGetStr(p, "DeviceName", t->DeviceName, sizeof(t->DeviceName));
}

void OutRpcDeleteDevice(PACK *p, RPC_DELETE_DEVICE *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
}

void InRpcEnumDevice(RPC_ENUM_DEVICE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_DEVICE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_DEVICE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DEVICE_ITEM *d = &t->Items[i];

		PackGetStrEx(p, "DeviceName", d->DeviceName, sizeof(d->DeviceName), i);
		d->Active = PackGetBoolEx(p, "Active", i);
	}

	t->IsLicenseSupported = PackGetBool(p, "IsLicenseSupported");
}

void OutRpcEnumDevice(PACK *p, RPC_ENUM_DEVICE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DEVICE_ITEM *d = &t->Items[i];

		PackAddStrEx(p, "DeviceName", d->DeviceName, i, t->NumItem);
		PackAddBoolEx(p, "Active", d->Active, i, t->NumItem);
	}

	PackAddBool(p, "IsLicenseSupported", t->IsLicenseSupported);
}

void FreeRpcEnumDevice(RPC_ENUM_DEVICE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_LICENSE_STATUS
void InRpcElLicenseStatus(RPC_EL_LICENSE_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_EL_LICENSE_STATUS));

	t->Valid = PackGetBool(p, "Valid");
	t->SystemId = PackGetInt64(p, "SystemId");
	t->SystemExpires = PackGetInt64(p, "SystemExpires");
}
void OutRpcElLicenseStatus(PACK *p, RPC_EL_LICENSE_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "Valid", t->Valid);
	PackAddInt64(p, "SystemId", t->SystemId);
	PackAddInt64(p, "SystemExpires", t->SystemExpires);
}

// Listener thread
void ElListenerProc(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *data = (TCP_ACCEPTED_PARAM *)param;
	EL *e;
	SOCK *s;
	UCHAR rand[SHA1_SIZE];
	UCHAR pass1[SHA1_SIZE], pass2[SHA1_SIZE];
	// Validate arguments
	if (data == NULL || thread == NULL)
	{
		return;
	}

	e = (EL *)data->r->ThreadParam;
	s = data->s;
	AddRef(s->ref);
	SetTimeout(s, 5000);
	LockList(e->AdminThreadList);
	{
		AddRef(thread->ref);
		AddRef(s->ref);
		Insert(e->AdminThreadList, thread);
		Insert(e->AdminSockList, s);
	}
	UnlockList(e->AdminThreadList);
	NoticeThreadInit(thread);

	// Submit a challenge
	Rand(rand, sizeof(rand));
	SendAll(s, rand, sizeof(rand), false);

	// Receive a response
	SecurePassword(pass1, e->HashedPassword, rand);
	Zero(pass2, sizeof(pass2));
	RecvAll(s, pass2, sizeof(pass2), false);

	if (Cmp(pass1, pass2, SHA1_SIZE) != 0)
	{
		// Password incorrect
		bool code = false;
		code = Endian32(code);
		SendAll(s, &code, sizeof(code), false);
	}
	else
	{
		// Password match
		bool code = true;
		RPC *r;

		code = Endian32(code);
		SendAll(s, &code, sizeof(code), false);

		SetTimeout(s, INFINITE);

		// Start operation as a RPC server
		r = StartRpcServer(s, ElRpcServer, e);
		RpcServer(r);
		RpcFree(r);
	}

	Disconnect(s);
	ReleaseSock(s);

	LockList(e->AdminThreadList);
	{
		if (Delete(e->AdminThreadList, thread))
		{
			ReleaseThread(thread);
		}
		if (Delete(e->AdminSockList, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(e->AdminThreadList);
}

// Listener start
void ElStartListener(EL *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	e->AdminThreadList = NewList(NULL);
	e->AdminSockList = NewList(NULL);

	e->Listener = NewListenerEx(e->Cedar, LISTENER_TCP, e->Port == 0 ? EL_ADMIN_PORT : e->Port,
		ElListenerProc, e);
}

// Listener stop
void ElStopListener(EL *e)
{
	UINT i;
	THREAD **threads;
	SOCK **socks;
	UINT num_threads, num_socks;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	StopAllListener(e->Cedar);

	LockList(e->AdminThreadList);
	{
		threads = ToArray(e->AdminThreadList);
		num_threads = LIST_NUM(e->AdminThreadList);
		DeleteAll(e->AdminThreadList);

		socks = ToArray(e->AdminSockList);
		num_socks = LIST_NUM(e->AdminSockList);
		DeleteAll(e->AdminSockList);
	}
	UnlockList(e->AdminThreadList);

	for (i = 0;i < num_socks;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}

	for (i = 0;i < num_threads;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}

	Free(threads);
	Free(socks);

	ReleaseList(e->AdminSockList);
	ReleaseList(e->AdminThreadList);

	ReleaseListener(e->Listener);
}

// Update the log configuration of the capture device
bool ElSetCaptureDeviceLogSetting(EL *e, char *name, HUB_LOG *log)
{
	EL_DEVICE *d;
	bool ret = false;
	// Validate arguments
	if (e == NULL || log == NULL || name == NULL)
	{
		return false;
	}

	LockList(e->DeviceList);
	{
		EL_DEVICE t;

		Zero(&t, sizeof(t));
		StrCpy(t.DeviceName, sizeof(t.DeviceName), name);

		d = Search(e->DeviceList, &t);

		if (d != NULL)
		{
			Copy(&d->LogSetting, log, sizeof(HUB_LOG));

			SetLogSwitchType(d->Logger, log->PacketLogSwitchType);

			ret = true;
		}
	}
	UnlockList(e->DeviceList);

	return ret;
}

// Confirm whether the beta version has expired
bool ElIsBetaExpired()
{
	SYSTEMTIME st;
	UINT64 expires64;
	UINT64 now64;
	if (ELOG_IS_BETA == false)
	{
		return false;
	}

	Zero(&st, sizeof(st));

	st.wYear = ELOG_BETA_EXPIRES_YEAR;
	st.wMonth = ELOG_BETA_EXPIRES_MONTH;
	st.wDay = ELOG_BETA_EXPIRES_DAY;

	expires64 = SystemToUINT64(&st);
	now64 = LocalTime64();

	if (now64 >= expires64)
	{
		return true;
	}

	return false;
}

// Capture thread
void ElCaptureThread(THREAD *thread, void *param)
{
}

// Delete the capture device
bool ElDeleteCaptureDevice(EL *e, char *name)
{
	bool ret = false;
	EL_DEVICE *d, t;
	// Validate arguments
	if (e == NULL || name == NULL)
	{
		return false;
	}

	LockList(e->DeviceList);
	{
		Zero(&t, sizeof(t));
		StrCpy(t.DeviceName, sizeof(t.DeviceName), name);

		d = Search(e->DeviceList, &t);

		if (d != NULL)
		{
			// Stop capture
			d->Halt = true;
			Cancel(d->Cancel1);

			// Wait for thread stop
			WaitThread(d->Thread, INFINITE);
			ReleaseThread(d->Thread);

			// Release the memory
			Delete(e->DeviceList, d);
			Free(d);

			ret = true;
		}
	}
	UnlockList(e->DeviceList);

	return ret;
}

// Add a capture device
bool ElAddCaptureDevice(EL *e, char *name, HUB_LOG *log, bool no_promiscus)
{
	EL_DEVICE *d, t;
	// Validate arguments
	if (e == NULL || name == NULL || log == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), name);

	LockList(e->DeviceList);
	{
		d = Search(e->DeviceList, &t);
		if (d != NULL)
		{
			// Capture settings with the same name already exists
			UnlockList(e->DeviceList);
			return false;
		}

		// Add a device
		d = ZeroMalloc(sizeof(EL_DEVICE));
		StrCpy(d->DeviceName, sizeof(d->DeviceName), name);
		Copy(&d->LogSetting, log, sizeof(HUB_LOG));
		d->NoPromiscus = no_promiscus;
		d->el = e;
		Insert(e->DeviceList, d);

		// Start the thread
		d->Thread = NewThread(ElCaptureThread, d);
		WaitThreadInit(d->Thread);
	}
	UnlockList(e->DeviceList);

	ElSaveConfig(e);

	return true;
}

// Write the license List
void EiWriteLicenseManager(FOLDER *f, EL *s)
{
}

// Read the license list
void EiLoadLicenseManager(EL *s, FOLDER *f)
{
}

// Configuration initialization
void ElInitConfig(EL *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	// Device list initialization
	e->DeviceList = NewList(ElCompareDevice);

	// Read configuration file
	ElLoadConfig(e);

	// Write configuration file
	ElSaveConfig(e);
}

// Write the configuration
void ElSaveConfig(EL *e)
{
	FOLDER *root;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	ElSaveConfigToFolder(e, root);

	SaveCfgRw(e->CfgRw, root);

	CfgDeleteFolder(root);
}

// Write the configuration to the folder
void ElSaveConfigToFolder(EL *e, FOLDER *root)
{
	UINT i;
	FOLDER *devices;
	// Validate arguments
	if (e == NULL || root == NULL)
	{
		return;
	}

	CfgAddInt64(root, "AutoDeleteCheckDiskFreeSpaceMin", e->AutoDeleteCheckDiskFreeSpaceMin);

	CfgAddInt(root, "AdminPort", e->Port);

	CfgAddByte(root, "AdminPassword", e->HashedPassword, sizeof(e->HashedPassword));

	if (ELOG_IS_BETA == false)
	{
		EiWriteLicenseManager(CfgCreateFolder(root, "LicenseManager"), e);
	}

	devices = CfgCreateFolder(root,"Devices");

	LockList(e->DeviceList);
	{
		for (i = 0;i < LIST_NUM(e->DeviceList);i++)
		{
			FOLDER *f;
			EL_DEVICE *d = LIST_DATA(e->DeviceList, i);

			f = CfgCreateFolder(devices, d->DeviceName);
			SiWriteHubLogCfgEx(f, &d->LogSetting, true);
			CfgAddBool(f, "NoPromiscusMode", d->NoPromiscus);
		}
	}
	UnlockList(e->DeviceList);
}

// Read the configuration from the folder
void ElLoadConfigFromFolder(EL *e, FOLDER *root)
{
	UINT i;
	TOKEN_LIST *t;
	FOLDER *devices;

	// Validate arguments
	if (e == NULL || root == NULL)
	{
		return;
	}

	i = CfgGetInt(root, "AdminPort");
	if (i >= 1 && i <= 65535)
	{
		e->Port = i;
	}

	e->AutoDeleteCheckDiskFreeSpaceMin = CfgGetInt64(root, "AutoDeleteCheckDiskFreeSpaceMin");
	if (CfgIsItem(root, "AutoDeleteCheckDiskFreeSpaceMin") == false && e->AutoDeleteCheckDiskFreeSpaceMin == 0)
	{
		e->AutoDeleteCheckDiskFreeSpaceMin = DISK_FREE_SPACE_DEFAULT;
	}

	if (e->AutoDeleteCheckDiskFreeSpaceMin != 0)
	{
		if (e->AutoDeleteCheckDiskFreeSpaceMin < DISK_FREE_SPACE_MIN)
		{
			e->AutoDeleteCheckDiskFreeSpaceMin = DISK_FREE_SPACE_MIN;
		}
	}

	if (CfgGetByte(root, "AdminPassword", e->HashedPassword, sizeof(e->HashedPassword)) != sizeof(e->HashedPassword))
	{
		Hash(e->HashedPassword, "", 0, true);
	}

	if (ELOG_IS_BETA == false)
	{
		EiLoadLicenseManager(e,	CfgGetFolder(root, "LicenseManager"));
	}

	devices = CfgGetFolder(root, "Devices");
	if(devices != NULL)
	{
		LockList(e->DeviceList);
		{
			t = CfgEnumFolderToTokenList(devices);
			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				FOLDER *f = CfgGetFolder(devices, name);

				if (f != NULL)
				{
					HUB_LOG g;

					Zero(&g, sizeof(g));
					SiLoadHubLogCfg(&g, f);
					ElAddCaptureDevice(e, name, &g, CfgGetBool(f, "NoPromiscusMode"));
				}
			}
			FreeToken(t);
		}
		UnlockList(e->DeviceList);
	}
}

// Reading configuration
bool ElLoadConfig(EL *e)
{
	FOLDER *root;
	bool ret = false;
	// Validate arguments
	if (e == NULL)
	{
		return false;
	}

	e->Port = EL_ADMIN_PORT;

	e->CfgRw = NewCfgRw(&root, EL_CONFIG_FILENAME);

	if (root != NULL)
	{
		ElLoadConfigFromFolder(e, root);

		CfgDeleteFolder(root);
	}
	else
	{
		char *pass = "";
		Hash(e->HashedPassword, pass, StrLen(pass), true);
		e->AutoDeleteCheckDiskFreeSpaceMin = DISK_FREE_SPACE_DEFAULT;
	}

	return ret;
}

// Configuration release
void ElFreeConfig(EL *e)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	// Write the configuration file
	ElSaveConfig(e);
	FreeCfgRw(e->CfgRw);

	// Stop all capture
	o = NewList(NULL);
	LockList(e->DeviceList);
	{
		for (i = 0;i < LIST_NUM(e->DeviceList);i++)
		{
			EL_DEVICE *d = LIST_DATA(e->DeviceList, i);
			Insert(o, CopyStr(d->DeviceName));
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char *name = LIST_DATA(o, i);
			ElDeleteCaptureDevice(e, name);
			Free(name);
		}
		ReleaseList(o);
	}
	UnlockList(e->DeviceList);

	ReleaseList(e->DeviceList);
}

// Comparison function of the device
int ElCompareDevice(void *p1, void *p2)
{
	EL_DEVICE *d1, *d2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(EL_DEVICE **)p1;
	d2 = *(EL_DEVICE **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}

	return StrCmpi(d1->DeviceName, d2->DeviceName);
}

// Clean-up the EL
void CleanupEl(EL *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	// Stop Eraser 
	FreeEraser(e->Eraser);

	// Stop Listener 
	ElStopListener(e);

	// Setting release
	ElFreeConfig(e);

	// Free the license system
	if(e->LicenseSystem != NULL)
	{
	}

	// Free the license status
	if(e->LicenseStatus != NULL)
	{
		Free(e->LicenseStatus);
	}

	// Ethernet release
	FreeEth();

	ReleaseCedar(e->Cedar);

	DeleteLock(e->lock);

	Free(e);
}

// Release the EL
void ReleaseEl(EL *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	if (Release(e->ref) == 0)
	{
		CleanupEl(e);
	}
}

// Create the EL
EL *NewEl()
{
	EL *e;

#ifdef OS_WIN32
	RegistWindowsFirewallAll();
#endif

	e = ZeroMalloc(sizeof(EL));
	e->lock = NewLock();
	e->ref = NewRef();

	e->Cedar = NewCedar(NULL, NULL);


	// Ethernet initialization
	InitEth();

	// Setting initialization
	ElInitConfig(e);

	// Listener start
	ElStartListener(e);

	// Initialize the license status
	ElParseCurrentLicenseStatus(e->LicenseSystem, e->LicenseStatus);

	// Eraser start
	e->Eraser = NewEraser(NULL, e->AutoDeleteCheckDiskFreeSpaceMin);

	return e;
}

// EL start
void ElStart()
{
	// Raise the priority
	OSSetHighPriority();

	Lock(el_lock);
	{
		el = NewEl();
	}
	Unlock(el_lock);
}

// EL stop
void ElStop()
{
	Lock(el_lock);
	{
		ReleaseEl(el);
		el = NULL;
	}
	Unlock(el_lock);
}

// EL initialization
void ElInit()
{
	// Lock initialization
	el_lock = NewLock();
}

// EL release
void ElFree()
{
	// Lock release
	DeleteLock(el_lock);
	el_lock = NULL;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
