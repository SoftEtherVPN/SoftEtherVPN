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


// EtherLog.h
// Header of EtherLog.c

#ifndef	ETHERLOG_H
#define	ETHERLOG_H

// Whether this is a beta version
#define	ELOG_IS_BETA						true

// Beta expiration date
#define	ELOG_BETA_EXPIRES_YEAR				2008
#define	ELOG_BETA_EXPIRES_MONTH				12
#define ELOG_BETA_EXPIRES_DAY				2

// Version information
//#define	EL_VER							201
//#define	EL_BUILD						1600
//#define	EL_BETA							1
#define MAX_LOGGING_QUEUE_LEN 100000

// RPC related
struct RPC_ADD_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	bool NoPromiscus;					// Without promiscuous mode
};

struct RPC_DELETE_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
};

struct RPC_ENUM_DEVICE_ITEM
{
	char DeviceName[MAX_SIZE];			// Device name
	bool Active;						// Running flag
};

struct RPC_ENUM_DEVICE
{
	UINT NumItem;						// Number of items
	RPC_ENUM_DEVICE_ITEM *Items;		// Items
	bool IsLicenseSupported;			// Whether the license system is supported
};

// License status of the service
struct RPC_EL_LICENSE_STATUS
{
	BOOL Valid;								// Enable flag
	UINT64 SystemId;						// System ID
	UINT64 SystemExpires;					// System expiration date
};

// Device
struct EL_DEVICE
{
	EL *el;								// EL
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	THREAD *Thread;						// Thread
	CANCEL *Cancel1;					// Cancel 1
	CANCEL *Cancel2;					// Cancel 2
	volatile bool Halt;					// Halting flag
	bool Active;						// Running flag
	bool NoPromiscus;					// Without promiscuous mode
	LOG *Logger;						// Logger
};

// License status
struct EL_LICENSE_STATUS
{
	BOOL Valid;				// Enable flag
	UINT64 SystemId;		// System ID
	UINT64 Expires;			// Expiration date
};

// EtherLogger
struct EL
{
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	LIST *DeviceList;					// Device list
	CFG_RW *CfgRw;						// Config R/W
	UINT Port;							// Port number
	LISTENER *Listener;					// Listener
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	LIST *AdminThreadList;				// Management thread list
	LIST *AdminSockList;				// Management socket list
	LICENSE_SYSTEM *LicenseSystem;		// License system
	EL_LICENSE_STATUS *LicenseStatus;	// License status
	UINT64 AutoDeleteCheckDiskFreeSpaceMin;	// Minimum free disk space
	ERASER *Eraser;						// Eraser
};

// Function prototype
void ElInit();
void ElFree();
void ElStart();
void ElStop();
EL *NewEl();
void ReleaseEl(EL *e);
void CleanupEl(EL *e);
void ElInitConfig(EL *e);
void ElFreeConfig(EL *e);
bool ElLoadConfig(EL *e);
void ElLoadConfigFromFolder(EL *e, FOLDER *root);
void ElSaveConfig(EL *e);
void ElSaveConfigToFolder(EL *e, FOLDER *root);
int ElCompareDevice(void *p1, void *p2);
bool ElAddCaptureDevice(EL *e, char *name, HUB_LOG *log, bool no_promiscus);
bool ElDeleteCaptureDevice(EL *e, char *name);
bool ElSetCaptureDeviceLogSetting(EL *e, char *name, HUB_LOG *log);
void ElCaptureThread(THREAD *thread, void *param);
void ElStartListener(EL *e);
void ElStopListener(EL *e);
void ElListenerProc(THREAD *thread, void *param);
PACK *ElRpcServer(RPC *r, char *name, PACK *p);
void ElCheckLicense(EL_LICENSE_STATUS *st, LICENSE *e);
void ElParseCurrentLicenseStatus(LICENSE_SYSTEM *s, EL_LICENSE_STATUS *st);
bool ElIsBetaExpired();


UINT EtAddDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtDelDevice(EL *e, RPC_DELETE_DEVICE *t);
UINT EtSetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtGetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtEnumDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtEnumAllDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtSetPassword(EL *e, RPC_SET_PASSWORD *t);
UINT EtAddLicenseKey(EL *a, RPC_TEST *t);
UINT EtDelLicenseKey(EL *a, RPC_TEST *t);
UINT EtEnumLicenseKey(EL *a, RPC_ENUM_LICENSE_KEY *t);
UINT EtGetLicenseStatus(EL *a, RPC_EL_LICENSE_STATUS *t);
UINT EtGetBridgeSupport(EL *a, RPC_BRIDGE_SUPPORT *t);
UINT EtRebootServer(EL *a, RPC_TEST *t);

UINT EcAddDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcDelDevice(RPC *r, RPC_DELETE_DEVICE *t);
UINT EcSetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcGetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcEnumDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcEnumAllDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcSetPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT EcAddLicenseKey(RPC *r, RPC_TEST *t);
UINT EcDelLicenseKey(RPC *r, RPC_TEST *t);
UINT EcEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT EcGetLicenseStatus(RPC *r, RPC_EL_LICENSE_STATUS *t);
UINT EcGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT EcRebootServer(RPC *r, RPC_TEST *t);

UINT EcConnect(char *host, UINT port, char *password, RPC **rpc);
void EcDisconnect(RPC *rpc);

void InRpcAddDevice(RPC_ADD_DEVICE *t, PACK *p);
void OutRpcAddDevice(PACK *p, RPC_ADD_DEVICE *t);
void InRpcDeleteDevice(RPC_DELETE_DEVICE *t, PACK *p);
void OutRpcDeleteDevice(PACK *p, RPC_DELETE_DEVICE *t);
void InRpcEnumDevice(RPC_ENUM_DEVICE *t, PACK *p);
void OutRpcEnumDevice(PACK *p, RPC_ENUM_DEVICE *t);
void FreeRpcEnumDevice(RPC_ENUM_DEVICE *t);
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void InRpcElLicenseStatus(RPC_EL_LICENSE_STATUS *t, PACK *p);
void OutRpcElLicenseStatus(PACK *p, RPC_EL_LICENSE_STATUS *t);

#endif	// ETHERLOG_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
