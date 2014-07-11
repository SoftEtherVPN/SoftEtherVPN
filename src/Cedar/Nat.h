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


// Nat.h
// Header of Nat.c

#ifndef	NAT_H
#define	NAT_H

// Constants
#define	NAT_CONFIG_FILE_NAME			"@vpn_router.config"	// NAT configuration file
#define	DEFAULT_NAT_ADMIN_PORT			2828		// Default port number for management
#define	NAT_ADMIN_PORT_LISTEN_INTERVAL	1000		// Interval for trying to open a port for management
#define	NAT_FILE_SAVE_INTERVAL			(30 * 1000)	// Interval to save


// NAT object
struct NAT
{
	LOCK *lock;							// Lock
	UCHAR HashedPassword[SHA1_SIZE];	// Administrative password
	VH_OPTION Option;					// Option
	CEDAR *Cedar;						// Cedar
	UINT AdminPort;						// Management port number
	bool Online;						// Online flag
	VH *Virtual;						// Virtual host object
	CLIENT_OPTION *ClientOption;		// Client Option
	CLIENT_AUTH *ClientAuth;			// Client authentication data
	CFG_RW *CfgRw;						// Config file R/W
	THREAD *AdminAcceptThread;			// Management connection reception thread
	SOCK *AdminListenSock;				// Management port socket
	EVENT *HaltEvent;					// Halting event
	volatile bool Halt;					// Halting flag
	LIST *AdminList;					// Management thread list
	X *AdminX;							// Server certificate for management
	K *AdminK;							// Server private key for management
	SNAT *SecureNAT;					// SecureNAT object
};

// NAT management connection
struct NAT_ADMIN
{
	NAT *Nat;							// NAT
	SOCK *Sock;							// Socket
	THREAD *Thread;						// Thread
};

// RPC_DUMMY
struct RPC_DUMMY
{
	UINT DummyValue;
};

// RPC_NAT_STATUS
struct RPC_NAT_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumTcpSessions;						// Number of TCP sessions
	UINT NumUdpSessions;						// Ntmber of UDP sessions
	UINT NumIcmpSessions;						// Nymber of ICMP sessions
	UINT NumDnsSessions;						// Number of DNS sessions
	UINT NumDhcpClients;						// Number of DHCP clients
	bool IsKernelMode;							// Whether kernel mode
};

// RPC_NAT_INFO *
struct RPC_NAT_INFO
{
	char NatProductName[128];					// Server product name
	char NatVersionString[128];					// Server version string
	char NatBuildInfoString[128];				// Server build information string
	UINT NatVerInt;								// Server version integer value
	UINT NatBuildInt;							// Server build number integer value
	char NatHostName[MAX_HOST_NAME_LEN + 1];	// Server host name
	OS_INFO OsInfo;								// OS information
	MEMINFO MemInfo;							// Memory information
};

// RPC_ENUM_NAT_ITEM
struct RPC_ENUM_NAT_ITEM
{
	UINT Id;									// ID
	UINT Protocol;								// Protocol
	UINT SrcIp;									// Source IP address
	char SrcHost[MAX_HOST_NAME_LEN + 1];		// Source host name
	UINT SrcPort;								// Source port number
	UINT DestIp;								// Destination IP address
	char DestHost[MAX_HOST_NAME_LEN + 1];		// Destination host name
	UINT DestPort;								// Destination port number
	UINT64 CreatedTime;							// Connection time
	UINT64 LastCommTime;						// Last communication time
	UINT64 SendSize;							// Transmission size
	UINT64 RecvSize;							// Receive size
	UINT TcpStatus;								// TCP state
};

// RPC_ENUM_NAT *
struct RPC_ENUM_NAT
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumItem;								// Number of items
	RPC_ENUM_NAT_ITEM *Items;					// Item
};

// RPC_ENUM_DHCP_ITEM
struct RPC_ENUM_DHCP_ITEM
{
	UINT Id;									// ID
	UINT64 LeasedTime;							// Lease time
	UINT64 ExpireTime;							// Expiration date
	UCHAR MacAddress[6];						// MAC address
	UCHAR Padding[2];							// Padding
	UINT IpAddress;								// IP address
	UINT Mask;									// Subnet mask
	char Hostname[MAX_HOST_NAME_LEN + 1];		// Host name
};

// RPC_ENUM_DHCP *
struct RPC_ENUM_DHCP
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumItem;								// Number of items
	RPC_ENUM_DHCP_ITEM *Items;					// Item
};


// Function prototype
NAT *NiNewNat();
NAT *NiNewNatEx(SNAT *snat, VH_OPTION *o);
void NiFreeNat(NAT *n);
void NiInitConfig(NAT *n);
void NiFreeConfig(NAT *n);
void NiInitDefaultConfig(NAT *n);
void NiSetDefaultVhOption(NAT *n, VH_OPTION *o);
void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial);
void NiWriteConfig(NAT *n);
void NiWriteVhOption(NAT *n, FOLDER *root);
void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root);
void NiWriteClientData(NAT *n, FOLDER *root);
void NiLoadVhOption(NAT *n, FOLDER *root);
void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root);
bool NiLoadConfig(NAT *n, FOLDER *root);
void NiLoadClientData(NAT *n, FOLDER *root);
void NiInitAdminAccept(NAT *n);
void NiFreeAdminAccept(NAT *n);
void NiListenThread(THREAD *thread, void *param);
void NiAdminThread(THREAD *thread, void *param);
void NiAdminMain(NAT *n, SOCK *s);
PACK *NiRpcServer(RPC *r, char *name, PACK *p);

RPC *NatAdminConnect(CEDAR *cedar, char *hostname, UINT port, void *hashed_password, UINT *err);
void NatAdminDisconnect(RPC *r);

void NtStartNat();
void NtStopNat();
void NtInit();
void NtFree();


UINT NtOnline(NAT *n, RPC_DUMMY *t);
UINT NtOffline(NAT *n, RPC_DUMMY *t);
UINT NtSetHostOption(NAT *n, VH_OPTION *t);
UINT NtGetHostOption(NAT *n, VH_OPTION *t);
UINT NtSetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetStatus(NAT *n, RPC_NAT_STATUS *t);
UINT NtGetInfo(NAT *n, RPC_NAT_INFO *t);
UINT NtEnumNatList(NAT *n, RPC_ENUM_NAT *t);
UINT NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t);
UINT NtSetPassword(NAT *n, RPC_SET_PASSWORD *t);


UINT NcOnline(RPC *r, RPC_DUMMY *t);
UINT NcOffline(RPC *r, RPC_DUMMY *t);
UINT NcSetHostOption(RPC *r, VH_OPTION *t);
UINT NcGetHostOption(RPC *r, VH_OPTION *t);
UINT NcSetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetStatus(RPC *r, RPC_NAT_STATUS *t);
UINT NcGetInfo(RPC *r, RPC_NAT_INFO *t);
UINT NcEnumNatList(RPC *r, RPC_ENUM_NAT *t);
UINT NcEnumDhcpList(RPC *r, RPC_ENUM_DHCP *t);
UINT NcSetPassword(RPC *r, RPC_SET_PASSWORD *t);




void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p);
void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t);
void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t);
void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p);
void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t);
void FreeRpcEnumNat(RPC_ENUM_NAT *t);
void InRpcNatInfo(RPC_NAT_INFO *t, PACK *p);
void OutRpcNatInfo(PACK *p, RPC_NAT_INFO *t);
void FreeRpcNatInfo(RPC_NAT_INFO *t);
void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p);
void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t);
void FreeRpcNatStatus(RPC_NAT_STATUS *t);
void InVhOption(VH_OPTION *t, PACK *p);
void OutVhOption(PACK *p, VH_OPTION *t);
void InRpcDummy(RPC_DUMMY *t, PACK *p);
void OutRpcDummy(PACK *p, RPC_DUMMY *t);




#endif	// NAT_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
