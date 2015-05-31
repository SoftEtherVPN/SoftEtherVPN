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


// BridgeWin32.h
// Header of BridgeWin32.c

#ifndef	BRIDGEWIN32_H
#define	BRIDGEWIN32_H

#define	BRIDGE_WIN32_PACKET_DLL		"Packet.dll"
#define	BRIDGE_WIN32_PCD_DLL		"|see.dll"
#define	BRIDGE_WIN32_PCD_SYS		"|DriverPackages\\See\\x86\\See_x86.sys"
#define	BRIDGE_WIN32_PCD_DLL_X64	"|see_x64.dll"
#define	BRIDGE_WIN32_PCD_SYS_X64	"|DriverPackages\\See\\x64\\See_x64.sys"
#define	BRIDGE_WIN32_PCD_REGKEY		"SYSTEM\\CurrentControlSet\\services\\SEE"
#define	BRIDGE_WIN32_PCD_BUILDVALUE	"CurrentInstalledBuild"

#define	BRIDGE_WIN32_ETH_BUFFER		(1048576)


typedef void *HANDLE;

#ifdef	BRIDGE_C

// Header for Internal function (for BridgeWin32.c)
typedef struct WP
{
	bool Inited;
	HINSTANCE hPacketDll;
	PCHAR (*PacketGetVersion)();
	PCHAR (*PacketGetDriverVersion)();
	BOOLEAN (*PacketSetMinToCopy)(LPADAPTER AdapterObject,int nbytes);
	BOOLEAN (*PacketSetNumWrites)(LPADAPTER AdapterObject,int nwrites);
	BOOLEAN (*PacketSetMode)(LPADAPTER AdapterObject,int mode);
	BOOLEAN (*PacketSetReadTimeout)(LPADAPTER AdapterObject,int timeout);
	BOOLEAN (*PacketSetBpf)(LPADAPTER AdapterObject,struct bpf_program *fp);
	INT (*PacketSetSnapLen)(LPADAPTER AdapterObject,int snaplen);
	BOOLEAN (*PacketGetStats)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketGetStatsEx)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketSetBuff)(LPADAPTER AdapterObject,int dim);
	BOOLEAN (*PacketGetNetType)(LPADAPTER AdapterObject,NetType *type);
	LPADAPTER (*PacketOpenAdapter)(PCHAR AdapterName);
	BOOLEAN (*PacketSendPacket)(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
	INT (*PacketSendPackets)(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
	LPPACKET (*PacketAllocatePacket)(void);
	VOID (*PacketInitPacket)(LPPACKET lpPacket,PVOID  Buffer,UINT  Length);
	VOID (*PacketFreePacket)(LPPACKET lpPacket);
	BOOLEAN (*PacketReceivePacket)(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync);
	BOOLEAN (*PacketSetHwFilter)(LPADAPTER AdapterObject,ULONG Filter);
	BOOLEAN (*PacketGetAdapterNames)(PTSTR pStr,PULONG  BufferSize);
	BOOLEAN (*PacketGetNetInfoEx)(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
	BOOLEAN (*PacketRequest)(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData);
	HANDLE (*PacketGetReadEvent)(LPADAPTER AdapterObject);
	BOOLEAN (*PacketSetDumpName)(LPADAPTER AdapterObject, void *name, int len);
	BOOLEAN (*PacketSetDumpLimits)(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
	BOOLEAN (*PacketIsDumpEnded)(LPADAPTER AdapterObject, BOOLEAN sync);
	BOOL (*PacketStopDriver)();
	VOID (*PacketCloseAdapter)(LPADAPTER lpAdapter);
	BOOLEAN (*PacketSetLoopbackBehavior)(LPADAPTER AdapterObject, UINT LoopbackBehavior);
} WP;

// Adapter list
typedef struct WP_ADAPTER
{
	char Name[MAX_SIZE];
	char Title[MAX_SIZE];
	char Guid[MAX_SIZE];
	UINT Id;
} WP_ADAPTER;

// Internal function prototype
void InitEthAdaptersList();
void FreeEthAdaptersList();
int CompareWpAdapter(void *p1, void *p2);
LIST *GetEthAdapterList();
LIST *GetEthAdapterListInternal();
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h);
bool IsPcdSupported();
HINSTANCE InstallPcdDriver();
HINSTANCE InstallPcdDriverInternal();
UINT LoadPcdDriverBuild();
void SavePcdDriverBuild(UINT build);

#endif	// BRIDGE_C

typedef struct _ADAPTER ADAPTER;
typedef struct _PACKET PACKET;

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	ADAPTER *Adapter;			// Adapter
	CANCEL *Cancel;				// Cancel object
	UCHAR *Buffer;				// Buffer
	UINT BufferSize;			// Buffer size
	PACKET *Packet;				// Packet
	PACKET *PutPacket;			// Write packet
	QUEUE *PacketQueue;			// Packet queue
	UINT64 LastSetSingleCpu;	// Date and time set to a single CPU to last
	bool LoopbackBlock;			// Whether to block the loop back packet
	bool Empty;					// It is empty
	UCHAR MacAddress[6];		// MAC address
	bool HasFatalError;			// A fatal error occurred on the transmission side

	SU *Su;						// SeLow handle
	SU_ADAPTER *SuAdapter;		// SeLow adapter handle
};

// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedInner();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden);
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);
bool IsWin32BridgeWithSee();
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);

bool Win32EthIsSuSupported();

void Win32EthSetShowAllIf(bool b);
bool Win32EthGetShowAllIf();

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
int CmpRpcEnumEthVLan(void *p1, void *p2);
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
bool SetVLanEnableStatus(char *title, bool enable);
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
char *SearchDeviceInstanceIdFromShortKey(char *short_key);
void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
UINT Win32EthGenIdFromGuid(char *guid);
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str);

struct WP_ADAPTER *Win32EthSearch(char *name);
bool Win32IsUsingSeLow();
void Win32SetEnableSeLow(bool b);
bool Win32GetEnableSeLow();

#endif	// BRIDGEWIN32_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
