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


// VLanWin32.h
// Header of VLanWin32.c

#ifndef	VLANWIN32_H
#define	VLANWIN32_H

// Routing table tracking timer
#define	TRACKING_INTERVAL_INITIAL		444		// Initial
#define	TRACKING_INTERVAL_ADD			444		// Adding value
#define	TRACKING_INTERVAL_MAX			12345	// Maximum value
#define	TRACKING_INTERVAL_MAX_RC		87654	// Maximum value (OS which change detection mechanism enabled)


typedef void *HANDLE;

// Routing tracking state machine
struct ROUTE_TRACKING
{
	UINT VLanInterfaceId;
	ROUTE_ENTRY *RouteToServer;
	bool RouteToServerAlreadyExists;
	ROUTE_ENTRY *DefaultGatewayByVLan;
	ROUTE_ENTRY *VistaDefaultGateway1, *VistaDefaultGateway2, *VistaOldDefaultGatewayByVLan;
	ROUTE_ENTRY *RouteToDefaultDns;
	ROUTE_ENTRY *RouteToEight;
	ROUTE_ENTRY *RouteToNatTServer;
	ROUTE_ENTRY *RouteToRealServerGlobal;
	UINT64 NextTrackingTime;
	UINT64 NextTrackingTimeAdd;
	UINT64 NextRouteChangeCheckTime;
	UINT LastRoutingTableHash;
	QUEUE *DeletedDefaultGateway;
	UINT OldDefaultGatewayMetric;
	IP OldDnsServer;
	bool VistaAndUsingPPP;
	ROUTE_CHANGE *RouteChange;
};

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halting flag
	bool Win9xMode;				// Windows 9x
	char *InstanceName;			// Instance name
	char *DeviceNameWin32;		// Win32 device name
	char *EventNameWin32;		// Win32 event name
	HANDLE Handle;				// Device driver file
	HANDLE Event;				// Handle of the event
	void *GetBuffer;			// Sent packet capturing buffer
	UINT CurrentPacketCount;	// Packet number to be read next
	void *PutBuffer;			// Buffer for writing received packet
	ROUTE_TRACKING *RouteState;	// Routing tracking state machine
};

// Instance list
struct INSTANCE_LIST
{
	UINT NumInstance;
	char **InstanceName;
};


// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
void FreeVLan(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanGetPacketsFromDriver(VLAN *v);
bool VLanPutPacketsToDriver(VLAN *v);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

INSTANCE_LIST *GetInstanceList();
void FreeInstanceList(INSTANCE_LIST *n);
UINT GetInstanceId(char *name);

void RouteTrackingStart(SESSION *s);
void RouteTrackingStop(SESSION *s, ROUTE_TRACKING *t);
void RouteTrackingMain(SESSION *s);
void Win32ReleaseAllDhcp9x(bool wait);

void Win32GetWinVer(RPC_WINVER *v);

#endif	// VLANWIN32_H

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
