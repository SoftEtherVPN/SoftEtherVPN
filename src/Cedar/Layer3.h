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


// Layer3.h
// Header of Layer3.c

#ifndef	LAYER3_H
#define	LAYER3_H

// Constants
#define	L3_USERNAME					"L3SW_"


// L3 ARP table entry
struct L3ARPENTRY
{
	UINT IpAddress;					// IP address
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 Expire;					// Expiration date
};

// L3 ARP resolution waiting list entry
struct L3ARPWAIT
{
	UINT IpAddress;					// IP address
	UINT64 LastSentTime;			// Time which the data has been sent last
	UINT64 Expire;					// Expiration date
};

// L3 IP packet table
struct L3PACKET
{
	PKT *Packet;					// Packet data body
	UINT64 Expire;					// Expiration date
	UINT NextHopIp;					// Local delivery destination IP address
};

// L3 routing table definition
struct L3TABLE
{
	UINT NetworkAddress;			// Network address
	UINT SubnetMask;				// Subnet mask
	UINT GatewayAddress;			// Gateway address
	UINT Metric;					// Metric
};

// L3 interface definition
struct L3IF
{
	L3SW *Switch;					// Layer-3 switch
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	UINT IpAddress;					// IP address
	UINT SubnetMask;				// Subnet mask

	HUB *Hub;						// Virtual HUB
	SESSION *Session;				// Session
	LIST *ArpTable;					// ARP table
	LIST *ArpWaitTable;				// ARP waiting table
	QUEUE *IpPacketQueue;			// IP packet queue (for reception from other interfaces)
	LIST *IpWaitList;				// IP waiting list
	QUEUE *SendQueue;				// Transmission queue
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 LastDeleteOldArpTable;	// Time that old ARP table entries are cleared
	LIST *CancelList;				// Cancellation list
	UINT64 LastBeaconSent;			// Time which the beacon has been sent last
};

// L3 switch definition
struct L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];	// Name
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool Active;					// During operation flag
	bool Online;					// Online flag
	volatile bool Halt;				// Halting flag
	LIST *IfList;					// Interface list
	LIST *TableList;				// Routing table list
	THREAD *Thread;					// Thread
};



// Function prototype
int CmpL3Sw(void *p1, void *p2);
int CmpL3ArpEntry(void *p1, void *p2);
int CmpL3ArpWaitTable(void *p1, void *p2);
int CmpL3Table(void *p1, void *p2);
int CmpL3If(void *p1, void *p2);
void InitCedarLayer3(CEDAR *c);
void FreeCedarLayer3(CEDAR *c);
L3SW *NewL3Sw(CEDAR *c, char *name);
void ReleaseL3Sw(L3SW *s);
void CleanupL3Sw(L3SW *s);
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet);
bool L3DelIf(L3SW *s, char *hubname);
bool L3AddTable(L3SW *s, L3TABLE *tbl);
bool L3DelTable(L3SW *s, L3TABLE *tbl);
L3IF *L3SearchIf(L3SW *s, char *hubname);
L3SW *L3GetSw(CEDAR *c, char *name);
L3SW *L3AddSw(CEDAR *c, char *name);
bool L3DelSw(CEDAR *c, char *name);
void L3FreeAllSw(CEDAR *c);
void L3SwStart(L3SW *s);
void L3SwStop(L3SW *s);
void L3SwThread(THREAD *t, void *param);
void L3Test(SERVER *s);
void L3InitAllInterfaces(L3SW *s);
void L3FreeAllInterfaces(L3SW *s);
void L3IfThread(THREAD *t, void *param);
void L3InitInterface(L3IF *f);
void L3FreeInterface(L3IF *f);
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop);
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip);
UINT L3GetNextPacket(L3IF *f, void **data);
void L3Polling(L3IF *f);
void L3PollingBeacon(L3IF *f);
void L3DeleteOldArpTable(L3IF *f);
void L3DeleteOldIpWaitList(L3IF *f);
void L3PollingArpWaitTable(L3IF *f);
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void L3SendArpRequestNow(L3IF *f, UINT dest_ip);
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void L3GenerateMacAddress(L3IF *f);
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip);
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p);
void L3SendIp(L3IF *f, L3PACKET *p);
void L3RecvArp(L3IF *f, PKT *p);
void L3RecvArpRequest(L3IF *f, PKT *p);
void L3RecvArpResponse(L3IF *f, PKT *p);
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac);
void L3SendArp(L3IF *f, UINT ip);
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac);
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a);
void L3PutPacket(L3IF *f, void *data, UINT size); 
void L3RecvL2(L3IF *f, PKT *p);
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p);
void L3RecvIp(L3IF *f, PKT *p, bool self);
void L3PollingIpQueue(L3IF *f);


#endif	// LAYER3_H




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
