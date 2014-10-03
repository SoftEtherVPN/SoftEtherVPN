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


// BridgeUnix.h
// Header of BridgeUnix.c

#ifndef	BRIDGEUNIX_H
#define	BRIDGEUNIX_H

// Macro
#ifndef SOL_PACKET
#define	SOL_PACKET	263
#endif
#ifndef ifr_newname
#define ifr_newname     ifr_ifru.ifru_slave
#endif

// Constants
#define	UNIX_ETH_TMP_BUFFER_SIZE		(2000)
#define	SOLARIS_MAXDLBUF				(32768)
#define BRIDGE_MAX_QUEUE_SIZE			(4096*1500)

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	CANCEL *Cancel;				// Cancel object
	int IfIndex;				// Index
	int Socket;					// Socket
	UINT InitialMtu;			// Initial MTU value
	UINT CurrentMtu;			// Current MTU value
	int SocketBsdIf;			// BSD interface operation socket
	UCHAR MacAddress[6];		// MAC address

#ifdef BRIDGE_PCAP
	void *Pcap;					// Pcap descriptor
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// Pcap relay thread
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
	UINT BufSize;				// Buffer size to read the BPF (error for other)
#ifdef BRIDGE_BPF_THREAD
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// BPF relay thread
#else // BRIDGE_BPF_THREAD
	UCHAR *Buffer;				// Buffer to read the BPF
	UCHAR *Next;
	int Rest;
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	VLAN *Tap;					// tap
	bool Linux_IsAuxDataSupported;	// Is PACKET_AUXDATA supported
};

#if defined( BRIDGE_BPF ) || defined( BRIDGE_PCAP )
struct CAPTUREBLOCK{
	UINT Size;
	UCHAR *Buf;
};
#endif // BRIDGE_BPF


// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedLinux();
bool IsEthSupportedSolaris();
bool IsEthSupportedPcap();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListLinux();
TOKEN_LIST *GetEthListSolaris();
TOKEN_LIST *GetEthListPcap();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr);
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
UINT EthGetPacketLinux(ETH *e, void **data);
UINT EthGetPacketSolaris(ETH *e, void **data);
UINT EthGetPacketPcap(ETH *e, void **data);
UINT EthGetPacketBpf(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size);
bool EthIsInterfaceDescriptionSupportedUnix();

#ifdef	UNIX_SOLARIS
// Function prototype for Solaris
bool DlipAttatchRequest(int fd, UINT devid);
bool DlipReceiveAck(int fd);
bool DlipPromiscuous(int fd, UINT level);
bool DlipBindRequest(int fd);
#endif	// OS_SOLARIS

int UnixEthOpenRawSocket();

#endif	// BRIDGEUNIX_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
