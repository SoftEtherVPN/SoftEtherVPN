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


// UdpAccel.h
// Header of UdpAccel.c

#ifndef	UDPACCEL_H
#define	UDPACCEL_H

// Constants
#define	UDP_ACCELERATION_COMMON_KEY_SIZE	20			// Common key size
#define	UDP_ACCELERATION_PACKET_KEY_SIZE	20			// Key size for the packet
#define	UDP_ACCELERATION_PACKET_IV_SIZE		20			// IV size for the packet
#define	UDP_ACCELERATION_TMP_BUF_SIZE		2048		// Temporary buffer size
#define	UDP_ACCELERATION_WINDOW_SIZE_MSEC	(30 * 1000)	// Receive window size (in milliseconds)

#define	UDP_ACCELERATION_SUPPORTED_MAX_PAYLOAD_SIZE	1600	// Maximum supported payload size
#define	UDP_ACCELERATION_MAX_PADDING_SIZE	32			// Maximum padding size

#define	UDP_ACCELERATION_REQUIRE_CONTINUOUS	(10 * 1000)	// Not to use if stable communication is not continued at least for this time

// Time constant for Build 8534 or earlier
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN	(1 * 1000)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX	(3 * 1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT		(9 * 1000)	// Time to disconnect time by non-communication

// Time constant for Build 8535 or later
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST	(500)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST	(1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST			(2100)	// Time to disconnect time by non-communication

// Range of port numbers
#define	UDP_SERVER_PORT_LOWER				40000		// Minimum port
#define	UDP_SERVER_PORT_HIGHER				44999		// Maximum port

// NAT-T port signature to be embedded in the Keep Alive of the session
#define	UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE			"NATT_MY_PORT"

// UDP Acceleration Mode
struct UDP_ACCEL
{
	CEDAR *Cedar;										// Cedar
	bool NoNatT;										// Not to communicate with the NAT-T server (To communicate with the query server instead)
	bool ClientMode;									// Whether client mode
	bool IsInCedarPortList;								// Whether included in the port list of the Cedar
	UINT64 Now;											// Current time
	UCHAR MyKey[UDP_ACCELERATION_COMMON_KEY_SIZE];		// Submit-direction common key
	UCHAR YourKey[UDP_ACCELERATION_COMMON_KEY_SIZE];	// Receiving-direction common key
	SOCK *UdpSock;										// UDP socket
	UINT MyPort;										// My port number
	UINT YourPort;										// Port number of the other party
	IP MyIp;											// My IP address
	IP YourIp;											// IP address of the other party
	IP YourIp2;											// IP address of the other party (second)
	bool IsIPv6;										// Whether it's an IPv6
	UCHAR TmpBuf[UDP_ACCELERATION_TMP_BUF_SIZE];		// Temporary buffer
	UINT64 LastRecvYourTick;							// Opponent's tick value of the last reception
	UINT64 LastRecvMyTick;								// My tick value of the last reception
	QUEUE *RecvBlockQueue;								// Reception block queue
	bool UseHMac;										// Flag to use the HMAC
	bool PlainTextMode;									// No encryption
	UINT64 LastSetSrcIpAndPortTick;						// Opponent's tick ??value at the time of storing the IP address and port number of the opponent at the end
	UINT64 LastRecvTick;								// Tick when data has received at the end
	UINT64 NextSendKeepAlive;							// Next time to send a KeepAlive packet
	UCHAR NextIv[UDP_ACCELERATION_PACKET_IV_SIZE];		// IV to be used next
	UINT MyCookie;										// My cookie
	UINT YourCookie;									// Cookie of the other party
	bool Inited;										// Initialized flag
	UINT Mss;											// Optimal MSS
	UINT MaxUdpPacketSize;								// Get the maximum transmittable UDP size
	LOCK *NatT_Lock;									// Lock the IP address field of NAT-T server
	IP NatT_IP;											// IP address of the NAT-T server
	THREAD *NatT_GetIpThread;							// IP address acquisition thread of NAT-T server
	bool NatT_Halt;										// Halting flag of IP address acquisition thread of NAT-T server
	EVENT *NatT_HaltEvent;								// Halting event of IP address acquisition thread of NAT-T server
	UINT64 NextPerformNatTTick;							// Time to communicate with NAT-T server next time
	UINT CommToNatT_NumFail;							// Number of failures to communicate with NAT-T server
	UINT MyPortByNatTServer;							// Self port number which is received from the NAT-T server
	bool MyPortByNatTServerChanged;						// The self port number which is received from the NAT-T server changes
	UINT YourPortByNatTServer;							// Port number of the opponent that was found via the NAT-T server
	bool YourPortByNatTServerChanged;					// Port number of the opponent that was found via the NAT-T server has been changed
	bool FatalError;									// A fatal error occurred
	bool NatT_IP_Changed;								// IP address of the NAT-T server has changed
	UINT64 NatT_TranId;									// Transaction ID to be exchanged with the NAT-T server
	bool IsReachedOnce;									// It is true if it succeeds in mutual transmission and reception of packets at least once
	UINT64 CreatedTick;									// Object creation time
	bool FastDetect;									// Fast disconnection detection mode
	UINT64 FirstStableReceiveTick;						// Start time of current stable continued receivable period
	bool UseSuperRelayQuery;							// Use the super relay query
	bool UseUdpIpQuery;									// Use the self IP address query by UDP
	IP UdpIpQueryHost;									// Host for the self IP address query by UDP
	UINT UdpIpQueryPort;								// Port number for self IP address for query by UDP
	UCHAR UdpIpQueryPacketData[16];						// Query packet data (final transmission)
	UINT UdpIpQueryPacketSize;							// Query packet data size (final transmission)
	UCHAR UdpHostUniqueKey[SHA1_SIZE];					// Unique key for UDP self endpoint query
};

// Function prototype
UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port, bool no_nat_t);
void FreeUdpAccel(UDP_ACCEL *a);
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *server_key, IP *server_ip, UINT server_port, UINT server_cookie, UINT client_cookie, IP *server_ip_2);
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *client_key, IP *client_ip, UINT client_port, IP *client_ip_2);
void UdpAccelPoll(UDP_ACCEL *a);
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64);
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port);
void UdpAccelCalcKey(UCHAR *key, UCHAR *common_key, UCHAR *iv);
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive);
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, bool compressed, UINT max_size, bool high_priority);
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b);
UINT UdpAccelCalcMss(UDP_ACCEL *a);
void NatT_GetIpThread(THREAD *thread, void *param);

#endif	// UDPACCEL_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
