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


// Interop_SSTP.h
// Header of Interop_SSTP.c

#ifndef	INTEROP_SSTP_H
#define	INTEROP_SSTP_H

//// Constants
#define	SSTP_URI				"/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"		// SSTP HTTPS URI
#define	SSTP_VERSION_1			0x10							// SSTP Version 1.0
#define	MAX_SSTP_PACKET_SIZE	4096							// Maximum packet size
#define SSTP_IPC_CLIENT_NAME			"Microsoft SSTP VPN Client"
#define	SSTP_IPC_POSTFIX				"SSTP"
#define	SSTP_ECHO_SEND_INTERVAL_MIN		2500					// Transmission interval of Echo Request (minimum)
#define	SSTP_ECHO_SEND_INTERVAL_MAX		4792					// Transmission interval of Echo Request (maximum)
#define	SSTP_TIMEOUT					10000					// Communication time-out of SSTP

// SSTP Message Type
#define	SSTP_MSG_CALL_CONNECT_REQUEST				0x0001
#define	SSTP_MSG_CALL_CONNECT_ACK					0x0002
#define	SSTP_MSG_CALL_CONNECT_NAK					0x0003
#define	SSTP_MSG_CALL_CONNECTED						0x0004
#define	SSTP_MSG_CALL_ABORT							0x0005
#define	SSTP_MSG_CALL_DISCONNECT					0x0006
#define	SSTP_MSG_CALL_DISCONNECT_ACK				0x0007
#define	SSTP_MSG_ECHO_REQUEST						0x0008
#define	SSTP_MSG_ECHO_RESPONSE						0x0009

// SSTP Attribute ID
#define	SSTP_ATTRIB_NO_ERROR						0x00
#define	SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID		0x01
#define	SSTP_ATTRIB_STATUS_INFO						0x02
#define	SSTP_ATTRIB_CRYPTO_BINDING					0x03
#define	SSTP_ATTRIB_CRYPTO_BINDING_REQ				0x04

// Protocol ID
#define	SSTP_ENCAPSULATED_PROTOCOL_PPP				0x0001

// Hash Protocol Bitmask
#define	CERT_HASH_PROTOCOL_SHA1						0x01
#define	CERT_HASH_PROTOCOL_SHA256					0x02

// Status
#define	ATTRIB_STATUS_NO_ERROR						0x00000000
#define	ATTRIB_STATUS_DUPLICATE_ATTRIBUTE			0x00000001
#define	ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE		0x00000002
#define	ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH	0x00000003
#define	ATTRIB_STATUS_VALUE_NOT_SUPPORTED			0x00000004
#define	ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED		0x00000005
#define	ATTRIB_STATUS_RETRY_COUNT_EXCEEDED			0x00000006
#define	ATTRIB_STATUS_INVALID_FRAME_RECEIVED		0x00000007
#define	ATTRIB_STATUS_NEGOTIATION_TIMEOUT			0x00000008
#define	ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG	0x00000009
#define	ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING	0x0000000A
#define	ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG	0x0000000B

// State of SSTP Server
#define	SSTP_SERVER_STATUS_REQUEST_PENGING			0	// Connection incomplete
#define	SSTP_SERVER_STATUS_CONNECTED_PENDING		1	// Connection completed. Authentication incomplete
#define	SSTP_SERVER_STATUS_ESTABLISHED				2	// Connection completed. Communication available

// Length of Nonce
#define	SSTP_NONCE_SIZE								32	// 256 bits


//// Type

// SSTP Attibute
struct SSTP_ATTRIBUTE
{
	UCHAR AttributeId;
	UCHAR *Data;
	UINT DataSize;
	UINT TotalLength;
};

// SSTP Packet
struct SSTP_PACKET
{
	UCHAR Version;
	bool IsControl;
	UCHAR *Data;
	UINT DataSize;
	USHORT MessageType;
	LIST *AttibuteList;
};

// SSTP Server
struct SSTP_SERVER
{
	CEDAR *Cedar;
	UINT64 Now;
	IP ClientIp, ServerIp;
	UINT ClientPort, ServerPort;
	char ClientHostName[MAX_HOST_NAME_LEN + 1];
	char ClientCipherName[MAX_SIZE];
	SOCK_EVENT *SockEvent;
	QUEUE *RecvQueue;						// Receive queue
	QUEUE *SendQueue;						// Transmission queue
	INTERRUPT_MANAGER *Interrupt;			// Interrupt manager
	bool Aborting;							// Forced disconnection flag
	bool AbortSent;							// Flag of whether to send the Abort
	bool AbortReceived;						// Flag of whether the Abort has been received
	bool Disconnecting;						// Disconnecting flag
	bool DisconnectSent;					// Flag of whether to send a Disconnect
	bool DisconnectRecved;					// Flag of whether a Disconnect has been received
	bool Disconnected;						// Flag as to disconnect
	UINT Status;							// State
	UCHAR SentNonce[SSTP_NONCE_SIZE];		// Random data sent
	TUBE *TubeRecv, *TubeSend;				// Delivery tube of packets to PPP module
	THREAD *PPPThread;						// PPP module thread
	UINT64 NextSendEchoRequestTick;			// Time to send the next Echo Request
	UINT64 LastRecvTick;					// Tick when some data has received at the end
	bool FlushRecvTube;						// Flag whether to flush the reception tube
	UINT EstablishedCount;					// Number of session establishment
};


//// Function prototype
bool AcceptSstp(CONNECTION *c);
bool ProcessSstpHttps(CEDAR *cedar, SOCK *s, SOCK_EVENT *se);

SSTP_SERVER *NewSstpServer(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip,
						   UINT server_port, SOCK_EVENT *se,
						   char *client_host_name, char *crypt_name);
void FreeSstpServer(SSTP_SERVER *s);
void SstpProcessInterrupt(SSTP_SERVER *s);
SSTP_PACKET *SstpParsePacket(UCHAR *data, UINT size);
LIST *SstpParseAttributeList(UCHAR *data, UINT size, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpParseAttribute(UCHAR *data, UINT size);
void SstpFreeAttribute(SSTP_ATTRIBUTE *a);
void SstpFreeAttributeList(LIST *o);
void SstpFreePacket(SSTP_PACKET *p);
BUF *SstpBuildPacket(SSTP_PACKET *p);
BUF *SstpBuildAttributeList(LIST *o, USHORT message_type);
BUF *SstpBuildAttribute(SSTP_ATTRIBUTE *a);
void SstpAbort(SSTP_SERVER *s);
void SstpDisconnect(SSTP_SERVER *s);
void SstpProcessPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessControlPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessDataPacket(SSTP_SERVER *s, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpFindAttribute(SSTP_PACKET *p, UCHAR attribute_id);
SSTP_ATTRIBUTE *SstpNewAttribute(UCHAR attribute_id, UCHAR *data, UINT data_size);
SSTP_ATTRIBUTE *SstpNewStatusInfoAttribute(UCHAR attrib_id, UINT status);
SSTP_ATTRIBUTE *SstpNewCryptoBindingRequestAttribute(UCHAR hash_protocol_bitmask, UCHAR *nonce_32bytes);
SSTP_PACKET *SstpNewDataPacket(UCHAR *data, UINT size);
SSTP_PACKET *SstpNewControlPacket(USHORT message_type);
SSTP_PACKET *SstpNewControlPacketWithAnAttribute(USHORT message_type, SSTP_ATTRIBUTE *a);
void SstpSendPacket(SSTP_SERVER *s, SSTP_PACKET *p);
bool GetNoSstp();
void SetNoSstp(bool b);

#endif	// INTEROP_SSTP_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
