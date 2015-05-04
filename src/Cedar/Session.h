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


// Session.h
// Header of Session.c

#ifndef	SESSION_H
#define	SESSION_H


// Interval to increment the number of logins after the connection
#define	NUM_LOGIN_INCREMENT_INTERVAL		(30 * 1000)

// Packet adapter function
typedef bool (PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void (PA_FREE)(SESSION *s);

// Client related function
typedef void (CLIENT_STATUS_PRINTER)(SESSION *s, wchar_t *status);

// Node information
struct NODE_INFO
{
	char ClientProductName[64];		// Client product name
	UINT ClientProductVer;			// Client version
	UINT ClientProductBuild;		// Client build number
	char ServerProductName[64];		// Server product name
	UINT ServerProductVer;			// Server version
	UINT ServerProductBuild;		// Server build number
	char ClientOsName[64];			// Client OS name
	char ClientOsVer[128];			// Client OS version
	char ClientOsProductId[64];		// Client OS Product ID
	char ClientHostname[64];		// Client host name
	UINT ClientIpAddress;			// Client IP address
	UINT ClientPort;				// Client port number
	char ServerHostname[64];		// Server host name
	UINT ServerIpAddress;			// Server IP address
	UINT ServerPort;				// Server port number
	char ProxyHostname[64];			// Proxy host name
	UINT ProxyIpAddress;			// Proxy Server IP Address
	UINT ProxyPort;					// Proxy port number
	char HubName[64];				// HUB name
	UCHAR UniqueId[16];				// Unique ID
	// The following is for IPv6 support
	UCHAR ClientIpAddress6[16];		// Client IPv6 address
	UCHAR ServerIpAddress6[16];		// Server IP address
	UCHAR ProxyIpAddress6[16];		// Proxy Server IP Address
	char Padding[304 - (16 * 3)];	// Padding
};

// Packet adapter
struct PACKET_ADAPTER
{
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
	UINT Id;
};

// Packet Adapter IDs
#define	PACKET_ADAPTER_ID_VLAN_WIN32		1


// Session structure
struct SESSION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool LocalHostSession;			// Local host session
	bool ServerMode;				// Server mode session
	bool NormalClient;				// Connecting session from a regular client (not such as localbridge)
	bool LinkModeClient;			// Link mode client
	bool LinkModeServer;			// Link mode server
	bool SecureNATMode;				// SecureNAT session
	bool BridgeMode;				// Bridge session
	bool BridgeIsEthLoopbackBlock;	// Loopback is disabled on the Ethernet level
	bool VirtualHost;				// Virtual host mode
	bool L3SwitchMode;				// Layer-3 switch mode
	bool InProcMode;				// In-process mode
	THREAD *Thread;					// Management thread
	CONNECTION *Connection;			// Connection
	char ClientIP[64];				// Client IP
	CLIENT_OPTION *ClientOption;	// Client connection options
	CLIENT_AUTH *ClientAuth;		// Client authentication data
	volatile bool Halt;				// Halting flag
	volatile bool CancelConnect;	// Cancel the connection
	EVENT *HaltEvent;				// Halting event
	UINT Err;						// Error value
	HUB *Hub;						// HUB
	CANCEL *Cancel1;				// Cancel object 1
	CANCEL *Cancel2;				// Cancel object 2
	PACKET_ADAPTER *PacketAdapter;	// Packet adapter
	UCHAR UdpSendKey[16];			// UDP encryption key for transmission
	UCHAR UdpRecvKey[16];			// UDP encryption key for reception
	UINT ClientStatus;				// Client Status
	bool RetryFlag;					// Retry flag (client)
	bool ForceStopFlag;				// Forced stop flag (client)
	UINT CurrentRetryCount;			// Current retry counter (client)
	UINT RetryInterval;				// Retry interval (client)
	bool ConnectSucceed;			// Connection success flag (client)
	bool SessionTimeOuted;			// Session times out
	UINT Timeout;					// Time-out period
	UINT64 NextConnectionTime;		// Time to put next additional connection
	IP ServerIP;					// IP address of the server
	bool ClientModeAndUseVLan;		// Use a virtual LAN card in client mode
	bool UseSSLDataEncryption;		// Use SSL data encryption
	LOCK *TrafficLock;				// Traffic data lock
	LINK *Link;						// A reference to the link object
	SNAT *SecureNAT;				// A reference to the SecureNAT object
	BRIDGE *Bridge;					// A reference to the Bridge object
	NODE_INFO NodeInfo;				// Node information
	UINT64 LastIncrementTraffic;	// Last time that updated the traffic data of the user
	bool AdministratorMode;			// Administrator mode
	LIST *CancelList;				// Cancellation list
	L3IF *L3If;						// Layer-3 interface
	IP DefaultDns;					// IP address of the default DNS server
	bool IPv6Session;				// IPv6 session (Physical communication is IPv6)
	UINT VLanId;					// VLAN ID
	UINT UniqueId;					// Unique ID
	UCHAR IpcMacAddress[6];			// MAC address for IPC
	UCHAR Padding[2];

	UINT64 CreatedTime;				// Creation date and time
	UINT64 LastCommTime;			// Last communication date and time
	UINT64 LastCommTimeForDormant;	// Last communication date and time (for dormant)
	TRAFFIC *Traffic;				// Traffic data
	TRAFFIC *OldTraffic;			// Old traffic data
	UINT64 TotalSendSize;			// Total transmitted data size
	UINT64 TotalRecvSize;			// Total received data size
	UINT64 TotalSendSizeReal;		// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;		// Total received data size (no compression)
	char *Name;						// Session name
	char *Username;					// User name
	char UserNameReal[MAX_USERNAME_LEN + 1];	// User name (real)
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	POLICY *Policy;					// Policy
	UCHAR SessionKey[SHA1_SIZE];	// Session key
	UINT SessionKey32;				// 32bit session key
	char SessionKeyStr[64];			// Session key string
	UINT MaxConnection;				// Maximum number of concurrent TCP connections
	bool UseEncrypt;				// Use encrypted communication
	bool UseFastRC4;				// Use high speed RC4 encryption
	bool UseCompress;				// Use data compression
	bool HalfConnection;			// Half connection mode
	bool QoS;						// VoIP / QoS
	bool NoSendSignature;			// Do not send a signature
	bool IsOpenVPNL3Session;		// Whether OpenVPN L3 session
	bool IsOpenVPNL2Session;		// Whether OpenVPN L2 session
	UINT NumDisconnected;			// Number of socket disconnection
	bool NoReconnectToSession;		// Disable to reconnect to the session
	char UnderlayProtocol[64];		// Physical communication protocol
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Completion time of this connection
	UINT NumConnectionsEatablished;	// Number of connections established so far
	UINT AdjustMss;					// MSS adjustment value
	bool IsVPNClientAndVLAN_Win32;	// Is the VPN Client session with a VLAN card (Win32)

	bool IsRUDPSession;				// Whether R-UDP session
	UINT RUdpMss;					// The value of the MSS should be applied while the R-UDP is used
	bool EnableBulkOnRUDP;			// Allow the bulk transfer in the R-UDP session
	bool EnableHMacOnBulkOfRUDP;	// Use the HMAC to sign the bulk transfer of R-UDP session
	bool EnableUdpRecovery;			// Enable the R-UDP recovery

	bool UseUdpAcceleration;		// Use of UDP acceleration mode
	bool UseHMacOnUdpAcceleration;	// Use the HMAC in the UDP acceleration mode
	UDP_ACCEL *UdpAccel;			// UDP acceleration
	bool IsUsingUdpAcceleration;	// Flag of whether the UDP acceleration is used
	UINT UdpAccelMss;				// MSS value to be applied while the UDP acceleration is used
	bool UdpAccelFastDisconnectDetect;	// Fast disconnection detection is enabled

	bool IsAzureSession;			// Whether the session via VPN Azure
	IP AzureRealServerGlobalIp;		// Real global IP of the server-side in the case of session via VPN Azure

	ACCOUNT *Account;				// Client account
	UINT VLanDeviceErrorCount;		// Number of times that the error occurred in the virtual LAN card
	bool Win32HideConnectWindow;	// Hide the status window
	bool Win32HideNicInfoWindow;	// Hide the NIC information window
	bool UserCanceled;				// Canceled by the user
	UINT64 LastTryAddConnectTime;	// Last time that attempted to add a connection

	bool IsMonitorMode;				// Whether the monitor mode
	bool IsBridgeMode;				// Whether the bridge mode
	bool UseClientLicense;			// Number of assigned client licenses
	bool UseBridgeLicense;			// Number of assigned bridge licenses

	COUNTER *LoggingRecordCount;	// Counter for the number of logging records

	bool FreeInfoShowed;			// Whether a warning about Free Edition has already displayed

	bool Client_NoSavePassword;		// Prohibit the password saving
	wchar_t *Client_Message;		// Message that has been sent from the server

	LIST *DelayedPacketList;		// Delayed packet list
	UINT Flag1;

	USER *NumLoginIncrementUserObject;	// User objects to increment the nymber of logins
	HUB *NumLoginIncrementHubObject;	// Virtual HUB object to increment the number of logins
	UINT64 NumLoginIncrementTick;		// Time to perform increment a number of log

	bool FirstTimeHttpRedirect;		// Redirect HTTP only for the first time
	char FirstTimeHttpRedirectUrl[128];	// URL for redirection only the first time
	UINT FirstTimeHttpAccessCheckIp;	// IP address for access checking

	// To examine the maximum number of alowed logging target packets per minute
	UINT64 MaxLoggedPacketsPerMinuteStartTick;	// Inspection start time
	UINT CurrentNumPackets;				// Current number of packets

	// Measures for D-Link bug
	UINT64 LastDLinkSTPPacketSendTick;	// Last D-Link STP packet transmission time
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];	// Last D-Link STP packet hash
};

// Password dialog
struct UI_PASSWORD_DLG
{
	UINT Type;						// Type of password
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char Password[MAX_PASSWORD_LEN + 1];	// Password
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT RetryIntervalSec;			// Time to retry
	EVENT *CancelEvent;				// Event to cancel the dialog display
	bool ProxyServer;				// The authentication by the proxy server
	UINT64 StartTick;				// Start time
	bool AdminMode;					// Administrative mode
	bool ShowNoSavePassword;		// Whether to display a check box that does not save the password
	bool NoSavePassword;			// Mode that not to save the password
	SOCK *Sock;						// Socket
};

// Message dialog
struct UI_MSG_DLG
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	wchar_t *Msg;					// Body
	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
};

// NIC information
struct UI_NICINFO
{
	wchar_t AccountName[MAX_SIZE];	// Connection setting name
	char NicName[MAX_SIZE];			// Virtual NIC name

	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
	ROUTE_CHANGE *RouteChange;		// Routing table change notification
	UINT CurrentIcon;				// Current icon
	UINT64 CloseAfterTime;			// Close automatically
};

// Connection Error dialog
struct UI_CONNECTERROR_DLG
{
	EVENT *CancelEvent;				// Event to cancel the dialog display
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT Err;						// Error code
	UINT CurrentRetryCount;			// Current retry count
	UINT RetryLimit;				// Limit of the number of retries
	UINT64 StartTick;				// Start time
	UINT RetryIntervalSec;			// Time to retry
	bool HideWindow;				// Hide the window
	SOCK *Sock;						// Socket
};

// Server certificate checking dialog
struct UI_CHECKCERT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	X *x;							// Server certificate
	X *parent_x;					// Parent certificate
	X *old_x;						// Certificate of previous
	bool DiffWarning;				// Display a warning of certificate forgery
	bool Ok;						// Connection permission flag
	bool SaveServerCert;			// Save the server certificate
	SESSION *Session;				// Session
	volatile bool Halt;				// Halting flag
	SOCK *Sock;						// Socket
};


// Function prototype
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, struct ACCOUNT *account);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option);
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str);
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
SESSION *NewServerSessionEx(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy, bool inproc_mode);
void ClientThread(THREAD *t, void *param);
void ReleaseSession(SESSION *s);
void CleanupSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
bool SessionConnect(SESSION *s);
bool ClientConnect(CONNECTION *c);
int CompareSession(void *p1, void *p2);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free);
void FreePacketAdapter(PACKET_ADAPTER *pa);
void SessionMain(SESSION *s);
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
SESSION *GetSessionFromKey32(CEDAR *cedar, UINT key32);
void DebugPrintSessionKey(UCHAR *session_key);
bool IsIpcMacAddress(UCHAR *mac);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);
void ClientAdditionalThread(THREAD *t, void *param);
void PrintSessionTotalDataSize(SESSION *s);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void Notify(SESSION *s, UINT code);
void PrintStatus(SESSION *s, wchar_t *str);
LIST *NewCancelList();
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool CompareNodeInfo(NODE_INFO *a, NODE_INFO *b);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);

#endif	// SESSION_H




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
