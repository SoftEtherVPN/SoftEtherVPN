// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori, Ph.D.
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


// Listener.c
// Listener module

#include "CedarPch.h"

static bool disable_dos = false;
static UINT max_connections_per_ip = DEFAULT_MAX_CONNECTIONS_PER_IP;
static UINT max_unestablished_connections = DEFAULT_MAX_UNESTABLISHED_CONNECTIONS;
static bool listener_proc_recv_rpc = false;

// Set the flag of whether to response to the RPC of RUDP
void ListenerSetProcRecvRpcEnable(bool b)
{
	listener_proc_recv_rpc = b;
}

// Get the number of allowed outstanding connections
UINT GetMaxUnestablishedConnections()
{
	return max_unestablished_connections;
}

// Set the number of allowed outstanding connections
void SetMaxUnestablishedConnections(UINT num)
{
	if (num == 0)
	{
		num = DEFAULT_MAX_UNESTABLISHED_CONNECTIONS;
	}

	max_unestablished_connections = MAX(num, max_connections_per_ip);
}

// Get the maximum number of connections per IP address
UINT GetMaxConnectionsPerIp()
{
	return max_connections_per_ip;
}

// Set the maximum number of connections per IP address
void SetMaxConnectionsPerIp(UINT num)
{
	if (num == 0)
	{
		num = DEFAULT_MAX_CONNECTIONS_PER_IP;
	}
	max_connections_per_ip = MAX(num, MIN_MAX_CONNECTIONS_PER_IP);
}

// Enable the DoS defense
void EnableDosProtect()
{
	disable_dos = false;
}

// Disable the DoS defense
void DisableDosProtect()
{
	disable_dos = true;
}

// An UDP packet has been received
void UDPReceivedPacket(CEDAR *cedar, SOCK *s, IP *ip, UINT port, void *data, UINT size)
{
	SESSION *session;
	UINT *key32;
	UCHAR *buf;
	CONNECTION *c;
	// Validate arguments
	if (s == NULL || ip == NULL || data == NULL || size == 0 || cedar == NULL)
	{
		return;
	}

	if (size < 16)
	{
		// Ignore since the packet size is not enough
		return;
	}
	buf = (UCHAR *)data;
	key32 = (UINT *)(buf + 4);


	// Get the session from the Key32 value
	session = GetSessionFromUDPEntry(cedar, Endian32(*key32));
	if (session == NULL)
	{
		Debug("Invalid UDP Session Key 32: 0x%X\n", *key32);
		return;
	}

	c = session->Connection;

	// Write the data
	PutUDPPacketData(c, buf, size);

	// Rewrite the UDP socket associated with the connection
	Lock(c->lock);
	{
		if (c->Protocol == CONNECTION_UDP)
		{
			if (c->Udp->s != s)
			{
				if (c->Udp->s != NULL)
				{
					ReleaseSock(c->Udp->s);
				}
				AddRef(s->ref);
				c->Udp->s = s;
			}
			Copy(&c->Udp->ip, ip, sizeof(UINT));
			c->Udp->port = port;
		}
	}
	Unlock(c->lock);

	// Invoke the Cancel
	Cancel(session->Cancel1);

	// Release the session
	ReleaseSession(session);
}

// Thread that processes the accepted TCP connection
void TCPAcceptedThread(THREAD *t, void *param)
{
	TCP_ACCEPTED_PARAM *data;
	LISTENER *r;
	SOCK *s;
	CONNECTION *c;
	bool flag1;
	char tmp[128];
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	// Initialize
	data = (TCP_ACCEPTED_PARAM *)param;
	r = data->r;
	s = data->s;
	AddRef(r->ref);
	AddRef(s->ref);

	// Create a connection
	c = NewServerConnection(r->Cedar, s, t);

	// Register to Cedar as a transient connection
	AddConnection(c->Cedar, c);

	NoticeThreadInit(t);

	AcceptInit(s);
	StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	if (IS_SPECIAL_PORT(s->RemotePort) == false)
	{
		SLog(r->Cedar, "LS_LISTENER_ACCEPT", r->Port, tmp, s->RemoteHostname, s->RemotePort);
	}

	// Reception
	ConnectionAccept(c);
	flag1 = c->flag1;

	// Release
	SLog(r->Cedar, "LS_CONNECTION_END_1", c->Name);
	ReleaseConnection(c);

	// Release
	if (flag1 == false)
	{
		Debug("%s %u flag1 == false\n", __FILE__, __LINE__);
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

		if (IS_SPECIAL_PORT(s->RemotePort) == false)
		{
			SLog(r->Cedar, "LS_LISTENER_DISCONNECT", tmp, s->RemotePort);
		}
		Disconnect(s);
	}
	ReleaseSock(s);
	ReleaseListener(r);
}

// Jump here if there is accepted connection in the TCP
void TCPAccepted(LISTENER *r, SOCK *s)
{
	TCP_ACCEPTED_PARAM *data;
	THREAD *t;
	char tmp[MAX_SIZE];
	UINT num_clients_from_this_ip = 0;
	CEDAR *cedar;
	// Validate arguments
	if (r == NULL || s == NULL)
	{
		return;
	}

	cedar = r->Cedar;

	num_clients_from_this_ip = GetNumIpClient(&s->RemoteIP);


	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	data = ZeroMalloc(sizeof(TCP_ACCEPTED_PARAM));
	data->r = r;
	data->s = s;

	if (r->ThreadProc == TCPAcceptedThread)
	{
		Inc(cedar->AcceptingSockets);
	}

	t = NewThread(r->ThreadProc, data);
	WaitThreadInit(t);
	Free(data);
	ReleaseThread(t);
}


// UDP listener main loop
void ListenerUDPMainLoop(LISTENER *r)
{
	UCHAR *data;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	Debug("ListenerUDPMainLoop Starts.\n");
	r->Status = LISTENER_STATUS_TRYING;

	while (true)
	{
		// Try to listen on the UDP port
		while (true)
		{
			// Stop flag inspection
			if (r->Halt)
			{
				// Stop
				return;
			}

			Debug("NewUDP()\n");
			r->Sock = NewUDPEx2(r->Port, false, &r->Cedar->Server->ListenIP);
			if (r->Sock != NULL)
			{
				// Wait success
				break;
			}

			// Wait failure
			Debug("Failed to NewUDP.\n");
			Wait(r->Event, LISTEN_RETRY_TIME);

			// Stop flag inspection
			if (r->Halt)
			{
				Debug("UDP Halt.\n");
				return;
			}
		}

		r->Status = LISTENER_STATUS_LISTENING;
		Debug("Start Listening at UDP Port %u.\n", r->Sock->LocalPort);

		// Stop flag inspection
		if (r->Halt)
		{
			// Stop
			goto STOP;
		}

		// Allocate the buffer area
		data = Malloc(UDP_PACKET_SIZE);

		// Read the next packet
		while (true)
		{
			IP src_ip;
			UINT src_port;
			UINT size;
			SOCKSET set;

			InitSockSet(&set);
			AddSockSet(&set, r->Sock);
			Select(&set, SELECT_TIME, NULL, NULL);

			size = RecvFrom(r->Sock, &src_ip, &src_port, data, UDP_PACKET_SIZE);
			if (((size == 0) && (r->Sock->IgnoreRecvErr == false)) || r->Halt)
			{
				// Error has occurred
STOP:
				Disconnect(r->Sock);
				ReleaseSock(r->Sock);
				r->Sock = NULL;
				Debug("UDP Listen Stopped.\n");
				Free(data);
				break;
			}

			// Received an UDP packet
			if (size != SOCK_LATER)
			{
				UDPReceivedPacket(r->Cedar, r->Sock, &src_ip, src_port, data, size);
			}
		}
	}
}

// RPC reception procedure
bool ListenerRUDPRpcRecvProc(RUDP_STACK *r, UDPPACKET *p)
{
	return false;
}

// TCP listener main loop
void ListenerTCPMainLoop(LISTENER *r)
{
	SOCK *new_sock;
	SOCK *s;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	Debug("ListenerTCPMainLoop Starts.\n");
	r->Status = LISTENER_STATUS_TRYING;

	while (true)
	{
		bool first_failed = true;
		Debug("Status = LISTENER_STATUS_TRYING\n");
		r->Status = LISTENER_STATUS_TRYING;

		// Try to Listen
		while (true)
		{
			UINT interval;
			// Stop flag inspection
			if (r->Halt)
			{
				// Stop
				return;
			}

			s = NULL;

			if (r->Protocol == LISTENER_TCP)
			{
				if (r->ShadowIPv6 == false)
				{
					if (r->Cedar->Server == NULL)
					{
						s = ListenEx2(r->Port, r->LocalOnly, r->EnableConditionalAccept, NULL);
					}
					else
					{
						s = ListenEx2(r->Port, r->LocalOnly, r->EnableConditionalAccept, &r->Cedar->Server->ListenIP);
					}
				}
				else
				{
					s = ListenEx6(r->Port, r->LocalOnly);
				}
			}
			else if (r->Protocol == LISTENER_INPROC)
			{
				s = ListenInProc();
			}
			else if (r->Protocol == LISTENER_RUDP)
			{
				s = ListenRUDPEx(VPN_RUDP_SVC_NAME, NULL, ListenerRUDPRpcRecvProc, NULL, 0, false, false, r->NatTGlobalUdpPort, r->RandPortId, &r->Cedar->Server->ListenIP);
			}
			else if (r->Protocol == LISTENER_ICMP)
			{
				s = ListenRUDP(VPN_RUDP_SVC_NAME, NULL, ListenerRUDPRpcRecvProc, NULL, MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4),
					true, false);
			}
			else if (r->Protocol == LISTENER_DNS)
			{
				s = ListenRUDP(VPN_RUDP_SVC_NAME, NULL, ListenerRUDPRpcRecvProc, NULL, 53, true, true);
			}
			else if (r->Protocol == LISTENER_REVERSE)
			{
				s = ListenReverse();
			}

			if (s != NULL)
			{
				// Listen success
				AddRef(s->ref);

				Lock(r->lock);
				{
					r->Sock = s;
				}
				Unlock(r->lock);

				if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
				{
					SLog(r->Cedar, "LS_LISTENER_START_2", r->Port);
				}
				break;
			}

			// Listen failure
			if (first_failed)
			{
				first_failed = false;
				if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
				{
					SLog(r->Cedar, "LS_LISTENER_START_3", r->Port, LISTEN_RETRY_TIME / 1000);
				}
			}

			interval = LISTEN_RETRY_TIME;

			if (r->ShadowIPv6)
			{
				if (IsIPv6Supported() == false)
				{
					interval = LISTEN_RETRY_TIME_NOIPV6;

					Debug("IPv6 is not supported.\n");
				}
			}

			Wait(r->Event, interval);

			// Stop flag inspection
			if (r->Halt)
			{
				// Stop
				Debug("Listener Halt.\n");
				return;
			}
		}

		r->Status = LISTENER_STATUS_LISTENING;
		Debug("Status = LISTENER_STATUS_LISTENING\n");

		// Stop flag inspection
		if (r->Halt)
		{
			// Stop
			goto STOP;
		}

		// Accept loop
		while (true)
		{
			// Accept
			Debug("Accept()\n");
			new_sock = Accept(s);
			if (new_sock != NULL)
			{
				// Accept success
				Debug("Accepted.\n");
				TCPAccepted(r, new_sock);
				ReleaseSock(new_sock);
			}
			else
			{
STOP:
				Debug("Accept Canceled.\n");
				// Failed to accept (socket is destroyed)
				// Close the listening socket
				Disconnect(s);
				ReleaseSock(s);
				s = NULL;

				Lock(r->lock);
				{
					if (r->Sock != NULL)
					{
						s = r->Sock;
						r->Sock = NULL;
					}
				}
				Unlock(r->lock);

				if (s != NULL)
				{
					ReleaseSock(s);
				}

				s = NULL;

				break;
			}
		}

		// Stop flag inspection
		if (r->Halt)
		{
			// Stop
			Debug("Listener Halt.\n");
			return;
		}
	}
}

//  Listener Thread
void ListenerThread(THREAD *thread, void *param)
{
	LISTENER *r;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Initialize
	r = (LISTENER *)param;
	AddRef(r->ref);
	r->Thread = thread;
	AddRef(thread->ref);
	NoticeThreadInit(thread);

	// Main loop
	switch (r->Protocol)
	{
	case LISTENER_TCP:
	case LISTENER_INPROC:
	case LISTENER_RUDP:
	case LISTENER_DNS:
	case LISTENER_ICMP:
	case LISTENER_REVERSE:
		// TCP or other stream-based protocol
		ListenerTCPMainLoop(r);
		break;

	case LISTENER_UDP:
		// UDP protocol
		ListenerUDPMainLoop(r);
		break;
	}

	// Release
	ReleaseListener(r);
}

// Shutdown the Listener
void StopListener(LISTENER *r)
{
	UINT port;
	SOCK *s = NULL;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	Lock(r->lock);
	if (r->Halt)
	{
		Unlock(r->lock);
		return;
	}

	// Stop flag set
	r->Halt = true;

	if (r->Sock != NULL)
	{
		s = r->Sock;

		AddRef(s->ref);
	}

	Unlock(r->lock);

	port = r->Port;

	if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_1", port);
	}

	// Close the socket
	if (s != NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;
	}

	// Set the event
	Set(r->Event);

	// Wait for stopping the thread
	WaitThread(r->Thread, INFINITE);

	// Stop the shadow listener
	if (r->ShadowIPv6 == false)
	{
		if (r->ShadowListener != NULL)
		{
			StopListener(r->ShadowListener);

			ReleaseListener(r->ShadowListener);

			r->ShadowListener = NULL;
		}
	}

	if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_2", port);
	}
}

// Cleanup the listener
void CleanupListener(LISTENER *r)
{
	UINT i = 0;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}


	if (r->Sock != NULL)
	{
		ReleaseSock(r->Sock);
	}

	DeleteLock(r->lock);
	ReleaseThread(r->Thread);
	ReleaseEvent(r->Event);

	ReleaseCedar(r->Cedar);

	Free(r);
}

// Release the listener
void ReleaseListener(LISTENER *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	if (Release(r->ref) == 0)
	{
		CleanupListener(r);
	}
}

// Comparison function of UDP entry list
int CompareUDPEntry(void *p1, void *p2)
{
	UDP_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(UDP_ENTRY **)p1;
	e2 = *(UDP_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->SessionKey32 > e2->SessionKey32)
	{
		return 1;
	}
	else if (e1->SessionKey32 == e2->SessionKey32)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// Comparison function of the listener
int CompareListener(void *p1, void *p2)
{
	LISTENER *r1, *r2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	r1 = *(LISTENER **)p1;
	r2 = *(LISTENER **)p2;
	if (r1 == NULL || r2 == NULL)
	{
		return 0;
	}

	if (r1->Protocol > r2->Protocol)
	{
		return 1;
	}
	else if (r1->Protocol < r2->Protocol)
	{
		return -1;
	}
	else if (r1->Port > r2->Port)
	{
		return 1;
	}
	else if (r1->Port < r2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Create a New Listener
LISTENER *NewListener(CEDAR *cedar, UINT proto, UINT port)
{
	return NewListenerEx(cedar, proto, port, TCPAcceptedThread, NULL);
}
LISTENER *NewListenerEx(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param)
{
	return NewListenerEx2(cedar, proto, port, proc, thread_param, false);
}
LISTENER *NewListenerEx2(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only)
{
	return NewListenerEx3(cedar, proto, port, proc, thread_param, local_only, false);
}
LISTENER *NewListenerEx3(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6)
{
	return NewListenerEx4(cedar, proto, port, proc, thread_param, local_only, shadow_ipv6, NULL, 0);
}
LISTENER *NewListenerEx4(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
						 volatile UINT *natt_global_udp_port, UCHAR rand_port_id)
{
	return NewListenerEx5(cedar, proto, port, proc, thread_param,
		local_only, shadow_ipv6, natt_global_udp_port, rand_port_id, false);
}
LISTENER *NewListenerEx5(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
						 volatile UINT *natt_global_udp_port, UCHAR rand_port_id, bool enable_ca)
{
	LISTENER *r;
	THREAD *t;
	// Validate arguments
	if ((proto == LISTENER_TCP && port == 0) || cedar == NULL)
	{
		return NULL;
	}
	// Check the protocol number
	if (proto != LISTENER_TCP && proto != LISTENER_INPROC &&
		proto != LISTENER_RUDP && proto != LISTENER_ICMP && proto != LISTENER_DNS &&
		proto != LISTENER_REVERSE)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(LISTENER));

	r->ThreadProc = proc;
	r->ThreadParam = thread_param;
	r->Cedar = cedar;
	AddRef(r->Cedar->ref);
	r->lock = NewLock();
	r->ref = NewRef();
	r->Protocol = proto;
	r->Port = port;
	r->Event = NewEvent();


	r->LocalOnly = local_only;
	r->ShadowIPv6 = shadow_ipv6;
	r->NatTGlobalUdpPort = natt_global_udp_port;
	r->RandPortId = rand_port_id;
	r->EnableConditionalAccept = enable_ca;

	if (r->ShadowIPv6 == false)
	{
		if (proto == LISTENER_TCP)
		{
			SLog(cedar, "LS_LISTENER_START_1", port);
		}
	}

	// Creating a thread
	t = NewThread(ListenerThread, r);
	WaitThreadInit(t);
	ReleaseThread(t);

	if (r->ShadowIPv6 == false && proto == LISTENER_TCP)
	{
		if (r->Cedar->DisableIPv6Listener == false)
		{
			// Add a shadow listener
			r->ShadowListener = NewListenerEx3(cedar, proto, port, proc, thread_param,
				local_only, true);
		}
	}

	if (r->ShadowIPv6 == false)
	{
		// Add to the Cedar
		AddListener(cedar, r);
	}

	return r;
}

// Get the session from the session key
SESSION *GetSessionFromUDPEntry(CEDAR *cedar, UINT key32)
{
	UDP_ENTRY *e, t;
	SESSION *s;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	t.SessionKey32 = key32;

	LockList(cedar->UDPEntryList);
	{
		e = Search(cedar->UDPEntryList, &t);
		if (e == NULL)
		{
			UnlockList(cedar->UDPEntryList);
			return NULL;
		}
		s = e->Session;
		AddRef(s->ref);
	}
	UnlockList(cedar->UDPEntryList);

	return s;
}

// Delete the UDP session from the UDP entry
void DelUDPEntry(CEDAR *cedar, SESSION *session)
{
	UINT num, i;
	// Validate arguments
	if (cedar == NULL || session == NULL)
	{
		return;
	}

	LockList(cedar->UDPEntryList);
	{
		num = LIST_NUM(cedar->UDPEntryList);
		for (i = 0;i < num;i++)
		{
			UDP_ENTRY *e = LIST_DATA(cedar->UDPEntryList, i);
			if (e->Session == session)
			{
				ReleaseSession(e->Session);
				Delete(cedar->UDPEntryList, e);
				Free(e);
				UnlockList(cedar->UDPEntryList);
				Debug("UDP_Entry Deleted.\n");
				return;
			}
		}
	}
	UnlockList(cedar->UDPEntryList);
}

// Add an UDP session to the UDP entry
void AddUDPEntry(CEDAR *cedar, SESSION *session)
{
	UDP_ENTRY *e;
	// Validate arguments
	if (cedar == NULL || session == NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(UDP_ENTRY));
	e->Session = session;
	e->SessionKey32 = session->SessionKey32;
	AddRef(session->ref);

	LockList(cedar->UDPEntryList);
	{
		Add(cedar->UDPEntryList, e);
	}
	UnlockList(cedar->UDPEntryList);

	Debug("UDP_Entry Added.\n");
}

// Clear the UDP entry
void CleanupUDPEntry(CEDAR *cedar)
{
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}
}

// Create a new dynamic listener
DYNAMIC_LISTENER *NewDynamicListener(CEDAR *c, bool *enable_ptr, UINT protocol, UINT port)
{
	DYNAMIC_LISTENER *d;
	// Validate arguments
	if (c == NULL || enable_ptr == NULL)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(DYNAMIC_LISTENER));

	d->Cedar = c;
	AddRef(d->Cedar->ref);

	d->Lock = NewLock();

	d->EnablePtr = enable_ptr;

	d->Listener = NULL;

	d->Protocol = protocol;
	d->Port = port;

	ApplyDynamicListener(d);

	return d;
}

// Release the dynamic listener
void FreeDynamicListener(DYNAMIC_LISTENER *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Lock(d->Lock);
	{
		if (d->Listener != NULL)
		{
			StopListener(d->Listener);
			ReleaseListener(d->Listener);
			d->Listener = NULL;
		}
	}
	Unlock(d->Lock);

	ReleaseCedar(d->Cedar);

	DeleteLock(d->Lock);

	Free(d);
}

// Set the state to dynamic listener
void ApplyDynamicListener(DYNAMIC_LISTENER *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Lock(d->Lock);
	{
		// Change the state
		if (*d->EnablePtr)
		{
			if (d->Listener == NULL)
			{
				// Create a listener
				WHERE;
				d->Listener = NewListener(d->Cedar, d->Protocol, d->Port);
			}
		}
		else
		{
			// Stop the listener
			if (d->Listener != NULL)
			{
				WHERE;
				StopListener(d->Listener);
				ReleaseListener(d->Listener);
				d->Listener = NULL;
			}
		}
	}
	Unlock(d->Lock);
}


