// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Listener.h
// Header of Listener.c

#ifndef	LISTENER_H
#define	LISTENER_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Network.h"

// Function to call when receiving a new connection
typedef void (NEW_CONNECTION_PROC)(CONNECTION *c);


// DOS attack list
struct DOS
{
	IP IpAddress;					// IP address
	UINT64 FirstConnectedTick;		// Time which a client connects at the first time
	UINT64 LastConnectedTick;		// Time which a client connected at the last time
	UINT64 CurrentExpireSpan;		// Current time-out period of this record
	UINT64 DeleteEntryTick;			// Time planned to delete this entry
	UINT AccessCount;				// The number of accesses
};

// Listener structure
struct LISTENER
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	UINT Protocol;					// Protocol
	UINT Port;						// Port number
	THREAD *Thread;					// Operating thread
	SOCK *Sock;						// Socket
	EVENT *Event;					// Event
	volatile bool Halt;				// Halting flag
	UINT Status;					// State

	LIST *DosList;					// DOS attack list
	UINT64 DosListLastRefreshTime;	// Time that the DOS list is refreshed at the last

	THREAD_PROC *ThreadProc;		// Thread procedure
	void *ThreadParam;				// Thread parameters
	bool LocalOnly;					// Can be connected only from localhost
	bool ShadowIPv6;				// Flag indicating that the shadow IPv6 listener
	LISTENER *ShadowListener;		// Reference to managing shadow IPv6 listener
	bool DisableDos;				// Disable the DoS attack detection
	volatile UINT *NatTGlobalUdpPort;	// NAT-T global UDP port number
	UCHAR RandPortId;				// NAT-T UDP random port ID
	bool EnableConditionalAccept;	// The flag of whether to enable the Conditional Accept
};

// Parameters of TCPAcceptedThread
struct TCP_ACCEPTED_PARAM
{
	LISTENER *r;
	SOCK *s;
};

// UDP entry
struct UDP_ENTRY
{
	UINT SessionKey32;				// 32bit session key
	SESSION *Session;				// Reference to the session
};

// Dynamic listener
struct DYNAMIC_LISTENER
{
	UINT Protocol;					// Protocol
	UINT Port;						// Port
	LOCK *Lock;						// Lock
	CEDAR *Cedar;					// Cedar
	bool *EnablePtr;				// A pointer to the flag of the valid / invalid state
	LISTENER *Listener;				// Listener
};


// Function prototype
LISTENER *NewListener(CEDAR *cedar, UINT proto, UINT port);
LISTENER *NewListenerEx(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param);
LISTENER *NewListenerEx2(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only);
LISTENER *NewListenerEx3(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6);
LISTENER *NewListenerEx4(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
						 volatile UINT *natt_global_udp_port, UCHAR rand_port_id);
LISTENER *NewListenerEx5(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
						 volatile UINT *natt_global_udp_port, UCHAR rand_port_id, bool enable_ca);
void ReleaseListener(LISTENER *r);
void CleanupListener(LISTENER *r);
void ListenerThread(THREAD *thread, void *param);
void ListenerTCPMainLoop(LISTENER *r);
void StopListener(LISTENER *r);
int CompareListener(void *p1, void *p2);
void TCPAccepted(LISTENER *r, SOCK *s);
void EnableDosProtect();
void DisableDosProtect();
void TCPAcceptedThread(THREAD *t, void *param);
void ListenerUDPMainLoop(LISTENER *r);
void UDPReceivedPacket(CEDAR *cedar, SOCK *s, IP *ip, UINT port, void *data, UINT size);
int CompareUDPEntry(void *p1, void *p2);
void CleanupUDPEntry(CEDAR *cedar);
void AddUDPEntry(CEDAR *cedar, SESSION *session);
void DelUDPEntry(CEDAR *cedar, SESSION *session);
SESSION *GetSessionFromUDPEntry(CEDAR *cedar, UINT key32);
UINT GetMaxConnectionsPerIp();
void SetMaxConnectionsPerIp(UINT num);
UINT GetMaxUnestablishedConnections();
void SetMaxUnestablishedConnections(UINT num);
DYNAMIC_LISTENER *NewDynamicListener(CEDAR *c, bool *enable_ptr, UINT protocol, UINT port);
void ApplyDynamicListener(DYNAMIC_LISTENER *d);
void FreeDynamicListener(DYNAMIC_LISTENER *d);
bool ListenerRUDPRpcRecvProc(RUDP_STACK *r, UDPPACKET *p);
void ListenerSetProcRecvRpcEnable(bool b);

int CompareDos(void *p1, void *p2);
DOS *SearchDosList(LISTENER *r, IP *ip);
void RefreshDosList(LISTENER *r);
bool CheckDosAttack(LISTENER *r, SOCK *s);
bool RemoveDosEntry(LISTENER *r, SOCK *s);

#endif	// LISTENER_H


