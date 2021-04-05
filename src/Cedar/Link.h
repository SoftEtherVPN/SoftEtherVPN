// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Link.h
// Header of Link.c

#ifndef	LINK_H
#define	LINK_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

struct LINK
{
	bool Started;					// Running flag
	volatile bool Halting;			// Halting flag
	bool Offline;					// Offline
	bool NoOnline;					// Do not set to online flag
	REF *ref;						// Reference counter
	LOCK *lock;						// Lock
	CEDAR *Cedar;					// Cedar
	HUB *Hub;						// HUB
	SESSION *ClientSession;			// Client session
	SESSION *ServerSession;			// Server session
	CLIENT_OPTION *Option;			// Client Option
	CLIENT_AUTH *Auth;				// Authentication data
	POLICY *Policy;					// Policy
	QUEUE *SendPacketQueue;			// Transmission packet queue
	UINT CurrentSendPacketQueueSize;	// Current send packet queue size
	UINT LastError;					// Last error
	bool CheckServerCert;			// To check the server certificate
	X *ServerCert;					// Server certificate
	bool LockFlag;					// Lock flag
	bool *StopAllLinkFlag;			// Stop all link flag
	UINT LastServerConnectionReceivedBlocksNum;	// Last server connection recv queue num
	UINT Flag1;
};


PACKET_ADAPTER *LinkGetPacketAdapter();
bool LinkPaInit(SESSION *s);
CANCEL *LinkPaGetCancel(SESSION *s);
UINT LinkPaGetNextPacket(SESSION *s, void **data);
bool LinkPaPutPacket(SESSION *s, void *data, UINT size);
void LinkPaFree(SESSION *s);

void LinkServerSessionThread(THREAD *t, void *param);
LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy);
void StartLink(LINK *k);
void StopLink(LINK *k);
void DelLink(HUB *hub, LINK *k);
void LockLink(LINK *k);
void UnlockLink(LINK *k);
void StopAllLink(HUB *h);
void StartAllLink(HUB *h);
void SetLinkOnline(LINK *k);
void SetLinkOffline(LINK *k);
void ReleaseLink(LINK *k);
void CleanupLink(LINK *k);
void ReleaseAllLink(HUB *h);
void NormalizeLinkPolicy(POLICY *p);

#endif	// LINK_H




