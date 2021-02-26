// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SecureNAT.h
// Header of SecureNAT.c

#ifndef	SECURENAT_H
#define	SECURENAT_H

struct SNAT
{
	LOCK *lock;						// Lock
	CEDAR *Cedar;					// Cedar
	HUB *Hub;						// HUB
	SESSION *Session;				// Session
	POLICY *Policy;					// Policy
	NAT *Nat;						// NAT
};


SNAT *SnNewSecureNAT(HUB *h, VH_OPTION *o);
void SnFreeSecureNAT(SNAT *s);
void SnSecureNATThread(THREAD *t, void *param);


#endif	// SECURENAT_H

