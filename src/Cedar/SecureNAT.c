// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SecureNAT.c
// SecureNAT code

#include "CedarPch.h"

// SecureNAT server-side thread
void SnSecureNATThread(THREAD *t, void *param)
{
	SNAT *s;
	CONNECTION *c;
	SESSION *se;
	POLICY *policy;
	HUB *h;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SNAT *)param;
	// Create a server connection
	c = NewServerConnection(s->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_SECURE_NAT;

	// Apply the default policy
	policy = ClonePolicy(GetDefaultPolicy());

	// Not to limit the number of broadcast
	policy->NoBroadcastLimiter = true;

	h = s->Hub;
	AddRef(h->ref);

	// create a server session
	se = NewServerSession(s->Cedar, c, s->Hub, SNAT_USER_NAME, policy);
	se->SecureNATMode = true;
	se->SecureNAT = s;
	c->Session = se;
	ReleaseConnection(c);

	HLog(se->Hub, "LH_NAT_START", se->Name);

	// User name
	se->Username = CopyStr(SNAT_USER_NAME_PRINT);

	s->Session = se;
	AddRef(se->ref);

	// Notification initialization completion
	NoticeThreadInit(t);

	ReleaseCancel(s->Nat->Virtual->Cancel);
	s->Nat->Virtual->Cancel = se->Cancel1;
	AddRef(se->Cancel1->ref);

	if (s->Nat->Virtual->NativeNat != NULL)
	{
		CANCEL *old_cancel = NULL;

		Lock(s->Nat->Virtual->NativeNat->CancelLock);
		{
			if (s->Nat->Virtual->NativeNat->Cancel != NULL)
			{
				old_cancel = s->Nat->Virtual->NativeNat->Cancel;

				s->Nat->Virtual->NativeNat->Cancel = se->Cancel1;

				AddRef(se->Cancel1->ref);
			}
		}
		Unlock(s->Nat->Virtual->NativeNat->CancelLock);

		if (old_cancel != NULL)
		{
			ReleaseCancel(old_cancel);
		}
	}

	// Main function of the session
	Debug("SecureNAT Start.\n");
	SessionMain(se);
	Debug("SecureNAT Stop.\n");

	HLog(se->Hub, "LH_NAT_STOP");

	ReleaseHub(h);

	ReleaseSession(se);
}

// Release the SecureNAT
void SnFreeSecureNAT(SNAT *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Stop the session 
	StopSession(s->Session);
	ReleaseSession(s->Session);

	// Virtual machine release
	Virtual_Free(s->Nat->Virtual);

	// NAT release
	NiFreeNat(s->Nat);

	DeleteLock(s->lock);

	Free(s);
}

// Create a new SecureNAT
SNAT *SnNewSecureNAT(HUB *h, VH_OPTION *o)
{
	SNAT *s;
	THREAD *t;
	// Validate arguments
	if (h == NULL || o == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SNAT));
	s->Cedar = h->Cedar;
	s->Hub = h;
	s->lock = NewLock();

	// Create a NAT
	s->Nat = NiNewNatEx(s, o);

	// Initialize the virtual machine
	VirtualInit(s->Nat->Virtual);

	// Create a thread
	t = NewThread(SnSecureNATThread, s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}

