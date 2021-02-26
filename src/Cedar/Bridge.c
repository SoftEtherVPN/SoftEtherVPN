// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Bridge.c
// Ethernet Bridge Program (Local Bridge)

#include <GlobalConst.h>

#define	BRIDGE_C

#ifdef	WIN32
#define	OS_WIN32
#endif

#ifdef	OS_WIN32

// Win32
#include "BridgeWin32.c"

#else

// Unix
#include "BridgeUnix.c"

#endif	// OS_WIN32

// Hash the list of current Ethernet devices
UINT GetEthDeviceHash()
{
#ifdef	OS_UNIX
	// UNIX
	UINT num = 0;
	UINT i;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];
	TOKEN_LIST *t = GetEthList();

	tmp[0] = 0;

	if (t != NULL)
	{
		num = t->NumTokens;
		for (i = 0; i < t->NumTokens; i++)
		{
			StrCat(tmp, sizeof(tmp), t->Token[i]);
		}
		FreeToken(t);
	}

	Sha0(hash, tmp, StrLen(tmp));

	Copy(&num, hash, sizeof(UINT));

	return num;
#else	// OS_UNIX
	// Win32
	UINT ret = 0;
	MS_ADAPTER_LIST *a = MsCreateAdapterListEx(true);
	UINT num;
	UINT i;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];

	tmp[0] = 0;
	if (a != NULL)
	{
		for (i = 0;i < a->Num;i++)
		{
			StrCat(tmp, sizeof(tmp), a->Adapters[i]->Title);
		}
	}
	MsFreeAdapterList(a);

	Sha0(hash, tmp, StrLen(tmp));

	Copy(&num, hash, sizeof(UINT));

	return num;
#endif	// OS_UNIX
}

// Get whether WinPcap is needed
bool IsNeedWinPcap()
{
	if (IsBridgeSupported() == false)
	{
		// Not in Windows
		return false;
	}
	else
	{
		// Windows
		if (IsEthSupported())
		{
			// Already success to access the Ethernet device
			return false;
		}
		else
		{
			// Failed to access the Ethernet device
			return true;
		}
	}
}

// Get whether the local-bridging is supported by current OS
bool IsBridgeSupported()
{
	UINT type = GetOsInfo()->OsType;

	if (OS_IS_WINDOWS(type))
	{
		if (IsEthSupported())
		{
			return true;
		}
		else
		{
			bool ret = false;

#ifdef	OS_WIN32
			ret = MsIsAdmin();
#endif	// OS_WIN32

			return ret;
		}
	}
	else
	{
		return IsEthSupported();
	}
}

// Delete a local-bridge
bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename)
{
	bool ret = false;
	// Validate arguments
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return false;
	}

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			UINT i;

			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

				if (StrCmpi(br->HubName, hubname) == 0)
				{
					if (StrCmpi(br->DeviceName, devicename) == 0)
					{
						if (br->Bridge != NULL)
						{
							BrFreeBridge(br->Bridge);
							br->Bridge = NULL;
						}

						Delete(c->LocalBridgeList, br);
						Free(br);

						ret = true;
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	return ret;
}

// Add a local-bridge
void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast)
{
	UINT i;
	HUB *h = NULL;
	LOCALBRIDGE *br = NULL;
	// Validate arguments
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return;
	}

	if (OS_IS_UNIX(GetOsInfo()->OsType) == false)
	{
		tapmode = false;
	}

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			bool exists = false;

			// Ensure that the same configuration local-bridge doesn't exist already 
			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
				if (StrCmpi(br->DeviceName, devicename) == 0)
				{
					if (StrCmpi(br->HubName, hubname) == 0)
					{
						if (br->TapMode == tapmode)
						{
							exists = true;
						}
					}
				}
			}

			if (exists == false)
			{
				// Add configuration
				br = ZeroMalloc(sizeof(LOCALBRIDGE));
				StrCpy(br->HubName, sizeof(br->HubName), hubname);
				StrCpy(br->DeviceName, sizeof(br->DeviceName), devicename);
				br->Bridge = NULL;
				br->Local = local;
				br->TapMode = tapmode;
				br->LimitBroadcast = limit_broadcast;
				br->Monitor = monitor;
				if (br->TapMode)
				{
					if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
					{
						Copy(br->TapMacAddress, tapaddr, 6);
					}
					else
					{
						GenMacAddress(br->TapMacAddress);
					}
				}

				Add(c->LocalBridgeList, br);

				// Find the hub
				for (i = 0;i < LIST_NUM(c->HubList);i++)
				{
					HUB *hub = LIST_DATA(c->HubList, i);
					if (StrCmpi(hub->Name, br->HubName) == 0)
					{
						h = hub;
						AddRef(h->ref);
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	// Start the local-bridge immediately
	if (h != NULL && br != NULL && h->Type != HUB_TYPE_FARM_DYNAMIC)
	{
		Lock(h->lock_online);
		{
			if (h->Offline == false)
			{
				LockList(c->LocalBridgeList);
				{
					if (IsInList(c->LocalBridgeList, br))
					{
						if (br->Bridge == NULL)
						{
							br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor, br->TapMode, br->TapMacAddress, br->LimitBroadcast, br);
						}
					}
				}
				UnlockList(c->LocalBridgeList);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);
}

// Initialize the local-bridge list
void InitLocalBridgeList(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->LocalBridgeList = NewList(NULL);
}

// Free the local-bridge list
void FreeLocalBridgeList(CEDAR *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
	{
		LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
		Free(br);
	}

	ReleaseList(c->LocalBridgeList);
	c->LocalBridgeList = NULL;
}

// Bridging thread
void BrBridgeThread(THREAD *thread, void *param)
{
	BRIDGE *b;
	CONNECTION *c;
	SESSION *s;
	HUB *h;
	char name[MAX_SIZE];
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	b = (BRIDGE *)param;

	// Create a connection object
	c = NewServerConnection(b->Cedar, NULL, thread);
	c->Protocol = CONNECTION_HUB_BRIDGE;

	// Create a session object
	s = NewServerSession(b->Cedar, c, b->Hub, BRIDGE_USER_NAME, b->Policy);
	HLog(b->Hub, "LH_START_BRIDGE", b->Name, s->Name);
	StrCpy(name, sizeof(name), b->Name);
	h = b->Hub;
	AddRef(h->ref);
	s->BridgeMode = true;
	s->Bridge = b;
	c->Session = s;
	ReleaseConnection(c);

	// Dummy user name for local-bridge
	s->Username = CopyStr(BRIDGE_USER_NAME_PRINT);

	b->Session = s;
	AddRef(s->ref);

	// Notify completion
	NoticeThreadInit(thread);

	// Main procedure of the session
	Debug("Bridge %s Start.\n", b->Name);
	SessionMain(s);
	Debug("Bridge %s Stop.\n", b->Name);

	HLog(h, "LH_STOP_BRIDGE", name);

	ReleaseHub(h);

	ReleaseSession(s);
}

// Free the local-bridge object
void BrFreeBridge(BRIDGE *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	if (b->ParentLocalBridge != NULL)
	{
		b->ParentLocalBridge = NULL;
	}

	// Stop session thread
	StopSession(b->Session);
	ReleaseSession(b->Session);

	Free(b);
}

// Create new local-bridge
BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge)
{
	BRIDGE *b;
	POLICY *policy;
	THREAD *t;
	// Validate arguments
	if (h == NULL || name == NULL || parent_local_bridge == NULL)
	{
		return NULL;
	}

	if (p == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}
	else
	{
		policy = ClonePolicy(p);
	}

	b = ZeroMalloc(sizeof(BRIDGE));
	b->Cedar = h->Cedar;
	b->Hub = h;
	StrCpy(b->Name, sizeof(b->Name), name);
	b->Policy = policy;
	b->Local = local;
	b->Monitor = monitor;
	b->TapMode = tapmode;
	b->LimitBroadcast = limit_broadcast;
	b->ParentLocalBridge = parent_local_bridge;

	if (b->TapMode)
	{
		if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
		{
			Copy(b->TapMacAddress, tapaddr, 6);
		}
		else
		{
			GenMacAddress(b->TapMacAddress);
		}
	}

	if (monitor)
	{
		// Enabling monitoring mode
		policy->MonitorPort = true;
	}

	if (b->LimitBroadcast == false)
	{
		// Disable broadcast limiter
		policy->NoBroadcastLimiter = true;
	}

	// Start thread
	t = NewThread(BrBridgeThread, b);
	WaitThreadInit(t);
	ReleaseThread(t);

	return b;
}

// Raw IP bridge is supported only on Linux
bool IsRawIpBridgeSupported()
{
#ifdef	UNIX_LINUX
	return true;
#else	// UNIX_LINUX
	return false;
#endif	// UNIX_LINUX
}

