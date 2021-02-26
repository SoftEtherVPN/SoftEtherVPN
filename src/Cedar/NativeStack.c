// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// NativeStack.c
// Native IP stack

#include "CedarPch.h"

// Stack main thread
void NsMainThread(THREAD *thread, void *param)
{
	NATIVE_STACK *a = (NATIVE_STACK *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		SOCKSET set;
		bool err = false;
		bool flush_tube;
		LIST *recv_packets;
		bool state_changed = false;

		InitSockSet(&set);
		AddSockSet(&set, a->Sock1);

		if (a->Halt)
		{
			break;
		}

		// Pass to the IPC by receiving from the bridge
LABEL_RESTART:
		state_changed = false;
		flush_tube = false;
		while (true)
		{
			void *data;
			UINT size;

			size = EthGetPacket(a->Eth, &data);

			if (size == INFINITE)
			{
				// Device error
				err = true;
				break;
			}
			else if (size == 0)
			{
				// Can not get any more
				break;
			}
			else
			{
				// Pass the IPC socket
				TubeSendEx(a->Sock1->SendTube, data, size, NULL, true);
				Free(data);
				flush_tube = true;
				state_changed = true;
			}
		}

		if (flush_tube)
		{
			TubeFlush(a->Sock1->SendTube);
		}

		// Pass to the bridge by receiving from IPC
		recv_packets = NULL;
		while (true)
		{
			TUBEDATA *d = TubeRecvAsync(a->Sock1->RecvTube);

			if (d == NULL)
			{
				break;
			}

			if (recv_packets == NULL)
			{
				recv_packets = NewListFast(NULL);
			}

			Add(recv_packets, d);

			state_changed = true;
		}
		if (recv_packets != NULL)
		{
			UINT i;
			UINT num = LIST_NUM(recv_packets);
			void **data_array;
			UINT *size_array;

			data_array = Malloc(sizeof(void *) * num);
			size_array = Malloc(sizeof(UINT) * num);

			for (i = 0;i < num;i++)
			{
				TUBEDATA *d = LIST_DATA(recv_packets, i);

				data_array[i] = d->Data;
				size_array[i] = d->DataSize;
			}

			EthPutPackets(a->Eth, num, data_array, size_array);

			for (i = 0;i < num;i++)
			{
				TUBEDATA *d = LIST_DATA(recv_packets, i);

				// Because the data buffer has been already released, not to release twice
				d->Data = NULL;

				FreeTubeData(d);
			}

			Free(data_array);
			Free(size_array);

			ReleaseList(recv_packets);
		}

		if (IsTubeConnected(a->Sock1->SendTube) == false || IsTubeConnected(a->Sock1->RecvTube) == false)
		{
			err = true;
		}

		if (err)
		{
			// An error has occured
			Debug("Native Stack: Error !\n");
			a->Halt = true;
			continue;
		}

		if (state_changed)
		{
			goto LABEL_RESTART;
		}

		Select(&set, 1234, a->Cancel, NULL);
	}

	Disconnect(a->Sock1);
	Disconnect(a->Sock2);
}

// Start the iptables tracking
bool NsStartIpTablesTracking(NATIVE_STACK *a)
{
	if (a->IpTablesThread != NULL)
	{
		return true;
	}

	a->IpTablesInitOk = false;

	a->IpTablesHalt = false;

	a->IpTablesHaltEvent = NewEvent();

	a->IpTablesThread = NewThread(NsIpTablesThread, a);

	WaitThreadInit(a->IpTablesThread);

	return a->IpTablesInitOk;
}

// iptables thread
void NsIpTablesThread(THREAD *thread, void *param)
{
	IPTABLES_STATE *state;
	NATIVE_STACK *s;
	UINT counter = 0;
	BUF *seed_buf;
	char exe_name[MAX_PATH];
	if (thread == NULL || param == NULL)
	{
		return;
	}

	s = (NATIVE_STACK *)param;

	seed_buf = NewBuf();

	WriteBuf(seed_buf, s->MacAddress, 6);

	GetExeName(exe_name, sizeof(exe_name));
	WriteBufStr(seed_buf, exe_name);

	state = StartAddIpTablesEntryForNativeStack(seed_buf->Buf, seed_buf->Size);

	FreeBuf(seed_buf);

	if (state == NULL)
	{
		NoticeThreadInit(thread);
		return;
	}

	s->IpTablesInitOk = true;
	NoticeThreadInit(thread);

	while (true)
	{
		UINT wait_interval;

		if (s->IpTablesHalt)
		{
			break;
		}

		if (MaintainAddIpTablesEntryForNativeStack(state))
		{
			counter = 0;
		}

		counter++;
		wait_interval = NS_CHECK_IPTABLES_INTERVAL_INIT * counter;
		wait_interval = MIN(wait_interval, NS_CHECK_IPTABLES_INTERVAL_MAX);

		//Debug("NsIpTablesThread: wait for %u\n", wait_interval);
		Wait(s->IpTablesHaltEvent, wait_interval);
	}

	EndAddIpTablesEntryForNativeStack(state);
}

// Stop the iptables tracking
void NsStopIpTablesTracking(NATIVE_STACK *a)
{
	if (a->IpTablesThread == NULL)
	{
		return;
	}

	a->IpTablesHalt = true;
	Set(a->IpTablesHaltEvent);

	WaitThread(a->IpTablesThread, INFINITE);

	ReleaseThread(a->IpTablesThread);
	ReleaseEvent(a->IpTablesHaltEvent);

	a->IpTablesThread = NULL;
	a->IpTablesHaltEvent = NULL;
	a->IpTablesInitOk = false;
	a->IpTablesHalt = false;
}

// Release the stack
void FreeNativeStack(NATIVE_STACK *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->Ipc != NULL && IsZero(&a->CurrentDhcpOptionList, sizeof(a->CurrentDhcpOptionList)) == false)
	{
		IP dhcp_server;

		UINTToIP(&dhcp_server, a->CurrentDhcpOptionList.ServerAddress);

		IPCDhcpFreeIP(a->Ipc, &dhcp_server);
		SleepThread(200);
	}

	a->Halt = true;
	Cancel(a->Cancel);
	Disconnect(a->Sock1);
	Disconnect(a->Sock2);

	WaitThread(a->MainThread, INFINITE);

	ReleaseThread(a->MainThread);

	CloseEth(a->Eth);
	FreeIPC(a->Ipc);

	NsStopIpTablesTracking(a);

	ReleaseCancel(a->Cancel);

	ReleaseSock(a->Sock1);
	ReleaseSock(a->Sock2);

	ReleaseCedar(a->Cedar);

	Free(a);
}

// Create a new stack
NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed)
{
	ETH *eth;
	NATIVE_STACK *a;
	IP localhost;
	char tmp[64];
	bool release_cedar = false;
	// Validate arguments
	if (device_name == NULL || mac_address_seed == NULL)
	{
		return NULL;
	}

	GetLocalHostIP4(&localhost);

	// Open the Eth device
	eth = OpenEth(device_name, false, false, NULL);
	if (eth == NULL)
	{
		return NULL;
	}

	if (cedar == NULL)
	{
		cedar = NewCedar(NULL, NULL);
		release_cedar = true;
	}

	a = ZeroMalloc(sizeof(NATIVE_STACK));

	NewSocketPair(&a->Sock1, &a->Sock2, &localhost, 1, &localhost, 1);

	a->Cedar = cedar;
	AddRef(a->Cedar->ref);

	NsGenMacAddress(a->MacAddress, mac_address_seed, device_name);

	BinToStr(tmp, sizeof(tmp), a->MacAddress, sizeof(a->MacAddress));
	Debug("NewNativeStack: MAC Address = %s\n", tmp);

	a->Ipc = NewIPCBySock(cedar, a->Sock2, a->MacAddress);

	StrCpy(a->DeviceName, sizeof(a->DeviceName), device_name);

	a->Eth = eth;
	a->Cancel = EthGetCancel(eth);

	a->MainThread = NewThread(NsMainThread, a);

	if (release_cedar)
	{
		ReleaseCedar(cedar);
	}

	a->IsIpRawMode = a->Eth->IsRawIpMode;

	return a;
}

// Identify whether the specified MAC address is for the Native Stack which operate on the same host
bool NsIsMacAddressOnLocalhost(UCHAR *mac)
{
	UCHAR tmp[2];
	// Validate arguments
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] != NS_MAC_ADDRESS_BYTE_1)
	{
		return false;
	}

	NsGenMacAddressSignatureForMachine(tmp, mac);

	if (Cmp(mac + 4, tmp, 2) == 0)
	{
		return true;
	}

	return false;
}

// Determine the last two bytes of the MAC address
void NsGenMacAddressSignatureForMachine(UCHAR *dst_last_2, UCHAR *src_mac_addr_4)
{
	char machine_name[MAX_SIZE];
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (dst_last_2 == NULL || src_mac_addr_4 == NULL)
	{
		return;
	}

	GetMachineHostName(machine_name, sizeof(machine_name));

	Trim(machine_name);
	StrUpper(machine_name);

	b = NewBuf();
	WriteBuf(b, src_mac_addr_4, 4);
	WriteBufStr(b, machine_name);

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(dst_last_2, hash, 2);
}

// Generate the MAC address
void NsGenMacAddress(void *dest, char *mac_address_seed, char *device_name)
{
	char tmp[MAX_SIZE];
	UCHAR mac[6];
	UCHAR hash[SHA1_SIZE];

	Zero(tmp, sizeof(tmp));

	StrCat(tmp, sizeof(tmp), mac_address_seed);
	StrCat(tmp, sizeof(tmp), "@");
	StrCat(tmp, sizeof(tmp), device_name);

	Trim(tmp);

	StrLower(tmp);

	Sha1(hash, tmp, StrLen(tmp));

	mac[0] = NS_MAC_ADDRESS_BYTE_1;
	mac[1] = hash[1];
	mac[2] = hash[2];
	mac[3] = hash[3];
	mac[4] = hash[4];
	mac[5] = hash[5];

	NsGenMacAddressSignatureForMachine(mac + 4, mac);

	Copy(dest, mac, 6);
}

// Add the iptables entries for native stack
IPTABLES_STATE *StartAddIpTablesEntryForNativeStack(void *seed, UINT seed_size)
{
	IPTABLES_STATE *ret = NULL;
	bool ok = false;

	if (IsIpTablesSupported())
	{
		IPTABLES_ENTRY *e;
		UINT i;

		ret = ZeroMalloc(sizeof(IPTABLES_STATE));

		ret->EntryList = NewListFast(NULL);

		Sha1(ret->SeedHash, seed, seed_size);

		// Create a pair of entry
		e = ZeroMalloc(sizeof(IPTABLES_ENTRY));
		GenerateDummyIpAndMark(ret->SeedHash, e, 0);
		StrCpy(e->Chain, sizeof(e->Chain), "OUTPUT");
		Format(e->ConditionAndArgs, sizeof(e->ConditionAndArgs),
			"-p tcp --tcp-flags RST RST --sport %u:%u ! -s %r/32 ! -d %r/32 -m connmark ! --mark 0x%x -j DROP",
			NN_RAW_IP_PORT_START, NN_RAW_IP_PORT_END,
			&e->DummySrcIp, &e->DummyDestIP, e->DummyMark);
		Add(ret->EntryList, e);

		e = ZeroMalloc(sizeof(IPTABLES_ENTRY));
		GenerateDummyIpAndMark(ret->SeedHash, e, 1);
		StrCpy(e->Chain, sizeof(e->Chain), "OUTPUT");
		Format(e->ConditionAndArgs, sizeof(e->ConditionAndArgs),
			"-p icmp --icmp-type 3/3 ! -s %r/32 ! -d %r/32 -m connmark ! --mark 0x%x -j DROP",
			&e->DummySrcIp, &e->DummyDestIP, e->DummyMark);
		Add(ret->EntryList, e);

		ok = true;

		// Insert entries if not exists
		for (i = 0; i < LIST_NUM(ret->EntryList);i++)
		{
			UINT j;
			IPTABLES_ENTRY *e = LIST_DATA(ret->EntryList, i);

			for (j = 0;j < 100;j++)
			{
				if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) != 0)
				{
					char cmdline[MAX_PATH];

					Format(cmdline, sizeof(cmdline),
						"iptables -D %s %s",
						e->Chain, e->ConditionAndArgs);

					system(cmdline);
				}
				else
				{
					break;
				}
			}

			if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) == 0)
			{
				char cmdline[MAX_PATH];

				Format(cmdline, sizeof(cmdline),
					"iptables -I %s %s",
					e->Chain, e->ConditionAndArgs);

				system(cmdline);

				if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) == 0)
				{
					Debug("Run \"%s\" failed.\n", cmdline);
					ok = false;
					break;
				}
				else
				{
					Debug("Run \"%s\" ok.\n", cmdline);
				}
			}
		}
	}

	if (ok == false)
	{
		EndAddIpTablesEntryForNativeStack(ret);
		ret = NULL;
	}

	return ret;
}

// Maintain the iptables
bool MaintainAddIpTablesEntryForNativeStack(IPTABLES_STATE *s)
{
	UINT i;
	bool ret = false;
	if (s == NULL)
	{
		return false;
	}

	if (s->HasError)
	{
		return false;
	}

	// Insert entries if not exists
	for (i = 0; i < LIST_NUM(s->EntryList);i++)
	{
		IPTABLES_ENTRY *e = LIST_DATA(s->EntryList, i);

		if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) == 0)
		{
			char cmdline[MAX_PATH];

			Format(cmdline, sizeof(cmdline),
				"iptables -I %s %s",
				e->Chain, e->ConditionAndArgs);

			system(cmdline);

			if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) == 0)
			{
				Debug("Run \"%s\" failed.\n", cmdline);
				s->HasError = true;
				break;
			}
			else
			{
				Debug("Run \"%s\" ok.\n", cmdline);
				ret = true;
			}
		}
	}

	return ret;
}

// Stop the iptables management
void EndAddIpTablesEntryForNativeStack(IPTABLES_STATE *s)
{
	UINT i;
	if (s == NULL)
	{
		return;
	}

	// Delete entries
	for (i = 0; i < LIST_NUM(s->EntryList);i++)
	{
		IPTABLES_ENTRY *e = LIST_DATA(s->EntryList, i);
		UINT j;

		for (j = 0;j < 100;j++)
		{
			if (GetCurrentIpTableLineNumber(e->Chain, &e->DummySrcIp, &e->DummyDestIP, e->DummyMark) != 0)
			{
				char cmdline[MAX_PATH];

				Format(cmdline, sizeof(cmdline),
					"iptables -D %s %s",
					e->Chain, e->ConditionAndArgs);

				system(cmdline);
			}
			else
			{
				break;
			}
		}
	}

	FreeIpTablesState(s);
}

// Generate a set of dummy IP addresses and mark
void GenerateDummyIpAndMark(void *hash_seed, IPTABLES_ENTRY *e, UINT id)
{
	PRAND *p;
	BUF *b;
	if (hash_seed == NULL || e == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBufInt(b, id);
	WriteBuf(b, hash_seed, SHA1_SIZE);
	WriteBufStr(b, "20151002");

	p = NewPRand(b->Buf, b->Size);
	FreeBuf(b);

	GenerateDummyIp(p, &e->DummySrcIp);
	GenerateDummyIp(p, &e->DummyDestIP);
	e->DummyMark = GenerateDummyMark(p);

	FreePRand(p);
}

// Generate a dummy iptables mark
UINT GenerateDummyMark(PRAND *p)
{
	UINT i;
	if (p == NULL)
	{
		return 0;
	}

	while (true)
	{
		i = PRandInt(p);

		if (i >= 1000000000 && i <= 0x7FFFFFFE)
		{
			return i;
		}
	}

	return 0;
}

// Generate a dummy IP
void GenerateDummyIp(PRAND *p, IP *ip)
{
	UINT i;
	if (p == NULL || ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (i = 1;i < 4;i++)
	{
		UINT v = 0;
		while (true)
		{
			v = PRandInt(p) % 256;
			if (v >= 1 && v <= 254)
			{
				break;
			}
		}

		ip->addr[i] = (UCHAR)v;
	}

	ip->addr[0] = 127;
}

// Search an entry
IPTABLES_ENTRY *SearchIpTables(IPTABLES_STATE *s, char *chain, IP *src_ip, IP *dest_ip, UINT mark)
{
	char ip_str1[64];
	char ip_str2[64];
	char mark_str1[64];
	char mark_str2[64];
	UINT i;
	if (s == NULL || chain == NULL || src_ip == NULL || dest_ip == NULL || mark == 0)
	{
		return NULL;
	}

	IPToStr(ip_str1, sizeof(ip_str1), src_ip);
	IPToStr(ip_str2, sizeof(ip_str2), dest_ip);
	ToStr(mark_str1, mark);
	Format(mark_str2, sizeof(mark_str2), "%x", mark);

	for (i = 0;i < LIST_NUM(s->EntryList);i++)
	{
		IPTABLES_ENTRY *e = LIST_DATA(s->EntryList, i);

		if (StrCmpi(e->Chain, chain) == 0)
		{
			if (InStr(e->ConditionAndArgs, ip_str1) &&
				InStr(e->ConditionAndArgs, ip_str2) &&
				(InStr(e->ConditionAndArgs, mark_str1) || InStr(e->ConditionAndArgs, mark_str2)))
			{
				return e;
			}
		}
	}

	return NULL;
}

// Search an entry and get the line number
UINT GetCurrentIpTableLineNumber(char *chain, IP *src_ip, IP *dest_ip, UINT mark)
{
	IPTABLES_STATE *s;
	IPTABLES_ENTRY *e;
	UINT ret = 0;

	if (chain == NULL || src_ip == NULL || dest_ip == NULL || mark == 0)
	{
		return 0;
	}

	s = GetCurrentIpTables();

	e = SearchIpTables(s, chain, src_ip, dest_ip, mark);

	if (e != NULL)
	{
		ret = e->LineNumber;
	}

	FreeIpTablesState(s);

	return ret;
}

// Free the iptables state
void FreeIpTablesState(IPTABLES_STATE *s)
{
	UINT i;
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->EntryList);i++)
	{
		IPTABLES_ENTRY *e = LIST_DATA(s->EntryList, i);

		Free(e);
	}

	ReleaseList(s->EntryList);

	Free(s);
}

// Get the current iptables state
IPTABLES_STATE *GetCurrentIpTables()
{
	IPTABLES_STATE *ret = NULL;
	TOKEN_LIST *t = NULL;

#ifdef	OS_UNIX
	t = UnixExec("iptables -L -x -n --line-numbers");
#endif	// OS_UNIX

	if (t != NULL)
	{
		UINT i;
		UINT tmp_num = 0;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *line = t->Token[i];
			if (StartWith(line, "Chain INPUT") ||
				StartWith(line, "Chain FORWARD") ||
				StartWith(line, "Chain OUTPUT"))
			{
				tmp_num++;
			}
		}

		if (tmp_num >= 3)
		{
			char current_chain[64];
			UINT mode = 0;

			Zero(current_chain, sizeof(current_chain));

			for (i = 0;i < t->NumTokens;i++)
			{
				char *line = t->Token[i];

				if (StartWith(line, "Chain"))
				{
					TOKEN_LIST *t2 = ParseToken(line, " \t");
					if (t2 != NULL)
					{
						if (t2->NumTokens >= 4)
						{
							StrCpy(current_chain, sizeof(current_chain), t2->Token[1]);
							mode = 1;

							if (ret == NULL)
							{
								ret = ZeroMalloc(sizeof(IPTABLES_STATE));
								ret->EntryList = NewListFast(NULL);
							}

						}
						FreeToken(t2);
					}
				}

				if (mode == 1)
				{
					if (StartWith(line, "num"))
					{
						mode = 2;
					}
				}
				else if (mode == 2)
				{
					TOKEN_LIST *t2 = ParseToken(line, " \t");
					if (t2 != NULL)
					{
						if (t2->NumTokens >= 6 && ToInt(t2->Token[0]) != 0)
						{
							IPTABLES_ENTRY *e = ZeroMalloc(sizeof(IPTABLES_ENTRY));

							StrCpy(e->Chain, sizeof(e->Chain), current_chain);
							e->LineNumber = ToInt(t2->Token[0]);
							StrCpy(e->ConditionAndArgs, sizeof(e->ConditionAndArgs), line);

							Add(ret->EntryList, e);
						}

						FreeToken(t2);
					}
				}
			}
		}

		FreeToken(t);
	}

	return ret;
}

// Get whether iptables is supported
bool IsIpTablesSupported()
{
#ifdef	UNIX_LINUX
	IPTABLES_STATE *s = GetCurrentIpTables();
	if (s != NULL)
	{
		FreeIpTablesState(s);
		return true;
	}
	else
	{
		return false;
	}
#else	// UNIX_LINUX
	return false;
#endif	// UNIX_LINUX
}




