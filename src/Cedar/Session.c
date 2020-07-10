// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Session.c
// Session Manager

#include "CedarPch.h"

// Main routine of the session
void SessionMain(SESSION *s)
{
	CONNECTION *c;
	POLICY *policy;
	UINT64 now;
	UINT i = 0;
	PACKET_ADAPTER *pa;
	bool pa_inited = false;
	UINT packet_size;
	void *packet;
	bool packet_put;
	bool pa_fail = false;
	UINT test = 0;
	bool update_hub_last_comm = false;
	UINT err = ERR_SESSION_TIMEOUT;
	UINT64 next_black_list_check = 0;
	UINT64 next_update_hub_last_comm = 0;
	UINT64 auto_disconnect_tick = 0;
	bool block_all_packets = false;
	UINT64 next_check_block_all_packets = 0;
	TRAFFIC t;
	SOCK *msgdlg_sock = NULL;
	SOCK *nicinfo_sock = NULL;
	bool is_server_session = false;
	bool lock_receive_blocks_queue = false;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Debug("SessionMain: %s\n", s->Name);

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	// Generate a string from the session key
	BinToStr(s->SessionKeyStr, sizeof(s->SessionKeyStr), s->SessionKey, sizeof(s->SessionKey));

	// Reset the number of retries
	s->CurrentRetryCount = 0;
	s->ConnectSucceed = true;
	s->SessionTimeOuted = false;
	s->NumDisconnected = 0;

	c = s->Connection;
	policy = s->Policy;

	// Initialize the packet adapter
#ifdef	OS_WIN32
	if (s->IsVPNClientAndVLAN_Win32)
	{
		MsBeginVLanCard();

		if (MsIsVLanCardShouldStop())
		{
			err = ERR_SUSPENDING;
			goto CLEANUP;
		}
	}
#endif	// OS_WIN32

	pa = s->PacketAdapter;
	if (pa->Init(s) == false)
	{
		// Initialization Failed
		if (s->VLanDeviceErrorCount >= 2)
		{
			s->ForceStopFlag = true;
		}
		else
		{
			s->VLanDeviceErrorCount++;
		}
		err = ERR_DEVICE_DRIVER_ERROR;
		goto CLEANUP;
	}
	pa_inited = true;

	if (s->BridgeMode == false)
	{
		s->Cancel2 = pa->GetCancel(s);
	}
	else
	{
		CANCEL *c = pa->GetCancel(s);
		CANCEL *old = s->Cancel1;
		s->Cancel1 = c;
		ReleaseCancel(old);
	}

	s->RetryFlag = false;

	s->LastCommTime = Tick64();
	if (s->ServerMode == false)
	{
		s->NextConnectionTime = Tick64() + (UINT64)((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
	}

	s->NumConnectionsEstablished++;
	s->CurrentConnectionEstablishTime = Tick64();
	if (s->FirstConnectionEstablisiedTime == 0) /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	{
		s->FirstConnectionEstablisiedTime = Tick64(); /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	}

	if (s->ServerMode == false && s->Cedar->Client != NULL)
	{
		if (s->Policy != NULL)
		{
			if (s->Policy->AutoDisconnect)
			{
				auto_disconnect_tick = s->CurrentConnectionEstablishTime +
					(UINT64)s->Policy->AutoDisconnect * 1000ULL;
			}
		}
	}

	s->LastIncrementTraffic = Tick64();

	c->Err = ERR_SESSION_TIMEOUT;
	s->VLanDeviceErrorCount = 0;

	s->LastTryAddConnectTime = Tick64();

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (policy != NULL)
	{
		// Determine the mode by referencing the contents of the policy
		if (policy->MonitorPort)
		{
			s->IsMonitorMode = true;
		}

		if (policy->NoRouting == false || policy->NoBridge == false)
		{
			s->IsBridgeMode = true;
		}
	}

	if (s->ServerMode == false && s->Cedar->Client != NULL)
	{
		if (IsEmptyUniStr(s->Client_Message) == false)
		{
			UI_MSG_DLG dlg;

			Zero(&dlg, sizeof(dlg));
			if (s->ClientOption != NULL)
			{
				StrCpy(dlg.HubName, sizeof(dlg.HubName), s->ClientOption->HubName);
				StrCpy(dlg.ServerName, sizeof(dlg.ServerName), s->ClientOption->Hostname);
			}

			dlg.Msg = s->Client_Message;

			msgdlg_sock = CncMsgDlg(&dlg);
		}

		if (s->Win32HideNicInfoWindow == false)
		{
			UI_NICINFO info;

			Zero(&info, sizeof(info));
			if (s->ClientOption != NULL)
			{
				StrCpy(info.NicName, sizeof(info.NicName), s->ClientOption->DeviceName);
				UniStrCpy(info.AccountName, sizeof(info.AccountName), s->ClientOption->AccountName);
			}

			nicinfo_sock = CncNicInfo(&info);
		}
	}

	is_server_session = s->ServerMode;

	lock_receive_blocks_queue = s->LinkModeServer;

	now = Tick64();

	while (true)
	{
		Zero(&t, sizeof(t));


		if (next_update_hub_last_comm == 0 ||
			(next_update_hub_last_comm <= now))
		{
			next_update_hub_last_comm = now + 1000;

			if (s->Hub != NULL)
			{
				if (update_hub_last_comm)
				{
					Lock(s->Hub->lock);
					{
						s->Hub->LastCommTime = SystemTime64();
					}
					Unlock(s->Hub->lock);

					update_hub_last_comm = false;
				}
			}
		}


		if (is_server_session && s->LinkModeServer == false && s->SecureNATMode == false && s->BridgeMode == false && s->L3SwitchMode == false)
		{
			if (s->Hub != NULL && s->Hub->ForceDisableComm)
			{
				// Disconnect the session forcibly because the ForceDisableComm flag is set
				err = ERR_SERVER_CANT_ACCEPT;
				pa_fail = true;
			}
		}

		if (s->InProcMode)
		{
			if (c->TubeSock == NULL || IsTubeConnected(c->TubeSock->SendTube) == false || IsTubeConnected(c->TubeSock->RecvTube) == false)
			{
				// Disconnection occurs in the in-process mode
				err = ERR_DISCONNECTED;
				pa_fail = true;
			}
		}

		if (s->IsRUDPSession)
		{
			if (s->NumDisconnected >= 1 && s->EnableUdpRecovery == false)
			{
				// Disconnection occurs in the R-UDP session (UDP recovery is invalid)
				err = ERR_DISCONNECTED;
				pa_fail = true;
			}
		}
		
		// Chance of additional connection
		if (is_server_session == false)
		{
			if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT) == false)
			{
				ClientAdditionalConnectChance(s);
			}
		}

		// Receive a block
		ConnectionReceive(c, s->Cancel1, s->Cancel2);

		// Get the current time
		now = Tick64();

		if (s->UseUdpAcceleration && s->UdpAccel != NULL && s->UdpAccel->FatalError)
		{
			// A serious error occurs during sending any data on UDP socket
			// in the case of using UDP acceleration function
			err = ERR_DISCONNECTED;
			pa_fail = true;
		}

#ifdef	OS_WIN32
		if (s->IsVPNClientAndVLAN_Win32)
		{
			if (MsIsVLanCardShouldStop())
			{
				// System is suspending
				err = ERR_SUSPENDING;
				pa_fail = true;
			}
		}
#endif	// OS_WIN32

		// Pass the received block to the PacketAdapter
		if (lock_receive_blocks_queue)
		{
			LockQueue(c->ReceivedBlocks);
		}
		{
			BLOCK *b;
			packet_put = false;
			while (true)
			{
				b = GetNext(c->ReceivedBlocks);
				if (b == NULL)
				{
					break;
				}

				PROBE_DATA2("GetNext", b->Buf, b->Size);

				update_hub_last_comm = true;

				if (b->Size >= 14)
				{
					if (b->Buf[0] & 0x01)
					{
						if (is_server_session == false)
						{
							t.Recv.BroadcastCount++;
							t.Recv.BroadcastBytes += (UINT64)b->Size;
						}
						else
						{
							t.Send.BroadcastCount++;
							t.Send.BroadcastBytes += (UINT64)b->Size;
						}
					}
					else
					{
						if (is_server_session == false)
						{
							t.Recv.UnicastCount++;
							t.Recv.UnicastBytes += (UINT64)b->Size;
						}
						else
						{
							t.Send.UnicastCount++;
							t.Send.UnicastBytes += (UINT64)b->Size;
						}
					}
				}

				packet_put = true;
				PROBE_DATA2("pa->PutPacket", b->Buf, b->Size);
				if (pa->PutPacket(s, b->Buf, b->Size) == false)
				{
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
					Free(b->Buf);
					Debug("  Error: pa->PutPacket(Packet) Failed.\n");
				}
				Free(b);
			}

			if (true /* packet_put || is_server_session 2014.7.23 for optimizing */)
			{
				PROBE_DATA2("pa->PutPacket", NULL, 0);
				if (pa->PutPacket(s, NULL, 0) == false)
				{
					Debug("  Error: pa->PutPacket(NULL) Failed.\n");
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
				}
			}
		}
		if (lock_receive_blocks_queue)
		{
			UnlockQueue(c->ReceivedBlocks);
		}

		// Add the packet to be transmitted to SendBlocks by acquiring from PacketAdapter
		{
			UINT i, max_num = MAX_SEND_SOCKET_QUEUE_NUM;
			i = 0;
			while (packet_size = pa->GetNextPacket(s, &packet))
			{
				BLOCK *b;
				if (packet_size == INFINITE)
				{
					err = ERR_DEVICE_DRIVER_ERROR;
					pa_fail = true;
					Debug("  Error: pa->GetNextPacket() Failed.\n");
					break;
				}

				update_hub_last_comm = true;

				if ((c->CurrentSendQueueSize > MAX_BUFFERING_PACKET_SIZE) ||
					block_all_packets)
				{
//					WHERE;
					// Discard because it exceeded the buffer size limit
					Free(packet);
				}
				else
				{
					bool priority;
					QUEUE *q = NULL;
					// Buffering
					if (packet_size >= 14)
					{
						UCHAR *buf = (UCHAR *)packet;
						if (buf[0] & 0x01)
						{
							if (is_server_session == false)
							{
								t.Send.BroadcastCount++;
								t.Send.BroadcastBytes += (UINT64)packet_size;
							}
							else
							{
								t.Recv.BroadcastCount++;
								t.Recv.BroadcastBytes += (UINT64)packet_size;
							}
						}
						else
						{
							if (is_server_session == false)
							{
								t.Send.UnicastCount++;
								t.Send.UnicastBytes += (UINT64)packet_size;
							}
							else
							{
								t.Recv.UnicastCount++;
								t.Recv.UnicastBytes += (UINT64)packet_size;
							}
						}
					}
					priority = IsPriorityHighestPacketForQoS(packet, packet_size);

					b = NewBlock(packet, packet_size, s->UseCompress ? 1 : 0);
					b->PriorityQoS = priority;

					if (b->PriorityQoS && c->Protocol == CONNECTION_TCP && s->QoS)
					{
						q = c->SendBlocks2;
					}
					else
					{
						q = c->SendBlocks;
					}

					if (q->num_item > MAX_STORED_QUEUE_NUM)
					{
						q = NULL;
					}

					if (q != NULL)
					{
						c->CurrentSendQueueSize += b->Size;
						InsertQueue(q, b);
					}
					else
					{
						FreeBlock(b);
					}
				}

				if ((i % 16) == 0)
				{
					int diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
					CedarAddCurrentTcpQueueSize(c->Cedar, diff);
					c->LastPacketQueueSize = c->CurrentSendQueueSize;
				}

				i++;
				if (i >= max_num)
				{
					break;
				}
			}
		}

		AddTrafficForSession(s, &t);

		if (true)
		{
			int diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
			CedarAddCurrentTcpQueueSize(c->Cedar, diff);
			c->LastPacketQueueSize = c->CurrentSendQueueSize;
		}

		now = Tick64();

		// Send a block
		ConnectionSend(c, now);

		// Determine the automatic disconnection
		if (auto_disconnect_tick != 0 && auto_disconnect_tick <= now)
		{
			err = ERR_AUTO_DISCONNECTED;
			s->CurrentRetryCount = INFINITE;
			break;
		}

		// Stop determination
		if (s->Halt)
		{
			if (s->ForceStopFlag)
			{
				err = ERR_USER_CANCEL;
			}
			break;
		}

		// Increments the number of logins for user object and Virtual HUB object.
		// (It's incremented only if the time 30 seconds passed after connection.
		// If not do this, it will be incremented on DoS attacks or any error.)
		if (s->NumLoginIncrementTick != 0 && s->NumLoginIncrementTick <= now)
		{
			s->NumLoginIncrementTick = 0;

			if (s->NumLoginIncrementHubObject != NULL)
			{
				s->NumLoginIncrementHubObject->NumLogin++;
			}

			if (s->NumLoginIncrementUserObject != NULL)
			{
				s->NumLoginIncrementUserObject->NumLogin++;
			}
		}

		if (is_server_session)
		{
			HUB *hub;

			// Update of traffic data of the user
			if ((s->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now)
			{
				IncrementUserTraffic(s->Hub, s->UserNameReal, s);
				s->LastIncrementTraffic = now;
			}

			hub = s->Hub;

			if (hub != NULL)
			{
				if ((hub->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now)
				{
					hub->LastIncrementTraffic = now;
					IncrementHubTraffic(s->Hub);
				}
			}
		}

		if (s->LinkModeServer == false && s->SecureNATMode == false && s->BridgeMode == false && s->L3SwitchMode == false && s->InProcMode == false)
		{
			bool timeouted = false;

			if ((now > s->LastCommTime) && ((now - s->LastCommTime) >= ((UINT64)s->Timeout)))
			{
				// When communication is not possible for the predetermined time
				timeouted = true;
				WHERE;
			}

			if (c->Protocol == CONNECTION_TCP)
			{
				if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT))
				{
					UINT num_tcp_connections = Count(c->CurrentNumConnection);

					if (num_tcp_connections == 0)
					{
						// All TCP connections are disconnected.
						// Terminate the session immediately.
						timeouted = true;
					}
				}
			}

			if (is_server_session == false && s->ClientOption != NULL && s->ClientOption->ConnectionDisconnectSpan == 0)
			{
				if (LIST_NUM(s->Connection->Tcp->TcpSockList) < s->MaxConnection)
				{
					if ((s->LastTryAddConnectTime +
						(UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2))
						<= Tick64())
					{
						if (s->IsRUDPSession == false ||  LIST_NUM(s->Connection->Tcp->TcpSockList) == 0)
						{
							timeouted = true;
							WHERE;
						}
					}
				}
			}

			if (timeouted)
			{
				// Timeout occurs
				Debug("** Session Timeouted.\n");
				s->SessionTimeOuted = true;
				err = ERR_SESSION_TIMEOUT;
			}
		}

		// Time-out decision
		if (pa_fail || s->SessionTimeOuted)
		{
			s->Halt = true;
			s->RetryFlag = true;	// Retry flag
			break;
		}
	}

CLEANUP:
	Debug("Session %s Finishing...\n", s->Name);

	// Remove from the session list of the HUB
	if (s->ServerMode)
	{
		// Update the user information
		IncrementUserTraffic(s->Hub, s->UserNameReal, s);

		DelSession(s->Hub, s);
	}

	s->ConnectSucceed = false;
	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (s->Connection)
	{
		int diff =  -((int)s->Connection->LastTcpQueueSize);
		s->Connection->LastTcpQueueSize = 0;
		s->Connection->Halt = true;
		CedarAddCurrentTcpQueueSize(s->Cedar, diff);

		diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = c->CurrentSendQueueSize;
	}

	// Release the packet adapter
	if (pa_inited)
	{
		pa->Free(s);
	}

#ifdef	OS_WIN32
	if (s->IsVPNClientAndVLAN_Win32)
	{
		MsEndVLanCard();
	}
#endif	// OS_WIN32

	if (s->ServerMode == false)
	{
		// Cancel to make all additional connection
		StopAllAdditionalConnectThread(s->Connection);
	}

	if (s->BridgeMode)
	{
		// Terminate the bridge
		if (s->Bridge->Active)
		{
			CloseEth(s->Bridge->Eth);
			s->Bridge->Eth = NULL;
		}
	}

	if (s->Cancel2 != NULL)
	{
		// Release the Cancel 2
		ReleaseCancel(s->Cancel2);
		s->Cancel2 = NULL;
	}

	// Terminate the connection
	EndTunnelingMode(c);

	if (nicinfo_sock != NULL)
	{
		CncNicInfoFree(nicinfo_sock);
	}

	if (msgdlg_sock != NULL)
	{
		CndMsgDlgFree(msgdlg_sock);
	}

	c->Err = err;
}

// Get the time for the next delayed packet
UINT GetNextDelayedPacketTickDiff(SESSION *s)
{
	UINT i;
	UINT ret = 0x7fffffff;
	UINT64 now;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	if (LIST_NUM(s->DelayedPacketList) >= 1)
	{
		now = TickHighres64();

		LockList(s->DelayedPacketList);
		{
			for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
			{
				PKT *p = LIST_DATA(s->DelayedPacketList, i);
				UINT64 t = p->DelayedForwardTick;
				UINT d = 0x7fffffff;

				if (now >= t)
				{
					d = 0;
				}
				else
				{
					d = (UINT)(t - now);
				}

				ret = MIN(ret, d);
			}
		}
		UnlockList(s->DelayedPacketList);
	}

	return ret;
}

// Determine whether the packet have priority in the VoIP / QoS function
bool IsPriorityHighestPacketForQoS(void *data, UINT size)
{
	UCHAR *buf;
	// Validate arguments
	if (data == NULL)
	{
		return false;
	}

	buf = (UCHAR *)data;
	if (size >= 16)
	{
		if (buf[12] == 0x08 && buf[13] == 0x00 && buf[15] != 0x00 && buf[15] != 0x08)
		{
			// IPv4 packet and ToS != 0
			return true;
		}

		if (size >= 34 && size <= 128)
		{
			if (buf[12] == 0x08 && buf[13] == 0x00 && buf[23] == 0x01)
			{
				// IMCPv4 packet
				return true;
			}
		}
	}

	return false;
}

// Update the traffic information of the user
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s)
{
	TRAFFIC report_traffic;
	// Validate arguments
	if (hub == NULL || username == NULL || s == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		// Calculate the traffic information (difference between last time) to be reported
		report_traffic.Send.BroadcastBytes =
			s->Traffic->Send.BroadcastBytes - s->OldTraffic->Send.BroadcastBytes;
		report_traffic.Send.BroadcastCount =
			s->Traffic->Send.BroadcastCount - s->OldTraffic->Send.BroadcastCount;
		report_traffic.Send.UnicastBytes =
			s->Traffic->Send.UnicastBytes - s->OldTraffic->Send.UnicastBytes;
		report_traffic.Send.UnicastCount =
			s->Traffic->Send.UnicastCount - s->OldTraffic->Send.UnicastCount;
		report_traffic.Recv.BroadcastBytes =
			s->Traffic->Recv.BroadcastBytes - s->OldTraffic->Recv.BroadcastBytes;
		report_traffic.Recv.BroadcastCount =
			s->Traffic->Recv.BroadcastCount - s->OldTraffic->Recv.BroadcastCount;
		report_traffic.Recv.UnicastBytes =
			s->Traffic->Recv.UnicastBytes - s->OldTraffic->Recv.UnicastBytes;
		report_traffic.Recv.UnicastCount =
			s->Traffic->Recv.UnicastCount - s->OldTraffic->Recv.UnicastCount;
		Copy(s->OldTraffic, s->Traffic, sizeof(TRAFFIC));

		if (hub->FarmMember == false)
		{
			// Update the user information in the local database if it is not a farm member
			AcLock(hub);
			{
				USER *u = AcGetUser(hub, username);
				if (u != NULL)
				{
					Lock(u->lock);
					{
						AddTraffic(u->Traffic, &report_traffic);
					}
					Unlock(u->lock);
					if (u->Group != NULL)
					{
						Lock(u->Group->lock);
						{
							AddTraffic(u->Group->Traffic, &report_traffic);
						}
						Unlock(u->Group->lock);
					}
					ReleaseUser(u);
				}
			}
			AcUnlock(hub);
		}
		else
		{
			// Update the traffic difference report list in the case of farm member
			AddTrafficDiff(hub, username, TRAFFIC_DIFF_USER, &report_traffic);
		}
	}
	Unlock(s->TrafficLock);
}

// Cumulate the traffic information of the connection
void AddTrafficForSession(SESSION *s, TRAFFIC *t)
{
	HUB *h;
	TRAFFIC t2;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		AddTraffic(s->Traffic, t);
	}
	Unlock(s->TrafficLock);

	if (s->ServerMode)
	{
		Copy(&t2.Recv, &t->Send, sizeof(TRAFFIC_ENTRY));
		Copy(&t2.Send, &t->Recv, sizeof(TRAFFIC_ENTRY));
		Lock(s->Cedar->TrafficLock);
		{
			AddTraffic(s->Cedar->Traffic, &t2);
		}
		Unlock(s->Cedar->TrafficLock);

		h = s->Hub;
		Lock(h->TrafficLock);
		{
			AddTraffic(h->Traffic, &t2);
		}
		Unlock(h->TrafficLock);
	}
}

// A chance to establish an additional connection for client
void ClientAdditionalConnectChance(SESSION *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->ServerMode)
	{
		// Do not connect additionally in the server mode
		return;
	}
	if (s->Connection->Protocol != CONNECTION_TCP)
	{
		// Connect additionally only in the case of TCP protocol
		return;
	}
	if (s->IsRUDPSession && s->EnableUdpRecovery == false)
	{
		// Do not connect additionally if the UDP recovery is disabled in the case of R-UDP session
		return;
	}

	if (s->IsRUDPSession && (s->Connection->AdditionalConnectionFailedCounter > MAX_ADDITIONAL_CONNECTION_FAILED_COUNTER))
	{
		// Not to make a large amount of repeated connection retry within a certain time in the case of R-UDP session
		return;
	}

	while (true)
	{
		if (s->Halt)
		{
			return;
		}
		// Consider whether there is a need to put an additional connection
		// by examining the number of current connections and MaxConnection property
		if (Count(s->Connection->CurrentNumConnection) < s->MaxConnection)
		{
			// Get the current time
			UINT64 now = Tick64();

			// Examine the NextConnectionTime, and if the time passed,
			// attempt to make a connection
			if (s->NextConnectionTime == 0 ||
				s->ClientOption->AdditionalConnectionInterval == 0 ||
				(s->NextConnectionTime <= now))
			{
				// Start the work to put an additional connection
				s->NextConnectionTime = now + ((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
				SessionAdditionalConnect(s);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
}

// Release the packet adapter
void FreePacketAdapter(PACKET_ADAPTER *pa)
{
	// Validate arguments
	if (pa == NULL)
	{
		return;
	}

	Free(pa);
}

// Create a new packet adapter
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free)
{
	PACKET_ADAPTER *pa;
	// Validate arguments
	if (init == NULL || getcancel == NULL || getnext == NULL || put == NULL || free == NULL)
	{
		return NULL;
	}

	pa = ZeroMalloc(sizeof(PACKET_ADAPTER));

	pa->Init = init;
	pa->Free = free;
	pa->GetCancel = getcancel;
	pa->GetNextPacket = getnext;
	pa->PutPacket = put;

	return pa;
}

// Thread for putting an additional connection
void ClientAdditionalThread(THREAD *t, void *param)
{
	SESSION *s;
	CONNECTION *c;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SESSION *)param;

	s->LastTryAddConnectTime = Tick64();

	c = s->Connection;
	// Increment of connection counter
	Inc(c->CurrentNumConnection);
	LockList(c->ConnectingThreads);
	{
		// Add to processing thread
		Add(c->ConnectingThreads, t);
		AddRef(t->ref);
	}
	UnlockList(c->ConnectingThreads);

	// Notify the completion of initialization
	NoticeThreadInit(t);

	Debug("Additional Connection #%u\n", Count(c->CurrentNumConnection));

	// Put an additional connection
	if (ClientAdditionalConnect(c, t) == false)
	{
		// Decrement the counter which is currently processing
		Dec(c->CurrentNumConnection);

		if (c->AdditionalConnectionFailedCounter == 0)
		{
			c->LastCounterResetTick = Tick64();
		}

		c->AdditionalConnectionFailedCounter++;

		if ((c->LastCounterResetTick + (UINT64)ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL) <= Tick64())
		{
			// Reset the number of failures periodically
			c->AdditionalConnectionFailedCounter = 0;
			c->LastCounterResetTick = Tick64();
		}
	}
	else
	{
		s->LastTryAddConnectTime = Tick64();
		c->AdditionalConnectionFailedCounter = 0;
		c->LastCounterResetTick = Tick64();
	}

	// Remove from the processing thread
	LockList(c->ConnectingThreads);
	{
		// Remove from the processing thread
		if (Delete(c->ConnectingThreads, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(c->ConnectingThreads);
	ReleaseSession(s);
}

// Put an additional connection from the client to the server
void SessionAdditionalConnect(SESSION *s)
{
	THREAD *t;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// s->LastTryAddConnectTime = Tick64();

	AddRef(s->ref);
	t = NewThread(ClientAdditionalThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// Connect the client session to the server
bool SessionConnect(SESSION *s)
{
	CONNECTION *c;
	bool ret = false;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	s->ClientStatus = CLIENT_STATUS_CONNECTING;

	Debug("SessionConnect() Started.\n");

	// Initialize the session
	Lock(s->lock);
	{
		s->Err = ERR_NO_ERROR;
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	s->CancelConnect = false;

	// Create a Client Connection
	c = NewClientConnection(s);
	s->Connection = c;

	// Connect the client to the server
	ret = ClientConnect(c);
	s->Err = c->Err;

	s->CancelConnect = false;

	if (s->Cedar->Client != NULL)
	{
		if (s->Policy != NULL)
		{
			if (s->Policy->NoSavePassword)
			{
				s->Client_NoSavePassword = true;

				if (s->Account != NULL)
				{
					Lock(s->Account->lock);
					{
						if (s->Account->ClientAuth != NULL)
						{
							if (s->Account->ClientAuth->AuthType == AUTHTYPE_PASSWORD ||
								s->Account->ClientAuth->AuthType == AUTHTYPE_RADIUS)
							{
								Zero(s->Account->ClientAuth->HashedPassword, sizeof(s->Account->ClientAuth->HashedPassword));
								Zero(s->Account->ClientAuth->PlainPassword, sizeof(s->Account->ClientAuth->PlainPassword));
							}
						}
					}
					Unlock(s->Account->lock);

					CiSaveConfigurationFile(s->Cedar->Client);
				}
			}
		}
	}

	if (c->ClientConnectError_NoSavePassword)
	{
		s->Client_NoSavePassword = true;
	}

	// Release the client connection
	s->Connection = NULL;
	ReleaseConnection(c);

	Lock(s->lock);
	{
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	return ret;
}

// Stop the session
void StopSession(SESSION *s)
{
	StopSessionEx(s, false);
}
void StopSessionEx(SESSION *s, bool no_wait)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Halting flag
	s->UserCanceled = true;
	s->CancelConnect = true;
	s->Halt = true;

	Debug("Stop Session %s\n", s->Name);

	// Cancel
	Cancel(s->Cancel1);

	// Event
	Set(s->HaltEvent);

	// Server and client mode
	if (s->Connection)
	{
		CONNECTION *c = s->Connection;
		AddRef(c->ref);
		StopConnection(c, no_wait);
		ReleaseConnection(c);
	}

	// Wait until the stop
	if (no_wait == false)
	{
		while (true)
		{
			s->ForceStopFlag = true;
			s->Halt = true;
			if (WaitThread(s->Thread, 20))
			{
				break;
			}
		}
	}
	else
	{
		s->ForceStopFlag = true;
		s->Halt = true;
	}
}

// Cleanup the session
void CleanupSession(SESSION *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Release the delayed packet list
	if (s->DelayedPacketList != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
		{
			PKT *p = LIST_DATA(s->DelayedPacketList, i);

			Free(p->PacketData);
			FreePacket(p);
		}

		ReleaseList(s->DelayedPacketList);
	}

	// Release the client connection options
	if (s->ClientOption != NULL)
	{
		Free(s->ClientOption);
	}

	// Release the client authentication data
	if (s->ClientAuth != NULL)
	{
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeX(s->ClientAuth->ClientX);
		}
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeK(s->ClientAuth->ClientK);
		}
		Free(s->ClientAuth);
	}

	FreeTraffic(s->Traffic);
	Free(s->Name);

	if (s->Thread != NULL)
	{
		ReleaseThread(s->Thread);
	}

	DeleteLock(s->lock);

	ReleaseEvent(s->HaltEvent);

	if (s->Cancel1)
	{
		ReleaseCancel(s->Cancel1);
	}

	if (s->Cancel2)
	{
		ReleaseCancel(s->Cancel2);
	}

	if (s->Policy)
	{
		Free(s->Policy);
	}

	if (s->Connection)
	{
		ReleaseConnection(s->Connection);
	}

	Free(s->Username);

	if (s->PacketAdapter)
	{
		FreePacketAdapter(s->PacketAdapter);
	}
#ifdef OS_UNIX
	if (s->ClientOption != NULL)
	{
		UnixVLanSetState(s->ClientOption->DeviceName, false);
	}
#endif
	if (s->OldTraffic != NULL)
	{
		FreeTraffic(s->OldTraffic);
	}

	DeleteLock(s->TrafficLock);

	if (s->CancelList != NULL)
	{
		ReleaseCancelList(s->CancelList);
	}

	if (s->Client_Message != NULL)
	{
		Free(s->Client_Message);
	}

	DeleteCounter(s->LoggingRecordCount);

	ReleaseSharedBuffer(s->IpcSessionSharedBuffer);

	Free(s);
}

// Release the session
void ReleaseSession(SESSION *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSession(s);
	}
}

// Display the total data transfer size of the session
void PrintSessionTotalDataSize(SESSION *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Debug(
		"-- SESSION TOTAL PKT INFORMATION --\n\n"
		"      TotalSendSize: %I64u\n"
		"  TotalSendSizeReal: %I64u\n"
		"      TotalRecvSize: %I64u\n"
		"  TotalRecvSizeReal: %I64u\n"
		"   Compression Rate: %.2f%% (Send)\n"
		"                     %.2f%% (Recv)\n",
		s->TotalSendSize, s->TotalSendSizeReal,
		s->TotalRecvSize, s->TotalRecvSizeReal,
		(float)((double)s->TotalSendSizeReal / (double)s->TotalSendSize * 100.0f),
		(float)((double)s->TotalRecvSizeReal / (double)s->TotalRecvSize * 100.0f)
		);

}

// Client thread
void ClientThread(THREAD *t, void *param)
{
	SESSION *s;
	bool use_password_dlg;
	bool no_save_password = false;
	bool is_vpngate_connection = false;
	CEDAR *cedar;
	bool num_active_sessions_incremented = false;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	Debug("ClientThread 0x%x Started.\n", t);

	s = (SESSION *)param;
	AddRef(s->ref);
	s->Thread = t;
	AddRef(t->ref);

	if (s->LinkModeClient == false)
	{
		CiIncrementNumActiveSessions();
		num_active_sessions_incremented = true;
	}

	NoticeThreadInit(t);

	cedar = s->Cedar;

	s->ClientStatus = CLIENT_STATUS_CONNECTING;
	s->RetryFlag = true;
	s->CurrentRetryCount = 0;

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);

	if (s->Cedar->Client != NULL)
	{
		no_save_password = s->Cedar->Client->DontSavePassword;
	}

	s->Win32HideConnectWindow = s->ClientOption->HideStatusWindow;
	s->Win32HideNicInfoWindow = s->ClientOption->HideNicInfoWindow;


	while (true)
	{
		Zero(&s->ServerIP_CacheForNextConnect, sizeof(IP));

		if (s->Link != NULL && ((*s->Link->StopAllLinkFlag) || s->Link->Halting))
		{
			s->Err = ERR_USER_CANCEL;
			break;
		}

		CLog(s->Cedar->Client, "LC_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);
		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);
		}

		Debug("Trying to Connect to Server... (%u / %u)\n", s->CurrentRetryCount + 0,
			s->ClientOption->NumRetry);

		// Initialize
//		s->TotalRecvSize = s->TotalRecvSizeReal = 
//			s->TotalSendSize = s->TotalSendSizeReal = 0;
		s->NextConnectionTime = 0;

		// Connect
		s->ClientStatus = CLIENT_STATUS_CONNECTING;
		s->Halt = false;
		SessionConnect(s);
		if (s->UserCanceled)
		{
			s->Err = ERR_USER_CANCEL;
		}
		Debug("Disconnected. Err = %u : %S\n", s->Err, _E(s->Err));

		PrintSessionTotalDataSize(s);

		CLog(s->Cedar->Client, "LC_CONNECT_ERROR", s->ClientOption->AccountName,
			GetUniErrorStr(s->Err), s->Err);
#ifdef OS_UNIX
		UnixVLanSetState(s->ClientOption->DeviceName, false);
#endif
		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_ERROR", s->ClientOption->AccountName,
				GetUniErrorStr(s->Err), s->Err);
		}

		s->ClientStatus = CLIENT_STATUS_RETRY;

		if (s->Link != NULL)
		{
			((LINK *)s->Link)->LastError = s->Err;
		}

		if (s->Halt && (s->RetryFlag == false) || s->ForceStopFlag)
		{
			// Must be aborted
			if (s->Err == ERR_DEVICE_DRIVER_ERROR)
			{
#ifdef	OS_WIN32
				wchar_t tmp[MAX_SIZE];
				if (s->Account != NULL && s->Cedar->Client != NULL)
				{
					UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_DEVICE_ERROR"), s->ClientOption->DeviceName,
						s->Err, _E(s->Err));
					MsgBox(NULL, 0x10000 | 0x40000 | 0x200000 | 0x30, tmp);
				}
#endif	// OS_WIN32
			}
			break;
		}
		// Determine whether to display the password re-entry dialog
		use_password_dlg = false;

		if (s->Account != NULL && s->Cedar->Client != NULL)
		{
#ifdef	OS_WIN32
			if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD || s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
			{
				if (s->Err == ERR_AUTH_FAILED || s->Err == ERR_PROXY_AUTH_FAILED)
				{
					use_password_dlg = true;
				}
			}
#endif	// OS_WIN32
		}

		// Failed to connect or the connection is disconnected
		// Wait for retry interval
		if (use_password_dlg == false)
		{
			UINT retry_interval = s->RetryInterval;

			if (s->LinkModeClient)
			{
				UINT current_num_links = Count(s->Cedar->CurrentActiveLinks);
				UINT max_retry_interval = MAX(1000 * current_num_links, retry_interval);

				retry_interval += retry_interval * MIN(s->CurrentRetryCount, 1000);
				retry_interval = MIN(retry_interval, max_retry_interval);

				// On the cascade client, adjust the retry_interval. (+/- 20%)
				if (retry_interval >= 1000 && retry_interval <= (60 * 60 * 1000))
				{
					retry_interval = (retry_interval * 8 / 10) + (Rand32() % (retry_interval * 4 / 10));
				}
			}

			if (s->Err == ERR_HUB_IS_BUSY || s->Err == ERR_LICENSE_ERROR ||
				s->Err == ERR_HUB_STOPPING || s->Err == ERR_TOO_MANY_USER_SESSION)
			{
				retry_interval = RETRY_INTERVAL_SPECIAL;
			}

			if (s->CurrentRetryCount >= s->ClientOption->NumRetry)
			{
				// Retry count excess

#ifndef	OS_WIN32

				break;

#else	// OS_WIN32

				if (s->Win32HideConnectWindow == false &&
					s->Cedar->Client != NULL && s->Account != NULL)
				{
					// Show a reconnection dialog
					UI_CONNECTERROR_DLG p;
					Zero(&p, sizeof(p));
					UniStrCpy(p.AccountName, sizeof(p.AccountName), s->ClientOption->AccountName);
					StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
					p.Err = s->Err;
					p.CurrentRetryCount = s->CurrentRetryCount + 1;
					s->Halt = false;
					p.RetryLimit = 0;
					p.RetryIntervalSec = 0;
					p.CancelEvent = s->HaltEvent;
					p.HideWindow = s->Win32HideConnectWindow;
					if (CncConnectErrorDlg(s, &p) == false)
					{
						// Abort
						break;
					}
					else
					{
						s->Win32HideConnectWindow = p.HideWindow;
						goto SKIP;
					}
				}
				else
				{
					break;
				}

#endif
			}

#ifndef	OS_WIN32

			// Simple wait
			Wait(s->HaltEvent, retry_interval);

#else	// OS_WIN32

			if (s->Win32HideConnectWindow == false &&
				s->Cedar->Client != NULL && s->Account != NULL)
			{
				// Show a reconnection dialog
				UI_CONNECTERROR_DLG p;
				Zero(&p, sizeof(p));
				UniStrCpy(p.AccountName, sizeof(p.AccountName), s->ClientOption->AccountName);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
				p.Err = s->Err;
				p.CurrentRetryCount = s->CurrentRetryCount + 1;
				p.RetryLimit = s->ClientOption->NumRetry;
				p.RetryIntervalSec = retry_interval;
				p.CancelEvent = s->HaltEvent;
				s->Halt = false;
				p.HideWindow = s->Win32HideConnectWindow;
				if (CncConnectErrorDlg(s, &p) == false)
				{
					// Abort
					break;
				}
				s->Win32HideConnectWindow = p.HideWindow;
			}
			else
			{
				// Simple wait
				Wait(s->HaltEvent, s->RetryInterval);
			}

#endif	// OS_WIN32
		}
		else
		{
#ifdef	OS_WIN32
			// Wait for re-entry the password
			UI_PASSWORD_DLG p;
			Zero(&p, sizeof(p));
			if (s->Client_NoSavePassword == false)
			{
				p.ShowNoSavePassword = true;
			}
			p.NoSavePassword = no_save_password;
			p.CancelEvent = s->HaltEvent;
			if (s->Err == ERR_PROXY_AUTH_FAILED)
			{
				p.ProxyServer = true;
			}

			if (p.ProxyServer)
			{
				StrCpy(p.Username, sizeof(p.Username), s->ClientOption->ProxyUsername);
				StrCpy(p.Password, sizeof(p.Password), s->ClientOption->ProxyPassword);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->ProxyName);
			}
			else
			{
				bool empty = false;

				StrCpy(p.Username, sizeof(p.Username), s->ClientAuth->Username);
				if (s->ClientAuth->AuthType == AUTHTYPE_RADIUS)
				{
					if (StrLen(s->ClientAuth->PlainPassword) == 0)
					{
						empty = true;
					}
				}
				else if (s->ClientAuth->AuthType == AUTHTYPE_PASSWORD)
				{
					if (IsZero(s->ClientAuth->HashedPassword, sizeof(s->ClientAuth->HashedPassword)))
					{
						empty = true;
					}
				}

				StrCpy(p.Password, sizeof(p.Password), empty ? "" : HIDDEN_PASSWORD);
				StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption->Hostname);
			}

			p.RetryIntervalSec = s->RetryInterval / 1000;
			p.Type = s->ClientAuth->AuthType;

			// Display the password re-entry dialog
			if (CncPasswordDlg(s, &p) == false)
			{
				// Abort the connection
				break;
			}
			else
			{
				// Overwrite the user name
				if (p.ProxyServer)
				{
					// User name of the proxy
					StrCpy(s->ClientOption->ProxyUsername, sizeof(s->ClientOption->ProxyUsername), p.Username);
				}
				else
				{
					// The user name for connecting to the server
					StrCpy(s->ClientAuth->Username, sizeof(s->ClientAuth->Username), p.Username);
					s->ClientAuth->AuthType = p.Type;
				}

				if (StrCmp(p.Password, HIDDEN_PASSWORD) != 0)
				{
					// Password is re-entered
					if (p.ProxyServer)
					{
						// Password for the proxy server
						StrCpy(s->ClientOption->ProxyPassword, sizeof(s->ClientOption->ProxyPassword), p.Password);
					}
					else
					{
						if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
						{
							// Plaintext password authentication
							StrCpy(s->ClientAuth->PlainPassword, sizeof(s->ClientAuth->PlainPassword), p.Password);
						}
						else
						{
							// Encrypted password authentication
							HashPassword(s->ClientAuth->HashedPassword, s->ClientAuth->Username, p.Password);
						}
					}
				}

				no_save_password = p.NoSavePassword;

				if (s->Account != NULL && s->Cedar->Client != NULL)
				{
					s->Cedar->Client->DontSavePassword = no_save_password;
					if (p.NoSavePassword == false)
					{
						// Update the account database of the client
						if (p.ProxyServer == false)
						{
							// Update the Server connection information
							ACCOUNT *a = s->Account;
							Lock(a->lock);
							{
								CiFreeClientAuth(a->ClientAuth);
								a->ClientAuth = CopyClientAuth(s->ClientAuth);
							}
							Unlock(a->lock);
							CiSaveConfigurationFile(s->Cedar->Client);
						}
						else
						{
							// Update the proxy connection information
							ACCOUNT *a = s->Account;
							Lock(a->lock);
							{
								Copy(a->ClientOption, s->ClientOption, sizeof(CLIENT_OPTION));
							}
							Unlock(a->lock);
							CiSaveConfigurationFile(s->Cedar->Client);
						}
					}
				}
			}
#endif	// OS_WIN32
		}

SKIP:
		// Increase the number of retries
		if (s->ConnectSucceed == false)
		{
			s->CurrentRetryCount++;
		}

		if (s->ForceStopFlag)
		{
			break;
		}
	}

	Debug("Session Halt.\n");

	s->ClientStatus = CLIENT_STATUS_IDLE;

	// Regard as that the session is ended here
	if (s->Account != NULL)
	{
		s->Account->ClientSession = NULL;
		ReleaseSession(s);
	}

	Notify(s, CLIENT_NOTIFY_ACCOUNT_CHANGED);


	ReleaseSession(s);

	if (num_active_sessions_incremented)
	{
		CiDecrementNumActiveSessions();
	}
}

// Create an RPC session
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option)
{
	return NewRpcSessionEx(cedar, option, NULL, NULL);
}
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str)
{
	return NewRpcSessionEx2(cedar, option, err, client_str, NULL);
}
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd)
{
	SESSION *s;
	CONNECTION *c;
	SOCK *sock;
	// Validate arguments
	if (cedar == NULL || option == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_RPC_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->TrafficLock = NewLock();
	s->Cancel1 = NewCancel();

	// Copy the client connection options
	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	// Create a connection
	c = s->Connection = NewClientConnectionEx(s, client_str, cedar->Version, cedar->Build);
	c->hWndForUI = hWnd;

	// Connect to the server
	sock = ClientConnectToServer(c);
	if (sock == NULL)
	{
		// Connection failure
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	// Send a signature
	if (ClientUploadSignature(sock) == false)
	{
		// Failure
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	// Receive a Hello packet
	if (ClientDownloadHello(c, sock) == false)
	{
		// Failure
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	return s;
}

// Create a client session
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, ACCOUNT *account)
{
	SESSION *s;
	THREAD *t;
	// Validate arguments
	if (cedar == NULL || option == NULL || auth == NULL || pa == NULL ||
		(auth->AuthType == CLIENT_AUTHTYPE_SECURE && auth->SecureSignProc == NULL))
	{
		return NULL;
	}

	// Initialize the SESSION object
	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();

	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->PacketAdapter = pa;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->Cancel1 = NewCancel();
	s->CancelList = NewCancelList();

	// Copy the client connection options
	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT))
	{
		s->ClientOption->DisableQoS = true;
		s->ClientOption->MaxConnection = 1;
		s->ClientOption->HalfConnection = false;
	}

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	// Set the retry interval
	s->RetryInterval = MAKESURE(option->RetryInterval, 0, 4000000) * 1000;
	s->RetryInterval = MAKESURE(s->RetryInterval, MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL);

	// Interval for additional connection creation is at least 1 second
	s->ClientOption->AdditionalConnectionInterval = MAX(s->ClientOption->AdditionalConnectionInterval, 1);

	// Hold whether the virtual LAN card is used in client mode
	s->ClientModeAndUseVLan = (StrLen(s->ClientOption->DeviceName) == 0) ? false : true;

	if (s->ClientOption->NoRoutingTracking)
	{
		s->ClientModeAndUseVLan = false;
	}

	if (pa->Id == PACKET_ADAPTER_ID_VLAN_WIN32)
	{
		s->IsVPNClientAndVLAN_Win32 = true;
	}

	if (StrLen(option->DeviceName) == 0)
	{
		// NAT mode
		s->ClientModeAndUseVLan = false;
		s->VirtualHost = true;
	}

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		// Prohibit the half-duplex mode in the case of Win9x
		s->ClientOption->HalfConnection = false;
	}

	// Copy the client authentication data
	s->ClientAuth = Malloc(sizeof(CLIENT_AUTH));
	Copy(s->ClientAuth, auth, sizeof(CLIENT_AUTH));

	// Clone the certificate and the private key
	if (s->ClientAuth->ClientX != NULL)
	{
		s->ClientAuth->ClientX = CloneX(s->ClientAuth->ClientX);
	}
	if (s->ClientAuth->ClientK != NULL)
	{
		s->ClientAuth->ClientK = CloneK(s->ClientAuth->ClientK);
	}

	if (StrCmpi(s->ClientOption->DeviceName, LINK_DEVICE_NAME) == 0)
	{
		// Link client mode
		s->LinkModeClient = true;
		s->Link = (LINK *)s->PacketAdapter->Param;
	}

	if (StrCmpi(s->ClientOption->DeviceName, SNAT_DEVICE_NAME) == 0)
	{
		// SecureNAT mode
		s->SecureNATMode = true;
	}

	if (StrCmpi(s->ClientOption->DeviceName, BRIDGE_DEVICE_NAME) == 0)
	{
		// Bridge mode
		s->BridgeMode = true;
	}

	if (s->VirtualHost)
	{
		VH *v = (VH *)s->PacketAdapter->Param;

		// Add the session object to VH
		v->Session = s;
		AddRef(s->ref);
	}

	s->Account = account;

	if (s->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
	{
		// Do not retry in the case of a smart card authentication
		s->ClientOption->NumRetry = 0;
	}

	// Create a client thread
	t = NewThread(ClientThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa)
{
	return NewClientSessionEx(cedar, option, auth, pa, NULL);
}

// Get the session from the session key
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key)
{
	HUB *h;
	UINT i, j;
	// Validate arguments
	if (cedar == NULL || session_key == NULL)
	{
		return NULL;
	}

	LockList(cedar->HubList);
	{
		for (i = 0;i < LIST_NUM(cedar->HubList);i++)
		{
			h = LIST_DATA(cedar->HubList, i);
			LockList(h->SessionList);
			{
				for (j = 0;j < LIST_NUM(h->SessionList);j++)
				{
					SESSION *s = LIST_DATA(h->SessionList, j);
					Lock(s->lock);
					{
						if (Cmp(s->SessionKey, session_key, SHA1_SIZE) == 0)
						{
							// Session found
							AddRef(s->ref);

							// Unlock
							Unlock(s->lock);
							UnlockList(h->SessionList);
							UnlockList(cedar->HubList);
							return s;
						}
					}
					Unlock(s->lock);
				}
			}
			UnlockList(h->SessionList);
		}
	}
	UnlockList(cedar->HubList);

	return NULL;
}

// Create a new session key
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32)
{
	// Validate arguments
	if (cedar == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return;
	}

	Rand(session_key, SHA1_SIZE);
	*session_key_32 = Rand32();
}

bool if_init(SESSION *s);
CANCEL *if_getcancel(SESSION *s);
UINT if_getnext(SESSION *s, void **data);
bool if_putpacket(SESSION *s, void *data, UINT size);
void if_free(SESSION *s);


// Create a server session
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy)
{
	return NewServerSessionEx(cedar, c, h, username, policy, false, NULL);
}
SESSION *NewServerSessionEx(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy, bool inproc_mode, UCHAR *ipc_mac_address)
{
	SESSION *s;
	char name[MAX_SIZE];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	// Validate arguments
	if (cedar == NULL || c == NULL || h == NULL || username == NULL || policy == NULL)
	{
		return NULL;
	}

	// Initialize the SESSION object
	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = true;
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->Cancel1 = NewCancel();
	s->CancelList = NewCancelList();
	s->Thread = c->Thread;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->QoS = GetServerCapsBool(cedar->Server, "b_support_qos");
	AddRef(s->Thread->ref);
	s->Hub = h;
	s->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	// Delayed packet list
	s->DelayedPacketList = NewList(NULL);

	// Packet adapter for the HUB
	s->PacketAdapter = GetHubPacketAdapter();

	s->Connection = c;
	AddRef(c->ref);

	// Determine the new session name
	StrCpy(hub_name_upper, sizeof(hub_name_upper), h->Name);
	StrUpper(hub_name_upper);
	StrCpy(user_name_upper, sizeof(user_name_upper), username);
	StrUpper(user_name_upper);

	if ((StrCmpi(username, ADMINISTRATOR_USERNAME) != 0) && (StrCmpi(username, BRIDGE_USER_NAME) != 0) || (cedar->Server == NULL || cedar->Server->ServerType == SERVER_TYPE_STANDALONE))
	{
		if (IsEmptyStr(c->InProcPrefix))
		{
			Format(name, sizeof(name), "SID-%s-%u", user_name_upper, Inc(h->SessionCounter));
		}
		else
		{
			Format(name, sizeof(name), "SID-%s-[%s]-%u", user_name_upper, c->InProcPrefix, Inc(h->SessionCounter));
		}

		if (h->IsVgsHub || h->IsVgsSuperRelayHub)
		{
			UCHAR rand[5];
			char tmp[32];

			Rand(rand, sizeof(rand));

			BinToStr(tmp, sizeof(tmp), rand, sizeof(rand));

			StrCat(name, sizeof(name), "-");
			StrCat(name, sizeof(name), tmp);
		}
	}
	else
	{
		UCHAR rand[SHA1_SIZE];
		char tmp[MAX_SIZE];
		Rand(rand, sizeof(rand));
		BinToStr(tmp, sizeof(tmp), rand, 3);

		if (StrCmpi(username, BRIDGE_USER_NAME) != 0)
		{
			Format(name, sizeof(name), "SID-%s-%s", user_name_upper,
				tmp);
		}
		else
		{
			char pc_name[MAX_SIZE];
			TOKEN_LIST *t;

			GetMachineName(tmp, sizeof(tmp));
			t = ParseToken(tmp, ".");
			if (t->NumTokens >= 1)
			{
				StrCpy(pc_name, sizeof(pc_name), t->Token[0]);
			}
			else
			{
				StrCpy(pc_name, sizeof(pc_name), "pc");
			}
			FreeToken(t);

			StrUpper(pc_name);

			Format(name, sizeof(name), "SID-%s-%s-%u", user_name_upper, pc_name,
				Inc(h->SessionCounter));
		}
	}

	s->Name = CopyStr(name);
	s->Policy = policy;
	s->InProcMode = inproc_mode;

	// Add a SESSION to the HUB
	AddSession(h, s);

	// Create a key
	NewSessionKey(cedar, s->SessionKey, &s->SessionKey32);

	// Generate a MAC address for IPC
	if (s->InProcMode)
	{
		if (ipc_mac_address != NULL)
		{
			Copy(s->IpcMacAddress, ipc_mac_address, 6);
		}
		else
		{
			char tmp[MAX_SIZE];
			char machine[MAX_SIZE];
			UCHAR hash[SHA1_SIZE];

			GetMachineName(machine, sizeof(machine));

			Format(tmp, sizeof(tmp), "%s@%s@%u", machine, h->Name, s->UniqueId);

			StrUpper(tmp);
			Trim(tmp);

			Sha0(hash, tmp, StrLen(tmp));

			s->IpcMacAddress[0] = 0xCA;
			s->IpcMacAddress[1] = hash[1];
			s->IpcMacAddress[2] = hash[2];
			s->IpcMacAddress[3] = hash[3];
			s->IpcMacAddress[4] = hash[4];
			s->IpcMacAddress[5] = hash[5];

			MacToStr(tmp, sizeof(tmp), s->IpcMacAddress);
			Debug("MAC Address for IPC: %s\n", tmp);
		}
	}

	return s;
}

// Check whether the specified MAC address is IPC address
bool IsIpcMacAddress(UCHAR *mac)
{
	// Validate arguments
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] == 0xCA)
	{
		return true;
	}

	return false;
}

// Display the status on the client
void PrintStatus(SESSION *s, wchar_t *str)
{
	// Validate arguments
	if (s == NULL || str == NULL || s->Account == NULL || s->Cedar->Client == NULL
		|| s->Account->StatusPrinter == NULL)
	{
		return;
	}

	// Inform the status to the callback function
	s->Account->StatusPrinter(s, str);
}

// Create a cancellation list
LIST *NewCancelList()
{
	return NewList(NULL);
}

// Add a Cancel to the cancellation list
void AddCancelList(LIST *o, CANCEL *c)
{
	UINT i;
	// Validate arguments
	if (o == NULL || c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *t = LIST_DATA(o, i);
		if (t == c)
		{
			return;
		}
	}

	AddRef(c->ref);
	Add(o, c);
}

// Issue all cancellations in the cancellation list
void CancelList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		Cancel(c);
		ReleaseCancel(c);
	}

	DeleteAll(o);
}

// Release the cancellation list
void ReleaseCancelList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		ReleaseCancel(c);
	}

	ReleaseList(o);
}

// Notify to the client
void Notify(SESSION *s, UINT code)
{
	// Validate arguments
	if (s == NULL || s->Account == NULL || s->Cedar->Client == NULL)
	{
		return;
	}

	CiNotify(s->Cedar->Client);
}


