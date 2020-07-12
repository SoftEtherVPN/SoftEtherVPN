// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Connection.c
// Connection Manager

#include "CedarPch.h"

// Determine whether the socket is to use to send
#define	IS_SEND_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode == false)))

// Determine whether the socket is to use to receive
#define	IS_RECV_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode == false)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode)))

// Conversion of SECURE_SIGN
void InRpcSecureSign(SECURE_SIGN *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(SECURE_SIGN));
	PackGetStr(p, "SecurePublicCertName", t->SecurePublicCertName, sizeof(t->SecurePublicCertName));
	PackGetStr(p, "SecurePrivateKeyName", t->SecurePrivateKeyName, sizeof(t->SecurePrivateKeyName));
	t->ClientCert = PackGetX(p, "ClientCert");
	PackGetData2(p, "Random", t->Random, sizeof(t->Random));
	PackGetData2(p, "Signature", t->Signature, sizeof(t->Signature));
	t->UseSecureDeviceId = PackGetInt(p, "UseSecureDeviceId");
	t->BitmapId = PackGetInt(p, "BitmapId");
}
void OutRpcSecureSign(PACK *p, SECURE_SIGN *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "SecurePublicCertName", t->SecurePublicCertName);
	PackAddStr(p, "SecurePrivateKeyName", t->SecurePrivateKeyName);
	PackAddX(p, "ClientCert", t->ClientCert);
	PackAddData(p, "Random", t->Random, sizeof(t->Random));
	PackAddData(p, "Signature", t->Signature, sizeof(t->Signature));
	PackAddInt(p, "UseSecureDeviceId", t->UseSecureDeviceId);
	PackAddInt(p, "BitmapId", t->BitmapId);
}
void FreeRpcSecureSign(SECURE_SIGN *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeX(t->ClientCert);
}

// Generate the next packet
BUF *NewKeepPacket(bool server_mode)
{
	BUF *b = NewBuf();
	char *string = KEEP_ALIVE_STRING;

	WriteBuf(b, string, StrLen(string));

	SeekBuf(b, 0, 0);

	return b;
}

// KEEP thread
void KeepThread(THREAD *thread, void *param)
{
	KEEP *k = (KEEP *)param;
	SOCK *s;
	char server_name[MAX_HOST_NAME_LEN + 1];
	UINT server_port;
	bool udp_mode;
	bool enabled;
	// Validate arguments
	if (thread == NULL || k == NULL)
	{
		return;
	}

WAIT_FOR_ENABLE:
	Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);

	// Wait until it becomes enabled
	while (true)
	{
		enabled = false;
		Lock(k->lock);
		{
			if (k->Enable)
			{
				if (StrLen(k->ServerName) != 0 && k->ServerPort != 0 && k->Interval != 0)
				{
					StrCpy(server_name, sizeof(server_name), k->ServerName);
					server_port = k->ServerPort;
					udp_mode = k->UdpMode;
					enabled = true;
				}
			}
		}
		Unlock(k->lock);
		if (enabled)
		{
			break;
		}
		if (k->Halt)
		{
			return;
		}
		Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
	}

	if (udp_mode == false)
	{
		// TCP mode
		// Try until a success to connection
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// Settings are changed
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// Stop
				return;
			}

			// Attempt to connect to the server
			connect_started_tick = Tick64();
			s = ConnectEx2(server_name, server_port, KEEP_TCP_TIMEOUT, (bool *)&k->Halt);
			if (s != NULL)
			{
				// Successful connection
				break;
			}

			// Connection failure: Wait until timeout or the setting is changed
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// Stop
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// Settings are changed
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// Success to connect the server
		// Send and receive packet data periodically
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				ret = Recv(s, buf, sizeof(buf), false);
				if (ret == 0)
				{
					// Disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// Send the next packet
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = Send(s, b->Buf, b->Size, false);
						FreeBuf(b);

						if (ret == 0)
						{
							// Disconnected
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// Setting has been changed or disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// Stop
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
	else
	{
		IP dest_ip;
		// UDP mode
		// Try to create socket until it successes
		while (true)
		{
			UINT64 connect_started_tick;
			bool changed = false;
			Lock(k->lock);
			{
				if (StrCmpi(k->ServerName, server_name) != 0 ||
					k->ServerPort != server_port || k->Enable == false ||
					k->UdpMode == false)
				{
					changed = true;
				}
			}
			Unlock(k->lock);
			if (changed)
			{
				// Settings are changed
				goto WAIT_FOR_ENABLE;
			}

			if (k->Halt)
			{
				// Stop
				return;
			}

			// Attempt to create a socket
			connect_started_tick = Tick64();

			// Attempt to resolve the name first
			if (GetIP(&dest_ip, server_name))
			{
				// After successful name resolution, create a socket
				s = NewUDP(0);
				if (s != NULL)
				{
					// Creating success
					break;
				}
			}

			// Failure to create: wait until timeout or the setting is changed
			while (true)
			{
				changed = false;
				if (k->Halt)
				{
					// Stop
					return;
				}
				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed)
				{
					// Settings are changed
					goto WAIT_FOR_ENABLE;
				}

				if ((Tick64() - connect_started_tick) >= KEEP_RETRY_INTERVAL)
				{
					break;
				}

				Wait(k->HaltEvent, KEEP_POLLING_INTERVAL);
			}
		}

		// Send the packet data periodically
		if (s != NULL)
		{
			UINT64 last_packet_sent_time = 0;
			UINT num_ignore_errors = 0;
			while (true)
			{
				SOCKSET set;
				UINT ret;
				UCHAR buf[MAX_SIZE];
				bool changed;
				IP src_ip;
				UINT src_port;

				InitSockSet(&set);
				AddSockSet(&set, s);

				Select(&set, KEEP_POLLING_INTERVAL, k->Cancel, NULL);

				// Receive
				ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));
				if (ret == 0)
				{
					if (s->IgnoreRecvErr == false)
					{
LABEL_DISCONNECTED:
						// Disconnected
						Disconnect(s);
						ReleaseSock(s);
						s = NULL;
					}
					else
					{
						if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
						{
							goto LABEL_DISCONNECTED;
						}
					}
				}

				if (s != NULL)
				{
					if ((Tick64() - last_packet_sent_time) >= (UINT64)k->Interval)
					{
						BUF *b;

						// Send the next packet
						last_packet_sent_time = Tick64();

						b = NewKeepPacket(k->Server);

						ret = SendTo(s, &dest_ip, server_port, b->Buf, b->Size);
						FreeBuf(b);

						if (ret == 0 && s->IgnoreSendErr == false)
						{
							// Disconnected
							Disconnect(s);
							ReleaseSock(s);
							s = NULL;
						}
					}
				}

				changed = false;

				Lock(k->lock);
				{
					if (StrCmpi(k->ServerName, server_name) != 0 ||
						k->ServerPort != server_port || k->Enable == false ||
						k->UdpMode == false)
					{
						changed = true;
					}
				}
				Unlock(k->lock);

				if (changed || s == NULL)
				{
					// Setting has been changed or disconnected
					Disconnect(s);
					ReleaseSock(s);
					s = NULL;
					goto WAIT_FOR_ENABLE;
				}
				else
				{
					if (k->Halt)
					{
						// Stop
						Disconnect(s);
						ReleaseSock(s);
						return;
					}
				}
			}
		}
	}
}

// Stop the KEEP
void StopKeep(KEEP *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	k->Halt = true;
	Set(k->HaltEvent);
	Cancel(k->Cancel);

	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);
	DeleteLock(k->lock);

	ReleaseCancel(k->Cancel);
	ReleaseEvent(k->HaltEvent);

	Free(k);
}

// Start the KEEP
KEEP *StartKeep()
{
	KEEP *k = ZeroMalloc(sizeof(KEEP));

	k->lock = NewLock();
	k->HaltEvent = NewEvent();
	k->Cancel = NewCancel();

	// Thread start
	k->Thread = NewThread(KeepThread, k);

	return k;
}

// Copy the client authentication data
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a)
{
	CLIENT_AUTH *ret;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		// Anonymous authentication
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		// Password authentication
		Copy(ret->HashedPassword, a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		// Plaintext password authentication
		StrCpy(ret->PlainPassword, sizeof(ret->PlainPassword), a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		// Certificate authentication
		ret->ClientX = CloneX(a->ClientX);
		ret->ClientK = CloneK(a->ClientK);
		break;

	case CLIENT_AUTHTYPE_SECURE:
		// Secure device authentication
		StrCpy(ret->SecurePublicCertName, sizeof(ret->SecurePublicCertName), a->SecurePublicCertName);
		StrCpy(ret->SecurePrivateKeyName, sizeof(ret->SecurePrivateKeyName), a->SecurePrivateKeyName);
		break;
	}

	return ret;
}

// Write data to the transmit FIFO (automatic encryption)
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->SendFifo, data, size);
}

// Write data to the reception FIFO (automatic decryption)
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->RecvFifo, data, size);
}

// TCP socket receive
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Receive
	return Recv(ts->Sock, data, size, s->UseEncrypt);
}

// TCP socket send
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	// Transmission
	return Send(ts->Sock, data, size, s->UseEncrypt);
}

// Send the data as UDP packet
void SendDataWithUDP(SOCK *s, CONNECTION *c)
{
	UCHAR *buf;
	BUF *b;
	UINT64 dummy_64 = 0;
	UCHAR dummy_buf[16];
	UINT64 now = Tick64();
	UINT ret;
	bool force_flag = false;
	bool packet_sent = false;
	// Validate arguments
	if (s == NULL || c == NULL)
	{
		return;
	}

	// Allocate the temporary buffer in heap
	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	if (c->Udp->NextKeepAliveTime == 0 || c->Udp->NextKeepAliveTime <= now)
	{
		force_flag = true;
	}

	// Creating a buffer
	while ((c->SendBlocks->num_item > 0) || force_flag)
	{
		UINT *key32;
		UINT64 *seq;
		char *sign;

		force_flag = false;

		// Assemble a buffer from the current queue
		b = NewBuf();

		// Keep an area for packet header (16 bytes)
		WriteBuf(b, dummy_buf, sizeof(dummy_buf));

		// Pack the packets in transmission queue
		while (true)
		{
			BLOCK *block;

			if (b->Size > UDP_BUF_SIZE)
			{
				break;
			}
			block = GetNext(c->SendBlocks);
			if (block == NULL)
			{
				break;
			}

			if (block->Size != 0)
			{
				WriteBufInt(b, block->Size);
				WriteBuf(b, block->Buf, block->Size);

				c->Session->TotalSendSize += (UINT64)block->SizeofData;
				c->Session->TotalSendSizeReal += (UINT64)block->Size;
			}

			FreeBlock(block);
			break;
		}

		// Write sequence number and session key
		sign = (char *)(((UCHAR *)b->Buf));
		key32 = (UINT *)(((UCHAR *)b->Buf + 4));
		seq = (UINT64 *)(((UCHAR *)b->Buf + 8));
		Copy(sign, SE_UDP_SIGN, 4);
		*key32 = Endian32(c->Session->SessionKey32);
		*seq = Endian64(c->Udp->Seq++); // Increment the sequence number

//		InsertQueue(c->Udp->BufferQueue, b);

		packet_sent = true;
/*	}

	// Send a buffer
	while (c->Udp->BufferQueue->num_item != 0)
	{
		FIFO *f = c->Udp->BufferQueue->fifo;
		BUF **pb = (BUF**)(((UCHAR *)f->p) + f->pos);
		BUF *b = *pb;

*/		ret = SendTo(s, &c->Udp->ip, c->Udp->port, b->Buf, b->Size);
		if (ret == SOCK_LATER)
		{
			// Blocking
			Debug(".");
//			break;
		}
		if (ret != b->Size)
		{
			if (s->IgnoreSendErr == false)
			{
				// Error
				Debug("******* SendTo Error !!!\n");
			}
		}

		// Memory release
		FreeBuf(b);
//		GetNext(c->Udp->BufferQueue);
	}

	if (packet_sent)
	{
		// KeepAlive time update
		c->Udp->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
	}
}

// Write the data of the UDP packet to the connection
void PutUDPPacketData(CONNECTION *c, void *data, UINT size)
{
	BUF *b;
	char sign[4];
	// Validate arguments
	if (c == NULL || data == NULL)
	{
		return;
	}

	// Examine the protocol
	if (c->Protocol != CONNECTION_UDP)
	{
		// UDP protocol is not used
		return;
	}

	// Buffer configuration
	b = NewBuf();
	WriteBuf(b, data, size);

	SeekBuf(b, 0, 0);
	ReadBuf(b, sign, 4);

	// Signature confirmation
	if (Cmp(sign, SE_UDP_SIGN, 4) == 0)
	{
		UINT key32;

		// Session key number
		key32 = ReadBufInt(b);

		if (c->Session->SessionKey32 == key32)
		{
			UINT64 seq;

			// Read the Sequence number
			ReadBuf(b, &seq, sizeof(seq));
			seq = Endian64(seq);

			if ((UINT)(seq - c->Udp->RecvSeq - (UINT64)1))
			{
				//Debug("** UDP Seq Lost %u\n", (UINT)(seq - c->Udp->RecvSeq - (UINT64)1));
			}
			c->Udp->RecvSeq = seq;

			//Debug("SEQ: %I32u\n", seq);

			while (true)
			{
				UINT size;

				size = ReadBufInt(b);
				if (size == 0)
				{
					break;
				}
				else if (size <= MAX_PACKET_SIZE)
				{
					void *tmp;
					BLOCK *block;

					tmp = Malloc(size);
					if (ReadBuf(b, tmp, size) != size)
					{
						Free(tmp);
						break;
					}

					// Block configuration
					block = NewBlock(tmp, size, 0);

					// Insert Block
					InsertReceivedBlockToQueue(c, block, false);
				}
			}

			// Update the last communication time
			c->Session->LastCommTime = Tick64();
		}
		else
		{
			Debug("Invalid SessionKey: 0x%X\n", key32);
		}
	}

	FreeBuf(b);
}

// Add a block to the receive queue
void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock)
{
	SESSION *s;
	// Validate arguments
	if (c == NULL || block == NULL)
	{
		return;
	}

	s = c->Session;
	
	if (c->Protocol == CONNECTION_TCP)
	{
		s->TotalRecvSizeReal += block->SizeofData;
		s->TotalRecvSize += block->Size;
	}

	if (no_lock == false)
	{
		LockQueue(c->ReceivedBlocks);
	}

	if (c->ReceivedBlocks->num_item < MAX_STORED_QUEUE_NUM)
	{
		InsertQueue(c->ReceivedBlocks, block);
	}
	else
	{
		FreeBlock(block);
	}

	if (no_lock == false)
	{
		UnlockQueue(c->ReceivedBlocks);
	}
}

// Generate the interval to the next Keep-Alive packet
// (This should be a random number for the network load reduction)
UINT GenNextKeepAliveSpan(CONNECTION *c)
{
	UINT a, b;
	// Validate arguments
	if (c == NULL)
	{
		return INFINITE;
	}

	a = c->Session->Timeout;
	b = rand() % (a / 2);
	b = MAX(b, a / 5);

	return b;
}

// send a Keep-Alive packet
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts)
{
	UINT size, i, num;
	UINT size_be;
	SESSION *s;
	UCHAR *buf;
	bool insert_natt_port = false;
	// Validate arguments
	if (c == NULL || ts == NULL)
	{
		return;
	}

	s = c->Session;

	size = rand() % MAX_KEEPALIVE_SIZE;
	num = KEEP_ALIVE_MAGIC;

	if (s != NULL && s->UseUdpAcceleration && s->UdpAccel != NULL)
	{
		if (s->UdpAccel->MyPortByNatTServer != 0)
		{
			size = MAX(size, (StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE) + sizeof(USHORT)));

			insert_natt_port = true;
		}
	}

	buf = MallocFast(size);

	for (i = 0;i < size;i++)
	{
		buf[i] = rand();
	}

	if (insert_natt_port)
	{
		USHORT myport = Endian16((USHORT)s->UdpAccel->MyPortByNatTServer);

		Copy(buf, UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE, StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE));
		Copy(buf + StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE), &myport, sizeof(USHORT));
	}

	num = Endian32(num);
	size_be = Endian32(size);
	WriteSendFifo(c->Session, ts, &num, sizeof(UINT));
	WriteSendFifo(c->Session, ts, &size_be, sizeof(UINT));
	WriteSendFifo(c->Session, ts, buf, size);

	c->Session->TotalSendSize += sizeof(UINT) * 2 + size;
	c->Session->TotalSendSizeReal += sizeof(UINT) * 2 + size;

	Free(buf);
}

// Transmission of block
void ConnectionSend(CONNECTION *c, UINT64 now)
{
	UINT i, num;
	UINT min_count;
	UINT64 max_recv_tick;
	TCPSOCK **tcpsocks;
	UINT size;
	SESSION *s;
	HUB *hub = NULL;
	bool use_qos = false;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	s = c->Session;

	if (s != NULL)
	{
		hub = s->Hub;
		use_qos = s->QoS;
	}

	// Protocol
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		TCP *tcp = c->Tcp;
		TCPSOCK *ts;
		TCPSOCK *ts_hp;
		UINT num_available;
		bool is_rudp = false;
		UINT tcp_queue_size = 0;
		int tcp_queue_size_diff = 0;
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		if (s != NULL)
		{
			is_rudp = s->IsRUDPSession;
		}

		// Select the socket that will be used to send
		// Select a socket which have least delay count
		min_count = INFINITE;
		max_recv_tick = 0;
		ts = NULL;
		ts_hp = NULL;

		num_available = 0;

		if (c->IsInProc == false)
		{
			for (i = 0;i < num;i++)
			{
				TCPSOCK *tcpsock = tcpsocks[i];
				if (s != NULL && tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
					IS_SEND_TCP_SOCK(tcpsock))
				{
					// Processing of KeepAlive
					if (now >= tcpsock->NextKeepAliveTime || tcpsock->NextKeepAliveTime == 0 ||
						(s->UseUdpAcceleration && s->UdpAccel != NULL && s->UdpAccel->MyPortByNatTServerChanged))
					{
						// Send the KeepAlive
						SendKeepAlive(c, tcpsock);
						tcpsock->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);

						if (s->UseUdpAcceleration && s->UdpAccel != NULL)
						{
							s->UdpAccel->MyPortByNatTServerChanged = false;
						}
					}

					// Count the number of available sockets to send
					num_available++;

					ts_hp = tcpsock;
				}
			}
		}

		for (i = 0;i < num;i++)
		{
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
				IS_SEND_TCP_SOCK(tcpsock))
			{
				// Selection of the socket
				bool b = false;

				if (use_qos == false)
				{
					b = true;
				}
				else if (num_available < 2)
				{
					b = true;
				}
				else if (tcpsock != ts_hp)
				{
					b = true;
				}

				if (b)
				{
					if (is_rudp == false)
					{
						// Use a socket which have minimum delay occurrences in the case of such as a TCP socket
						if (tcpsock->LateCount <= min_count)
						{
							min_count = tcpsock->LateCount;
							ts = tcpsock;
						}
					}
					else
					{
						// Use socket which have the largest last received time in the case of R-UDP socket
						if (tcpsock->LastRecvTime >= max_recv_tick)
						{
							max_recv_tick = tcpsock->LastRecvTime;
							ts = tcpsock;
						}
					}
				}
			}

			tcp_queue_size += tcpsock->SendFifo->size;
		}

		tcp_queue_size_diff = ((int)tcp_queue_size) - ((int)c->LastTcpQueueSize);

		CedarAddCurrentTcpQueueSize(c->Cedar, tcp_queue_size_diff);

		c->LastTcpQueueSize = tcp_queue_size;

		if (ts_hp == NULL)
		{
			ts_hp = ts;
		}

		if (use_qos == false)
		{
			ts_hp = ts;
		}

		if (ts == NULL || ts_hp == NULL)
		{
			// The socket available to send doesn't currently exist
		}
		else
		{
			TCPSOCK *tss;
			UINT j;
			QUEUE *q;

			if (s != NULL && s->UdpAccel != NULL)
			{
				UdpAccelSetTick(s->UdpAccel, now);
			}

			for (j = 0;j < 2;j++)
			{
				if (j == 0)
				{
					q = c->SendBlocks2;
					tss = ts_hp;
				}
				else
				{
					q = c->SendBlocks;
					tss = ts;
				}
				// I reserve the data to send on the selected socket ts
				if (q->num_item != 0)
				{
					UINT num_data;
					BLOCK *b;
					UINT size_quota_v1 = MAX_SEND_SOCKET_QUEUE_SIZE / s->MaxConnection;
					UINT size_quota_v2 = MIN_SEND_SOCKET_QUEUE_SIZE;
					UINT size_quota = MAX(size_quota_v1, size_quota_v2);

					if (tss->SendFifo->size >= size_quota)
					{
						// The size of the socket send queue is exceeded
						// Unable to send
						while (b = GetNext(q))
						{
							if (b != NULL)
							{
								c->CurrentSendQueueSize -= b->Size;
								FreeBlock(b);
							}
						}
					}
					else
					{
						if (c->IsInProc == false)
						{
							if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, true))
							{
								// UDP acceleration mode
								while (b = GetNext(q))
								{
									UdpAccelSendBlock(s->UdpAccel, b);

									s->TotalSendSize += b->Size;
									s->TotalSendSizeReal += b->Size;

									c->CurrentSendQueueSize -= b->Size;

									FreeBlock(b);
								}
							}
							else if (s->IsRUDPSession && s->EnableBulkOnRUDP && ts->Sock != NULL && ts->Sock->BulkSendTube != NULL)
							{
								// R-UDP bulk transfer
								TUBE *t = ts->Sock->BulkSendTube;
								bool flush = false;
								TCP_PAIR_HEADER h;

								Zero(&h, sizeof(h));
								h.EnableHMac = s->EnableHMacOnBulkOfRUDP;

								while (b = GetNext(q))
								{
									if (b->Compressed == false)
									{
										// Uncompressed
										TubeSendEx(t, b->Buf, b->Size, &h, true);

										s->TotalSendSize += b->Size;
										s->TotalSendSizeReal += b->Size;

										c->CurrentSendQueueSize -= b->Size;
									}
									else
									{
										// Compressed
										UCHAR *new_buf = Malloc(b->Size + sizeof(UINT64));

										WRITE_UINT64(new_buf, CONNECTION_BULK_COMPRESS_SIGNATURE);

										Copy(new_buf + sizeof(UINT64), b->Buf, b->Size);

										TubeSendEx(t, new_buf, b->Size + sizeof(UINT64), &h, true);

										s->TotalSendSize += b->SizeofData;
										s->TotalSendSizeReal += b->Size;

										c->CurrentSendQueueSize -= b->Size;

										Free(new_buf);
									}

									FreeBlock(b);

									flush = true;
								}

								if (flush)
								{
									TubeFlush(t);
								}
							}
							else
							{
								// TCP/IP socket
								bool update_keepalive_timer = false;
								// Number of data
								num_data = Endian32(q->num_item);
								PROBE_DATA2("WriteSendFifo num", &num_data, sizeof(UINT));
								WriteSendFifo(s, tss, &num_data, sizeof(UINT));

								s->TotalSendSize += sizeof(UINT);
								s->TotalSendSizeReal += sizeof(UINT);

								while (b = GetNext(q))
								{
									// Size data
									UINT size_data;
									size_data = Endian32(b->Size);
									PROBE_DATA2("WriteSendFifo size", &size_data, sizeof(UINT));
									WriteSendFifo(s, tss, &size_data, sizeof(UINT));

									c->CurrentSendQueueSize -= b->Size;

									s->TotalSendSize += sizeof(UINT);
									s->TotalSendSizeReal += sizeof(UINT);

									// Data body
									PROBE_DATA2("WriteSendFifo data", b->Buf, b->Size);
									WriteSendFifo(s, tss, b->Buf, b->Size);

									s->TotalSendSize += b->SizeofData;
									s->TotalSendSizeReal += b->Size;

									update_keepalive_timer = true;

									// Block release
									FreeBlock(b);
								}

								if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, false))
								{
									update_keepalive_timer = false;
								}

								if (update_keepalive_timer)
								{
									// Increase the KeepAlive timer
									tss->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
								}
							}
						}
						else
						{
							bool flush = false;
							// In-process socket
							while (b = GetNext(q))
							{
								TubeSendEx(ts->Sock->SendTube, b->Buf, b->Size, NULL, true);
								flush = true;

								s->TotalSendSize += b->Size;
								s->TotalSendSizeReal += b->Size;

								c->CurrentSendQueueSize -= b->Size;

								FreeBlock(b);
							}

							if (flush)
							{
								TubeFlush(ts->Sock->SendTube);
							}
						}
					}
				}
			}
		}

		// Send the reserved data to send registered in each socket now
		if (c->IsInProc == false)
		{
			for (i = 0;i < num;i++)
			{
				ts = tcpsocks[i];

SEND_START:
				if (ts->Sock->Connected == false)
				{
					s->LastTryAddConnectTime = Tick64();
					// Communication is disconnected
					LockList(tcp->TcpSockList);
					{
						// Remove the socket from socket list
						Delete(tcp->TcpSockList, ts);
						// Release of TCPSOCK
						FreeTcpSock(ts);
						// Decrement the count
						Dec(c->CurrentNumConnection);
						Debug("--- TCP Connection Decremented: %u (%s Line %u)\n", Count(c->CurrentNumConnection), __FILE__, __LINE__);
						Debug("LIST_NUM(tcp->TcpSockList): %u\n", LIST_NUM(tcp->TcpSockList));
					}
					UnlockList(tcp->TcpSockList);

					continue;
				}

				// Get Fifo size
				if (ts->SendFifo->size != 0)
				{
					UCHAR *buf;
					UINT want_send_size;
					// Send only if the data to send exists by 1 byte or more
					// Get the pointer to the buffer
					buf = (UCHAR *)ts->SendFifo->p + ts->SendFifo->pos;
					want_send_size = ts->SendFifo->size;

					PROBE_DATA2("TcpSockSend", buf, want_send_size);
					size = TcpSockSend(s, ts, buf, want_send_size);

					if (size == 0)
					{
						// Disconnected
						continue;
					}
					else if (size == SOCK_LATER)
					{
						// Packet is jammed
						ts->LateCount++; // Increment of the delay counter
						PROBE_STR("ts->LateCount++;");
					}
					else
					{
						// Packet is sent only by 'size'
						// Advance FIFO
						ReadFifo(ts->SendFifo, NULL, size);
						if (size < want_send_size)
						{
							// Fail to transmit all of the data that has been scheduled
#ifdef	USE_PROBE
							{
								char tmp[MAX_SIZE];

								snprintf(tmp, sizeof(tmp), "size < want_send_size: %u < %u",
									size, want_send_size);

								PROBE_STR(tmp);
							}
#endif	// USE_PROBE
						}
						else
						{
							// Because sending all the packets is completed
							// (The queue is exhausted), reset the delay counter
							ts->LateCount = 0;

							PROBE_STR("TcpSockSend All Completed");
						}
						// Updated the last communication date and time
						UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);

						goto SEND_START;
					}
				}
			}
		}

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_UDP)
	{
		// UDP
		UDP *udp = c->Udp;
		SOCK *sock = NULL;

		Lock(c->lock);
		{
			sock = udp->s;
			if (sock != NULL)
			{
				AddRef(sock->ref);
			}
		}
		Unlock(c->lock);

		if (sock != NULL)
		{
			// Send with UDP

			// KeepAlive sending
			if ((udp->NextKeepAliveTime == 0 || udp->NextKeepAliveTime <= now) ||
				(c->SendBlocks->num_item != 0) || (udp->BufferQueue->num_item != 0))
			{
				// Send the current queue with UDP
				SendDataWithUDP(sock, c);
			}
		}

		if (sock != NULL)
		{
			ReleaseSock(sock);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_SECURE_NAT)
	{
		// SecureNAT session
		SNAT *snat = s->SecureNAT;
		VH *v = snat->Nat->Virtual;
		BLOCK *block;
		UINT num_packet = 0;

		if (hub != NULL)
		{
			NatSetHubOption(v, hub->Option);
		}

		while (block = GetNext(c->SendBlocks))
		{
			num_packet++;
			c->CurrentSendQueueSize -= block->Size;
			VirtualPutPacket(v, block->Buf, block->Size);
			Free(block);
		}

		if (num_packet != 0)
		{
			VirtualPutPacket(v, NULL, 0);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LAYER3)
	{
		// Layer-3 session
		L3IF *f = s->L3If;
		BLOCK *block;
		UINT num_packet = 0;

		while (block = GetNext(c->SendBlocks))
		{
			num_packet++;
			c->CurrentSendQueueSize -= block->Size;
			L3PutPacket(f, block->Buf, block->Size);
			Free(block);
		}

		if (num_packet != 0)
		{
			L3PutPacket(f, NULL, 0);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		// HUB Link
		LINK *k = (LINK *)s->Link;

		if (k != NULL)
		{
			UINT num_blocks = 0;
			LockQueue(k->SendPacketQueue);
			{
				BLOCK *block;

				// Transfer the packet queue to the client thread
				while (block = GetNext(c->SendBlocks))
				{
					c->CurrentSendQueueSize -= block->Size;

					if (k->SendPacketQueue->num_item >= MAX_STORED_QUEUE_NUM)
					{
						FreeBlock(block);
					}
					else
					{
						num_blocks++;
						k->CurrentSendPacketQueueSize += block->Size;
						InsertQueue(k->SendPacketQueue, block);
					}
				}
			}
			UnlockQueue(k->SendPacketQueue);

			if (num_blocks != 0)
			{
				// Issue of cancellation
				Cancel(k->ClientSession->Cancel1);
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		// Local bridge
		BRIDGE *b = s->Bridge;

		if (b != NULL)
		{
			if (b->Active)
			{
				BLOCK *block;
				UINT num_packet = c->SendBlocks->num_item; // Packet count

				if (num_packet != 0)
				{
					// Packet data array
					void **datas = MallocFast(sizeof(void *) * num_packet);
					UINT *sizes = MallocFast(sizeof(UINT) * num_packet);
					UINT i;

					i = 0;
					while (block = GetNext(c->SendBlocks))
					{
						if (hub != NULL && hub->Option != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
							b->Eth != NULL && IsDhcpPacketForSpecificMac(block->Buf, block->Size, b->Eth->MacAddress))
						{
							// DHCP Packet is filtered
							datas[i] = NULL;
							sizes[i] = 0;

							Free(block->Buf);
						}
						else
						{
							datas[i] = block->Buf;
							sizes[i] = block->Size;

							if (block->Size > 1514)
							{
								NormalizeEthMtu(b, c, block->Size);
							}
						}

						c->CurrentSendQueueSize -= block->Size;
						Free(block);
						i++;
					}

					// Write the packet
					EthPutPackets(b->Eth, num_packet, datas, sizes);

					Free(datas);
					Free(sizes);
				}
			}
		}
	}
}

// Reception of the block
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2)
{
	UINT i, num;
	SOCKSET set;
	SESSION *s;
	TCPSOCK **tcpsocks;
	UCHAR *buf;
	UINT size;
	UINT time;
	UINT num_delayed = 0;
	bool no_spinlock_for_delay = false;
	UINT64 now = Tick64();
	HUB *hub = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	PROBE_STR("ConnectionReceive");

	s = c->Session;

	if (s != NULL)
	{
		hub = s->Hub;
	}

	if (hub != NULL)
	{
		no_spinlock_for_delay = hub->Option->NoSpinLockForPacketDelay;
	}

	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	// Protocol
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		TCP *tcp = c->Tcp;
		UINT next_delay_packet_diff = 0;
		UINT current_recv_fifo_size = 0;
		int recv_fifo_size_middle_update = 0;

		// Disconnect if disconnection interval is specified
		if (s->ServerMode == false)
		{
			if (s->ClientOption->ConnectionDisconnectSpan != 0)
			{
				LockList(tcp->TcpSockList);
				{
					UINT i;
					for (i = 0;i < LIST_NUM(tcp->TcpSockList);i++)
					{
						TCPSOCK *ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->DisconnectTick != 0 &&
							ts->DisconnectTick <= now)
						{
							Debug("ts->DisconnectTick <= now\n");
							Disconnect(ts->Sock);
						}
					}
				}
				UnlockList(tcp->TcpSockList);
			}
		}

		if (s->HalfConnection && (s->ServerMode == false))
		{
			// Check the direction of the current TCP connections.
			//  Disconnect one if the number of connections reaches 
			// the limit and has only one direction
			LockList(tcp->TcpSockList);
			{
				UINT i, num;
				UINT c2s, s2c;
				c2s = s2c = 0;
				num = LIST_NUM(tcp->TcpSockList);
				if (num >= s->MaxConnection)
				{
					TCPSOCK *ts;
					for (i = 0;i < num;i++)
					{
						ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->Direction == TCP_SERVER_TO_CLIENT)
						{
							s2c++;
						}
						else
						{
							c2s++;
						}
					}
					if (s2c == 0 || c2s == 0)
					{
						// Disconnect the last socket
						Disconnect(ts->Sock);
						Debug("Disconnect (s2c=%u, c2s=%u)\n", s2c, c2s);
					}
				}
			}
			UnlockList(tcp->TcpSockList);
		}

		// Initializing the socket set
		InitSockSet(&set);
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		for (i = 0;i < num;i++)
		{
			AddSockSet(&set, tcpsocks[i]->Sock);
		}

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			if (s->UdpAccel->UdpSock != NULL)
			{
				AddSockSet(&set, s->UdpAccel->UdpSock);
			}
		}

		// Select
		time = SELECT_TIME;
		if (s->VirtualHost)
		{
			time = MIN(time, SELECT_TIME_FOR_NAT);
		}
		next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
		time = MIN(time, next_delay_packet_diff);
		num_delayed = LIST_NUM(s->DelayedPacketList);

		PROBE_STR("ConnectionReceive: Select 0");

		if (s->Flag1 != set.NumSocket)
		{
			Select(&set, (num_delayed == 0 ? time : 1), c1, c2);
			s->Flag1 = set.NumSocket;
		}
		else
		{
			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(&set, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
				s->Flag1 = set.NumSocket;
			}
			else
			{
				YieldCpu();
			}
		}

		now = Tick64();

		PROBE_STR("ConnectionReceive: Select 1");

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			// Read the data received by the UDP If using the UDP acceleration mode
			UdpAccelSetTick(s->UdpAccel, now);
			UdpAccelPoll(s->UdpAccel);

			if (s->UdpAccelMss == 0)
			{
				s->UdpAccelMss = UdpAccelCalcMss(s->UdpAccel);
			}

			while (true)
			{
				UINT current_packet_index = 0;
				BLOCK *b = GetNext(s->UdpAccel->RecvBlockQueue);

				if (b == NULL)
				{
					break;
				}

				if (b->Size > MAX_PACKET_SIZE)
				{
					// Packet size exceeded
					FreeBlock(b);
				}
				else
				{
					if (CedarGetQueueBudgetBalance(c->Cedar) == 0)
					{
						FreeBlock(b);
					}
					else
					{
						// Add the data block to queue
						InsertReceivedBlockToQueue(c, b, true);

						if ((current_packet_index % 32) == 0)
						{
							UINT current_recv_block_num = c->ReceivedBlocks->num_item;
							int diff = (int)current_recv_block_num - (int)c->LastRecvBlocksNum;

							CedarAddQueueBudget(c->Cedar, diff);

							c->LastRecvBlocksNum = current_recv_block_num;
						}

						current_packet_index++;
					}
				}
			}
		}

		{
			bool new_status = UdpAccelIsSendReady(s->UdpAccel, true);

			if (s->IsUsingUdpAcceleration != new_status)
			{
				Debug("UDP Status Changed: %u\n", new_status);
			}

			s->IsUsingUdpAcceleration = new_status;
		}

		// Read all the data that has arrived to the TCP socket
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			SOCK *sock = ts->Sock;

			if (s->IsRUDPSession)
			{
				TUBE *t = sock->BulkRecvTube;

				if (s->EnableBulkOnRUDP)
				{
					// R-UDP bulk transfer data reception
					if (t != NULL && IsTubeConnected(t))
					{
						UINT current_packet_index = 0;
						while (true)
						{
							TUBEDATA *d = TubeRecvAsync(t);
							BLOCK *block;
							if (d == NULL)
							{
								// All reception complete
								break;
							}

							if (d->DataSize > sizeof(UINT64) && READ_UINT64(d->Data) == CONNECTION_BULK_COMPRESS_SIGNATURE)
							{
								// Compression
								block = NewBlock(Clone(((UCHAR *)d->Data) + sizeof(UINT64),
									d->DataSize - sizeof(UINT64)),
									d->DataSize - sizeof(UINT64),
									-1);
							}
							else
							{
								// Uncompressed
								block = NewBlock(Clone(d->Data, d->DataSize), d->DataSize, 0);
							}

							if (block->Size > MAX_PACKET_SIZE)
							{
								// Packet size exceeded
								FreeBlock(block);
							}
							else
							{
								if (CedarGetQueueBudgetBalance(c->Cedar) == 0)
								{
									FreeBlock(block);
								}
								else
								{
									// Add the data block to queue
									InsertReceivedBlockToQueue(c, block, true);

									if ((current_packet_index % 32) == 0)
									{
										UINT current_recv_block_num = c->ReceivedBlocks->num_item;
										int diff = (int)current_recv_block_num - (int)c->LastRecvBlocksNum;

										CedarAddQueueBudget(c->Cedar, diff);

										c->LastRecvBlocksNum = current_recv_block_num;
									}

									current_packet_index++;
								}
							}

							FreeTubeData(d);

							UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);
							UPDATE_LAST_COMM_TIME(ts->LastRecvTime, now);
							UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
						}
					}
				}
			}

			if (c->IsInProc)
			{
				TUBEDATA *d;
				UINT current_packet_index = 0;

				// Socket for in-process connection
				if (IsTubeConnected(sock->RecvTube) == false)
				{
					// Communication is disconnected
					goto DISCONNECT_THIS_TCP;
				}

				while (true)
				{
					BLOCK *block;
					// Get the packet data from the tube
					d = TubeRecvAsync(sock->RecvTube);
					if (d == NULL)
					{
						// All acquisition completed
						break;
					}

					block = NewBlock(Clone(d->Data, d->DataSize), d->DataSize, 0);

					if (block->Size > MAX_PACKET_SIZE)
					{
						// Packet size exceeded
						FreeBlock(block);
					}
					else
					{
						if (CedarGetQueueBudgetBalance(c->Cedar) == 0)
						{
							FreeBlock(block);
						}
						else
						{
							// Add the data block to queue
							InsertReceivedBlockToQueue(c, block, true);

							if ((current_packet_index % 32) == 0)
							{
								UINT current_recv_block_num = c->ReceivedBlocks->num_item;
								int diff = (int)current_recv_block_num - (int)c->LastRecvBlocksNum;

								CedarAddQueueBudget(c->Cedar, diff);

								c->LastRecvBlocksNum = current_recv_block_num;
							}

							current_packet_index++;
						}
					}

					FreeTubeData(d);
				}

				UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
			}
			else
			{
				UINT current_fifo_budget = 0;
				UINT current_packet_index = 0;
				// A normal socket (Not in-process)
				if (ts->WantSize == 0)
				{
					// Read for sizeof(UINT) first
					ts->WantSize = sizeof(UINT);
				}

				now = Tick64();

RECV_START:
				current_fifo_budget = CedarGetFifoBudgetBalance(c->Cedar);
				// Receive
				if (ts->RecvFifo->size < current_fifo_budget)
				{
					UINT recv_buf_size = current_fifo_budget - ts->RecvFifo->size;

					recv_buf_size = MIN(recv_buf_size, RECV_BUF_SIZE);

					size = TcpSockRecv(s, ts, buf, recv_buf_size);
				}
				else
				{
					size = SOCK_LATER;

					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);
				}

				/*
				// Experiment
				if (c->ServerMode)
				{
					if ((ts->EstablishedTick + (UINT64)3000) <= now)
					{
						size = 0;
						WHERE;
					}
				}*/

				if (size == 0)
				{
DISCONNECT_THIS_TCP:
					s->LastTryAddConnectTime = Tick64();
					s->NumDisconnected++;
					// Communication is disconnected
					LockList(tcp->TcpSockList);
					{
						// Remove the socket from socket list
						Delete(tcp->TcpSockList, ts);
						// Release of TCPSOCK
						FreeTcpSock(ts);
						// Decrement
						Dec(c->CurrentNumConnection);
						Debug("--- TCP Connection Decremented: %u (%s Line %u)\n", Count(c->CurrentNumConnection), __FILE__, __LINE__);
						Debug("LIST_NUM(tcp->TcpSockList): %u\n", LIST_NUM(tcp->TcpSockList));
					}
					UnlockList(tcp->TcpSockList);

					continue;
				}
				else if (size == SOCK_LATER)
				{
					// State of waiting reception : don't do anything
					if (IS_RECV_TCP_SOCK(ts))
					{
						if ((now > ts->LastCommTime) && ((now - ts->LastCommTime) >= ((UINT64)s->Timeout)))
						{
							// The connection has timed out
							Debug("Connection %u Timeouted.\n", i);
							goto DISCONNECT_THIS_TCP;
						}
					}
				}
				else
				{
					UINT budget_balance = CedarGetFifoBudgetBalance(c->Cedar);
					UINT fifo_size_limit = budget_balance;

					if (fifo_size_limit > MAX_BUFFERING_PACKET_SIZE)
					{
						fifo_size_limit = MAX_BUFFERING_PACKET_SIZE;
					}

					// Update the last communication time
					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastRecvTime, now);

					CedarAddFifoBudget(c->Cedar, (int)size);
					recv_fifo_size_middle_update += (int)size;

					// Write the received data into the FIFO
					PROBE_DATA2("WriteRecvFifo", buf, size);
					WriteRecvFifo(s, ts, buf, size);

					// Stop receiving  when the receive buffer is full
					if (ts->RecvFifo->size < fifo_size_limit)
					{
						goto RECV_START;
					}
				}

				current_recv_fifo_size += FifoSize(ts->RecvFifo);

				// process the data written to FIFO
				while (ts->RecvFifo->size >= ts->WantSize)
				{
					UCHAR *buf;
					void *data;
					BLOCK *block;
					UINT sz;
					// A sufficient amount of data is already stored
					// Get the pointer of the data
					buf = (UCHAR *)ts->RecvFifo->p + ts->RecvFifo->pos;

					switch (ts->Mode)
					{
					case 0:
						// The number of Data blocks
						ts->WantSize = sizeof(UINT);
						Copy(&sz, buf, sizeof(UINT));
						PROBE_DATA2("ReadFifo 0", buf, sizeof(UINT));
						sz = Endian32(sz);
						ts->NextBlockNum = sz;
						ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

						s->TotalRecvSize += sizeof(UINT);
						s->TotalRecvSizeReal += sizeof(UINT);

						ts->CurrentPacketNum = 0;
						if (ts->NextBlockNum != 0)
						{
							if (ts->NextBlockNum == KEEP_ALIVE_MAGIC)
							{
								ts->Mode = 3;
							}
							else
							{
								ts->Mode = 1;
							}
						}
						break;

					case 1:
						// Data block size
						Copy(&sz, buf, sizeof(UINT));
						sz = Endian32(sz);
						PROBE_DATA2("ReadFifo 1", buf, sizeof(UINT));
						if (sz > (MAX_PACKET_SIZE * 2))
						{
							// received a strange data size
							// TCP/IP Error?
							Debug("%s %u sz > (MAX_PACKET_SIZE * 2)\n", __FILE__, __LINE__);
							Disconnect(ts->Sock);
						}
						ts->NextBlockSize = MIN(sz, MAX_PACKET_SIZE * 2);
						ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

						s->TotalRecvSize += sizeof(UINT);
						s->TotalRecvSizeReal += sizeof(UINT);

						ts->WantSize = ts->NextBlockSize;
						if (ts->WantSize != 0)
						{
							ts->Mode = 2;
						}
						else
						{
							ts->Mode = 1;
							ts->WantSize = sizeof(UINT);
							ts->CurrentPacketNum++;
							if (ts->CurrentPacketNum >= ts->NextBlockNum)
							{
								ts->Mode = 0;
							}
						}
						break;

					case 2:
						// Data block body
						ts->WantSize = sizeof(UINT);
						ts->CurrentPacketNum++;
						data = MallocFast(ts->NextBlockSize);
						Copy(data, buf, ts->NextBlockSize);
						PROBE_DATA2("ReadFifo 2", buf, ts->NextBlockSize);
						ReadFifo(ts->RecvFifo, NULL, ts->NextBlockSize);
						block = NewBlock(data, ts->NextBlockSize, s->UseCompress ? -1 : 0);

						UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
						UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

						if (block->Size > MAX_PACKET_SIZE)
						{
							// Packet size exceeded
							FreeBlock(block);
						}
						else
						{
							if (CedarGetQueueBudgetBalance(c->Cedar) == 0)
							{
								FreeBlock(block);
							}
							else
							{
								// Add the data block to queue
								InsertReceivedBlockToQueue(c, block, true);

								if ((current_packet_index % 32) == 0)
								{
									UINT current_recv_block_num = c->ReceivedBlocks->num_item;
									int diff = (int)current_recv_block_num - (int)c->LastRecvBlocksNum;

									CedarAddQueueBudget(c->Cedar, diff);

									c->LastRecvBlocksNum = current_recv_block_num;
								}

								current_packet_index++;
							}
						}

						if (ts->CurrentPacketNum >= ts->NextBlockNum)
						{
							// Reception of all the data blocks completed
							ts->Mode = 0;
						}
						else
						{
							// Receive next data block size
							ts->Mode = 1;
						}
						break;

					case 3:
						// Keep-Alive packet size
						ts->Mode = 4;
						Copy(&sz, buf, sizeof(UINT));
						PROBE_DATA2("ReadFifo 3", buf, sizeof(UINT));
						sz = Endian32(sz);
						if (sz > MAX_KEEPALIVE_SIZE)
						{
							// received a strange data size
							// TCP/IP Error?
							Debug("%s %u sz > MAX_KEEPALIVE_SIZE\n", __FILE__, __LINE__);
							Disconnect(ts->Sock);
						}
						ts->NextBlockSize = MIN(sz, MAX_KEEPALIVE_SIZE);
						ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

						UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
						UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

						s->TotalRecvSize += sizeof(UINT);
						s->TotalRecvSizeReal += sizeof(UINT);

						ts->WantSize = sz;
						break;

					case 4:
						// Keep-Alive packet body
						//Debug("KeepAlive Recved.\n");
						ts->Mode = 0;
						sz = ts->NextBlockSize;

						if (sz >= (StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE) + sizeof(USHORT)))
						{
							UCHAR *keep_alive_buffer = FifoPtr(ts->RecvFifo);

							if (Cmp(keep_alive_buffer, UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE, StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE)) == 0)
							{
								USHORT us = READ_USHORT(keep_alive_buffer + StrLen(UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE));

								if (us != 0)
								{
									if (s->UseUdpAcceleration && s->UdpAccel != NULL)
									{
										UINT port = (UINT)us;

										if (s->UdpAccel->YourPortByNatTServer != port)
										{
											s->UdpAccel->YourPortByNatTServer = port;
											s->UdpAccel->YourPortByNatTServerChanged = true;

											Debug("s->UdpAccel->YourPortByNatTServer: %u\n",
												s->UdpAccel->YourPortByNatTServer);
										}
									}
								}
							}
						}

						PROBE_DATA2("ReadFifo 4", NULL, 0);
						ReadFifo(ts->RecvFifo, NULL, sz);

						UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
						UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

						s->TotalRecvSize += sz;
						s->TotalRecvSizeReal += sz;

						ts->WantSize = sizeof(UINT);
						break;
					}
				}

				ShrinkFifoMemory(ts->RecvFifo);
				//printf("Fifo: %u\n", ts->RecvFifo->memsize);
			}
		}

		if (true)
		{
			int diff;

			diff = (int)current_recv_fifo_size - (int)c->LastRecvFifoTotalSize;

			CedarAddFifoBudget(c->Cedar, (diff - recv_fifo_size_middle_update));

			c->LastRecvFifoTotalSize = current_recv_fifo_size;
		}

		if (true)
		{
			UINT current_recv_block_num = c->ReceivedBlocks->num_item;
			int diff = (int)current_recv_block_num - (int)c->LastRecvBlocksNum;

			CedarAddQueueBudget(c->Cedar, diff);

			c->LastRecvBlocksNum = current_recv_block_num;
		}

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_UDP)
	{
		// UDP
		UDP *udp = c->Udp;
		SOCK *sock = NULL;

		if (s->ServerMode == false)
		{
			Lock(c->lock);
			{
				if (c->Udp->s != NULL)
				{
					sock = c->Udp->s;
					if (sock != NULL)
					{
						AddRef(sock->ref);
					}
				}
			}
			Unlock(c->lock);

			InitSockSet(&set);

			if (sock != NULL)
			{
				AddSockSet(&set, sock);
			}

			Select(&set, SELECT_TIME, c1, c2);

			if (sock != NULL)
			{
				IP ip;
				UINT port;
				UCHAR *buf;
				UINT size;

				while (true)
				{
					buf = c->RecvBuf;
					size = RecvFrom(sock, &ip, &port, buf, RECV_BUF_SIZE);
					if (size == 0 && sock->IgnoreRecvErr == false)
					{
						Debug("UDP Socket Disconnected.\n");
						Lock(c->lock);
						{
							ReleaseSock(udp->s);
							udp->s = NULL;
						}
						Unlock(c->lock);
						break;
					}
					else if (size == SOCK_LATER)
					{
						break;
					}
					else
					{
						if (size)
						{
							PutUDPPacketData(c, buf, size);
						}
					}
				}
			}

			if (sock != NULL)
			{
				Release(sock->ref);
			}
		}
		else
		{
			Select(NULL, SELECT_TIME, c1, c2);
		}
	}
	else if (c->Protocol == CONNECTION_HUB_SECURE_NAT)
	{
		SNAT *snat = c->Session->SecureNAT;
		VH *v = snat->Nat->Virtual;
		UINT size;
		void *data;
		UINT num;
		UINT select_wait_time = SELECT_TIME_FOR_NAT;
		UINT next_delay_packet_diff = 0;

		if (snat->Nat != NULL && snat->Nat->Option.UseNat == false)
		{
			select_wait_time = SELECT_TIME;
		}
		else
		{
			if (snat->Nat != NULL)
			{
				LockList(v->NatTable);
				{
					if (LIST_NUM(v->NatTable) == 0 && LIST_NUM(v->ArpWaitTable) == 0)
					{
						select_wait_time = SELECT_TIME;
					}
				}
				UnlockList(v->NatTable);
			}
		}

		next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
		select_wait_time = MIN(select_wait_time, next_delay_packet_diff);
		num_delayed = LIST_NUM(s->DelayedPacketList);

		if (no_spinlock_for_delay || select_wait_time >= 50 || num_delayed == false)
		{
			Select(NULL, (num_delayed == 0 ? select_wait_time :
				(select_wait_time > 100 ? (select_wait_time - 100) : 1)), c1, c2);
		}
		else
		{
			YieldCpu();
		}

		num = 0;

		if (hub != NULL)
		{
			NatSetHubOption(v, hub->Option);
		}

		// Receive a packet from the virtual machine
		while (size = VirtualGetNextPacket(v, &data))
		{
			BLOCK *block;

			// Generate packet block
			block = NewBlock(data, size, 0);
			if (block->Size > MAX_PACKET_SIZE)
			{
				// Packet size exceeded
				FreeBlock(block);
			}
			else
			{
				// Add the data block to queue
				InsertReceivedBlockToQueue(c, block, true);
			}
			num++;
			if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
			{
//				WHERE;
				break;
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		// HUB Link
		// Waiting Cancel simply
		if (c->SendBlocks->num_item == 0)
		{
			UINT time = SELECT_TIME;
			UINT next_delay_packet_diff = 0;

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_LAYER3)
	{
		// Layer-3 switch session
		L3IF *f = s->L3If;
		UINT size, num = 0;
		void *data;

		if (f->SendQueue->num_item == 0)
		{
			UINT time = SELECT_TIME_FOR_NAT;
			UINT next_delay_packet_diff = 0;

			if (f->ArpWaitTable != NULL)
			{
				LockList(f->ArpWaitTable);
				{
					if (LIST_NUM(f->ArpWaitTable) == 0)
					{
						time = SELECT_TIME;
					}
				}
				UnlockList(f->ArpWaitTable);
			}

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}
		}

		// Get the next packet
		while (size = L3GetNextPacket(f, &data))
		{
			BLOCK *block = NewBlock(data, size, 0);
			if (block->Size > MAX_PACKET_SIZE)
			{
				FreeBlock(block);
			}
			else
			{
				InsertReceivedBlockToQueue(c, block, true);
			}

			num++;
			if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
			{
				break;
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		BRIDGE *b = c->Session->Bridge;

		// Bridge session
		if (b->Active)
		{
			void *data;
			UINT ret;
			UINT num = 0;
			bool check_device_num = false;
			UINT time = SELECT_TIME;
			UINT next_delay_packet_diff = 0;

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			// Bridge is operating
			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}

			if ((b->LastNumDeviceCheck + BRIDGE_NUM_DEVICE_CHECK_SPAN) <= Tick64())
			{
#ifdef	OS_WIN32
				check_device_num = true;
#endif	// OS_WIN32
				b->LastNumDeviceCheck = Tick64();
			}

			// Get the next packet from the bridge
			while (true)
			{
				if (check_device_num && b->LastNumDevice != GetEthDeviceHash())
				{
					ret = INFINITE;
				}
				else
				{
					ret = EthGetPacket(b->Eth, &data);
				}

#ifdef	OS_WIN32
				if (c->Session != NULL)
				{
					c->Session->BridgeIsEthLoopbackBlock = false;
					if (b->Eth != NULL && b->Eth->LoopbackBlock)
					{
						// Check whether The Ethernet device in the bridge
						// has the ability to block the loopback packet
						c->Session->BridgeIsEthLoopbackBlock = true;
					}
				}
#endif	// OS_WIN32

				if (ret == INFINITE)
				{
					// Error occured: stop the bridge
					CloseEth(b->Eth);
					b->Eth = NULL;
					b->Active = false;
					ReleaseCancel(s->Cancel2);
					s->Cancel2 = NULL;

					HLog(s->Hub, "LH_BRIDGE_2", s->Name, b->Name);
					Debug("Bridge Device Error.\n");

					break;
				}
				else if (ret == 0)
				{
					// There is no more packet to receive
					break;
				}
				else
				{
					if (hub != NULL && hub->Option != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
						b->Eth != NULL && IsDhcpPacketForSpecificMac(data, ret, b->Eth->MacAddress))
					{
						// DHCP Packet is filtered.
						Free(data);
					}
					else
					{
						// Add the packet to queue
						BLOCK *block = NewBlock(data, ret, 0);

						PROBE_DATA2("ConnectionReceive: NewBlock", data, ret);

						if (ret > 1514)
						{
							NormalizeEthMtu(b, c, ret);
						}

						if (block->Size > MAX_PACKET_SIZE)
						{
							// Packet size exceeded
							FreeBlock(block);
						}
						else
						{
							InsertReceivedBlockToQueue(c, block, true);
						}
						num++;
						if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
						{
	//						WHERE;
							break;
						}
					}
				}
			}
		}
		else
		{
			ETH *e;
			// Bridge is stopped currently
			Select(NULL, SELECT_TIME, c1, NULL);

			if (b->LastBridgeTry == 0 || (b->LastBridgeTry + BRIDGE_TRY_SPAN) <= Tick64())
			{
				b->LastBridgeTry = Tick64();

				// Try to open an Ethernet device
				e = OpenEth(b->Name, b->Local, b->TapMode, b->TapMacAddress);
				if (e != NULL)
				{
					// Success
					b->Eth = e;
					b->Active = true;
					b->LastNumDeviceCheck = Tick64();
					b->LastNumDevice = GetEthDeviceHash();

					// Update the NIC name of the bridge
#ifdef	OS_WIN32
					if (IsEmptyStr(e->Title) == false)
					{
						StrCpy(b->Name, sizeof(b->Name), e->Title);

						if (b->ParentLocalBridge != NULL)
						{
							StrCpy(b->ParentLocalBridge->DeviceName, sizeof(b->ParentLocalBridge->DeviceName), e->Title);
						}
					}
#endif	// OS_WIN32

					Debug("Bridge Open Succeed.\n");

					HLog(c->Session->Hub, "LH_BRIDGE_1", c->Session->Name, b->Name);

					s->Cancel2 = EthGetCancel(b->Eth);
				}
			}
		}
	}
}

// Normalize the MTU of the Ethernet device
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size)
{
	// Validate arguments
	if (packet_size == 0 || b == NULL || c == NULL)
	{
		return;
	}

	// Raise the MTU when the packet exceeds the current MTU
	if (EthIsChangeMtuSupported(b->Eth))
	{
		UINT currentMtu = EthGetMtu(b->Eth);
		if (currentMtu != 0)
		{
			if (packet_size > currentMtu)
			{
				bool ok = EthSetMtu(b->Eth, packet_size);

				if (ok)
				{
					HLog(c->Session->Hub, "LH_SET_MTU", c->Session->Name,
						b->Name, currentMtu, packet_size, packet_size);
				}
				else
				{
					UINT64 now = Tick64();

					if (b->LastChangeMtuError == 0 ||
						now >= (b->LastChangeMtuError + 60000ULL))
					{
						HLog(c->Session->Hub, "LH_SET_MTU_ERROR", c->Session->Name,
							b->Name, currentMtu, packet_size, packet_size);

						b->LastChangeMtuError = now;
					}
				}
			}
		}
	}
}

// Release of the block
void FreeBlock(BLOCK *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	Free(b->Buf);
	Free(b);
}

// Create a new block
BLOCK *NewBlock(void *data, UINT size, int compress)
{
	BLOCK *b;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	b = MallocFast(sizeof(BLOCK));

	b->RawFlagRetUdpAccel = 0;

	b->IsFlooding = false;

	b->PriorityQoS = b->Ttl = b->Param1 = 0;

	if (compress == 0)
	{
		// Uncompressed
		b->Compressed = FALSE;
		b->Buf = data;
		b->Size = size;
		b->SizeofData = size;
	}
	else if (compress == 1)
	{
		UINT max_size;

		// Compressed
		b->Compressed = TRUE;
		max_size = CalcCompress(size);
		b->Buf = MallocFast(max_size);
		b->Size = Compress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// Discard old data block
		Free(data);
	}
	else
	{
		// Expand
		UINT max_size;

		b->Compressed = FALSE;
		max_size = MAX_PACKET_SIZE;
		b->Buf = MallocFast(max_size);
		b->Size = Uncompress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		// Discard old data
		Free(data);
	}

	return b;
}

// Create a TCP socket
TCPSOCK *NewTcpSock(SOCK *s)
{
	TCPSOCK *ts;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	ts = ZeroMalloc(sizeof(TCPSOCK));

	ts->Sock = s;
	AddRef(s->ref);

	ts->RecvFifo = NewFifo();
	ts->SendFifo = NewFifo();
	ts->EstablishedTick = ts->LastRecvTime = ts->LastCommTime = Tick64();

	// Unset the time-out value
	SetTimeout(s, TIMEOUT_INFINITE);

	return ts;
}

// Release of TCP socket
void FreeTcpSock(TCPSOCK *ts)
{
	// Validate arguments
	if (ts == NULL)
	{
		return;
	}

	Disconnect(ts->Sock);
	ReleaseSock(ts->Sock);
	ReleaseFifo(ts->RecvFifo);
	ReleaseFifo(ts->SendFifo);

	if (ts->SendKey)
	{
		FreeCrypt(ts->SendKey);
	}
	if (ts->RecvKey)
	{
		FreeCrypt(ts->RecvKey);
	}

	Free(ts);
}

// Exit the tunneling mode of connection
void EndTunnelingMode(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Protocol
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		DisconnectTcpSockets(c);
	}
	else
	{
		// UDP
		DisconnectUDPSockets(c);
	}
}

// Shift the connection to tunneling mode
void StartTunnelingMode(CONNECTION *c)
{
	SOCK *s;
	TCP *tcp;
	TCPSOCK *ts;
	IP ip;
	UINT port;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	tcp = c->Tcp;

	// Protocol
	if (c->Protocol == CONNECTION_TCP)
	{
		// TCP
		s = c->FirstSock;

		if (c->IsInProc)
		{
			AddRef(s->ref);
			c->TubeSock = s;
		}

		ts = NewTcpSock(s);

		if (c->ServerMode == false)
		{
			if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
			{
				ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
			}
		}

		LockList(tcp->TcpSockList);
		{
			Add(tcp->TcpSockList, ts);
		}
		UnlockList(tcp->TcpSockList);
		ReleaseSock(s);
		c->FirstSock = NULL;
	}
	else
	{
		// UDP
		s = c->FirstSock;
		Copy(&ip, &s->RemoteIP, sizeof(IP));
		// May disconnect TCP connection at this point
		c->FirstSock = NULL;
		Disconnect(s);
		ReleaseSock(s);

		// Initialization of UDP structure
		c->Udp = ZeroMalloc(sizeof(UDP));

		if (c->ServerMode)
		{
			// Server mode
			// Add an UDP Entry
			AddUDPEntry(c->Cedar, c->Session);
			c->Udp->s = NULL;
		}
		else
		{
			port = c->Session->ClientOption->PortUDP;
			// Client mode
			c->Udp->s = NewUDP(0);
			// Write the IP address and port number
			Copy(&c->Udp->ip, &ip, sizeof(IP));
			c->Udp->port = port;
		}

		// Queue
		c->Udp->BufferQueue = NewQueue();
	}
}

// Generate a random value that depends on each machine
UINT GetMachineRand()
{
	char pcname[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];

	Zero(pcname, sizeof(pcname));
	GetMachineName(pcname, sizeof(pcname));

	Sha1(hash, pcname, StrLen(pcname));

	return READ_UINT(hash);
}

// Function that accepts a new connection
void ConnectionAccept(CONNECTION *c)
{
	SOCK *s;
	X *x;
	K *k;
	char tmp[128];
	UINT initial_timeout = CONNECTING_TIMEOUT;
	UCHAR ctoken_hash[SHA1_SIZE];

	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Zero(ctoken_hash, sizeof(ctoken_hash));

	// Get a socket
	s = c->FirstSock;
	AddRef(s->ref);

	Dec(c->Cedar->AcceptingSockets);

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	SLog(c->Cedar, "LS_CONNECTION_START_1", tmp, s->RemoteHostname, (IS_SPECIAL_PORT(s->RemotePort) ? 0 : s->RemotePort), c->Name);

	// Timeout setting
	initial_timeout += GetMachineRand() % (CONNECTING_TIMEOUT / 2);
	SetTimeout(s, initial_timeout);

	// Handle third-party protocols
	if (s->IsReverseAcceptedSocket == false && s->Type == SOCK_TCP)
	{
		if (c->Cedar != NULL && c->Cedar->Server != NULL)
		{
			PROTO *proto = c->Cedar->Server->Proto;
			if (proto && ProtoHandleConnection(proto, s, NULL) == true)
			{
				c->Type = CONNECTION_TYPE_OTHER;
				goto FINAL;
			}
		}
	}

	// Specify the encryption algorithm
	Lock(c->Cedar->lock);
	{
		if (c->Cedar->CipherList != NULL)
		{
			SetWantToUseCipher(s, c->Cedar->CipherList);
		}

		x = CloneX(c->Cedar->ServerX);
		k = CloneK(c->Cedar->ServerK);
	}
	Unlock(c->Cedar->lock);

	// Start the SSL communication
	Copy(&s->SslAcceptSettings, &c->Cedar->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));
	if (StartSSL(s, x, k) == false)
	{
		// Failed
		AddNoSsl(c->Cedar, &s->RemoteIP);
		Debug("ConnectionAccept(): StartSSL() failed\n");
		FreeX(x);
		FreeK(k);

		goto FINAL;
	}

	FreeX(x);
	FreeK(k);

	SLog(c->Cedar, "LS_SSL_START", c->Name, s->CipherName);

	Copy(c->CToken_Hash, ctoken_hash, SHA1_SIZE);

	// Accept the connection
	if (ServerAccept(c) == false)
	{
		// Failed
		Debug("ConnectionAccept(): ServerAccept() failed with error %u\n", c->Err);
	}

FINAL:
	if (c->flag1 == false)
	{
		Debug("%s %u c->flag1 == false\n", __FILE__, __LINE__);
		Disconnect(s);
	}

	DelConnection(c->Cedar, c);
	ReleaseSock(s);
}

// Stop the threads putting additional connection of all that are currently running
void StopAllAdditionalConnectThread(CONNECTION *c)
{
	UINT i, num;
	SOCK **socks;
	THREAD **threads;
	// Validate arguments
	if (c == NULL || c->ServerMode != false)
	{
		return;
	}

	// Disconnect the socket first
	LockList(c->ConnectingSocks);
	{
		num = LIST_NUM(c->ConnectingSocks);
		socks = ToArray(c->ConnectingSocks);
		DeleteAll(c->ConnectingSocks);
	}
	UnlockList(c->ConnectingSocks);
	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	// Then, wait for the suspension of the thread
	LockList(c->ConnectingThreads);
	{
		num = LIST_NUM(c->ConnectingThreads);
		Debug("c->ConnectingThreads: %u\n", num);
		threads = ToArray(c->ConnectingThreads);
		DeleteAll(c->ConnectingThreads);
	}
	UnlockList(c->ConnectingThreads);
	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	Free(threads);
}

// Stop the connection
void StopConnection(CONNECTION *c, bool no_wait)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Debug("Stop Connection: %s\n", c->Name);

	// Stop flag
	c->Halt = true;
	Disconnect(c->FirstSock);

	if (no_wait == false)
	{
		// Wait until the thread terminates
		WaitThread(c->Thread, INFINITE);
	}
}

// Close all the UDP socket
void DisconnectUDPSockets(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_UDP)
	{
		return;
	}

	// Delete entry
	if (c->ServerMode)
	{
		DelUDPEntry(c->Cedar, c->Session);
	}

	// Delete the UDP structure
	if (c->Udp != NULL)
	{
		if (c->Udp->s != NULL)
		{
			ReleaseSock(c->Udp->s);
		}
		if (c->Udp->BufferQueue != NULL)
		{
			// Release of the queue
			BUF *b;
			while (b = GetNext(c->Udp->BufferQueue))
			{
				FreeBuf(b);
			}
			ReleaseQueue(c->Udp->BufferQueue);
		}
		Free(c->Udp);
		c->Udp = NULL;
	}

	if (c->FirstSock != NULL)
	{
		Disconnect(c->FirstSock);
		ReleaseSock(c->FirstSock);
		c->FirstSock = NULL;
	}
}

// Close all TCP connections
void DisconnectTcpSockets(CONNECTION *c)
{
	UINT i, num;
	TCP *tcp;
	TCPSOCK **tcpsocks;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_TCP)
	{
		return;
	}

	tcp = c->Tcp;
	LockList(tcp->TcpSockList);
	{
		tcpsocks = ToArray(tcp->TcpSockList);
		num = LIST_NUM(tcp->TcpSockList);
		DeleteAll(tcp->TcpSockList);
	}
	UnlockList(tcp->TcpSockList);

	if (num != 0)
	{
		Debug("--- SOCKET STATUS ---\n");
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			Debug(" SOCK %2u: %u\n", i, ts->Sock->SendSize);
			FreeTcpSock(ts);
		}
	}

	Free(tcpsocks);
}

// Clean up of the connection
void CleanupConnection(CONNECTION *c)
{
	UINT i, num;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->LastRecvFifoTotalSize != 0)
	{
		CedarAddFifoBudget(c->Cedar, -((int)c->LastRecvFifoTotalSize));
		c->LastRecvFifoTotalSize = 0;
	}

	if (c->LastRecvBlocksNum != 0)
	{
		CedarAddQueueBudget(c->Cedar, -((int)c->LastRecvBlocksNum));
		c->LastRecvBlocksNum = 0;
	}

	if (c->LastTcpQueueSize != 0)
	{
		int diff = -((int)c->LastTcpQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastTcpQueueSize = 0;
	}

	if (c->LastPacketQueueSize != 0)
	{
		int diff = -((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = 0;
	}

	DeleteLock(c->lock);
	ReleaseCedar(c->Cedar);

	switch (c->Protocol)
	{
	case CONNECTION_TCP:
		// Release of TCP connection list
		DisconnectTcpSockets(c);
		break;

	case CONNECTION_UDP:
		break;
	}

	ReleaseList(c->Tcp->TcpSockList);
	Free(c->Tcp);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseSock(c->TubeSock);
	c->TubeSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	// Release all the receive block and send block
	if (c->SendBlocks)
	{
		LockQueue(c->SendBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	if (c->SendBlocks2)
	{
		LockQueue(c->SendBlocks2);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks2))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks2);
	}
	if (c->ReceivedBlocks)
	{
		LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->ReceivedBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->ReceivedBlocks);
	}

	if (c->ConnectingThreads)
	{
		THREAD **threads;
		LockList(c->ConnectingThreads);
		{
			num = LIST_NUM(c->ConnectingThreads);
			threads = ToArray(c->ConnectingThreads);
			for (i = 0;i < num;i++)
			{
				ReleaseThread(threads[i]);
			}
			Free(threads);
		}
		UnlockList(c->ConnectingThreads);
		ReleaseList(c->ConnectingThreads);
	}

	if (c->ConnectingSocks)
	{
		SOCK **socks;
		LockList(c->ConnectingSocks);
		{
			num = LIST_NUM(c->ConnectingSocks);
			socks = ToArray(c->ConnectingSocks);
			for (i = 0;i < num;i++)
			{
				Disconnect(socks[i]);
				ReleaseSock(socks[i]);
			}
			Free(socks);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseList(c->ConnectingSocks);
	}

	if (c->RecvBuf)
	{
		Free(c->RecvBuf);
	}

	if (c->ServerX != NULL)
	{
		FreeX(c->ServerX);
	}

	if (c->ClientX != NULL)
	{
		FreeX(c->ClientX);
	}

	ReleaseQueue(c->ReceivedBlocks);
	ReleaseQueue(c->SendBlocks);
	ReleaseQueue(c->SendBlocks2);

	DeleteCounter(c->CurrentNumConnection);

	if (c->CipherName != NULL)
	{
		Free(c->CipherName);
	}

	Free(c);
}

// Release of the connection
void ReleaseConnection(CONNECTION *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupConnection(c);
	}
}

// Comparison of connection
int CompareConnection(void *p1, void *p2)
{
	CONNECTION *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CONNECTION **)p1;
	c2 = *(CONNECTION **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

// Creating a server connection
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t)
{
	CONNECTION *c;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Type = CONNECTION_TYPE_INIT;
	c->FirstSock = s;
	if (s != NULL)
	{
		AddRef(c->FirstSock->ref);
		Copy(&c->ClientIp, &s->RemoteIP, sizeof(IP));
		StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	}
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = true;
	c->Status = CONNECTION_STATUS_ACCEPTED;
	c->Name = CopyStr("INITING");
	c->Thread = t;
	AddRef(t->ref);
	c->CurrentNumConnection = NewCounter();
	Inc(c->CurrentNumConnection);

	c->ServerVer = cedar->Version;
	c->ServerBuild = cedar->Build;
	StrCpy(c->ServerStr, sizeof(c->ServerStr), cedar->ServerStr);
	GetServerProductName(cedar->Server, c->ServerStr, sizeof(c->ServerStr));

	if (s != NULL && s->RemoteX != NULL)
	{
		c->ServerX = CloneX(s->RemoteX);
	}

	if (s != NULL && s->Type == SOCK_INPROC)
	{
		// In-process socket
		c->IsInProc = true;
	}

	// Creating a Queue
	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}

// Creating a Client Connection
CONNECTION *NewClientConnection(SESSION *s)
{
	return NewClientConnectionEx(s, NULL, 0, 0);
}
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build)
{
	CONNECTION *c;

	// Initialization of CONNECTION object
	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = s->Cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = false;
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Name = CopyStr("CLIENT_CONNECTION");
	c->Session = s;
	c->CurrentNumConnection = NewCounter();
	c->LastCounterResetTick = Tick64();
	Inc(c->CurrentNumConnection);

	c->ConnectingThreads = NewList(NULL);
	c->ConnectingSocks = NewList(NULL);

	if (client_str == NULL)
	{
		c->ClientVer = s->Cedar->Version;
		c->ClientBuild = s->Cedar->Build;

		if (c->Session->VirtualHost == false)
		{
			if (c->Session->LinkModeClient == false)
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_CLIENT_STR);
			}
			else
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_SERVER_LINK_STR);
			}
		}
		else
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_ROUTER_STR);
		}
	}
	else
	{
		c->ClientVer = client_ver;
		c->ClientBuild = client_build;
		StrCpy(c->ClientStr, sizeof(c->ClientStr), client_str);
	}

	// Server name and port number
	StrCpy(c->ServerName, sizeof(c->ServerName), s->ClientOption->Hostname);
	c->ServerPort = s->ClientOption->Port;

	// Create queues
	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}
