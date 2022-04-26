// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// UdpAccel.c
// UDP acceleration function

#include "UdpAccel.h"

#include "Connection.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>

// Polling process
void UdpAccelPoll(UDP_ACCEL *a)
{
	IP nat_t_ip;
	UINT num_ignore_errors = 0;
	UCHAR *tmp;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	tmp = a->TmpBuf;

	Lock(a->NatT_Lock);
	{
		Copy(&nat_t_ip, &a->NatT_IP, sizeof(IP));
	}
	Unlock(a->NatT_Lock);

	if (IsZeroIp(&nat_t_ip) == false)
	{
		// Release the thread which gets the IP address of the NAT-T server because it is no longer needed
		if (a->NatT_GetIpThread != NULL)
		{
			WaitThread(a->NatT_GetIpThread, INFINITE);
			ReleaseThread(a->NatT_GetIpThread);
			a->NatT_GetIpThread = NULL;
		}
	}

	// Receive a new UDP packet
	while (true)
	{
		IP src_ip;
		UINT src_port;
		UINT ret;

		ret = RecvFrom(a->UdpSock, &src_ip, &src_port, tmp, UDP_ACCELERATION_TMP_BUF_SIZE);

		if (ret != 0 && ret != SOCK_LATER)
		{
			if (a->UseUdpIpQuery && a->UdpIpQueryPacketSize >= 8 && CmpIpAddr(&a->UdpIpQueryHost, &src_ip) == 0 &&
				src_port == a->UdpIpQueryPort)
			{
				/*
				// Receive a response of the query for IP and port number
				IP my_ip = {0};
				UINT myport = 0;
				BUF *b = MemToBuf(a->UdpIpQueryPacketData, a->UdpIpQueryPacketSize);
				FreeBuf(b);
				*/
			}
			else if (IsZeroIp(&nat_t_ip) == false && CmpIpAddr(&nat_t_ip, &src_ip) == 0 &&
				src_port == UDP_NAT_T_PORT)
			{
				// Receive a response from the NAT-T server
				IP ip;
				UINT port;
				if (RUDPParseIPAndPortStr(tmp, ret, &ip, &port))
				{
					if (a->MyPortNatT != port && port >= 1 && port <= 65535)
					{
						Debug("NAT-T: MyIP = %r, MyPort = %hu\n", &ip, port);

						a->CommToNatT_NumFail = 0;
						Copy(&a->MyIpNatT, &ip, sizeof(a->MyIpNatT));
						a->MyPortNatT = port;
						a->MyIpOrPortNatTChanged = true;
					}
				}
/*
				BUF *b = NewBuf();
				PACK *p;

				WriteBuf(b, tmp, ret);
				SeekBufToBegin(b);

				p = BufToPack(b);
				if (p != NULL)
				{
					if (PackCmpStr(p, "opcode", "query_for_nat_traversal"))
					{
						if (PackGetBool(p, "ok"))
						{
							if (PackGetInt64(p, "tran_id") == a->NatT_TranId)
							{
								UINT myport = PackGetInt(p, "your_port");

								if (myport >= 1 && myport <= 65535)
								{
									if (a->MyPortByNatTServer != myport)
									{
										a->MyPortByNatTServer = myport;
										a->MyPortByNatTServerChanged = true;

										Debug("NAT-T: MyPort = %u\n", myport);
									}
								}
							}
						}
					}

					FreePack(p);
				}

				FreeBuf(b);*/
			}
			else
			{
				BLOCK *b = UdpAccelProcessRecvPacket(a, tmp, ret, &src_ip, src_port);

				//Debug("UDP Recv: %u %u %u\n", ret, (b == NULL ? 0 : b->Size), (b == NULL ? 0 : b->Compressed));

				/*if (b != NULL)
				{
					char tmp[MAX_SIZE * 10];
					BinToStr(tmp, sizeof(tmp), b->Buf, b->Size);
					Debug("Recv Pkt: %s\n", tmp);
				}*/

				if (b != NULL)
				{
					// Receive a packet
					InsertQueue(a->RecvBlockQueue, b);
				}
			}
		}
		else
		{
			if (ret == 0)
			{
				if (a->UdpSock->IgnoreRecvErr == false)
				{
					// Serious UDP reception error occurs
					a->FatalError = true;
					break;
				}

				if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
				{
					a->FatalError = true;
					break;
				}
			}
			else
			{
				// SOCK_LATER
				break;
			}
		}
	}

	// Send a Keep-Alive packet
	if (a->NextSendKeepAlive == 0 || (a->NextSendKeepAlive <= a->Now) || a->YourIpOrPortNatTChanged)
	{
		a->YourIpOrPortNatTChanged = false;

		if (UdpAccelIsSendReady(a, false))
		{
			UINT rand_interval;

			if (a->FastDetect == false)
			{
				rand_interval = rand() % (UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX - UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN) + UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN;
			}
			else
			{
				rand_interval = rand() % (UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST - UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST) + UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST;
			}

			a->NextSendKeepAlive = a->Now + (UINT64)rand_interval;

			//Debug("UDP KeepAlive\n");

			UdpAccelSend(a, NULL, 0, false, 1000, false);
		}
	}

	// Send a NAT-T request packet (Only if the connection by UDP has not be established yet)
	if (a->NoNatT == false)
	{
		// In the usual case
		if (IsZeroIp(&nat_t_ip) == false)
		{
			if (UdpAccelIsSendReady(a, true) == false)
			{
				if (a->NextPerformNatTTick == 0 || (a->NextPerformNatTTick <= a->Now))
				{
					UINT rand_interval;
					UCHAR c = 'B';

					a->CommToNatT_NumFail++;
					
					rand_interval = UDP_NAT_T_INTERVAL_INITIAL * MIN(a->CommToNatT_NumFail, UDP_NAT_T_INTERVAL_FAIL_MAX);
					//PACK *p = NewPack();
					//BUF *b;

					if (a->MyPortNatT != 0)
					{
						rand_interval = GenRandInterval(UDP_NAT_T_INTERVAL_MIN, UDP_NAT_T_INTERVAL_MAX);
					}

					a->NextPerformNatTTick = a->Now + (UINT64)rand_interval;

					// Generate the request packet
					/*PackAddStr(p, "description", UDP_NAT_T_SIGNATURE);
					PackAddStr(p, "opcode", "query_for_nat_traversal");
					PackAddInt64(p, "tran_id", a->NatT_TranId);
					b = PackToBuf(p);
					FreePack(p);*/

					// Send the request packet
					SendTo(a->UdpSock, &nat_t_ip, UDP_NAT_T_PORT, &c, 1);

					//FreeBuf(b);
				}
			}
			else
			{
				a->NextPerformNatTTick = 0;
				a->CommToNatT_NumFail = 0;
			}
		}
	}
	else
	{
		// NAT_T is disabled, but there is a reference host (such as VGC)
		if (a->UseUdpIpQuery || a->UseSuperRelayQuery)
		{
		}
	}
}

// Send a packet block
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b)
{
	// Validate arguments
	if (a == NULL || b == NULL)
	{
		return;
	}

	UdpAccelSend(a, b->Buf, b->Size, b->Compressed ? 1 : 0, a->MaxUdpPacketSize, b->PriorityQoS);
}

// Calculate the best MSS
UINT UdpAccelCalcMss(UDP_ACCEL *a)
{
	UINT ret;

	// Validate arguments
	if (a == NULL)
	{
		return 0;
	}

	ret = MTU_FOR_PPPOE;

	// IPv4
	if (a->IsIPv6)
	{
		ret -= 40;
	}
	else
	{
		ret -= 20;
	}

	// UDP
	ret -= 8;

	if (a->PlainTextMode == false)
	{
		// IV
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;
	}

	// Cookie
	ret -= sizeof(UINT);

	// My Tick
	ret -= sizeof(UINT64);

	// Your Tick
	ret -= sizeof(UINT64);

	// Size
	ret -= sizeof(USHORT);

	// Compress Flag
	ret -= sizeof(UCHAR);

	if (a->PlainTextMode == false)
	{
		// Verify
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;
	}

	// Ethernet header (communication packets)
	ret -= 14;

	// IPv4 Header (communication packets)
	ret -= 20;

	// TCP header (communication packet)
	ret -= 20;

	return ret;
}

// Send
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size, bool high_priority)
{
	UCHAR buffer[UDP_ACCELERATION_TMP_BUF_SIZE];
	UCHAR *buf = buffer;
	UINT size = 0;
	UINT64 tmp;
	UINT ret;
	UINT u32;
	USHORT u16;
	// Validate arguments
	if (a == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}
	if (max_size == 0)
	{
		max_size = INFINITE;
	}

	if (a->PlainTextMode == false)
	{
		if (a->Version > 1)
		{
			Copy(buf, a->NextIv_V2, UDP_ACCELERATION_PACKET_IV_SIZE_V2);

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
		}
		else
		{
			Copy(buf, a->NextIv, UDP_ACCELERATION_PACKET_IV_SIZE_V1);

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
		}
	}

	// Cookie
	u32 = Endian32(a->YourCookie);
	Copy(buf, &u32, sizeof(UINT));
	buf += sizeof(UINT);
	size += sizeof(UINT);

	// My tick
	tmp = Endian64(a->Now == 0 ? 1ULL : a->Now);
	Copy(buf, &tmp, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	// Your tick
	tmp = Endian64(a->LastRecvYourTick);
	Copy(buf, &tmp, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	// Size
	u16 = Endian16(data_size);
	Copy(buf, &u16, sizeof(USHORT));
	buf += sizeof(USHORT);
	size += sizeof(USHORT);

	// Flag
	Copy(buf, &flag, sizeof(UCHAR));
	buf += sizeof(UCHAR);
	size += sizeof(UCHAR);

	// Data
	Copy(buf, data, data_size);
	buf += data_size;
	size += data_size;

	if (a->PlainTextMode == false)
	{
		// Add padding to make protocol identification harder to accomplish
		const UINT current_total_size = size + (a->Version > 1 ? UDP_ACCELERATION_PACKET_MAC_SIZE_V2 : UDP_ACCELERATION_PACKET_IV_SIZE_V1);
		if (current_total_size < max_size)
		{
			UCHAR pad[UDP_ACCELERATION_MAX_PADDING_SIZE];
			UINT pad_size = MIN(max_size - current_total_size, UDP_ACCELERATION_MAX_PADDING_SIZE);
			pad_size = rand() % pad_size;
			Zero(pad, sizeof(pad));
			Copy(buf, pad, pad_size);
			buf += pad_size;
			size += pad_size;
		}

		if (a->Version > 1)
		{
			const UINT inner_size = size - UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			UCHAR *inner = buffer + UDP_ACCELERATION_PACKET_IV_SIZE_V2;

			ret = CipherProcessAead(a->CipherEncrypt, a->NextIv_V2, inner + inner_size, UDP_ACCELERATION_PACKET_MAC_SIZE_V2, inner, inner, inner_size, NULL, 0);
			if (ret == 0)
			{
				Debug("UdpAccelSend(): CipherProcessAead() failed!\n");
				return;
			}

			Copy(a->NextIv_V2, inner, UDP_ACCELERATION_PACKET_IV_SIZE_V2);

			// Tag (appended to the buffer by CipherProcessAead())
			size += UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
		}
		else
		{
			UCHAR *inner = buffer + UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE_V1];
			const UINT inner_size = size; // We don't have to subtract because we add below
			CRYPT *c;

			// Simple integrity check system: we fill some bytes with zeroes.
			// The remote host verifies whether all the zeroes are present.
			Zero(buf, UDP_ACCELERATION_PACKET_IV_SIZE_V1);
			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V1;

			UdpAccelCalcKeyV1(key, a->MyKey, a->NextIv);

			c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE_V1);
			Encrypt(c, inner, inner, inner_size);
			FreeCrypt(c);

			Copy(a->NextIv, buf - UDP_ACCELERATION_PACKET_IV_SIZE_V1, UDP_ACCELERATION_PACKET_IV_SIZE_V1);
		}
	}

	SetSockHighPriority(a->UdpSock, high_priority);

	if (SendTo(a->UdpSock, &a->YourIp, a->YourPort, buffer, size) == 0)
	{
		Debug("UdpAccelSend(): SendTo() failed! IP: %r, port: %u, size: %u\n", &a->YourIp, a->YourPort, size);
		if (a->UdpSock->IgnoreSendErr == false)
		{
			a->FatalError = true;
			return;
		}
	}

	if (data_size > 0 || UdpAccelIsSendReady(a, true))
	{
		return;
	}

	Debug("UdpAccelSend(): Peer has not replied in a while, sending keep-alive packet to alt destinations...\n");

	IP *ips[3];
	ips[0] = &a->YourIp;
	ips[1] = CmpIpAddr(&a->YourIpReported, &a->YourIp) == 0 ? NULL : &a->YourIpReported;
	ips[2] = CmpIpAddr(&a->YourIpNatT, &a->YourIp) == 0 || CmpIpAddr(&a->YourIpNatT, &a->YourIpReported) == 0 ? NULL : &a->YourIpNatT;

	USHORT ports[3];
	ports[0] = a->YourPort;
	ports[1] = a->YourPortReported == a->YourPort ? 0 : a->YourPortReported;
	ports[2] = a->YourPortNatT == a->YourPort || a->YourPortNatT == a->YourPortReported ? 0 : a->YourPortNatT;

	for (BYTE i = 0; i < sizeof(ips) / sizeof(ips[0]); ++i)
	{
		if (IsZeroIP(ips[i]))
		{
			continue;
		}

		for (BYTE j = 0; j < sizeof(ports) / sizeof(ports[0]); ++j)
		{
			if (ports[j] == 0)
			{
				continue;
			}

			if (CmpIpAddr(ips[i], &a->YourIp) == 0 && ports[j] == a->YourPort)
			{
				continue;
			}

			if (SendTo(a->UdpSock, ips[i], ports[j], buffer, size) == 0)
			{
				Debug("UdpAccelSend(): SendTo() failed! IP: %r, port: %u, size: %u\n", ips[i], ports[j], size);
				if (a->UdpSock->IgnoreSendErr == false)
				{
					a->FatalError = true;
					return;
				}
			}

			if (UdpAccelIsSendReady(a, true))
			{
				break;
			}
		}
	}
}

// Determine whether transmission is possible
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive)
{
	UINT64 timeout_value;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	if (a->Inited == false)
	{
		return false;
	}

	if (a->YourPort == 0)
	{
		return false;
	}

	if (IsZeroIp(&a->YourIp))
	{
		return false;
	}

	timeout_value = UDP_ACCELERATION_KEEPALIVE_TIMEOUT;

	if (a->FastDetect)
	{
		timeout_value = UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST;
	}

	if (check_keepalive)
	{
		if (a->LastRecvTick == 0 || ((a->LastRecvTick + timeout_value) < a->Now))
		{
			a->FirstStableReceiveTick = 0;
			return false;
		}
		else
		{
			if ((a->FirstStableReceiveTick + (UINT64)UDP_ACCELERATION_REQUIRE_CONTINUOUS) <= a->Now)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

// Process the received packet
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port)
{
	UINT64 my_tick, your_tick;
	UINT inner_size;
	UCHAR *inner_data = NULL;
	bool compress_flag;
	UCHAR raw_flag;
	BLOCK *b = NULL;
	UINT cookie;
	// Validate arguments
	if (a == NULL || buf == NULL || size == 0 || src_ip == NULL)
	{
		return NULL;
	}

	if (a->PlainTextMode == false)
	{
		UCHAR *iv = buf;

		if (a->Version > 1)
		{
			UINT data_size;

			if (size < UDP_ACCELERATION_PACKET_IV_SIZE_V2)
			{
				return NULL;
			}

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			size -= UDP_ACCELERATION_PACKET_IV_SIZE_V2;

			if (size < UDP_ACCELERATION_PACKET_MAC_SIZE_V2)
			{
				return NULL;
			}

			data_size = size - UDP_ACCELERATION_PACKET_MAC_SIZE_V2;

			if (CipherProcessAead(a->CipherDecrypt, iv, buf + data_size, UDP_ACCELERATION_PACKET_MAC_SIZE_V2, buf, buf, data_size, NULL, 0) == 0)
			{
				Debug("UdpAccelProcessRecvPacket(): CipherProcessAead() failed!\n");
				return NULL;
			}

			size -= UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
		}
		else
		{
			UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE_V1];
			CRYPT *c;

			if (size < UDP_ACCELERATION_PACKET_IV_SIZE_V1)
			{
				return NULL;
			}

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;

			UdpAccelCalcKeyV1(key, a->YourKey, iv);

			c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE_V1);
			Encrypt(c, buf, buf, size);
			FreeCrypt(c);
		}
	}

	// Cookie
	if (size < sizeof(UINT))
	{
		return NULL;
	}
	cookie = READ_UINT(buf);
	buf += sizeof(UINT);
	size -= sizeof(UINT);

	if (cookie != a->MyCookie)
	{
		return NULL;
	}

	// My tick
	if (size < sizeof(UINT64))
	{
		return NULL;
	}
	my_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	// Your tick
	if (size < sizeof(UINT64))
	{
		return NULL;
	}
	your_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	// Inner data size
	if (size < sizeof(USHORT))
	{
		return NULL;
	}
	inner_size = READ_USHORT(buf);
	buf += sizeof(USHORT);
	size -= sizeof(USHORT);

	// Flag
	if (size < sizeof(UCHAR))
	{
		return NULL;
	}
	if (a->ReadRawFlagMode == false)
	{
		compress_flag = *((UCHAR *)buf);
	}
	else
	{
		raw_flag = *((UCHAR *)buf);
	}

	buf += sizeof(UCHAR);
	size -= sizeof(UCHAR);

	if (size < inner_size)
	{
		return NULL;
	}

	// Inner_data
	if (inner_size >= 1)
	{
		inner_data = buf;
		buf += inner_size;
		size -= inner_size;
	}

	if (a->PlainTextMode == false)
	{
		// Verify packet integrity
		if (a->Version == 1)
		{
			UINT pad_size;

			if (size < UDP_ACCELERATION_PACKET_IV_SIZE_V1)
			{
				return false;
			}

			pad_size = size - UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			buf += pad_size;
			size -= pad_size;

			if (size != UDP_ACCELERATION_PACKET_IV_SIZE_V1)
			{
				return NULL;
			}

			if (IsZero(buf, UDP_ACCELERATION_PACKET_IV_SIZE_V1) == false)
			{
				return NULL;
			}
		}
	}

	if (my_tick < a->LastRecvYourTick)
	{
		if ((a->LastRecvYourTick - my_tick) >= ((UINT64)UDP_ACCELERATION_WINDOW_SIZE_MSEC))
		{
			return NULL;
		}
	}

	a->LastRecvMyTick = MAX(a->LastRecvMyTick, your_tick);
	a->LastRecvYourTick = MAX(a->LastRecvYourTick, my_tick);

	if (inner_size >= 1)
	{
		b = NewBlock(Clone(inner_data, inner_size), inner_size, a->ReadRawFlagMode == false ? (compress_flag ? -1 : 0) : 0);
		if (a->ReadRawFlagMode)
		{
			b->RawFlagRetUdpAccel = raw_flag;
		}
	}

	if (a->LastSetSrcIpAndPortTick < a->LastRecvYourTick)
	{
		a->LastSetSrcIpAndPortTick = a->LastRecvYourTick;

		Copy(&a->YourIp, src_ip, sizeof(IP));
		a->YourPort = src_port;
	}

	if (a->LastRecvMyTick != 0)
	{
		if ((a->LastRecvMyTick + (UINT64)(UDP_ACCELERATION_WINDOW_SIZE_MSEC)) >= a->Now)
		{
			a->LastRecvTick = a->Now;

			a->IsReachedOnce = true;

			if (a->FirstStableReceiveTick == 0)
			{
				a->FirstStableReceiveTick = a->Now;
			}
		}
	}

	return b;
}

// Calculate V1 key
void UdpAccelCalcKeyV1(UCHAR *key, UCHAR *common_key, UCHAR *iv)
{
	UCHAR tmp[UDP_ACCELERATION_COMMON_KEY_SIZE_V1 + UDP_ACCELERATION_PACKET_IV_SIZE_V1];
	// Validate arguments
	if (key == NULL || common_key == NULL || iv == NULL)
	{
		return;
	}

	Copy(tmp, common_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
	Copy(tmp + UDP_ACCELERATION_COMMON_KEY_SIZE_V1, iv, UDP_ACCELERATION_PACKET_IV_SIZE_V1);

	Sha1(key, tmp, sizeof(tmp));
}

// Set the current time
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	a->Now = tick64;
}

// Initialize the server-side
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port)
{
	// Validate arguments
	if (a == NULL || key == NULL || detected_ip == NULL || port == 0)
	{
		return false;
	}

	Debug("UdpAccelInitServer(): Version: %u, detected_ip: %r, reported_ip: %r, port: %hu, YourCookie: %u, MyCookie: %u\n",
		  a->Version, detected_ip, reported_ip, port, a->YourCookie, a->MyCookie);

	if (IsIP6(detected_ip) != a->IsIPv6)
	{
		return false;
	}

	if (a->Version > 1)
	{
		a->CipherEncrypt = NewCipher("ChaCha20-Poly1305");
		a->CipherDecrypt = NewCipher("ChaCha20-Poly1305");

		SetCipherKey(a->CipherEncrypt, a->MyKey_V2, true);
		SetCipherKey(a->CipherDecrypt, key, false);
	}
	else
	{
		Copy(a->YourKey, key, sizeof(a->YourKey));
	}

	Copy(&a->YourIp, detected_ip, sizeof(a->YourIp));
	Copy(&a->YourIpReported, reported_ip, sizeof(a->YourIpReported));

	a->YourPort = a->YourPortReported = port;

	a->Now = Tick64();

	a->Inited = true;

	return true;
}

// Initialize the client-side
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port, UINT cookie, UINT my_cookie)
{
	// Validate arguments
	if (a == NULL || key == NULL || detected_ip == NULL || port == 0)
	{
		return false;
	}

	Debug("UdpAccelInitClient(): Version: %u, detected_ip: %s, reported_ip: %s, port: %hu, cookie: %u, my_cookie: %u\n",
		  a->Version, detected_ip, reported_ip, port, cookie, my_cookie);

	if (IsIP6(detected_ip) != a->IsIPv6)
	{
		return false;
	}

	if (a->Version > 1)
	{
		a->CipherEncrypt = NewCipher("ChaCha20-Poly1305");
		a->CipherDecrypt = NewCipher("ChaCha20-Poly1305");

		SetCipherKey(a->CipherEncrypt, a->MyKey_V2, true);
		SetCipherKey(a->CipherDecrypt, key, false);
	}
	else
	{
		Copy(a->YourKey, key, sizeof(a->YourKey));
	}

	Copy(&a->YourIp, detected_ip, sizeof(a->YourIp));
	Copy(&a->YourIpReported, reported_ip, sizeof(a->YourIpReported));

	a->YourPort = a->YourPortReported = port;

	a->Now = Tick64();

	a->MyCookie = my_cookie;
	a->YourCookie = cookie;

	a->Inited = true;

	return true;
}

// Create a new UDP acceleration function
UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port, bool no_nat_t)
{
	UDP_ACCEL *a;
	SOCK *s;
	UINT max_udp_size;
	bool is_in_cedar_port_list = false;

	if (IsZeroIP(ip))
	{
		ip = NULL;
	}

	if (client_mode || random_port)
	{
		// Use a appropriate vacant port number in the case of using random port or client mode
		s = NewUDPEx3(0, ip);
	}
	else
	{
		// Specify in the range in the case of server mode
		UINT i;
		s = NULL;

		LockList(cedar->UdpPortList);
		{
			for (i = UDP_SERVER_PORT_LOWER;i <= UDP_SERVER_PORT_HIGHER;i++)
			{
				if (IsIntInList(cedar->UdpPortList, i) == false)
				{
					s = NewUDPEx3(i, ip);

					if (s != NULL)
					{
						is_in_cedar_port_list = true;
						break;
					}
				}
			}

			if (s == NULL)
			{
				// Leave the port selection to the OS because the available port is not found within the range
				s = NewUDPEx3(0, ip);
			}

			if (s != NULL && is_in_cedar_port_list)
			{
				AddIntDistinct(cedar->UdpPortList, i);
			}
		}
		UnlockList(cedar->UdpPortList);
	}

	if (s == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(UDP_ACCEL));

	a->Cedar = cedar;
	AddRef(a->Cedar->ref);

	a->NoNatT = no_nat_t;

	a->Version = 1;

	a->NatT_TranId = Rand64();

	a->CreatedTick = Tick64();

	a->IsInCedarPortList = is_in_cedar_port_list;

	a->ClientMode = client_mode;

	a->Now = Tick64();
	a->UdpSock = s;

	Rand(a->MyKey, sizeof(a->MyKey));
	Rand(a->MyKey_V2, sizeof(a->MyKey_V2));

	Copy(&a->MyIp, ip, sizeof(a->MyIp));
	a->MyPort = s->LocalPort;

	a->IsIPv6 = IsIP6(ip);

	if (a->IsIPv6)
	{
		a->NoNatT = true;
	}

	a->RecvBlockQueue = NewQueue();

	Rand(a->NextIv, sizeof(a->NextIv));
	Rand(a->NextIv_V2, sizeof(a->NextIv_V2));

	do
	{
		a->MyCookie = Rand32();
	}
	while (a->MyCookie == 0);

	do
	{
		a->YourCookie = Rand32();
	}
	while (a->MyCookie == 0 || a->MyCookie == a->YourCookie);

	// Calculate the maximum transmittable UDP packet size
	max_udp_size = MTU_FOR_PPPOE;

	if (a->IsIPv6 == false)
	{
		// IPv4
		max_udp_size -= 20;
	}
	else
	{
		// IPv6
		max_udp_size -= 40;
	}

	// UDP
	max_udp_size -= 8;

	a->MaxUdpPacketSize = max_udp_size;

	Debug("Udp Accel My Port = %u\n", a->MyPort);

	// Initialize the NAT-T server IP address acquisition thread
	a->NatT_Lock = NewLock();
	a->NatT_HaltEvent = NewEvent();

	if (a->NoNatT == false)
	{
		a->NatT_GetIpThread = NewThread(NatT_GetIpThread, a);
	}

	return a;
}

// NAT-T server IP address acquisition thread
void NatT_GetIpThread(THREAD *thread, void *param)
{
	UDP_ACCEL *a;
	char hostname[MAX_SIZE];
	static IP dummy_ip = {0};
	UINT num_retry = 0;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	a = (UDP_ACCEL *)param;

	if (IsZeroIP(&dummy_ip))
	{
		SetIP(&dummy_ip, 11, Rand8(), Rand8(), Rand8());
	}

	RUDPGetRegisterHostNameByIP(hostname, sizeof(hostname), &dummy_ip);

	while (a->NatT_Halt == false)
	{
		IP ip;
		UINT wait_time = UDP_NAT_T_GET_IP_INTERVAL;

		// Get the IP address
		bool ret = GetIP4Ex(&ip, hostname, 0, &a->NatT_Halt);

		if (ret && (IsZeroIp(&ip) == false))
		{
			char tmp[128];

			// Success to get
			Lock(a->NatT_Lock);
			{
				Copy(&a->NatT_IP, &ip, sizeof(IP));
			}
			Unlock(a->NatT_Lock);

			IPToStr(tmp, sizeof(tmp), &ip);
			Debug("NAT-T IP Address Resolved: %s = %s\n", hostname, tmp);

			a->NatT_IP_Changed = true;

			break;
		}

		// Fail to get
		num_retry++;

		wait_time = (UINT)(MIN((UINT64)UDP_NAT_T_GET_IP_INTERVAL * (UINT64)num_retry, (UINT64)UDP_NAT_T_GET_IP_INTERVAL_MAX));

		Wait(a->NatT_HaltEvent, wait_time);
	}
}

// Release the UDP acceleration function
void FreeUdpAccel(UDP_ACCEL *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	while (true)
	{
		BLOCK *b = GetNext(a->RecvBlockQueue);

		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(a->RecvBlockQueue);

	ReleaseSock(a->UdpSock);

	if (a->IsInCedarPortList)
	{
		LockList(a->Cedar->UdpPortList);
		{
			DelInt(a->Cedar->UdpPortList, a->MyPort);
		}
		UnlockList(a->Cedar->UdpPortList);
	}

	// Release of NAT-T related
	a->NatT_Halt = true;
	Set(a->NatT_HaltEvent);

	if (a->NatT_GetIpThread != NULL)
	{
		WaitThread(a->NatT_GetIpThread, INFINITE);
		ReleaseThread(a->NatT_GetIpThread);
	}

	ReleaseEvent(a->NatT_HaltEvent);
	DeleteLock(a->NatT_Lock);

	ReleaseCedar(a->Cedar);

	FreeCipher(a->CipherEncrypt);
	FreeCipher(a->CipherDecrypt);

	Free(a);
}
