// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
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


// UdpAccel.c
// UDP acceleration function

#include "CedarPch.h"

// Polling process
void UdpAccelPoll(UDP_ACCEL *a)
{
	UCHAR *tmp = a->TmpBuf;
	IP nat_t_ip;
	UINT num_ignore_errors = 0;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

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
				// Receive a response of the query for IP and port number
				IP my_ip = {0};
				UINT myport = 0;
				BUF *b = MemToBuf(a->UdpIpQueryPacketData, a->UdpIpQueryPacketSize);


				FreeBuf(b);
			}
			else if (IsZeroIp(&nat_t_ip) == false && CmpIpAddr(&nat_t_ip, &src_ip) == 0 &&
				src_port == UDP_NAT_T_PORT)
			{
				// Receive a response from the NAT-T server
				IP my_ip;
				UINT myport;

				if (RUDPParseIPAndPortStr(tmp, ret, &my_ip, &myport))
				{
					if (myport >= 1 && myport <= 65535)
					{
						if (a->MyPortByNatTServer != myport)
						{
							a->MyPortByNatTServer = myport;
							a->MyPortByNatTServerChanged = true;
							a->CommToNatT_NumFail = 0;

							Debug("NAT-T: MyPort = %u\n", myport);
						}
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
	if (a->NextSendKeepAlive == 0 || (a->NextSendKeepAlive <= a->Now) || a->YourPortByNatTServerChanged)
	{
		a->YourPortByNatTServerChanged = false;

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

					if (a->MyPortByNatTServer != 0)
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

	UdpAccelSend(a, b->Buf, b->Size, b->Compressed, a->MaxUdpPacketSize, b->PriorityQoS);
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
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE;
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
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE;
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
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, bool compressed, UINT max_size, bool high_priority)
{
	UCHAR tmp[UDP_ACCELERATION_TMP_BUF_SIZE];
	UCHAR *buf;
	UINT size;
	UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE];
	UINT64 ui64;
	USHORT us;
	UCHAR c;
	UINT current_size;
	UINT ui32;
	bool fatal_error = false;
	UINT r;
	// Validate arguments
	if (a == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}
	if (max_size == 0)
	{
		max_size = INFINITE;
	}

	buf = tmp;
	size = 0;

	// IV
	if (a->PlainTextMode == false)
	{
		// IV
		Copy(buf, a->NextIv, UDP_ACCELERATION_PACKET_IV_SIZE);

		buf += UDP_ACCELERATION_PACKET_IV_SIZE;
		size += UDP_ACCELERATION_PACKET_IV_SIZE;

		// Calculate the key
		UdpAccelCalcKey(key, a->MyKey, a->NextIv);

		if (false)
		{
			char tmp1[256];
			char tmp2[256];
			char tmp3[256];
			BinToStr(tmp1, sizeof(tmp1), a->MyKey, sizeof(a->MyKey));
			BinToStr(tmp2, sizeof(tmp2), a->NextIv, UDP_ACCELERATION_PACKET_IV_SIZE);
			BinToStr(tmp3, sizeof(tmp3), key, sizeof(key));
			Debug("My Key  : %s\n"
				  "IV      : %s\n"
				  "Comm Key: %s\n",
				  tmp1, tmp2, tmp3);
		}
	}

	// Cookie
	ui32 = Endian32(a->YourCookie);
	Copy(buf, &ui32, sizeof(UINT));
	buf += sizeof(UINT);
	size += sizeof(UINT);

	// My Tick
	ui64 = Endian64(a->Now == 0 ? 1ULL : a->Now);
	Copy(buf, &ui64, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	// Your Tick
	ui64 = Endian64(a->LastRecvYourTick);
	Copy(buf, &ui64, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	// Size
	us = Endian16(data_size);
	Copy(buf, &us, sizeof(USHORT));
	buf += sizeof(USHORT);
	size += sizeof(USHORT);

	// Compress Flag
	c = (compressed ? 1 : 0);
	Copy(buf, &c, sizeof(UCHAR));
	buf += sizeof(UCHAR);
	size += sizeof(UCHAR);

	// Data
	if (data_size >= 1)
	{
		Copy(buf, data, data_size);
		buf += data_size;
		size += data_size;
	}

	if (a->PlainTextMode == false)
	{
		static UCHAR zero[UDP_ACCELERATION_PACKET_IV_SIZE] = {0};
		CRYPT *c;

		current_size = UDP_ACCELERATION_PACKET_IV_SIZE + sizeof(UINT) + sizeof(UINT64) * 2 +
			sizeof(USHORT) + sizeof(UCHAR) + data_size + UDP_ACCELERATION_PACKET_IV_SIZE;

		if (current_size < max_size)
		{
			// Padding
			UCHAR pad[UDP_ACCELERATION_MAX_PADDING_SIZE];
			UINT pad_size = MIN(max_size - current_size, UDP_ACCELERATION_MAX_PADDING_SIZE);
			pad_size = rand() % pad_size;

			Zero(pad, sizeof(pad));
			Copy(buf, pad, pad_size);
			buf += pad_size;
			size += pad_size;
		}

		// Verify
		Copy(buf, zero, UDP_ACCELERATION_PACKET_IV_SIZE);
		buf += UDP_ACCELERATION_PACKET_IV_SIZE;
		size += UDP_ACCELERATION_PACKET_IV_SIZE;

		// Encryption
		c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE);
		Encrypt(c, tmp + UDP_ACCELERATION_PACKET_IV_SIZE, tmp + UDP_ACCELERATION_PACKET_IV_SIZE, size - UDP_ACCELERATION_PACKET_IV_SIZE);
		FreeCrypt(c);

		// Next Iv
		Copy(a->NextIv, buf - UDP_ACCELERATION_PACKET_IV_SIZE, UDP_ACCELERATION_PACKET_IV_SIZE);
	}

	// Send
	SetSockHighPriority(a->UdpSock, high_priority);

	r = SendTo(a->UdpSock, &a->YourIp, a->YourPort, tmp, size);
	if (r == 0 && a->UdpSock->IgnoreSendErr == false)
	{
		fatal_error = true;
		Debug("Error: SendTo: %r %u %u\n", &a->YourIp, a->YourPort, size);
		WHERE;
	}

	if (data_size == 0)
	{
		if (UdpAccelIsSendReady(a, true) == false)
		{
			if ((a->YourPortByNatTServer != 0) && (a->YourPort != a->YourPortByNatTServer))
			{
				r = SendTo(a->UdpSock, &a->YourIp, a->YourPortByNatTServer, tmp, size);
				if (r == 0 && a->UdpSock->IgnoreSendErr == false)
				{
					fatal_error = true;
					WHERE;
				}
			}
		}
	}

	if (data_size == 0)
	{
		if (IsZeroIP(&a->YourIp2) == false && CmpIpAddr(&a->YourIp, &a->YourIp2) != 0)
		{
			if (UdpAccelIsSendReady(a, true) == false)
			{
				// When the KeepAlive, if the opponent may be behind a NAT,
				// send the packet to the IP address of outside of the NAT
				r = SendTo(a->UdpSock, &a->YourIp2, a->YourPort, tmp, size);
				if (r == 0 && a->UdpSock->IgnoreSendErr == false)
				{
					fatal_error = true;
					WHERE;
				}

				if ((a->YourPortByNatTServer != 0) && (a->YourPort != a->YourPortByNatTServer))
				{
					r = SendTo(a->UdpSock, &a->YourIp2, a->YourPortByNatTServer, tmp, size);
					if (r == 0 && a->UdpSock->IgnoreSendErr == false)
					{
						fatal_error = true;
						WHERE;
					}
				}
			}
		}
	}

	if (fatal_error)
	{
		a->FatalError = true;
		WHERE;
	}

	//Debug("UDP Send: %u\n", size);
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
	UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE];
	UCHAR *iv;
	CRYPT *c;
	UINT64 my_tick, your_tick;
	UINT inner_size;
	UCHAR *inner_data = NULL;
	UINT pad_size;
	UCHAR *verify;
	bool compress_flag;
	BLOCK *b = NULL;
	UINT cookie;
	// Validate arguments
	if (a == NULL || buf == NULL || size == 0 || src_ip == NULL)
	{
		return NULL;
	}

	if (a->PlainTextMode == false)
	{
		// IV
		if (size < UDP_ACCELERATION_PACKET_IV_SIZE)
		{
			return NULL;
		}
		iv = buf;
		buf += UDP_ACCELERATION_PACKET_IV_SIZE;
		size -= UDP_ACCELERATION_PACKET_IV_SIZE;

		// Calculate the key
		UdpAccelCalcKey(key, a->YourKey, iv);

		if (false)
		{
			char tmp1[256];
			char tmp2[256];
			char tmp3[256];
			BinToStr(tmp1, sizeof(tmp1), a->YourKey, sizeof(a->YourKey));
			BinToStr(tmp2, sizeof(tmp2), iv, UDP_ACCELERATION_PACKET_IV_SIZE);
			BinToStr(tmp3, sizeof(tmp3), key, sizeof(key));
			Debug("Your Key: %s\n"
				  "IV      : %s\n"
				  "Comm Key: %s\n",
				tmp1, tmp2, tmp3);
		}

		// Decryption
		c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE);
		Encrypt(c, buf, buf, size);
		FreeCrypt(c);
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

	// My Tick
	if (size < sizeof(UINT64))
	{
		return NULL;
	}
	my_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	// Your Tick
	if (size < sizeof(UINT64))
	{
		return NULL;
	}
	your_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	// inner_size
	if (size < sizeof(USHORT))
	{
		return NULL;
	}
	inner_size = READ_USHORT(buf);
	buf += sizeof(USHORT);
	size -= sizeof(USHORT);

	// compress_flag
	if (size < sizeof(UCHAR))
	{
		return NULL;
	}
	compress_flag = *((UCHAR *)buf);
	buf += sizeof(UCHAR);
	size -= sizeof(UCHAR);

	if (size < inner_size)
	{
		return NULL;
	}

	// inner_data
	if (inner_size >= 1)
	{
		inner_data = buf;
		buf += inner_size;
		size -= inner_size;
	}

	if (a->PlainTextMode == false)
	{
		// padding
		if (size < UDP_ACCELERATION_PACKET_IV_SIZE)
		{
			return false;
		}
		pad_size = size - UDP_ACCELERATION_PACKET_IV_SIZE;
		buf += pad_size;
		size -= pad_size;

		// verify
		if (size != UDP_ACCELERATION_PACKET_IV_SIZE)
		{
			return NULL;
		}

		verify = buf;

		if (IsZero(verify, UDP_ACCELERATION_PACKET_IV_SIZE) == false)
		{
			return NULL;
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
		b = NewBlock(Clone(inner_data, inner_size), inner_size, compress_flag ? -1 : 0);
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

// Calculate the key
void UdpAccelCalcKey(UCHAR *key, UCHAR *common_key, UCHAR *iv)
{
	UCHAR tmp[UDP_ACCELERATION_COMMON_KEY_SIZE + UDP_ACCELERATION_PACKET_IV_SIZE];
	// Validate arguments
	if (key == NULL || common_key == NULL || iv == NULL)
	{
		return;
	}

	Copy(tmp, common_key, UDP_ACCELERATION_COMMON_KEY_SIZE);
	Copy(tmp + UDP_ACCELERATION_COMMON_KEY_SIZE, iv, UDP_ACCELERATION_PACKET_IV_SIZE);

	HashSha1(key, tmp, sizeof(tmp));
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
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *client_key, IP *client_ip, UINT client_port, IP *client_ip_2)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (a == NULL || client_key == NULL)
	{
		return false;
	}

	IPToStr(tmp, sizeof(tmp), client_ip);
	Debug("UdpAccelInitServer: client_ip=%s, client_port=%u, server_cookie=%u, client_cookie=%u\n", tmp, client_port,
		a->MyCookie, a->YourCookie);

	if (IsIP6(client_ip) != a->IsIPv6)
	{
		return false;
	}

	Copy(a->YourKey, client_key, UDP_ACCELERATION_COMMON_KEY_SIZE);

	Copy(&a->YourIp, client_ip, sizeof(IP));
	Copy(&a->YourIp2, client_ip_2, sizeof(IP));
	a->YourPort = client_port;

	a->Now = Tick64();

	a->Inited = true;

	return true;
}

// Initialize the client-side
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *server_key, IP *server_ip, UINT server_port, UINT server_cookie, UINT client_cookie, IP *server_ip_2)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (a == NULL || server_key == NULL || server_ip == NULL || server_port == 0)
	{
		return false;
	}

	IPToStr(tmp, sizeof(tmp), server_ip);
	Debug("UdpAccelInitClient: server_ip=%s, server_port=%u, server_cookie=%u, client_cookie=%u\n", tmp, server_port, server_cookie, client_cookie);

	if (IsIP6(server_ip) != a->IsIPv6)
	{
		return false;
	}

	Copy(a->YourKey, server_key, UDP_ACCELERATION_COMMON_KEY_SIZE);

	Copy(&a->YourIp, server_ip, sizeof(IP));
	Copy(&a->YourIp2, server_ip_2, sizeof(IP));
	a->YourPort = server_port;

	a->Now = Tick64();

	a->MyCookie = client_cookie;
	a->YourCookie = server_cookie;

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


	a->NatT_TranId = Rand64();

	a->CreatedTick = Tick64();

	a->IsInCedarPortList = is_in_cedar_port_list;

	a->ClientMode = client_mode;

	a->Now = Tick64();
	a->UdpSock = s;
	Rand(a->MyKey, sizeof(a->MyKey));
	Rand(a->YourKey, sizeof(a->YourKey));

	Copy(&a->MyIp, ip, sizeof(IP));
	a->MyPort = s->LocalPort;

	a->IsIPv6 = IsIP6(ip);

	if (a->IsIPv6)
	{
		a->NoNatT = true;
	}

	a->RecvBlockQueue = NewQueue();

	Rand(a->NextIv, sizeof(a->NextIv));

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

	Free(a);
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
