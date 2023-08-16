// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_PPP.c
// PPP protocol stack

#include "Proto_PPP.h"

#include "Account.h"
#include "Cedar.h"
#include "Connection.h"
#include "Hub.h"
#include "IPC.h"
#include "Logging.h"
#include "Radius.h"
#include "Server.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

// PPP main thread
void PPPThread(THREAD *thread, void *param)
{
	PPP_SESSION *p = (PPP_SESSION *)param;
	UINT i;
	USHORT next_protocol = 0;
	bool ret = false;
	char ipstr1[128], ipstr2[128];
	bool authReqSent = false;

	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Initialize

	Debug("PPP Initialize");

	PPPSetStatus(p, PPP_STATUS_CONNECTED);

	p->Eap_Protocol = PPP_UNSPECIFIED;

	p->Mru1 = p->Mru2 = PPP_MRU_DEFAULT;
	p->RecvPacketList = NewList(NULL);
	p->SentReqPacketList = NewList(NULL);
	p->DelayedPackets = NewList(PPPDelayedPacketsComparator);

	p->UseEapRadius = CedarIsThereAnyEapEnabledRadiusConfig(p->Cedar);

	Debug("UseEapRadius = 0x%x\n", p->UseEapRadius);

	//// Link establishment phase

	Debug("PPP Link establishment phase\n");

	IPToStr(ipstr1, sizeof(ipstr1), &p->ClientIP);
	IPToStr(ipstr2, sizeof(ipstr2), &p->ServerIP);
	PPPLog(p, "LP_CONNECTED", p->Postfix, ipstr1, p->ClientHostname, p->ClientPort, ipstr2, p->ServerPort,
	       p->ClientSoftwareName, p->AdjustMss);

	// We need that so we don't time out on connection immediately
	p->LastRecvTime = Tick64();

	Debug("PPP starting main dataloop\n");

	// Dataloop active if the receiving tube is still connected
	while (true)
	{
		PPP_LCP *lcp;
		bool receivedPacketProcessed = false;
		TUBE *tubes[2];
		UINT r;
		UINT64 now = Tick64();

		PPPGetNextPacket(p);

		if (p->CurrentPacket != NULL)
		{
			// First we process any possible unsupported packets
			receivedPacketProcessed = PPPRejectUnsupportedPacket(p, p->CurrentPacket);

			// Now do some basic processing
			if (receivedPacketProcessed == false && p->CurrentPacket->IsControl && p->CurrentPacket->Protocol == PPP_PROTOCOL_LCP)
			{
				if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_ECHO_REQUEST && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
				{
					// Immediately return the echo response to the echo request
					PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));

					pp2->IsControl = true;
					pp2->Protocol = PPP_PROTOCOL_LCP;
					pp2->Lcp = NewPPPLCP(PPP_LCP_CODE_ECHO_RESPONSE, p->CurrentPacket->Lcp->Id);
					pp2->Lcp->Data = Clone(p->CurrentPacket->Lcp->Data, p->CurrentPacket->Lcp->DataSize);
					pp2->Lcp->DataSize = p->CurrentPacket->Lcp->DataSize;

					if (PPPSendPacketAndFree(p, pp2) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
					}

					receivedPacketProcessed = true;
				}
				else if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_ECHO_RESPONSE && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
				{
					receivedPacketProcessed = true;
					// Ignore the Echo response packet
				}
				else if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_DROP && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
				{
					receivedPacketProcessed = true;
					// Ignore the Drop packet
				}
				else if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_IDENTIFICATION && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
				{
					receivedPacketProcessed = true;
					// Ignore the Identification packet
					WHERE;
				}
				else if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_TERMINATE_REQ)
				{
					PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));;
					receivedPacketProcessed = true;
					// Return the Terminate ACK If a Terminate Request has been received

					pp2->IsControl = true;
					pp2->Protocol = PPP_PROTOCOL_LCP;
					pp2->Lcp = NewPPPLCP(PPP_LCP_CODE_TERMINATE_ACK, p->CurrentPacket->Lcp->Id);
					pp2->Lcp->Data = Clone(p->CurrentPacket->Lcp->Data, p->CurrentPacket->Lcp->DataSize);
					pp2->Lcp->DataSize = p->CurrentPacket->Lcp->DataSize;

					p->IsTerminateReceived = true;

					if (PPPSendPacketAndFree(p, pp2) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
					}
					else
					{
						SleepThread(100);
						PPPSetStatus(p, PPP_STATUS_CLOSED);
					}
				}
				else if (p->CurrentPacket->Lcp->Code == PPP_LCP_CODE_TERMINATE_ACK)
				{
					PPPSetStatus(p, PPP_STATUS_CLOSED);
				}
			}

			// Process responses
			if (receivedPacketProcessed == false && p->CurrentPacket != NULL && p->CurrentPacket->IsControl && PPP_CODE_IS_RESPONSE(p->CurrentPacket->Protocol, p->CurrentPacket->Lcp->Code) && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
			{
				PPP_PACKET *request = NULL;
				// Removing from resend list
				for (i = 0; i < LIST_NUM(p->SentReqPacketList); i++)
				{
					PPP_REQUEST_RESEND *t = LIST_DATA(p->SentReqPacketList, i);

					if (t->Id == p->CurrentPacket->Lcp->Id)
					{
						request = t->Packet;
						Delete(p->SentReqPacketList, t);
						Free(t);
						break;
					}
				}
				PPPProcessResponsePacket(p, p->CurrentPacket, request);
				FreePPPPacket(request);
				receivedPacketProcessed = true;
			}

			// Process requests
			if (receivedPacketProcessed == false && p->CurrentPacket != NULL && p->CurrentPacket->IsControl && PPP_CODE_IS_REQUEST(p->CurrentPacket->Protocol, p->CurrentPacket->Lcp->Code) && PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false)
			{
				PPPProcessRequestPacket(p, p->CurrentPacket);
				receivedPacketProcessed = true;
			}

			// Process data packets, discarded before we got any links up
			if (receivedPacketProcessed == false && p->CurrentPacket != NULL && p->CurrentPacket->IsControl == false && p->PPPStatus == PPP_STATUS_NETWORK_LAYER && p->Ipc != NULL)
			{
				UINT64 timeBeforeLoop = Tick64();
				while (true)
				{
					UINT64 nowL;
					// Here client to server
					if (p->CurrentPacket->Protocol == PPP_PROTOCOL_IP &&
					        IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_OPENED)
					{
						receivedPacketProcessed = true;
						IPCSendIPv4(p->Ipc, p->CurrentPacket->Data, p->CurrentPacket->DataSize);
					}
					else if (p->CurrentPacket->Protocol == PPP_PROTOCOL_IP)
					{
						Debug("Got IPv4 packet before IPv4 ready!\n");
					}
					else if (p->CurrentPacket->Protocol == PPP_PROTOCOL_IPV6 &&
					         IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_OPENED)
					{
						receivedPacketProcessed = true;
						IPCIPv6Send(p->Ipc, p->CurrentPacket->Data, p->CurrentPacket->DataSize);
					}
					else if (p->CurrentPacket->Protocol == PPP_PROTOCOL_IPV6)
					{
						Debug("Got IPv6 packet before IPv6 ready!\n");
					}

					// Let's break out of the loop once in a while so we don't get stuck here endlessly
					nowL = Tick64();
					if (nowL > timeBeforeLoop + PPP_PACKET_RESEND_INTERVAL)
					{
						break;
					}

					PPPGetNextPacket(p);
					if (p->CurrentPacket == NULL)
					{
						break;
					}
					// Making sure we got a correctly parsed packet by rejecting all invalid ones
					if (PPPRejectUnsupportedPacket(p, p->CurrentPacket))
					{
						break;
					}
					if (p->CurrentPacket->IsControl || p->PPPStatus != PPP_STATUS_NETWORK_LAYER || p->Ipc == NULL)
					{
						PPPAddNextPacket(p, p->CurrentPacket, 0);
						p->CurrentPacket = NULL;
						break;
					}
				}
			}

			if (receivedPacketProcessed == false && p->CurrentPacket != NULL)
			{
				Debug("Unprocessed and unrejected packet, protocol = 0x%x\n", p->CurrentPacket->Protocol);
			}
		}
		else if (p->PPPStatus == PPP_STATUS_BEFORE_AUTH && p->AuthProtocol == PPP_PROTOCOL_EAP)
		{
			PPP_LCP *lcpEap;
			PPP_EAP *eapPacket;
			UCHAR *welcomeMessage = "Welcome to the SoftEther VPN server!";
			UCHAR flags = PPP_EAP_TLS_FLAG_NONE;
			// We got to start EAP when we got no LCP packets from the client on previous iteration
			// which means we parsed all the client requests and responses

			switch (p->Eap_Protocol)
			{
			case PPP_EAP_TYPE_TLS:
				// Sending TLS Start...
				flags |= PPP_EAP_TLS_FLAG_SSLSTARTED;
				p->Eap_PacketId = p->NextId++;
				lcpEap = BuildEAPTlsRequest(p->Eap_PacketId, 0, flags);
				PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);
				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcpEap) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					break;
				}
				break;
			case PPP_EAP_TYPE_MSCHAPV2:
				// Sending challenge
				p->Eap_PacketId = p->NextId; // Do not increase NextId so that MSCHAPv2 could use the same id
				lcp = BuildMSCHAP2ChallengePacket(p);
				BUF *b = BuildLCPData(lcp);
				FreePPPLCP(lcp);
				lcpEap = BuildEAPPacketEx(PPP_EAP_CODE_REQUEST, p->Eap_PacketId, PPP_EAP_TYPE_MSCHAPV2, b->Size);
				eapPacket = lcpEap->Data;
				Copy(eapPacket->Data, b->Buf, b->Size);
				FreeBuf(b);
				PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);
				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcpEap) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					break;
				}
				break;
			case PPP_EAP_TYPE_IDENTITY:
			default: // We treat the unspecified protocol as the IDENTITY protocol
				p->Eap_Protocol = PPP_EAP_TYPE_IDENTITY;
				p->Eap_PacketId = p->NextId++;
				lcpEap = BuildEAPPacketEx(PPP_EAP_CODE_REQUEST, p->Eap_PacketId, PPP_EAP_TYPE_IDENTITY, StrLen(welcomeMessage) + 1);
				eapPacket = lcpEap->Data;
				Copy(eapPacket->Data, welcomeMessage, StrLen(welcomeMessage));
				PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);
				PPPFreeEapClient(p);
				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcpEap) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					break;
				}
				break;
			}
		}
		else if (p->PPPStatus == PPP_STATUS_BEFORE_AUTH && p->AuthProtocol == PPP_PROTOCOL_CHAP)
		{
			// We got to start CHAP when we got no LCP packets from the client on previous iteration
			// which means we parsed all the client requests and responses
			Debug("Starting PPP Authentication phase MS-CHAP v2\n");

			lcp = BuildMSCHAP2ChallengePacket(p);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_CHAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
			}

			PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);
		}

		if (p->PPPStatus == PPP_STATUS_CONNECTED && authReqSent == false)
		{
			// EAP code
			PPP_LCP *c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
			USHORT eap_code = Endian16(PPP_LCP_AUTH_EAP);

			Debug("Request EAP\n");
			Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &eap_code, sizeof(eap_code)));
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, c) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
			}
			authReqSent = true;
		}

		if (p->PPPStatus == PPP_STATUS_AUTHENTICATING)
		{
			//Debug("Tick waiting for auth...\n");
		}

		if (p->PPPStatus == PPP_STATUS_AUTH_FAIL)
		{
			Debug("PPP auth failed, giving up\n");
			p->DisconnectCauseCode = 15;
			p->DisconnectCauseDirection = 1;
			PPPSetStatus(p, PPP_STATUS_CLOSING);
		}

		if (p->PPPStatus == PPP_STATUS_NETWORK_LAYER)
		{
			UINT64 timeBeforeLoop;
			if (IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_OPENED)
			{
				if (p->DhcpAllocated)
				{
					if (now >= p->DhcpNextRenewTime)
					{
						IP ip;

						// DHCP renewal procedure
						p->DhcpNextRenewTime = now + p->DhcpRenewInterval;

						UINTToIP(&ip, p->ClientAddressOption.ServerAddress);

						IPCDhcpRenewIP(p->Ipc, &ip);
					}
				}
			}

			IPCProcessL3Events(p->Ipc);

			timeBeforeLoop = Tick64();

			while (true)
			{
				UINT64 nowL;
				bool no4packets = false;
				bool no6packets = false;
				if (IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_OPENED)
				{
					BLOCK *b = IPCRecvIPv4(p->Ipc);
					if (b == NULL)
					{
						no4packets = true;
					}
					else
					{
						PPP_PACKET *pp;
						PPP_PACKET tmp;

						// Since receiving the IP packet, send it to the client by PPP
						pp = &tmp;
						pp->IsControl = false;
						pp->Protocol = PPP_PROTOCOL_IP;
						pp->Lcp = NULL;
						pp->Data = b->Buf;
						pp->DataSize = b->Size;

						PPPSendPacketEx(p, pp, true);

						FreePPPPacketEx(pp, true);
						Free(b); // Not FreeBlock because freed in FreePPPPacketEx
					}
				}
				else
				{
					no4packets = true;
				}

				if (IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_OPENED)
				{
					BLOCK *b = IPCIPv6Recv(p->Ipc);
					if (b == NULL)
					{
						no6packets = true;
					}
					else
					{
						PPP_PACKET *pp;
						PPP_PACKET tmp;

						// Since receiving the IP packet, send it to the client by PPP
						pp = &tmp;
						pp->IsControl = false;
						pp->Protocol = PPP_PROTOCOL_IPV6;
						pp->Lcp = NULL;
						pp->Data = b->Buf;
						pp->DataSize = b->Size;

						PPPSendPacketEx(p, pp, true);

						FreePPPPacketEx(pp, true);
						Free(b); // Not FreeBlock because freed in FreePPPPacketEx
					}
				}
				else
				{
					no6packets = true;
				}

				// Let's break out of the loop once in a while so we don't get stuck here endlessly
				nowL = Tick64();
				if (nowL > timeBeforeLoop + PPP_PACKET_RESEND_INTERVAL || (no4packets && no6packets))
				{
					break;
				}
			}

			FlushTubeFlushList(p->FlushList);
		}

		if (p->PPPStatus == PPP_STATUS_AUTH_SUCCESS)
		{
			Debug("PPP auth success, ready for network layer on next tick\n");
			p->AuthOk = true;
			PPPSetStatus(p, PPP_STATUS_NETWORK_LAYER);
		}

		if ((p->PPPStatus == PPP_STATUS_CLOSING || p->PPPStatus == PPP_STATUS_FAIL) && IsTubeConnected(p->TubeRecv) && IsTubeConnected(p->TubeSend))
		{
			Debug("Trying to cleanly close the connection, status = 0x%x\n", p->PPPStatus);
			PPPSetStatus(p, PPP_STATUS_CLOSING_WAIT);
			lcp = NewPPPLCP(PPP_LCP_CODE_TERMINATE_REQ, 0);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
			}
		}

		if (PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false || p->PPPStatus == PPP_STATUS_CLOSING_WAIT)
		{
			PPPProcessRetransmissions(p);
			PPPSendEchoRequest(p);
		}

		tubes[0] = p->TubeRecv;

		if (p->PPPStatus == PPP_STATUS_NETWORK_LAYER && p->Ipc != NULL && IsIPCConnected(p->Ipc))
		{
			r = GetNextIntervalForInterrupt(p->Ipc->Interrupt);
			tubes[1] = p->Ipc->Sock->RecvTube;
			WaitForTubes(tubes, 2, MIN(r, PPP_PACKET_RESEND_INTERVAL));
		}
		else
		{
			WaitForTubes(tubes, 1, 300); // Increasing timeout to make the ticks a bit slower
		}

		if (IsTubeConnected(p->TubeRecv) == false || IsTubeConnected(p->TubeSend) == false)
		{
			// Higher-level protocol is disconnected
			PPPLog(p, "LP_UPPER_PROTOCOL_DISCONNECTED", p->Postfix);
			break;
		}

		if (IsIPCConnected(p->Ipc) == false && p->PPPStatus == PPP_STATUS_NETWORK_LAYER)
		{
			// IPC VPN session is disconnected
			PPPLog(p, "LP_VPN_SESSION_TERMINATED");
			break;
		}

		// Time-out inspection
		if ((p->LastRecvTime + (UINT64)p->DataTimeout) <= now)
		{
			// Communication time-out occurs
			PPPLog(p, "LP_DATA_TIMEOUT");
			break;
		}

		// Maximum PPP session time of the user reached inspection
		if (p->UserConnectionTick != 0 && p->UserConnectionTimeout != 0 &&
		        p->UserConnectionTick + p->UserConnectionTimeout <= now)
		{
			// User connection time-out occurs
			PPPLog(p, "LP_USER_TIMEOUT");
			break;
		}

		// Terminate if the PPP disconnected
		if (p->IsTerminateReceived)
		{
			PPPLog(p, "LP_NORMAL_TERMINATE");
			break;
		}

		if (p->PPPStatus == PPP_STATUS_FAIL || p->PPPStatus == PPP_STATUS_CLOSED)
		{
			Debug("Exiting main dataloop, status = 0x%x\n", p->PPPStatus);
			break;
		}
	}

	Debug("Exited main dataloop, status = 0x%x\n", p->PPPStatus);

	if (p->PPPStatus != PPP_STATUS_FAIL)
	{
		IP ip;
		char tmp[MAX_SIZE];

		// Disconnected normally
		PPPLog(p, "LP_DISCONNECTED");

		if (p != NULL && p->DhcpAllocated && IsIPCConnected(p->Ipc) && p->ClientAddressOption.ServerAddress != 0)
		{
			// If any address is assigned from the DHCP, release it
			UINTToIP(&ip, p->ClientAddressOption.ServerAddress);

			IPToStr(tmp, sizeof(tmp), &ip);
			Debug("Releasing IP Address from DHCP Server %s...\n", tmp);

			IPCDhcpFreeIP(p->Ipc, &ip);
			IPCProcessL3Events(p->Ipc);

			SleepThread(300);
		}
	}
	else
	{
		PPPLog(p, "LP_DISCONNECTED_ABNORMAL");
	}

	FreePPPSession(p);
	Debug("PPP Session ended correctly\n");
}


// Entry point

// Create a new PPP session
THREAD *NewPPPSession(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, TUBE *send_tube, TUBE *recv_tube, char *postfix, char *client_software_name, char *client_hostname, char *crypt_name, UINT adjust_mss)
{
	PPP_SESSION *p;
	THREAD *t;
	// Validate arguments
	if (cedar == NULL || client_ip == NULL || server_ip == NULL || send_tube == NULL || recv_tube == NULL)
	{
		return NULL;
	}
	if (IsEmptyStr(postfix))
	{
		postfix = "PPP";
	}
	if (IsEmptyStr(crypt_name))
	{
		crypt_name = "";
	}
	if (IsEmptyStr(client_software_name))
	{
		client_software_name = "PPP VPN Client";
	}

	// Data structure initialization
	p = ZeroMalloc(sizeof(PPP_SESSION));

	p->EnableMSCHAPv2 = true;
	p->AuthProtocol = PPP_UNSPECIFIED;
	p->MsChapV2_ErrorCode = 691;
	p->EapClient = NULL;
	Zero(&p->Eap_Identity, sizeof(p->Eap_Identity));
	p->Eap_TlsCtx.DisableTls13 = false;
	p->Eap_TlsCtx.Tls13SessionTicketsCount = 2; // Default count as per hardcoded in OpenSSL

	p->DataTimeout = PPP_DATA_TIMEOUT;
	p->PacketRecvTimeout = PPP_PACKET_RECV_TIMEOUT;
	p->UserConnectionTimeout = 0;

	p->Cedar = cedar;
	AddRef(cedar->ref);

	p->AdjustMss = adjust_mss;

	StrCpy(p->CryptName, sizeof(p->CryptName), crypt_name);

	Copy(&p->ClientIP, client_ip, sizeof(IP));
	p->ClientPort = client_port;

	Copy(&p->ServerIP, server_ip, sizeof(IP));
	p->ServerPort = server_port;

	p->TubeRecv = recv_tube;
	p->TubeSend = send_tube;

	AddRef(p->TubeRecv->Ref);
	AddRef(p->TubeSend->Ref);

	StrCpy(p->Postfix, sizeof(p->Postfix), postfix);
	StrCpy(p->ClientSoftwareName, sizeof(p->ClientSoftwareName), client_software_name);

	if (IsEmptyStr(client_hostname))
	{
		IPToStr(p->ClientHostname, sizeof(p->ClientHostname), client_ip);
	}
	else
	{
		StrCpy(p->ClientHostname, sizeof(p->ClientHostname), client_hostname);
	}

	p->FlushList = NewTubeFlushList();

	// Thread creation
	t = NewThread(PPPThread, p);

	return t;
}

// PPP processing functions

// Finds out if a packet is supported, if not - sends a notification to the peer
// result: false - supported, true - unsupported
bool PPPRejectUnsupportedPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPRejectUnsupportedPacketEx(p, pp, false);
}
bool PPPRejectUnsupportedPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool force)
{
	bool result = false;
	if (p == NULL || pp == NULL)
	{
		return false;
	}

	if (PPP_IS_SUPPORTED_PROTOCOL(pp->Protocol) == false || force == true)
	{
		// Unsupported algorithm
		PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));
		BUF *buf;
		UCHAR c;
		USHORT us;

		Debug("Rejecting PPP protocol = 0x%x\n", pp->Protocol);
		result = true;

		pp2->Protocol = PPP_PROTOCOL_LCP;
		pp2->IsControl = false;

		buf = NewBuf();

		// Code
		c = PPP_LCP_CODE_PROTOCOL_REJECT;
		WriteBuf(buf, &c, 1);

		// ID
		c = p->NextId++;
		WriteBuf(buf, &c, 1);

		// Length
		us = Endian16(pp->DataSize + 6);
		WriteBuf(buf, &us, 2);

		// Rejected Protocol
		us = Endian16(pp->Protocol);
		WriteBuf(buf, &us, 2);

		// Packet Data
		WriteBuf(buf, pp->Data, pp->DataSize);

		pp2->Data = Clone(buf->Buf, buf->Size);
		pp2->DataSize = buf->Size;

		FreeBuf(buf);

		if (PPPSendPacketAndFree(p, pp2) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
		}
	}
	return result;
}

// Do the retransmissions if needed
bool PPPProcessRetransmissions(PPP_SESSION *p)
{
	INT64 i = 0;
	UINT64 now = Tick64();
	UINT64 count;
	if (p->SentReqPacketList == NULL)
	{
		Debug("Somehow SentReqPacketList is NULL!\n");
		return false;
	}
	// Making it signed but expanding to 64 bits
	count = LIST_NUM(p->SentReqPacketList);
	if (count == 0)
	{
		return true;
	}
	for (i = count - 1; i >= 0; --i)
	{
		PPP_REQUEST_RESEND *t = LIST_DATA(p->SentReqPacketList, i);

		if (t->TimeoutTime <= now)
		{
			Debug("Timing out on resending control packet protocol = 0x%x\n", t->Packet->Protocol);
			Delete(p->SentReqPacketList, t);
			FreePPPPacket(t->Packet);
			Free(t);
		}
		else if (t->ResendTime <= now)
		{
			Debug("Resending control packet protocol = 0x%x\n", t->Packet->Protocol);
			if (PPPSendPacketEx(p, t->Packet, false) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			t->ResendTime = now + PPP_PACKET_RESEND_INTERVAL;
		}
	}
	return true;
}

// Send the PPP Echo Request
bool PPPSendEchoRequest(PPP_SESSION *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	UINT64 now = Tick64();
	if (p->NextEchoSendTime == 0 || now >= p->NextEchoSendTime)
	{
		PPP_PACKET *pp;
		char echo_data[] = "\0\0\0\0Aho Baka Manuke";

		p->NextEchoSendTime = now + (UINT64)PPP_ECHO_SEND_INTERVAL;
		if (IsIPCConnected(p->Ipc))
		{
			AddInterrupt(p->Ipc->Interrupt, p->NextEchoSendTime);
		}

		pp = ZeroMalloc(sizeof(PPP_PACKET));
		pp->Protocol = PPP_PROTOCOL_LCP;
		pp->IsControl = true;
		pp->Lcp = NewPPPLCP(PPP_LCP_CODE_ECHO_REQUEST, 0);

		pp->Lcp->Data = Clone(echo_data, sizeof(echo_data));
		pp->Lcp->DataSize = sizeof(echo_data);

		if (PPPSendPacketAndFree(p, pp) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}
		return true;
	}
	return false;
}

// Processes response packets
bool PPPProcessResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	if (req == NULL)
	{
		Debug("We received a response for... What? We never sent this request, protocol = 0x%x, code = 0x%x\n", pp->Protocol, pp->Lcp->Code);
		// Let's just discard this, as this was probably already parsed, and we just stumbled upon a resend
		return false;
	}

	switch (pp->Protocol)
	{
	case PPP_PROTOCOL_LCP:
		return PPPProcessLCPResponsePacket(p, pp, req);
		break;
	case PPP_PROTOCOL_PAP:
		Debug("Got a response PAP, which is invalid, we should get a request instead\n");
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
		break;
	case PPP_PROTOCOL_CHAP:
		return PPPProcessCHAPResponsePacket(p, pp, req);
		break;
	case PPP_PROTOCOL_IPCP:
		return PPPProcessIPCPResponsePacket(p, pp, req);
		break;
	case PPP_PROTOCOL_IPV6CP:
		return PPPProcessIPv6CPResponsePacket(p, pp, req);
		break;
	case PPP_PROTOCOL_EAP:
		return PPPProcessEAPResponsePacket(p, pp, req);
		break;
	default:
		Debug("We received a response for an unsupported protocol??? Should be filtered out already! protocol = 0x%x, code = 0x%x\n", pp->Protocol, pp->Lcp->Code);
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
	}

	return false;
}

bool PPPProcessLCPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	UINT i;
	bool isAccepted = PPP_LCP_CODE_IS_NEGATIVE(pp->Lcp->Code) == false;
	bool result = true;
	// MSCHAPv2 code
	UCHAR ms_chap_v2_code[3];
	WRITE_USHORT(ms_chap_v2_code, PPP_LCP_AUTH_CHAP);
	ms_chap_v2_code[2] = PPP_CHAP_ALG_MS_CHAP_V2;

	// We got one of rejects here, not NACKs
	if (isAccepted == false && pp->Lcp->Code == PPP_LCP_CODE_PROTOCOL_REJECT)
	{
		// If we receive a protocol reject before we finished authenticating
		// probably means the PPP client is not compatible anyway so we fail the connection
		if (p->PPPStatus != PPP_STATUS_NETWORK_LAYER)
		{
			USHORT *protocol = pp->Lcp->Data;
			Debug("Protocol 0x%x rejected before auth, probably unsupported client, failing connection\n", *protocol);
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}
		else
		{
			USHORT *protocol = pp->Lcp->Data;
			if (*protocol == PPP_PROTOCOL_IPCP || *protocol == PPP_PROTOCOL_IP)
			{
				IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_REJECTED);
			}
			if (*protocol == PPP_PROTOCOL_IPV6CP || *protocol == PPP_PROTOCOL_IPV6)
			{
				IPC_PROTO_SET_STATUS(p->Ipc, IPv6State, IPC_PROTO_STATUS_REJECTED);
			}
		}
	}

	if (isAccepted == false && pp->Lcp->Code == PPP_LCP_CODE_CODE_REJECT)
	{
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
	}

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);
		PPP_OPTION *opt = NULL;

		switch (t->Type)
		{
		case PPP_LCP_OPTION_MRU:
			// MRU
			if (t->DataSize == sizeof(USHORT))
			{
				USHORT value = READ_USHORT(t->Data);
				if (isAccepted == false)
				{
					if (pp->Lcp->Code != PPP_LCP_CODE_NAK)
					{
						Debug("MRU setup failed, rejected");
						p->Mru1 = p->Mru2 = PPP_MRU_DEFAULT;
					}
					if (value < PPP_MRU_MIN || value > PPP_MRU_MAX)
					{
						Debug("Couldn't agree on an MRU! Breaking link... MRU = 0x%x\n", value);
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
					else
					{
						PPP_LCP *lcp = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
						Add(lcp->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &value, sizeof(USHORT)));
						if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, lcp) == false)
						{
							PPPSetStatus(p, PPP_STATUS_FAIL);
							WHERE;
							return false;
						}
						Debug("PPP: Server got %u as MRU from NACK, re-requesting\n", p->Mru2);
					}
				}
				else if (value < PPP_MRU_MIN || value > PPP_MRU_MAX)
				{
					Debug("The client somehow ACKed an invalid MRU, breaking link... MRU = 0x%x\n", value);
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					result = false;
				}
				else
				{
					p->Mru2 = value;
					Debug("PPP: Server set %u as MRU\n", p->Mru2);
				}
			}
			break;
		case PPP_LCP_OPTION_AUTH:
			opt = PPPGetOptionValue(req->Lcp, PPP_LCP_OPTION_AUTH);
			if (opt == NULL)
			{
				Debug("We got some weird response with option absent in request, wut? Disconnecting\n");
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			if (opt->DataSize == sizeof(USHORT) && *((USHORT *)(opt->Data)) == Endian16(PPP_LCP_AUTH_EAP))
			{
				// Try to request MS-CHAPv2 then
				if (isAccepted == false)
				{
					UINT64 offer = 0;
					PPP_LCP *c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
					UCHAR ms_chap_v2_code[3];

					WRITE_USHORT(ms_chap_v2_code, PPP_LCP_AUTH_CHAP);
					ms_chap_v2_code[2] = PPP_CHAP_ALG_MS_CHAP_V2;

					Copy(&offer, ms_chap_v2_code, sizeof(ms_chap_v2_code));
					Debug("NACK proto with code = 0x%x, cypher = 0x%x, offered cypher = 0x%x\n", pp->Lcp->Code, *((USHORT *)(opt->Data)), offer);
					Debug("Request MSCHAPv2\n");
					Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &ms_chap_v2_code, sizeof(ms_chap_v2_code)));
					if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, c) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
				}
				else
				{
					p->AuthProtocol = PPP_PROTOCOL_EAP;
					Debug("Setting BEFORE_AUTH from ACK on LCP response parse on EAP accept\n");
					PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				}
			}
			else if (opt->DataSize == sizeof(ms_chap_v2_code) && Cmp(opt->Data, ms_chap_v2_code, opt->DataSize) == 0)
			{
				// Try to request PAP then
				if (isAccepted == false || p->EnableMSCHAPv2 == false)
				{
					UINT64 offer = 0;
					PPP_LCP *c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
					USHORT proto = Endian16(PPP_LCP_AUTH_PAP);
					Copy(&offer, t->Data, t->DataSize > sizeof(UINT64) ? sizeof(UINT64) : t->DataSize);
					Debug("NACK proto with code = 0x%x, cypher = 0x%x, offered cypher = 0x%x\n", pp->Lcp->Code, *((USHORT *)(opt->Data)), offer);
					Debug("Request PAP\n");
					Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &proto, sizeof(USHORT)));
					if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, c) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
				}
				else if (p->AuthProtocol == PPP_UNSPECIFIED)
				{
					p->AuthProtocol = PPP_PROTOCOL_CHAP;
					Debug("Setting BEFORE_AUTH from ACK on LCP response parse on CHAP accept\n");
					PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				}

			}
			else if (opt->DataSize == sizeof(USHORT) && *((USHORT *)(opt->Data)) == Endian16(PPP_LCP_AUTH_PAP))
			{
				// We couldn't agree on auth proto, failing connection
				if (isAccepted == false)
				{
					UINT64 offer = 0;
					Copy(&offer, t->Data, t->DataSize > sizeof(UINT64) ? sizeof(UINT64) : t->DataSize);
					Debug("NACK proto with code = 0x%x, cypher = 0x%x, offered cypher = 0x%x\n", pp->Lcp->Code, *((USHORT *)(opt->Data)), offer);
					Debug("Couldn't agree on auth protocol!\n");
					PPPLog(p, "LP_PAP_MSCHAPV2_REJECTED");
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				else if (p->AuthProtocol == PPP_UNSPECIFIED)
				{
					p->AuthProtocol = PPP_PROTOCOL_PAP;
					Debug("Setting BEFORE_AUTH from ACK on LCP response parse on PAP accept\n");
					PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				}
			}
			break;
		}
	}

	return result;
}

// Process CHAP responses
bool PPPProcessCHAPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	return PPPProcessCHAPResponsePacketEx(p, pp, req, pp->Lcp, false);
}
bool PPPProcessCHAPResponsePacketEx(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req, PPP_LCP *chap, bool use_eap)
{
	PPP_LCP *lcp;
	if (chap->Code == PPP_CHAP_CODE_RESPONSE)
	{
		bool ok = false;
		if (p->PPPStatus != PPP_STATUS_AUTHENTICATING && p->AuthOk == false)
		{
			Debug("Receiving CHAP response packets outside of auth status, some errors probably!");
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}
		if (p->AuthProtocol != PPP_PROTOCOL_CHAP && use_eap == false)
		{
			Debug("Receiving CHAP packet when auth protocol set to 0x%x\n", p->AuthProtocol);
			PPPLog(p, "LP_NEXT_PROTOCOL_IS_NOT_PAP", pp->Protocol);
			PPPRejectUnsupportedPacketEx(p, pp, true);
			return false;
		}

		ok = PPPParseMSCHAP2ResponsePacketEx(p, chap, use_eap);

		// If we got only first packet of double CHAP then send second challenge
		if (ok && p->UseEapRadius && p->EapClient != NULL && p->Ipc == NULL)
		{
			lcp = BuildMSCHAP2ChallengePacket(p);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_CHAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
		}
		// We got a successful MSCHAPv2 response, so let's send a SUCCESS
		else if (ok)
		{
			char hex[MAX_SIZE];
			char ret_str[MAX_SIZE];
			BUF *lcp_ret_data = NewBuf();
			BinToStr(hex, sizeof(hex), p->MsChapV2_ServerResponse, 20);

			Format(ret_str, sizeof(ret_str),
			       "S=%s", hex);

			WriteBuf(lcp_ret_data, ret_str, StrLen(ret_str));

			lcp = NewPPPLCP(PPP_CHAP_CODE_SUCCESS, p->MsChapV2_PacketId);
			lcp->Data = Clone(lcp_ret_data->Buf, lcp_ret_data->Size);
			lcp->DataSize = lcp_ret_data->Size;

			if (lcp_ret_data != NULL)
			{
				FreeBuf(lcp_ret_data);
			}

			if (use_eap == false)
			{
				PPP_PACKET *res = ZeroMalloc(sizeof(PPP_PACKET));
				res->Lcp = lcp;
				res->IsControl = true;
				res->Protocol = PPP_PROTOCOL_CHAP;

				if (PPPSendPacketAndFree(p, res) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				PPPSetStatus(p, PPP_STATUS_AUTH_SUCCESS);
			}
			else
			{
				BUF *b = BuildLCPData(lcp);
				FreePPPLCP(lcp);
				p->Eap_PacketId = p->NextId++;
				lcp = BuildEAPPacketEx(PPP_EAP_CODE_REQUEST, p->Eap_PacketId, PPP_EAP_TYPE_MSCHAPV2, b->Size);
				PPP_EAP *eapPacket = lcp->Data;
				Copy(eapPacket->Data, b->Buf, b->Size);
				FreeBuf(b);

				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
			}

			p->AuthOk = true;
		}
		// We failed MSCHAPv2 auth
		else
		{
			char hex[MAX_SIZE];
			char ret_str[MAX_SIZE];
			BUF *lcp_ret_data = NewBuf();

			BinToStr(hex, sizeof(hex), p->MsChapV2_ServerChallenge, 16);

			Format(ret_str, sizeof(ret_str),
			       "E=%u R=0 C=%s V=3", p->MsChapV2_ErrorCode, hex);

			WriteBuf(lcp_ret_data, ret_str, StrLen(ret_str));

			lcp = NewPPPLCP(PPP_CHAP_CODE_FAILURE, p->MsChapV2_PacketId);
			lcp->Data = Clone(lcp_ret_data->Buf, lcp_ret_data->Size);
			lcp->DataSize = lcp_ret_data->Size;

			if (lcp_ret_data != NULL)
			{
				FreeBuf(lcp_ret_data);
			}

			if (use_eap == false)
			{
				PPP_PACKET *res = ZeroMalloc(sizeof(PPP_PACKET));
				res->Lcp = lcp;
				res->IsControl = true;
				res->Protocol = PPP_PROTOCOL_CHAP;

				if (PPPSendPacketAndFree(p, res) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
			}
			else
			{
				BUF *b = BuildLCPData(lcp);
				FreePPPLCP(lcp);
				p->Eap_PacketId = p->NextId++;
				lcp = BuildEAPPacketEx(PPP_EAP_CODE_REQUEST, p->Eap_PacketId, PPP_EAP_TYPE_MSCHAPV2, b->Size);
				PPP_EAP *eapPacket = lcp->Data;
				Copy(eapPacket->Data, b->Buf, b->Size);
				FreeBuf(b);

				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
			}

			PPPLog(p, "LP_CHAP_FAILED");
		}

		return ok;
	}
	return false;
}

// Process IPCP responses
bool PPPProcessIPCPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	bool isAccepted = PPP_LCP_CODE_IS_NEGATIVE(pp->Lcp->Code) == false;

	IP addrStruct;
	char addrStr[MAX_SIZE];
	UINT addr;
	IP prevAddrStruct;
	char prevAddrStr[MAX_SIZE];
	UINT prevAddr;
	PPP_LCP *c;
	UINT ui;

	if (PPPGetIPAddressValueFromLCP(pp->Lcp, PPP_IPCP_OPTION_IP, &addrStruct) == false || pp->Lcp->Code == PPP_LCP_CODE_REJECT || pp->Lcp->Code == PPP_LCP_CODE_CODE_REJECT)
	{
		Debug("Unsupported IPCP protocol");
		IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_REJECTED);
		PPPRejectUnsupportedPacketEx(p, pp, true);
		return false;
	}

	// We're dealing either with ACK or NACK
	addr = IPToUINT(&addrStruct);
	IPToStr(addrStr, MAX_SIZE, &addrStruct);

	if (isAccepted)
	{
		Debug("Accepted server IP address of %s\n", addrStr);

		// We already configured client address, now server address is also confirmed, ready for IPv4 data flow
		if (IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_CONFIG)
		{
			IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_CONFIG_WAIT);
		}
		return true;
	}

	IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_CONFIG);

	PPPGetIPAddressValueFromLCP(req->Lcp, PPP_IPCP_OPTION_IP, &prevAddrStruct);
	prevAddr = IPToUINT(&prevAddrStruct);
	IPToStr(prevAddrStr, MAX_SIZE, &prevAddrStruct);

	Debug("Denied server IP address %s, proposed %s\n", prevAddrStr, addrStr);

	// Fallback mechanism - just request 192.0.0.8
	if (prevAddr == Endian32(0xc0000008))
	{
		Debug("We already tried the fallback IP of 192.0.0.8, giving up\n");
		IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_REJECTED);
		PPPRejectUnsupportedPacketEx(p, pp, true);
		return false;
	}

	c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
	ui = Endian32(0xc0000008);	// We always push 192.0.0.8, which is defined in RFC7600 as dummy IPv4 address.
	Add(c->OptionList, NewPPPOption(PPP_IPCP_OPTION_IP, &ui, sizeof(UINT)));
	if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_IPCP, c) == false)
	{
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
	}

	return false;
}

// Process EAP responses
bool PPPProcessEAPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	if (pp->Lcp->DataSize >= 1)
	{
		PPP_EAP *eap_packet = pp->Lcp->Data;
		UINT eap_datasize = pp->Lcp->DataSize - 1;
		UINT64 offer = 0;
		PPP_LCP *c;
		UCHAR ms_chap_v2_code[3];
		HUB *hub;
		bool found = false;
		UINT authtype = AUTHTYPE_ANONYMOUS;
		UCHAR eapidentitypkt[MAX_SIZE] = { 0 };

		WRITE_USHORT(ms_chap_v2_code, PPP_LCP_AUTH_CHAP);
		ms_chap_v2_code[2] = PPP_CHAP_ALG_MS_CHAP_V2;

		// Forward EAP response to Radius server
		if (p->EapClient != NULL)
		{
			return PPPProcessEapResponseForRadius(p, eap_packet, eap_datasize);
		}

		switch (eap_packet->Type)
		{
		case PPP_EAP_TYPE_IDENTITY:
			p->Eap_MatchUserByCert = false;
			// Parse username
			Copy(eapidentitypkt, eap_packet->Data, MIN(MAX_SIZE, eap_datasize));
			
			Zero(&p->Eap_Identity, sizeof(p->Eap_Identity));
			PPPParseUsername(p->Cedar, eapidentitypkt, &p->Eap_Identity);
			Debug("EAP: username=%s, hubname=%s\n", p->Eap_Identity.UserName, p->Eap_Identity.HubName);

			// Locate user
			LockHubList(p->Cedar);
			{
				hub = GetHub(p->Cedar, p->Eap_Identity.HubName);
			}
			UnlockHubList(p->Cedar);
			if (hub != NULL)
			{
				AcLock(hub);
				{
					USER *user = AcGetUser(hub, p->Eap_Identity.UserName);
					if (user == NULL)
					{
						user = AcGetUser(hub, "*");
					}
					if (user != NULL)
					{
						found = true;
						authtype = user->AuthType;
						ReleaseUser(user);
					}
					else if (hub->Option->AllowEapMatchUserByCert == true)
					{
						authtype = AUTHTYPE_USERCERT;
						Zero(p->Eap_Identity.UserName, sizeof(p->Eap_Identity.UserName));
						p->Eap_MatchUserByCert = true;
					}
				}
				AcUnlock(hub);
				ReleaseHub(hub);
			}

			if (found == false && p->Eap_MatchUserByCert == false)
			{
				// User not found, fail immediately
				PPP_PACKET *pack = ZeroMalloc(sizeof(PPP_PACKET));
				pack->IsControl = true;
				pack->Protocol = PPP_PROTOCOL_EAP;
				PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
				pack->Lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, p->Eap_PacketId);

				if (PPPSendPacketAndFree(p, pack) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				break;
			}

			// Select EAP method based on auth type
			switch (authtype)
			{
			case AUTHTYPE_RADIUS:
				// Create EAP client if needed
				if (p->EapClient == NULL)
				{
					char client_ip_tmp[256];
					PPP_LCP *response = NULL;
					IPToStr(client_ip_tmp, sizeof(client_ip_tmp), &p->ClientIP);
					Debug("Creating EAP RADIUS client\n");
					p->EapClient = HubNewEapClient(p->Cedar, p->Eap_Identity.HubName, client_ip_tmp, p->Eap_Identity.UserName, "L3:PPP", true, 
													&response, pp->Lcp->Id);

					if (p->EapClient == NULL || response == NULL)
					{
						PPP_PACKET *pack = ZeroMalloc(sizeof(PPP_PACKET));
						pack->IsControl = true;
						pack->Protocol = PPP_PROTOCOL_EAP;
						PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
						pack->Lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, p->Eap_PacketId);
						Debug("Failed to connect to a RADIUS server\n");

						if (PPPSendPacketAndFree(p, pack) == false)
						{
							PPPSetStatus(p, PPP_STATUS_FAIL);
							WHERE;
							return false;
						}
					}
					else
					{
						// Send first response to client
						if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, response) == false)
						{
							PPPSetStatus(p, PPP_STATUS_FAIL);
							WHERE;
							return false;
						}
					}	

					break;
				}
			case AUTHTYPE_ANONYMOUS:
			case AUTHTYPE_PASSWORD:
			case AUTHTYPE_NT:
				// Propose EAP-MSCHAPv2 directly
				p->Eap_Protocol = PPP_EAP_TYPE_MSCHAPV2;
				PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				break;
			default:
				// Propose EAP-TLS first
				p->Eap_Protocol = PPP_EAP_TYPE_TLS;
				PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				break;
			}
			break;
		case PPP_EAP_TYPE_NOTIFICATION:
			// Basically this is just an acknoweldgment that the notification was accepted by the client. Nothing to do here...
			break;
		case PPP_EAP_TYPE_NAK:
			if (p->Eap_Protocol == PPP_EAP_TYPE_TLS && p->Eap_MatchUserByCert == false)
			{
				// Propose EAP-MSCHAPv2
				p->Eap_Protocol = PPP_EAP_TYPE_MSCHAPV2;
				PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
				break;
			}
			// Fallback to auth protocol selection to try to select MSCHAP or PAP
			Debug("Got a EAP_NAK, abandoning EAP protocol\n");
			PPPRejectUnsupportedPacketEx(p, pp, true);
			PPPSetStatus(p, PPP_STATUS_CONNECTED);

			c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
			Copy(&offer, ms_chap_v2_code, sizeof(ms_chap_v2_code));
			Debug("Request MSCHAPv2 from EAP NAK\n");
			Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &ms_chap_v2_code, sizeof(ms_chap_v2_code)));
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_LCP, c) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			break;
		case PPP_EAP_TYPE_TLS:
			PPPProcessEAPTlsResponse(p, eap_packet, eap_datasize);
			break;
		case PPP_EAP_TYPE_MSCHAPV2:
			if (p->PPPStatus != PPP_STATUS_AUTHENTICATING)
			{
				Debug("Received EAP-MSCHAPv2 response not during authentication\n");
				break;
			}
			if (eap_datasize == 1)
			{
				// Success or failure response
				PPP_PACKET *pack = ZeroMalloc(sizeof(PPP_PACKET));
				pack->IsControl = true;
				pack->Protocol = PPP_PROTOCOL_EAP;

				if (p->AuthOk)
				{
					PPPSetStatus(p, PPP_STATUS_AUTH_SUCCESS);
					pack->Lcp = NewPPPLCP(PPP_EAP_CODE_SUCCESS, p->Eap_PacketId);
				}
				else
				{
					PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
					pack->Lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, p->Eap_PacketId);
				}

				if (PPPSendPacketAndFree(p, pack) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
			}
			else
			{
				// CHAP response
				PPP_LCP *chap = PPPParseLCP(PPP_PROTOCOL_CHAP, eap_packet->Data, eap_datasize);
				if (chap == NULL)
				{
					Debug("Received an invalid EAP-MSCHAPv2 packet\n");
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				PPPProcessCHAPResponsePacketEx(p, pp, req, chap, true);
				FreePPPLCP(chap);
			}
			break;
		default:
			Debug("We got an unexpected EAP response packet! Ignoring...\n");
			break;
		}
	}
	else
	{
		PPP_EAP *eap;

		Debug("We got a CODE=%i ID=%i from client with zero size EAP structure, that shouldn't be happening!\n", pp->Lcp->Code, pp->Lcp->Id);

		eap = req->Lcp->Data;
		if (eap->Type == PPP_EAP_TYPE_TLS)
		{
			p->Eap_PacketId = p->NextId++;
			PPP_LCP *lcp = BuildEAPTlsRequest(p->Eap_PacketId, 0, PPP_EAP_TLS_FLAG_NONE);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
		}
	}
	return false;
}

// Process IPv6CP responses
bool PPPProcessIPv6CPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req)
{
	bool isAccepted = PPP_LCP_CODE_IS_NEGATIVE(pp->Lcp->Code) == false;

	// If we got a reject or a NACK, we just reject the whole IPv6 configuration, there is no way we can recover even from a NACK as we can't change the link-local address of an already existing router
	if (isAccepted == false)
	{
		Debug("Unsupported IPv6CP protocol");
		IPC_PROTO_SET_STATUS(p->Ipc, IPv6State, IPC_PROTO_STATUS_REJECTED);
		PPPRejectUnsupportedPacketEx(p, pp, true);
		return false;
	}

	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) != IPC_PROTO_STATUS_CONFIG)
	{
		Debug("We got an early IPv6CP response, ignoring for now...\n");
		return false;
	}

	Debug("Accepted server IPv6CP handshake\n");
	IPC_PROTO_SET_STATUS(p->Ipc, IPv6State, IPC_PROTO_STATUS_CONFIG_WAIT);
	return true;
}

// Process EAP response for RADIUS (as proxy)
bool PPPProcessEapResponseForRadius(PPP_SESSION *p, PPP_EAP *eap_packet, UINT eap_datasize)
{
	PPP_LCP *lcp;
	IPC *ipc;
	UINT error_code;

	if (p == NULL || eap_packet == NULL || p->EapClient == NULL)
	{
		return false;
	}

	lcp = EapClientSendEapRequest(p->EapClient, eap_packet, eap_datasize);
	if (lcp == NULL)
	{
		return false;
	}

	switch (lcp->Code)
	{
	case PPP_EAP_CODE_REQUEST:
		// Send back to client
		if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}

		return true;
	case PPP_EAP_CODE_SUCCESS:
		if (p->Ipc == NULL)
		{
			Debug("PPP Radius creating IPC\n");
			ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, p->Eap_Identity.HubName, p->Eap_Identity.UserName, "", NULL,
							&error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
							p->ClientHostname, p->CryptName, false, p->AdjustMss, p->EapClient, NULL,
							true, IPC_LAYER_3);

			if (ipc != NULL)
			{
				p->Ipc = ipc;

				// Setting user timeouts
				p->PacketRecvTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000 * 3 / 4; // setting to 3/4 of the user timeout
				p->DataTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000;
				if (p->TubeRecv != NULL)
				{
					p->TubeRecv->DataTimeout = p->DataTimeout;
				}
				p->UserConnectionTimeout = (UINT64)p->Ipc->Policy->AutoDisconnect * 1000;
				p->UserConnectionTick = Tick64();
				p->AuthOk = true;
				PPPSetStatus(p, PPP_STATUS_AUTH_SUCCESS);
				break;
			}
		}
	case PPP_EAP_CODE_FAILURE:
	default:
		PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
		break;
	}

	// Send success or failure
	PPP_PACKET* pack;
	pack = ZeroMalloc(sizeof(PPP_PACKET));
	pack->IsControl = true;
	pack->Protocol = PPP_PROTOCOL_EAP;
	pack->Lcp = lcp;
	if (PPPSendPacketAndFree(p, pack) == false)
	{
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
	}

	return true;
}

// Processes request packets
bool PPPProcessRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	switch (pp->Protocol)
	{
	case PPP_PROTOCOL_LCP:
		return PPPProcessLCPRequestPacket(p, pp);
		break;
	case PPP_PROTOCOL_PAP:
		return PPPProcessPAPRequestPacket(p, pp);
		break;
	case PPP_PROTOCOL_CHAP:
		Debug("Got a CHAP request, which is invalid, we should get CHAP response instead\n");
		PPPSetStatus(p, PPP_STATUS_FAIL);
		WHERE;
		return false;
		break;
	case PPP_PROTOCOL_IPCP:
		return PPPProcessIPCPRequestPacket(p, pp);
		break;
	case PPP_PROTOCOL_IPV6CP:
		return PPPProcessIPv6CPRequestPacket(p, pp);
		break;
	case PPP_PROTOCOL_EAP:
		return PPPProcessEAPRequestPacket(p, pp);
		break;
	default:
		Debug("Unsupported protocols should be already filtered out! protocol = 0x%x, code = 0x%x\n", pp->Protocol, pp->Lcp->Code);
		return false;
		break;
	}
	return false;
}

bool PPPProcessLCPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	bool result = true;
	UINT i = 0;

	USHORT NegotiatedAuthProto = PPP_UNSPECIFIED;
	USHORT NegotiatedMRU = PPP_UNSPECIFIED;
	// MSCHAPv2 code
	UCHAR ms_chap_v2_code[3];
	USHORT eap_code = PPP_LCP_AUTH_EAP;

	WRITE_USHORT(ms_chap_v2_code, PPP_LCP_AUTH_CHAP);
	ms_chap_v2_code[2] = PPP_CHAP_ALG_MS_CHAP_V2;

	Debug("Got LCP packet request ID=%i OptionsListSize=%i\n", pp->Lcp->Id, LIST_NUM(pp->Lcp->OptionList));

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		switch (t->Type)
		{
		case PPP_LCP_OPTION_AUTH:
			t->IsSupported = true;
			if (t->DataSize == sizeof(USHORT) && *((USHORT *)t->Data) == PPP_LCP_AUTH_EAP && p->AuthProtocol == PPP_UNSPECIFIED)
			{
				t->IsAccepted = true;
				NegotiatedAuthProto = PPP_PROTOCOL_EAP;
			}
			else if (t->DataSize == sizeof(USHORT) && *((USHORT *)t->Data) == PPP_LCP_AUTH_PAP && p->AuthProtocol == PPP_UNSPECIFIED)
			{
				t->IsAccepted = true;
				NegotiatedAuthProto = PPP_PROTOCOL_PAP;
			}
			else if (t->DataSize == sizeof(ms_chap_v2_code) && Cmp(t->Data, ms_chap_v2_code, t->DataSize) == 0 && p->AuthProtocol == PPP_UNSPECIFIED)
			{
				t->IsAccepted = true;
				NegotiatedAuthProto = PPP_PROTOCOL_CHAP;
			}
			else
			{
				// We're recommending EAP by default as a more secure algo
				t->IsAccepted = false;
				t->AltDataSize = sizeof(eap_code);
				Copy(t->AltData, &eap_code, sizeof(eap_code));
			}
			break;
		case PPP_LCP_OPTION_MRU:
			t->IsSupported = true;
			if (t->DataSize == sizeof(USHORT))
			{
				USHORT value = READ_USHORT(t->Data);
				if (value < PPP_MRU_MIN || value > PPP_MRU_MAX)
				{
					t->IsAccepted = false;
					value = MAKESURE(value, PPP_MRU_MIN, PPP_MRU_MAX);
					//Debug("MRU not accepted, sending NACK with value = 0x%x\n", value);
					t->AltDataSize = sizeof(USHORT);
					WRITE_USHORT(t->AltData, value);
				}
				else
				{
					t->IsAccepted = true;
					NegotiatedMRU = value;
					//Debug("MRU accepted, value = 0x%x\n", value);
				}
			}
			else
			{
				t->IsAccepted = false;
				t->AltDataSize = sizeof(USHORT);
				WRITE_USHORT(t->AltData, PPP_MRU_DEFAULT);
			}
			break;
		default:
			t->IsSupported = false;
			Debug("Unsupported LCP option = 0x%x\n", t->Type);
			break;
		}
	}

	if (PPPRejectLCPOptions(p, pp))
	{
		Debug("Rejected LCP options...\n");
		return false;
	}

	if (PPPNackLCPOptions(p, pp))
	{
		Debug("NACKed LCP options...\n");
		return false;
	}

	if (PPPAckLCPOptions(p, pp) == false)
	{
		return false;
	}

	if (NegotiatedAuthProto != PPP_UNSPECIFIED)
	{
		if (p->AuthProtocol == PPP_UNSPECIFIED)
		{
			p->AuthProtocol = NegotiatedAuthProto;
			PPPSetStatus(p, PPP_STATUS_BEFORE_AUTH);
			Debug("Setting BEFORE_AUTH from REQ on LCP request parse\n");
		}
	}
	if (NegotiatedMRU != PPP_UNSPECIFIED)
	{
		p->Mru1 = NegotiatedMRU;
	}

	return true;
}

bool PPPProcessPAPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	if (p->PPPStatus != PPP_STATUS_BEFORE_AUTH && p->AuthOk == false)
	{
		PPP_LCP *lcp = NewPPPLCP(PPP_PAP_CODE_NAK, pp->Lcp->Id);
		PPP_PACKET *ret = ZeroMalloc(sizeof(PPP_PACKET));

		Debug("Got a PAP request before we're ready for AUTH procedure!\n");

		ret->IsControl = true;
		ret->Protocol = PPP_PROTOCOL_PAP;
		ret->Lcp = lcp;
		if (PPPSendPacketAndFree(p, ret) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}

		return false;
	}
	if (p->AuthProtocol != PPP_PROTOCOL_PAP)
	{
		Debug("Trying to auth with PAP when should be 0x%x\n", p->AuthProtocol);
		PPPLog(p, "LP_NEXT_PROTOCOL_IS_NOT_CHAP", pp->Protocol);

		// Forcing rejection of PAP on configured MSCHAPv2
		PPPRejectUnsupportedPacketEx(p, pp, true);

		return false;
	}
	if (p->AuthOk == false)
	{
		UCHAR *data;
		UINT size;

		PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);

		if (p->Ipc == NULL)
		{
			// PAP

			// Extract the ID and the password
			data = pp->Lcp->Data;
			size = pp->Lcp->DataSize;

			if (size >= 1)
			{
				UCHAR len_id = data[0];
				data++;
				size--;

				if (size >= len_id)
				{
					char username[256];
					char password[256];

					Zero(username, sizeof(username));
					Zero(password, sizeof(password));

					Copy(username, data, len_id);
					data += len_id;
					size -= len_id;

					if (size >= 1)
					{
						UCHAR len_pass = data[0];
						data++;
						size--;

						if (size >= len_pass)
						{
							IPC *ipc;
							char id[MAX_SIZE];
							char hub[MAX_SIZE];
							ETHERIP_ID d;

							Zero(id, sizeof(id));
							Zero(hub, sizeof(hub));

							Copy(password, data, len_pass);

							Debug("PPP: id=%s, pw=%s\n", username, password);

							// The user name is divided into the ID and the virtual HUB name
							Zero(&d, sizeof(d));
							PPPParseUsername(p->Cedar, username, &d);

							StrCpy(id, sizeof(id), d.UserName);
							StrCpy(hub, sizeof(hub), d.HubName);

							if (IsEmptyStr(id) == false)
							{
								// Attempt to connect with IPC
								UINT error_code;

								ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, hub, id, password, NULL,
								             &error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
								             p->ClientHostname, p->CryptName, false, p->AdjustMss, NULL, NULL,
								             false, IPC_LAYER_3);

								if (ipc != NULL)
								{
									p->Ipc = ipc;

									// Setting user timeouts
									p->PacketRecvTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000 * 3 / 4; // setting to 3/4 of the user timeout
									p->DataTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000;
									if (p->TubeRecv != NULL)
									{
										p->TubeRecv->DataTimeout = p->DataTimeout;
									}
									p->UserConnectionTimeout = (UINT64)p->Ipc->Policy->AutoDisconnect * 1000;
									p->UserConnectionTick = Tick64();

									p->AuthOk = true;
								}
								else
								{
									PPPSetStatus(p, PPP_STATUS_FAIL);
									WHERE;
									return false;
								}
							}
						}
					}
				}
			}
		}
		else
		{
			// Return success for a request from the second time when it is successfully authenticated once
			p->AuthOk = true;
		}
	}
	if (p->AuthOk)
	{
		PPP_LCP *lcp = NewPPPLCP(PPP_PAP_CODE_ACK, pp->Lcp->Id);
		PPP_PACKET *ret = ZeroMalloc(sizeof(PPP_PACKET));
		ret->IsControl = true;
		ret->Protocol = PPP_PROTOCOL_PAP;
		ret->Lcp = lcp;
		if (PPPSendPacketAndFree(p, ret) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}

		if (p->PPPStatus == PPP_STATUS_AUTHENTICATING)
		{
			PPPSetStatus(p, PPP_STATUS_AUTH_SUCCESS);
		}
		return true;
	}
	if (p->AuthOk == false)
	{
		PPP_LCP *lcp = NewPPPLCP(PPP_PAP_CODE_NAK, pp->Lcp->Id);
		PPP_PACKET *ret = ZeroMalloc(sizeof(PPP_PACKET));
		ret->IsControl = true;
		ret->Protocol = PPP_PROTOCOL_PAP;
		ret->Lcp = lcp;
		if (PPPSendPacketAndFree(p, ret) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}

		if (p->PPPStatus == PPP_STATUS_AUTHENTICATING)
		{
			PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);
			PPPLog(p, "LP_PAP_FAILED");
		}

		return false;
	}
	return p->AuthOk;
}


bool PPPProcessIPCPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	PPP_IPOPTION o;
	PPP_IPOPTION res;
	PPP_OPTION *dummyIpOption;
	UINT dummyIp = 0;
	DHCP_OPTION_LIST cao;
	IP client_ip;
	IP subnet;
	IP zero;
	IP gw;
	bool ok = true;
	bool processed = false;
	bool isEmptyIpAddress = false;

	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_REJECTED)
	{
		Debug("We got an IPCP packet after we had it rejected\n");
		return PPPRejectUnsupportedPacketEx(p, pp, true);
	}

	if (PPPGetIPOptionFromLCP(&o, pp->Lcp) == false)
	{
		Debug("IPCP request without client IP address received! Treating as zeroed out client IP...\n");
		isEmptyIpAddress = true;
		dummyIpOption = NewPPPOption(PPP_IPCP_OPTION_IP, &dummyIp, sizeof(UINT));
		dummyIpOption->IsSupported = true;
		dummyIpOption->IsAccepted = false;
		Add(pp->Lcp->OptionList, dummyIpOption);
	}

	// Process if not configured yet by server
	if ((IsZero(&p->ClientAddressOption, sizeof(DHCP_OPTION_LIST)) || isEmptyIpAddress) && ok)
	{
		// Decide if we received a static IP from client and it is allowed
		if (IsZeroIP(&o.IpAddress) == false)
		{
			if (p->Ipc->Policy->DHCPForce == false)
			{
				if (p->DhcpAllocated == false)
				{
					if (p->UseStaticIPAddress == false)
					{
						DHCP_OPTION_LIST cao;

						// The client specify an IP address
						Zero(&cao, sizeof(cao));

						cao.ClientAddress = IPToUINT(&o.IpAddress);

						Copy(&p->ClientAddressOption, &cao, sizeof(cao));

						p->UseStaticIPAddress = true;
					}
				}
			}
		}
		else
		{
			p->UseStaticIPAddress = false;
		}

		// Get additional information for static clients
		if (p->UseStaticIPAddress)
		{
			if (p->DhcpIpInformTried == false)
			{
				// Get additional information such as the subnet mask from the DHCP server
				SetIP(&subnet, 255, 0, 0, 0);
				Zero(&zero, sizeof(zero));

				UINTToIP(&client_ip, p->ClientAddressOption.ClientAddress);

				Zero(&cao, sizeof(cao));

				IPCSetIPv4Parameters(p->Ipc, &client_ip, &subnet, &zero, NULL);

				p->DhcpIpInformTried = true;

				PPPLog(p, "LP_DHCP_INFORM_TRYING");

				if (IPCDhcpRequestInformIP(p->Ipc, &cao, p->TubeRecv, &client_ip))
				{
					Debug("IPCDhcpRequestInformIP ok.\n");
					Copy(&p->ClientAddressOption, &cao, sizeof(cao));
					p->ClientAddressOption.ClientAddress = IPToUINT(&client_ip);

					if (true)
					{
						char server_ip_str[64];
						char subnet_str[64], defgw_str[64];
						char dns1_str[64], dns2_str[64];
						char wins1_str[64], wins2_str[64];

						IPToStr32(server_ip_str, sizeof(server_ip_str), cao.ServerAddress);
						IPToStr32(subnet_str, sizeof(subnet_str), cao.SubnetMask);
						IPToStr32(defgw_str, sizeof(defgw_str), cao.Gateway);
						IPToStr32(dns1_str, sizeof(dns1_str), cao.DnsServer);
						IPToStr32(dns2_str, sizeof(dns2_str), cao.DnsServer2);
						IPToStr32(wins1_str, sizeof(wins1_str), cao.WinsServer);
						IPToStr32(wins2_str, sizeof(wins2_str), cao.WinsServer2);

						PPPLog(p, "LP_DHCP_INFORM_OK",
						       subnet_str, defgw_str, cao.DomainName,
						       dns1_str, dns2_str, wins1_str, wins2_str,
						       server_ip_str);
					}
				}
				else
				{
					Debug("IPCDhcpRequestInformIP failed.\n");
					ok = false;
					p->DhcpIpInformTried = false;
					PPPLog(p, "LP_DHCP_INFORM_NG");
				}

				IPCSetIPv4Parameters(p->Ipc, &zero, &zero, &zero, NULL);
			}
		}
		// Get IP address and additional information from DHCP
		else
		{
			if (p->DhcpIpAllocTried == false)
			{
				DHCP_OPTION_LIST cao;

				Zero(&cao, sizeof(cao));
				p->DhcpIpAllocTried = true;

				PPPLog(p, "LP_DHCP_REQUEST_TRYING");

				if (IPCDhcpAllocateIP(p->Ipc, &cao, p->TubeRecv))
				{
					UINT t;

					Debug("IPCDhcpAllocateIP ok.\n");

					// IP address has been determined
					Copy(&p->ClientAddressOption, &cao, sizeof(cao));

					p->DhcpAllocated = true;

					// Determine the DHCP update interval
					t = cao.LeaseTime;
					if (t == 0)
					{
						t = 600;
					}

					t = t / 3;

					if (t == 0)
					{
						t = 1;
					}

					p->DhcpRenewInterval = (UINT64)t * (UINT64)1000;
					p->DhcpNextRenewTime = Tick64() + p->DhcpRenewInterval;

					if (true)
					{
						char client_ip_str[64], server_ip_str[64];
						char subnet_str[64], defgw_str[64];
						char dns1_str[64], dns2_str[64];
						char wins1_str[64], wins2_str[64];

						IPToStr32(client_ip_str, sizeof(client_ip_str), cao.ClientAddress);
						IPToStr32(server_ip_str, sizeof(server_ip_str), cao.ServerAddress);
						IPToStr32(subnet_str, sizeof(subnet_str), cao.SubnetMask);
						IPToStr32(defgw_str, sizeof(defgw_str), cao.Gateway);
						IPToStr32(dns1_str, sizeof(dns1_str), cao.DnsServer);
						IPToStr32(dns2_str, sizeof(dns2_str), cao.DnsServer2);
						IPToStr32(wins1_str, sizeof(wins1_str), cao.WinsServer);
						IPToStr32(wins2_str, sizeof(wins2_str), cao.WinsServer2);

						PPPLog(p, "LP_DHCP_REQUEST_OK",
						       client_ip_str, subnet_str, defgw_str, cao.DomainName,
						       dns1_str, dns2_str, wins1_str, wins2_str,
						       server_ip_str, cao.LeaseTime);
					}
				}
				else
				{
					Debug("IPCDhcpAllocateIP failed.\n");
					p->DhcpIpAllocTried = false;
					ok = false;
					PPPLog(p, "LP_DHCP_REQUEST_NG");
				}
			}
		}
	}

	// If we already have a configured IP data - send it along
	if (IsValidUnicastIPAddressUINT4(p->ClientAddressOption.ClientAddress) &&
	        p->ClientAddressOption.SubnetMask != 0 && ok)
	{
		// Success to determine the address
		UINTToIP(&subnet, p->ClientAddressOption.SubnetMask);
		UINTToIP(&gw, p->ClientAddressOption.Gateway);

		Zero(&res, sizeof(res));
		UINTToIP(&res.IpAddress, p->ClientAddressOption.ClientAddress);
		UINTToIP(&res.DnsServer1, p->ClientAddressOption.DnsServer);
		UINTToIP(&res.DnsServer2, p->ClientAddressOption.DnsServer2);
		UINTToIP(&res.WinsServer1, p->ClientAddressOption.WinsServer);
		UINTToIP(&res.WinsServer2, p->ClientAddressOption.WinsServer2);

		if (IPCSetIPv4Parameters(p->Ipc, &res.IpAddress, &subnet, &gw, &p->ClientAddressOption.ClasslessRoute))
		{
			char client_ip_str[64];
			char subnet_str[64], defgw_str[64];
			char dns1_str[64], dns2_str[64];
			char wins1_str[64], wins2_str[64];

			// IPv4 parameters have been set for the first time
			Debug("Param First Set.\n");

			IPToStr(client_ip_str, sizeof(client_ip_str), &res.IpAddress);
			IPToStr(subnet_str, sizeof(subnet_str), &subnet);
			IPToStr(defgw_str, sizeof(defgw_str), &gw);
			IPToStr(dns1_str, sizeof(dns1_str), &res.DnsServer1);
			IPToStr(dns2_str, sizeof(dns2_str), &res.DnsServer2);
			IPToStr(wins1_str, sizeof(wins1_str), &res.WinsServer1);
			IPToStr(wins2_str, sizeof(wins2_str), &res.WinsServer2);

			PPPLog(p, "LP_SET_IPV4_PARAM", client_ip_str, subnet_str,
			       defgw_str, dns1_str, dns2_str, wins1_str, wins2_str);
		}

		/*// Backporting static configuration received from client - let him use whatever he wants,
		// he won't accept anything else anyway (as per testing with Windows clients)
		if (!IsZeroIP(&o.DnsServer1))
		{
			CopyIP(&res.DnsServer1, &o.DnsServer1);
			Debug("Setting DNS1 from client\n");
		}
		if (!IsZeroIP(&o.DnsServer2))
		{
			CopyIP(&res.DnsServer2, &o.DnsServer2);
			Debug("Setting DNS2 from client\n");
		}
		if (!IsZeroIP(&o.WinsServer1))
		{
			CopyIP(&res.WinsServer1, &o.WinsServer1);
			Debug("Setting WINS1 from client\n");
		}
		if (!IsZeroIP(&o.WinsServer2))
		{
			CopyIP(&res.WinsServer2, &o.WinsServer2);
			Debug("Setting WINS2 from client\n");
		}*/
		/*if (!IsZeroIP(&res.DnsServer1) && IsZeroIP(&res.DnsServer2))
		{
			CopyIP(&res.DnsServer2, &res.DnsServer1);
		}
		if (!IsZeroIP(&res.WinsServer1) && IsZeroIP(&res.WinsServer2))
		{
			CopyIP(&res.WinsServer2, &res.WinsServer1);
		}*/
		PPPSetIPOptionToLCP(&res, pp->Lcp, true);
	}
	// We couldn't configure address for the client
	else
	{
		// Failed to determine the address
		Debug("IP Address Determination Failed.\n");

		Zero(&res, sizeof(res));
		// We will try to reconfigure if we receive another request by wiping all data
		Zero(&p->ClientAddressOption, sizeof(DHCP_OPTION_LIST));
		p->UseStaticIPAddress = false;

		PPPSetIPOptionToLCP(&res, pp->Lcp, true);
	}

	if (PPPRejectLCPOptionsEx(p, pp, processed))
	{
		Debug("Rejected IPCP options ID = 0x%x\n", pp->Lcp->Id);
		processed = true;
	}

	if (ok && PPPNackLCPOptionsEx(p, pp, processed))
	{
		Debug("NACKed IPCP options ID = 0x%x\n", pp->Lcp->Id);
		processed = true;
	}

	// We will delay this packet ACK and send the server IP first, then wait for a reparse
	// it is kind of dirty but fixes issues on some clients (namely VPN Client Pro on Android)
	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_CLOSED && p->ClientAddressOption.ServerAddress != 0 && ok)
	{
		PPP_LCP *c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
		UINT ui = p->ClientAddressOption.ServerAddress;
		Add(c->OptionList, NewPPPOption(PPP_IPCP_OPTION_IP, &ui, sizeof(UINT)));
		if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_IPCP, c) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}
		IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_CONFIG);
		if (processed == false)
		{
			PPPAddNextPacket(p, pp, 1);
		}
		return false;
	}

	// We still haven't received any answer from client about server IP, keep waiting...
	if ((IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_CONFIG ||
	        IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_CLOSED) && processed == false)
	{
		PPPAddNextPacket(p, pp, 1);
		return false;
	}

	//Debug("PPPAckLCPOptionsEx ok=%x, processed=%x", ok, processed);
	if (ok == false || PPPAckLCPOptionsEx(p, pp, processed) == false)
	{
		return false;
	}
	Debug("ACKed IPCP options ID = 0x%x\n", pp->Lcp->Id);

	if (ok && IPC_PROTO_GET_STATUS(p->Ipc, IPv4State) == IPC_PROTO_STATUS_CONFIG_WAIT)
	{
		IPC_PROTO_SET_STATUS(p->Ipc, IPv4State, IPC_PROTO_STATUS_OPENED);
		Debug("IPv4 OPENED\n");
	}
	return ok;
}

// Process EAP request packets
bool PPPProcessEAPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	Debug("We got an EAP request, which is weird...\n");
	return false;
}

// Process IPv6CP request packets
bool PPPProcessIPv6CPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	UINT i;
	bool processed = false;
	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_REJECTED)
	{
		Debug("We got an IPv6CP packet after we had it rejected\n");
		return PPPRejectUnsupportedPacketEx(p, pp, true);
	}

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		switch (t->Type)
		{
		case PPP_IPV6CP_OPTION_EUI:
			t->IsSupported = true;
			if (t->DataSize == sizeof(UINT64))
			{
				UINT64 newValue = 0;
				UINT64 value = READ_UINT64(t->Data);
				if (value != 0 && value != p->Ipc->IPv6ServerEUI && IPCIPv6CheckExistingLinkLocal(p->Ipc, value) == false)
				{
					t->IsAccepted = true;
					p->Ipc->IPv6ClientEUI = value;
				}
				else
				{
					t->IsAccepted = false;
					while (true)
					{
						newValue = Rand64();
						if (newValue != 0 && newValue != p->Ipc->IPv6ServerEUI && IPCIPv6CheckExistingLinkLocal(p->Ipc, newValue) == false)
						{
							WRITE_UINT64(t->AltData, newValue);
							t->AltDataSize = sizeof(UINT64);
							break;
						}
					}
				}
			}
			break;
		default:
			t->IsSupported = false;
			break;
		}
	}

	if (PPPRejectLCPOptionsEx(p, pp, processed))
	{
		Debug("Rejected IPv6CP options ID = 0x%x\n", pp->Lcp->Id);
		processed = true;
	}

	if (PPPNackLCPOptionsEx(p, pp, processed))
	{
		Debug("NACKed IPv6CP options ID = 0x%x\n", pp->Lcp->Id);
		processed = true;
	}

	if (p->Ipc->IPv6ClientEUI != 0 && IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_CLOSED)
	{
		PPP_LCP *c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
		Add(c->OptionList, NewPPPOption(PPP_IPV6CP_OPTION_EUI, &p->Ipc->IPv6ServerEUI, sizeof(UINT64)));
		if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_IPV6CP, c) == false)
		{
			PPPSetStatus(p, PPP_STATUS_FAIL);
			WHERE;
			return false;
		}

		IPC_PROTO_SET_STATUS(p->Ipc, IPv6State, IPC_PROTO_STATUS_CONFIG);
	}

	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_CONFIG && processed == false)
	{
		PPPAddNextPacket(p, pp, 1);
		return false;
	}

	if (PPPAckLCPOptionsEx(p, pp, processed) == false)
	{
		return false;
	}
	Debug("ACKed IPv6CP options ID = 0x%x\n", pp->Lcp->Id);

	if (IPC_PROTO_GET_STATUS(p->Ipc, IPv6State) == IPC_PROTO_STATUS_CONFIG_WAIT)
	{
		IPC_PROTO_SET_STATUS(p->Ipc, IPv6State, IPC_PROTO_STATUS_OPENED);
		Debug("IPv6 OPENED\n");
	}

	return true;
}

// LCP option based packets utility
bool PPPRejectLCPOptions(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPRejectLCPOptionsEx(p, pp, false);
}
bool PPPRejectLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate)
{
	UINT i = 0;
	bool toBeRejected = false;
	PPP_PACKET *ret;
	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsSupported == false)
		{
			toBeRejected = true;
			break;
		}
	}

	if (toBeRejected == false)
	{
		return false;
	}

	ret = ZeroMalloc(sizeof(PPP_PACKET));
	ret->IsControl = true;
	ret->Protocol = pp->Protocol;
	// Return a Reject if there are unsupported parameters
	ret->Lcp = NewPPPLCP(PPP_LCP_CODE_REJECT, pp->Lcp->Id);

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsSupported == false)
		{
			// Attach the original option value as is
			Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->Data, t->DataSize));
			Debug("Rejected LCP option = 0x%x, proto = 0x%x\n", t->Type, pp->Protocol);
		}
	}

	if (LIST_NUM(ret->Lcp->OptionList) == 0 || simulate)
	{
		FreePPPPacket(ret);
		return false;
	}

	PPPSendPacketAndFree(p, ret);
	return true;
}
bool PPPNackLCPOptions(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPNackLCPOptionsEx(p, pp, false);
}
bool PPPNackLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate)
{
	UINT i = 0;
	PPP_PACKET *ret;
	bool toBeNACKed = false;
	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsAccepted == false && t->IsSupported == true)
		{
			toBeNACKed = true;
			break;
		}
	}

	if (toBeNACKed == false)
	{
		return false;
	}

	ret = ZeroMalloc(sizeof(PPP_PACKET));
	ret->IsControl = true;
	ret->Protocol = pp->Protocol;
	// Return a NAK if there are any unacceptable parameter
	// even that all parameters are supported
	ret->Lcp = NewPPPLCP(PPP_LCP_CODE_NAK, pp->Lcp->Id);

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsAccepted == false && t->IsSupported == true)
		{
			// Replace the original option value with an acceptable value
			Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->AltData, t->AltDataSize));
			Debug("NACKed LCP option = 0x%x, proto = 0x%x\n", t->Type, pp->Protocol);
		}
	}

	if (LIST_NUM(ret->Lcp->OptionList) == 0 || simulate)
	{
		FreePPPPacket(ret);
		return false;
	}

	PPPSendPacketAndFree(p, ret);
	return true;
}
bool PPPAckLCPOptions(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPAckLCPOptionsEx(p, pp, false);
}
bool PPPAckLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate)
{
	UINT i = 0;
	PPP_PACKET *ret;
	bool toBeACKed = false;
	if (LIST_NUM(pp->Lcp->OptionList) == 0)
	{
		// We acknoweldge an empty option list
		toBeACKed = true;
		Debug("ACKing empty LCP options list, id=%i\n", pp->Lcp->Id);
	}
	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsAccepted == true && t->IsSupported == true)
		{
			toBeACKed = true;
			break;
		}
	}

	if (toBeACKed == false)
	{
		return false;
	}

	ret = ZeroMalloc(sizeof(PPP_PACKET));
	ret->IsControl = true;
	ret->Protocol = pp->Protocol;
	// Return an ACK if all parameters are accepted
	ret->Lcp = NewPPPLCP(PPP_LCP_CODE_ACK, pp->Lcp->Id);

	for (i = 0; i < LIST_NUM(pp->Lcp->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(pp->Lcp->OptionList, i);

		if (t->IsAccepted == true && t->IsSupported == true)
		{
			// Attach the original option value as is
			Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->Data, t->DataSize));
			Debug("ACKed LCP option = 0x%x, proto = 0x%x\n", t->Type, pp->Protocol);
		}
	}

	if (simulate)
	{
		FreePPPPacket(ret);
		return false;
	}

	PPPSendPacketAndFree(p, ret);
	return true;
}

// PPP networking functions
// Send a request packet in the PPP
bool PPPSendAndRetransmitRequest(PPP_SESSION *p, USHORT protocol, PPP_LCP *c)
{
	PPP_PACKET *pp;
	UINT64 now = Tick64();
	PPP_REQUEST_RESEND *resend;

	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return false;
	}

	pp = ZeroMalloc(sizeof(PPP_PACKET));
	pp->Protocol = protocol;
	pp->IsControl = true;
	pp->Lcp = c;
	if (pp->Lcp->Id == 0)
	{
		pp->Lcp->Id = p->NextId++;
	}

	// Send the PPP packet
	if (PPPSendPacketEx(p, pp, false) == false)
	{
		PPPSetStatus(p, PPP_STATUS_FAIL);
		FreePPPPacket(pp);
		WHERE;
		return false;
	}

	resend = ZeroMalloc(sizeof(PPP_REQUEST_RESEND));
	resend->Id = pp->Lcp->Id;
	resend->Packet = pp;
	resend->ResendTime = now + PPP_PACKET_RESEND_INTERVAL;
	resend->TimeoutTime = now + p->PacketRecvTimeout;

	Add(p->SentReqPacketList, resend);

	return true;
}
// Send the PPP packet and frees the sent packet
bool PPPSendPacketAndFree(PPP_SESSION *p, PPP_PACKET *pp)
{
	bool result = PPPSendPacketEx(p, pp, false);
	FreePPPPacket(pp);
	return result;
}
// Send the PPP packet
bool PPPSendPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool no_flush)
{
	bool ret = false;
	BUF *b;
	// Validate arguments
	if (p == NULL || pp == NULL)
	{
		return false;
	}

	b = BuildPPPPacketData(pp);
	if (b == NULL)
	{
		return false;
	}

	ret = TubeSendEx(p->TubeSend, b->Buf, b->Size, NULL, no_flush);

	if (no_flush)
	{
		AddTubeToFlushList(p->FlushList, p->TubeSend);
	}

	FreeBuf(b);

	return ret;
}

// Receive a PPP packet
PPP_PACKET *PPPRecvPacket(PPP_SESSION *p, bool async)
{
	TUBEDATA *d;
	PPP_PACKET *pp;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

LABEL_LOOP:

	if (async == false)
	{
		d = TubeRecvSync(p->TubeRecv, (UINT)p->PacketRecvTimeout);
	}
	else
	{
		d = TubeRecvAsync(p->TubeRecv);
	}

	if (d == NULL)
	{
		return NULL;
	}

	pp = ParsePPPPacket(d->Data, d->DataSize);
	FreeTubeData(d);

	if (pp == NULL)
	{
		// A broken packet is received
		goto LABEL_LOOP;
	}

	p->LastRecvTime = Tick64();

	return pp;
}

PPP_PACKET *PPPGetNextPacket(PPP_SESSION *p)
{
	PPP_PACKET *ret = NULL;
	UINT i = 0;
	if (p->CurrentPacket != NULL)
	{
		FreePPPPacket(p->CurrentPacket);
		p->CurrentPacket = NULL;
	}
	for (i = 0; i < LIST_NUM(p->DelayedPackets); i++)
	{
		PPP_DELAYED_PACKET *t = LIST_DATA(p->DelayedPackets, i);
		if (t->DelayTicks > 0)
		{
			t->DelayTicks--;
		}
		else
		{
			ret = t->Packet;
			Delete(p->DelayedPackets, t);
			Free(t);
			break;
		}
	}

	if (ret != NULL)
	{
		p->CurrentPacket = ret;
		return ret;
	}

	ret = PPPRecvPacket(p, true);

	if (ret != NULL && ret->IsControl && ret->Lcp != NULL)
	{
		PPP_DELAYED_PACKET *firstRelated = NULL;
		for (i = 0; i < LIST_NUM(p->DelayedPackets); i++)
		{
			PPP_DELAYED_PACKET *t = LIST_DATA(p->DelayedPackets, i);
			char related = PPPRelatedPacketComparator(ret, t->Packet);
			if (related != 0xF && related != 0xE)
			{
				if (related == 0)
				{
					// It's the same packet, just remove it and wait for it's delays
					FreePPPPacket(ret);
					firstRelated = NULL;
					ret = NULL;
					break;
				}
				if (related == 1)
				{
					// We got a packet which should come later than any of delayed ones
					PPPAddNextPacket(p, ret, t->DelayTicks);
					firstRelated = NULL;
					ret = NULL;
					break;
				}
				if (related == -1)
				{
					char prevFoundRelated = -1;
					if (firstRelated != NULL)
					{
						prevFoundRelated = PPPRelatedPacketComparator(t->Packet, firstRelated->Packet);
					}
					if (prevFoundRelated == -1)
					{
						firstRelated = t;
					}
				}
			}
		}

		if (firstRelated != NULL)
		{
			PPPAddNextPacket(p, ret, firstRelated->DelayTicks);
			ret = NULL;
		}
	}

	p->CurrentPacket = ret;
	return ret;
}

void PPPAddNextPacket(PPP_SESSION *p, PPP_PACKET *pp, UINT delay)
{
	PPP_DELAYED_PACKET *t = ZeroMalloc(sizeof(PPP_DELAYED_PACKET));
	if (p->CurrentPacket == pp)
	{
		p->CurrentPacket = NULL;
	}
	t->Packet = pp;
	t->DelayTicks = delay;
	Add(p->DelayedPackets, t);
	Sort(p->DelayedPackets);
	/*Debug("after sorting delayeds\n");
	for (i = 0; i < LIST_NUM(p->DelayedPackets); i++)
	{
		t = LIST_DATA(p->DelayedPackets, i);
		if (t->Packet->Lcp != NULL)
		{
			Debug("> Packet proto = 0x%x, id = 0x%x, code = 0x%x, delay = 0x%x\n", t->Packet->Protocol, t->Packet->Lcp->Id, t->Packet->Lcp->Code, t->DelayTicks);
		}
	}
	Debug("after sorting delayeds end\n");*/
}

int PPPDelayedPacketsComparator(void *a, void *b)
{
	PPP_DELAYED_PACKET *first = a;
	PPP_DELAYED_PACKET *second = b;

	char related = PPPRelatedPacketComparator(first->Packet, second->Packet);

	if (related == 0xF || related == 0xE)
	{
		if (first->DelayTicks < second->DelayTicks)
		{
			return -1;
		}
		if (first->DelayTicks > second->DelayTicks)
		{
			return 1;
		}
		return 0;
	}

	// We make all delay ticks to be accounted with the sorting
	if (related <= 1 && related >= -1)
	{
		if (related == -1 && first->DelayTicks >= second->DelayTicks)
		{
			second->DelayTicks = first->DelayTicks;
			second->DelayTicks++;
		}
		else if (related == 1 && first->DelayTicks <= second->DelayTicks)
		{
			first->DelayTicks = second->DelayTicks;
			first->DelayTicks++;
		}
		return related;
	}
	return 0;
}

// -1 - packet a comes before packet b
// 0 - this is the same packet
// 1 - packet a comes after packet b
// 0xF - packet is not related
// 0xE - we got an error while comparing, treating as not related would be the most correct
char PPPRelatedPacketComparator(PPP_PACKET *a, PPP_PACKET *b)
{
	if (a->IsControl && b->IsControl &&
	        a->Lcp != NULL && b->Lcp != NULL &&
	        a->Protocol == b->Protocol &&
	        PPP_CODE_IS_REQUEST(a->Protocol, a->Lcp->Code) == PPP_CODE_IS_REQUEST(b->Protocol, b->Lcp->Code) &&
	        PPP_CODE_IS_RESPONSE(a->Protocol, a->Lcp->Code) == PPP_CODE_IS_RESPONSE(b->Protocol, b->Lcp->Code))
	{
		// The packet is related!
		if (a->Lcp->Id < b->Lcp->Id)
		{
			return -1;
		}
		else if (a->Lcp->Id == b->Lcp->Id)
		{
			if (a->Lcp->Code == b->Lcp->Code)
			{
				return 0;
			}
			else
			{
				return 0xE;
			}
		}
		else if (a->Lcp->Id > b->Lcp->Id)
		{
			return 1;
		}
		else
		{
			return 0xE;
		}
	}
	else
	{
		// The packet is not related!
		return 0xF;
	}
}

// PPP utility functions
// Packet structure creation utilities

// Create the LCP
PPP_LCP *NewPPPLCP(UCHAR code, UCHAR id)
{
	PPP_LCP *c = ZeroMalloc(sizeof(PPP_LCP));

	c->Code = code;
	c->Id = id;
	c->OptionList = NewListFast(NULL);

	return c;
}

// Create a new PPP options
PPP_OPTION *NewPPPOption(UCHAR type, void *data, UINT size)
{
	PPP_OPTION *o;
	// Validate arguments
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(PPP_OPTION));

	o->Type = type;
	Copy(o->Data, data, size);
	o->DataSize = size;

	return o;
}

// Packet parse utilities

// Analyse the PPP packet
PPP_PACKET *ParsePPPPacket(void *data, UINT size)
{
	PPP_PACKET *pp;
	UCHAR *buf;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	pp = ZeroMalloc(sizeof(PPP_PACKET));

	buf = (UCHAR *)data;

	// Address
	if (buf[0] != 0xff)
	{
		goto LABEL_ERROR;
	}
	size--;
	buf++;

	// Control
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	if (buf[0] != 0x03)
	{
		goto LABEL_ERROR;
	}
	size--;
	buf++;

	// Protocol
	if (size < 2)
	{
		goto LABEL_ERROR;
	}
	pp->Protocol = READ_USHORT(buf);

	size -= 2;
	buf += 2;

	if (pp->Protocol == PPP_PROTOCOL_LCP || pp->Protocol == PPP_PROTOCOL_PAP || pp->Protocol == PPP_PROTOCOL_CHAP || pp->Protocol == PPP_PROTOCOL_IPCP || pp->Protocol == PPP_PROTOCOL_IPV6CP || pp->Protocol == PPP_PROTOCOL_EAP)
	{
		pp->IsControl = true;
	}

	pp->Data = Clone(buf, size);
	pp->DataSize = size;

	if (pp->IsControl)
	{
		pp->Lcp = PPPParseLCP(pp->Protocol, pp->Data, pp->DataSize);
		if (pp->Lcp == NULL)
		{
			goto LABEL_ERROR;
		}
	}

	return pp;

LABEL_ERROR:
	FreePPPPacket(pp);
	return NULL;
}

// Analyse the LCP data
PPP_LCP *PPPParseLCP(USHORT protocol, void *data, UINT size)
{
	UCHAR *buf;
	PPP_LCP *c;
	USHORT len;
	bool has_option_list = false;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	buf = (UCHAR *)data;
	c = ZeroMalloc(sizeof(PPP_LCP));

	c->OptionList = NewListFast(NULL);

	// Code
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	c->Code = buf[0];
	buf++;
	size--;

	// ID
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	c->Id = buf[0];
	buf++;
	size--;

	// Length
	if (size < 2)
	{
		goto LABEL_ERROR;
	}
	len = READ_USHORT(buf);
	// Fix bad endianness
	if (len > size)
	{
		USHORT len1 = Swap16(len);
		if (len1 <= size)
		{
			len = len1;
		}
	}
	if (len < 4)
	{
		goto LABEL_ERROR;
	}
	len -= 4;
	buf += 2;
	size -= 2;

	// Options or Data
	if (size < len)
	{
		goto LABEL_ERROR;
	}

	has_option_list = PPP_CODE_IS_WITH_OPTION_LIST(protocol, c->Code);

	if (has_option_list == false)
	{
		c->Data = Clone(buf, size);
		c->DataSize = size;
	}
	else
	{
		// Option List
		while (len >= 1)
		{
			PPP_OPTION o;

			Zero(&o, sizeof(o));

			// Type
			if (len < 1)
			{
				goto LABEL_ERROR;
			}
			o.Type = buf[0];
			buf++;
			len--;

			// Length
			if (len < 1)
			{
				goto LABEL_ERROR;
			}
			o.DataSize = buf[0];
			if (o.DataSize < 2)
			{
				goto LABEL_ERROR;
			}
			o.DataSize -= 2;
			buf++;
			len--;

			// Data
			if (len < o.DataSize)
			{
				goto LABEL_ERROR;
			}
			Copy(o.Data, buf, o.DataSize);
			buf += o.DataSize;
			len -= o.DataSize;

			Add(c->OptionList, Clone(&o, sizeof(o)));
		}
	}

	return c;

LABEL_ERROR:
	FreePPPLCP(c);
	return NULL;
}

// Analyse MS CHAP v2 Response packet
bool PPPParseMSCHAP2ResponsePacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPParseMSCHAP2ResponsePacketEx(p, pp->Lcp, false);
}
bool PPPParseMSCHAP2ResponsePacketEx(PPP_SESSION *p, PPP_LCP *lcp, bool use_eap)
{
	bool ok = false;

	char client_ip_tmp[256];
	EAP_CLIENT *eap;

	UCHAR client_response_buffer[49];
	UCHAR *client_challenge_16;
	UCHAR *client_response_24;
	char username_tmp[MAX_SIZE];
	IPC *ipc = NULL;
	char id[MAX_SIZE];
	char hub[MAX_SIZE];
	char password[MAX_SIZE];
	char server_challenge_hex[MAX_SIZE];
	char client_challenge_hex[MAX_SIZE];
	char client_response_hex[MAX_SIZE];
	char eap_client_hex[64];
	ETHERIP_ID d;
	UINT error_code;
	UINT64 eap_client_ptr = (UINT64)p->EapClient;

	if (lcp != NULL && lcp->DataSize >= 51)
	{
		BUF *b;
		if (lcp->Id != p->MsChapV2_PacketId)
		{
			Debug("Got incorrect LCP PacketId! Should be 0x%x, got 0x%x\n", p->MsChapV2_PacketId, lcp->Id);
			p->MsChapV2_PacketId = lcp->Id;
		}

		b = NewBuf();

		WriteBuf(b, lcp->Data, lcp->DataSize);
		SeekBuf(b, 0, 0);

		if (ReadBufChar(b) == 49)
		{
			ReadBuf(b, client_response_buffer, 49);

			Zero(username_tmp, sizeof(username_tmp));
			ReadBuf(b, username_tmp, sizeof(username_tmp) - 1);
			Debug("MS-CHAPv2: id=%s\n", username_tmp);

			client_challenge_16 = client_response_buffer + 0;
			client_response_24 = client_response_buffer + 16 + 8;

			Copy(p->MsChapV2_ClientChallenge, client_challenge_16, 16);
			Copy(p->MsChapV2_ClientResponse, client_response_24, 24);

			Zero(id, sizeof(id));
			Zero(hub, sizeof(hub));

			// The user name is divided into the ID and the virtual HUB name
			Zero(&d, sizeof(d));
			PPPParseUsername(p->Cedar, username_tmp, &d);

			StrCpy(id, sizeof(id), d.UserName);
			StrCpy(hub, sizeof(hub), d.HubName);
			Debug("MS-CHAPv2: username=%s, hubname=%s\n", id, hub);

			IPToStr(client_ip_tmp, sizeof(client_ip_tmp), &p->ClientIP);

			// Convert the MS-CHAPv2 data to a password string
			BinToStr(server_challenge_hex, sizeof(server_challenge_hex),
			         p->MsChapV2_ServerChallenge, sizeof(p->MsChapV2_ServerChallenge));
			BinToStr(client_challenge_hex, sizeof(client_challenge_hex),
			         p->MsChapV2_ClientChallenge, sizeof(p->MsChapV2_ClientChallenge));
			BinToStr(client_response_hex, sizeof(client_response_hex),
			         p->MsChapV2_ClientResponse, sizeof(p->MsChapV2_ClientResponse));
			BinToStr(eap_client_hex, sizeof(eap_client_hex),
			         &eap_client_ptr, 8);

			Format(password, sizeof(password), "%s%s:%s:%s:%s:%s",
			       IPC_PASSWORD_MSCHAPV2_TAG,
			       username_tmp,
			       server_challenge_hex,
			       client_challenge_hex,
			       client_response_hex,
			       eap_client_hex);

			// Normal MSCHAPv2 only
			// For EAP-MSCHAPv2, EAP client is created before sending the challenge
			if (p->UseEapRadius && p->EapClient == NULL && use_eap == false)
			{
				Debug("Double MSCHAPv2 creating EAP client\n");
				eap = HubNewEapClient(p->Cedar, hub, client_ip_tmp, id, "L3:PPP", false, NULL, 0);

				// We do not know the user's auth type, so do not fail PPP if eap is null
				if (eap)
				{
					ok = true;
					p->EapClient = eap;
					FreeBuf(b);
					return ok;
				}
			}
			if (p->Ipc == NULL)
			{
				Debug("MSCHAPv2 creating IPC\n");
				ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, hub, id, password, NULL,
				             &error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
				             p->ClientHostname, p->CryptName, false, p->AdjustMss, p->EapClient, NULL,
				             false, IPC_LAYER_3);

				if (ipc != NULL)
				{
					p->Ipc = ipc;

					// Setting user timeouts
					p->PacketRecvTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000 * 3 / 4; // setting to 3/4 of the user timeout
					p->DataTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000;
					if (p->TubeRecv != NULL)
					{
						p->TubeRecv->DataTimeout = p->DataTimeout;
					}
					p->UserConnectionTimeout = (UINT64)p->Ipc->Policy->AutoDisconnect * 1000;
					p->UserConnectionTick = Tick64();

					Copy(p->MsChapV2_ServerResponse, ipc->MsChapV2_ServerResponse, 20);

					ok = true;

					p->AuthOk = true;
				}
			}
			else
			{
				Debug("Got weird packet when we already have an active IPC! Ipc = 0x%x, AuthOk = 0x%x, Status = 0x%x\n", p->Ipc, p->AuthOk, p->PPPStatus);
				ok = p->AuthOk;
			}
		}

		FreeBuf(b);
	}
	else
	{
		Debug("Got invalid MSCHAPv2 packet\n");
	}

	return ok;
}

// Packet building utilities

// Build a PPP packet data
BUF *BuildPPPPacketData(PPP_PACKET *pp)
{
	BUF *ret;
	UCHAR c;
	USHORT us;
	// Validate arguments
	if (pp == NULL)
	{
		return NULL;
	}

	ret = NewBuf();

	// Address
	c = 0xff;
	WriteBuf(ret, &c, 1);

	// Control
	c = 0x03;
	WriteBuf(ret, &c, 1);

	// Protocol
	us = Endian16(pp->Protocol);
	WriteBuf(ret, &us, 2);

	if (pp->IsControl)
	{
		// LCP
		BUF *b = BuildLCPData(pp->Lcp);

		WriteBufBuf(ret, b);

		FreeBuf(b);
	}
	else
	{
		// Data
		WriteBuf(ret, pp->Data, pp->DataSize);
	}

	SeekBuf(ret, 0, 0);

	return ret;
}

// Build the LCP packet data
BUF *BuildLCPData(PPP_LCP *c)
{
	BUF *b;
	UCHAR zero = 0;
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Code
	WriteBuf(b, &c->Code, 1);

	// ID
	WriteBuf(b, &c->Id, 1);

	// Length (to be updated later)
	zero = 0;
	WriteBuf(b, &zero, 1);
	WriteBuf(b, &zero, 1);

	if (c->Data == NULL)
	{
		// Option List
		for (i = 0; i < LIST_NUM(c->OptionList); i++)
		{
			PPP_OPTION *o = LIST_DATA(c->OptionList, i);
			UCHAR sz = o->DataSize + 2;

			WriteBuf(b, &o->Type, 1);
			WriteBuf(b, &sz, 1);

			WriteBuf(b, o->Data, o->DataSize);
		}
	}
	else
	{
		// Data
		WriteBuf(b, c->Data, c->DataSize);
	}

	SeekBuf(b, 0, 0);

	// Update Length
	WRITE_USHORT(((UCHAR *)b->Buf) + 2, b->Size);

	return b;
}

// Build the MS CHAP v2 challenge packet
PPP_LCP *BuildMSCHAP2ChallengePacket(PPP_SESSION *p)
{
	PPP_LCP *lcp;
	BUF *b;
	char machine_name[MAX_SIZE];
	UINT64 now = Tick64();

	// Generate a Server Challenge packet of MS-CHAP v2
	GetMachineHostName(machine_name, sizeof(machine_name));

	if (p->EapClient == NULL)
	{
		MsChapV2Server_GenerateChallenge(p->MsChapV2_ServerChallenge);
	}
	else
	{
		Copy(p->MsChapV2_ServerChallenge, p->EapClient->MsChapV2Challenge.Chap_ChallengeValue, 16);
	}

	p->MsChapV2_PacketId = p->NextId++;
	lcp = NewPPPLCP(PPP_CHAP_CODE_CHALLENGE, p->MsChapV2_PacketId);

	b = NewBuf();
	WriteBufChar(b, 16);
	WriteBuf(b, p->MsChapV2_ServerChallenge, sizeof(p->MsChapV2_ServerChallenge));
	WriteBuf(b, machine_name, StrLen(machine_name));
	lcp->Data = Clone(b->Buf, b->Size);
	lcp->DataSize = b->Size;
	FreeBuf(b);

	Debug("Building MS-CHAP v2 Challenge\n");

	return lcp;
}

// IPCP packet utilities

// Set the IP options of PPP to LCP
bool PPPSetIPOptionToLCP(PPP_IPOPTION *o, PPP_LCP *c, bool only_modify)
{
	bool ret = false;
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	ret = PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_IP, &o->IpAddress, only_modify);

	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_DNS1, &o->DnsServer1, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_DNS2, &o->DnsServer2, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_WINS1, &o->WinsServer1, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_WINS2, &o->WinsServer2, only_modify);

	return ret;
}

// Get the IP options of PPP from LCP
bool PPPGetIPOptionFromLCP(PPP_IPOPTION *o, PPP_LCP *c)
{
	bool ret;
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	Zero(o, sizeof(PPP_IPOPTION));

	ret = PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_IP, &o->IpAddress);

	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_DNS1, &o->DnsServer1);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_DNS2, &o->DnsServer2);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_WINS1, &o->WinsServer1);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_WINS2, &o->WinsServer2);

	return ret;
}

// Set the IP address data to the option list of the LCP
bool PPPSetIPAddressValueToLCP(PPP_LCP *c, UINT type, IP *ip, bool only_modify)
{
	IP ip2;
	UINT ui;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	ui = IPToUINT(ip);

	if (PPPGetIPAddressValueFromLCP(c, type, &ip2))
	{
		PPP_OPTION *opt;
		opt = PPPGetOptionValue(c, type);

		if (opt != NULL)
		{
			if (IsZeroIP(ip) == false)
			{
				if (CmpIpAddr(&ip2, ip) == 0)
				{
					// No change
					opt->IsAccepted = true;
					opt->IsSupported = true;
				}
				else
				{
					// Changed
					opt->IsAccepted = false;
					opt->IsSupported = true;
					opt->AltDataSize = 4;
					Copy(opt->AltData, &ui, 4);
				}
			}
			else
			{
				// The parameter itself is not supported
				// (if the IP address is 0.0.0.0)
				opt->IsSupported = false;
				opt->IsAccepted = false;
			}
		}

		return true;
	}
	else
	{
		if (IsZeroIP(ip) == false)
		{
			// Add as a new item
			if (only_modify != false)
			{
				return false;
			}
			else
			{
				PPP_OPTION *opt2 = NewPPPOption(type, &ui, 4);
				UCHAR ipstr[MAX_SIZE];

				opt2->IsAccepted = true;
				opt2->IsSupported = true;
				Copy(opt2->AltData, opt2->Data, opt2->DataSize);
				opt2->AltDataSize = opt2->DataSize;

				Add(c->OptionList, opt2);
				IPToStr(ipstr, MAX_SIZE, ip);

				return true;
			}
		}
		else
		{
			return false;
		}
	}
}

// Get the IP address data from the option list of the LCP
bool PPPGetIPAddressValueFromLCP(PPP_LCP *c, UINT type, IP *ip)
{
	PPP_OPTION *opt;
	UINT ui;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	opt = PPPGetOptionValue(c, type);
	if (opt == NULL)
	{
		return false;
	}

	if (opt->DataSize != 4)
	{
		return false;
	}

	opt->IsSupported = true;

	ui = *((UINT *)opt->Data);

	UINTToIP(ip, ui);

	return true;
}

// EAP packet utilities
bool PPPProcessEAPTlsResponse(PPP_SESSION *p, PPP_EAP *eap_packet, UINT eapSize)
{
	UCHAR *dataBuffer;
	UINT dataSize;
	UINT tlsLength = 0;
	bool isFragmented = false;
	PPP_LCP *lcp;
	PPP_EAP *eap;
	UCHAR flags = PPP_EAP_TLS_FLAG_NONE;
	UINT sizeLeft = 0;
	Debug("Got EAP-TLS size=%i\n", eapSize);
	if (eapSize == 0)
	{
		// This is a broken packet without flags, ignore it
		return false;
	}
	if (eapSize == 1 && eap_packet->Tls.Flags == PPP_EAP_TLS_FLAG_NONE)
	{
		// This is an EAP-TLS message ACK
		if (p->Eap_TlsCtx.CachedBufferSend != NULL)
		{
			// We got an ACK to transmit the next fragmented message
			dataSize = p->Mru1 - 8 - 1 - 1; // Calculating the maximum payload size (without TlsLength)
			sizeLeft = GetMemSize(p->Eap_TlsCtx.CachedBufferSend);
			sizeLeft -= (UINT)(p->Eap_TlsCtx.CachedBufferSendPntr - p->Eap_TlsCtx.CachedBufferSend);

			flags = PPP_EAP_TLS_FLAG_FRAGMENTED; // M flag
			if (dataSize > sizeLeft)
			{
				dataSize = sizeLeft;
				flags = PPP_EAP_TLS_FLAG_NONE; // Clearing the M flag because it is the last packet
			}
			p->Eap_PacketId = p->NextId++;
			lcp = BuildEAPTlsRequest(p->Eap_PacketId, dataSize, flags);
			eap = lcp->Data;
			Copy(eap->Tls.TlsDataWithoutLength, p->Eap_TlsCtx.CachedBufferSendPntr, dataSize);
			p->Eap_TlsCtx.CachedBufferSendPntr += (UINT64)dataSize;

			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			Debug("Sent EAP-TLS size=%i type=%i flag=%i\n", lcp->DataSize, eap->Type, eap->Tls.Flags);

			if (flags == PPP_EAP_TLS_FLAG_NONE)
			{
				// As it is the latest message, we need to cleanup
				Free(p->Eap_TlsCtx.CachedBufferSend);
				p->Eap_TlsCtx.CachedBufferSend = NULL;
				p->Eap_TlsCtx.CachedBufferSendPntr = NULL;
			}
		}
		else if (p->AuthOk == true && p->Ipc != NULL && p->PPPStatus == PPP_STATUS_AUTHENTICATING)
		{
			// The handshake terminated and we received the final ACK, the auth is successful
			// Just send an EAP-Success
			PPP_PACKET* pack;
			UINT identificator = p->Eap_PacketId;

			PPPSetStatus(p, PPP_STATUS_AUTH_SUCCESS);
			pack = ZeroMalloc(sizeof(PPP_PACKET));
			pack->IsControl = true;
			pack->Protocol = PPP_PROTOCOL_EAP;
			lcp = NewPPPLCP(PPP_EAP_CODE_SUCCESS, identificator);
			pack->Lcp = lcp;
			Debug("Sent EAP-TLS size=%i SUCCESS\n", lcp->DataSize);
			if (PPPSendPacketAndFree(p, pack) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			return true;
		}
		else if (p->Eap_TlsCtx.ClientCert.X == NULL)
		{
			// Some clients needs a little help it seems - namely VPN Client Pro on Android
			flags |= PPP_EAP_TLS_FLAG_SSLSTARTED;
			p->Eap_PacketId = p->NextId++;
			lcp = BuildEAPTlsRequest(p->Eap_PacketId, 0, flags);
			PPPSetStatus(p, PPP_STATUS_AUTHENTICATING);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			Debug("Sent EAP-TLS size=%i\n", lcp->DataSize);
		}
		return true;
	}
	dataBuffer = eap_packet->Tls.TlsDataWithoutLength;
	dataSize = eapSize - 1;
	if (eap_packet->Tls.Flags & PPP_EAP_TLS_FLAG_TLS_LENGTH && dataSize >= 4)
	{
		dataBuffer = eap_packet->Tls.TlsDataWithLength.Data;
		dataSize -= 4;
		tlsLength = Endian32(eap_packet->Tls.TlsDataWithLength.TlsLength);
	}
	/*Debug("=======RECV EAP-TLS PACKET DUMP=======\n");
	for (i = 0; i < dataSize; i++)
	{
		if (i > 0) printf(" ");
		Debug("%02X", dataBuffer[i]);
	}
	Debug("\n=======RECV EAP-TLS PACKET DUMP END=======\n");*/
	if (eap_packet->Tls.Flags & PPP_EAP_TLS_FLAG_FRAGMENTED)
	{
		isFragmented = true;
	}

	if (p->PPPStatus == PPP_STATUS_AUTHENTICATING)
	{
		// First we initialize the SslPipe if it is not already inited
		if (p->Eap_TlsCtx.SslPipe == NULL)
		{
			p->Eap_TlsCtx.Dh = DhNewFromBits(DH_PARAM_BITS_DEFAULT);
			p->Eap_TlsCtx.SslPipe = NewSslPipeEx3(true, p->Cedar->ServerX, p->Cedar->ServerK, p->Cedar->ServerChain, p->Eap_TlsCtx.Dh, true, &(p->Eap_TlsCtx.ClientCert), p->Eap_TlsCtx.Tls13SessionTicketsCount, p->Eap_TlsCtx.DisableTls13);
			if (p->Eap_TlsCtx.SslPipe == NULL)
			{
				Debug("EAP-TLS: NewSslPipeEx3 failed\n");
				PPPSetStatus(p, PPP_STATUS_FAIL);
				return false;
			}
		}

		// If the current frame is fragmented, or it is a possible last of a fragmented series, bufferize it
		if (isFragmented || p->Eap_TlsCtx.CachedBufferRecv != NULL)
		{
			if (p->Eap_TlsCtx.CachedBufferRecv == NULL && tlsLength > 0)
			{
				p->Eap_TlsCtx.CachedBufferRecv = ZeroMalloc(MAX(dataSize, tlsLength));
				p->Eap_TlsCtx.CachedBufferRecvPntr = p->Eap_TlsCtx.CachedBufferRecv;
			}
			else if (p->Eap_TlsCtx.CachedBufferRecv == NULL)
			{
				p->Eap_TlsCtx.CachedBufferRecv = ZeroMalloc(MAX(dataSize, PPP_MRU_MAX * 10)); // 10 MRUs should be enough
				p->Eap_TlsCtx.CachedBufferRecvPntr = p->Eap_TlsCtx.CachedBufferRecv;
			}
			sizeLeft = GetMemSize(p->Eap_TlsCtx.CachedBufferRecv);
			sizeLeft -= (UINT)(p->Eap_TlsCtx.CachedBufferRecvPntr - p->Eap_TlsCtx.CachedBufferRecv);

			Copy(p->Eap_TlsCtx.CachedBufferRecvPntr, dataBuffer, MIN(sizeLeft, dataSize));

			p->Eap_TlsCtx.CachedBufferRecvPntr += MIN(sizeLeft, dataSize);
		}

		// If we got a cached buffer, we should feed the FIFOs via it
		if (p->Eap_TlsCtx.CachedBufferRecv != NULL)
		{
			dataBuffer = p->Eap_TlsCtx.CachedBufferRecv;
			dataSize = GetMemSize(p->Eap_TlsCtx.CachedBufferRecv);
			if (dataSize == MAX_BUFFERING_PACKET_SIZE)
			{
				dataSize = (UINT)(p->Eap_TlsCtx.CachedBufferRecvPntr - p->Eap_TlsCtx.CachedBufferRecv);
			}
		}

		// Just acknoweldge that we buffered the fragmented data
		if (isFragmented)
		{
			p->Eap_PacketId = p->NextId++;
			PPP_LCP *lcp = BuildEAPTlsRequest(p->Eap_PacketId, 0, PPP_EAP_TLS_FLAG_NONE);
			if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
			{
				PPPSetStatus(p, PPP_STATUS_FAIL);
				WHERE;
				return false;
			}
			Debug("Sent EAP-TLS size=%i\n", lcp->DataSize);
			return true;
		}
		else
		{
			bool syncOk;
			/*Debug("=======RECV EAP-TLS FIFO DUMP=======\n");
			for (i = 0; i < dataSize; i++)
			{
				if (i > 0) printf(" ");
				Debug("%02X", dataBuffer[i]);
			}
			Debug("\n=======RECV EAP-TLS PACKET FIFO END=======\n");*/
			WriteFifo(p->Eap_TlsCtx.SslPipe->RawIn->SendFifo, dataBuffer, dataSize);
			syncOk = SyncSslPipe(p->Eap_TlsCtx.SslPipe);

			// Delete the cached buffer after we fed it into the pipe
			if (p->Eap_TlsCtx.CachedBufferRecv != NULL)
			{
				Free(p->Eap_TlsCtx.CachedBufferRecv);
				p->Eap_TlsCtx.CachedBufferRecv = NULL;
				p->Eap_TlsCtx.CachedBufferRecvPntr = NULL;
			}

			// Special case - we attempt to restart downgrading TLS settings
			if (!syncOk && (p->Eap_TlsCtx.DisableTls13 == false || p->Eap_TlsCtx.Tls13SessionTicketsCount == 0))
			{
				// If we authenticated earlier, deauthenticate back
				p->DataTimeout = PPP_DATA_TIMEOUT;
				p->PacketRecvTimeout = PPP_PACKET_RECV_TIMEOUT;
				p->UserConnectionTimeout = 0;
				p->UserConnectionTick = 0;
				if (p->Ipc != NULL)
				{
					FreeIPC(p->Ipc);
					p->Ipc = NULL;
					p->AuthOk = false;
				}

				FreeSslPipe(p->Eap_TlsCtx.SslPipe);
				DhFree(p->Eap_TlsCtx.Dh);
				p->Eap_TlsCtx.SslPipe = NULL;
				p->Eap_TlsCtx.Dh = NULL;
				if (p->Eap_TlsCtx.Tls13SessionTicketsCount == 0)
				{
					p->Eap_TlsCtx.DisableTls13 = true;
				}
				else
				{
					p->Eap_TlsCtx.Tls13SessionTicketsCount = 0;
				}
				flags |= PPP_EAP_TLS_FLAG_SSLSTARTED;
				p->Eap_PacketId = p->NextId++;
				lcp = BuildEAPTlsRequest(p->Eap_PacketId, 0, flags);
				if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				Debug("EAP-TLS: Restarting the handshake! Tls13SessionTicketsCount = %d, DisableTls13 = %d\n", p->Eap_TlsCtx.Tls13SessionTicketsCount, p->Eap_TlsCtx.DisableTls13);
				Debug("Sent EAP-TLS size=%i\n", lcp->DataSize);
				return false;
			}

			// If on the server we have enough data to authenticate, let's do this before we continue with the handshake
			// Check if we received the client certificate and the handshake is finished
			if (p->Eap_TlsCtx.ClientCert.X != NULL && p->Ipc == NULL)
			{
				IPC* ipc;
				UINT error_code;

				if (p->Eap_MatchUserByCert)
				{
					HUB *hub;
					bool found = false;

					LockHubList(p->Cedar);
					{
						hub = GetHub(p->Cedar, p->Eap_Identity.HubName);
					}
					UnlockHubList(p->Cedar);

					if (hub != NULL)
					{
						AcLock(hub);
						{
							USER* user = AcGetUserByCert(hub, p->Eap_TlsCtx.ClientCert.X);
							if (user != NULL)
							{
								StrCpy(p->Eap_Identity.UserName, sizeof(p->Eap_Identity.UserName), user->Name);
								found = true;
								ReleaseUser(user);
							}
						}
						AcUnlock(hub);
						ReleaseHub(hub);
					}

					if (found == false)
					{
						PPP_PACKET* pack;
						UINT identificator = p->Eap_PacketId;

						ReleaseHub(hub);

						PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);

						pack = ZeroMalloc(sizeof(PPP_PACKET));
						pack->IsControl = true;
						pack->Protocol = PPP_PROTOCOL_EAP;
						lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, identificator);
						pack->Lcp = lcp;
						Debug("Sent EAP-TLS size=%i FAILURE\n", lcp->DataSize);
						if (PPPSendPacketAndFree(p, pack) == false)
						{
							PPPSetStatus(p, PPP_STATUS_FAIL);
							WHERE;
							return false;
						}
						return false;
					}
				}

				ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, p->Eap_Identity.HubName, p->Eap_Identity.UserName, "", NULL,
					&error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
					p->ClientHostname, p->CryptName, false, p->AdjustMss, NULL, p->Eap_TlsCtx.ClientCert.X,
					false, IPC_LAYER_3);

				// We use the SAM authentication here, because the handshake can still fail at this point
				if (ipc != NULL)
				{
					// Setting user timeouts
					p->Ipc = ipc;
					p->PacketRecvTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000 * 3 / 4; // setting to 3/4 of the user timeout
					p->DataTimeout = (UINT64)p->Ipc->Policy->TimeOut * 1000;
					if (p->TubeRecv != NULL)
					{
						p->TubeRecv->DataTimeout = p->DataTimeout;
					}
					p->UserConnectionTimeout = (UINT64)p->Ipc->Policy->AutoDisconnect * 1000;
					p->UserConnectionTick = Tick64();

					p->AuthOk = true;

					if (p->Eap_TlsCtx.SslPipe->SslVersion == TLS1_3_VERSION)
					{
						// Before starting IPC and sending an EAP-Success in case of TLS 1.3 we need to send a 0x00 data packet as per RFC 9190
						char zeroPacket[1] = { 0 };
						WriteFifo(p->Eap_TlsCtx.SslPipe->SslInOut->SendFifo, zeroPacket, sizeof(zeroPacket));
						if (!SyncSslPipe(p->Eap_TlsCtx.SslPipe))
						{
							PPPSetStatus(p, PPP_STATUS_FAIL);
							WHERE;
							return false;
						}
					}
				}
				else
				{
					PPP_PACKET* pack;
					UINT identificator = p->Eap_PacketId;

					PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);

					pack = ZeroMalloc(sizeof(PPP_PACKET));
					pack->IsControl = true;
					pack->Protocol = PPP_PROTOCOL_EAP;
					lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, identificator);
					pack->Lcp = lcp;
					Debug("Sent EAP-TLS size=%i FAILURE\n", lcp->DataSize);
					if (PPPSendPacketAndFree(p, pack) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
					return false;
				}
			}

			// We continue the TLS handshake
			if (p->Eap_TlsCtx.SslPipe->IsDisconnected == false)
			{
				dataSize = FifoSize(p->Eap_TlsCtx.SslPipe->RawOut->RecvFifo);
				// Do we need to send a fragmented packet?
				if (dataSize > p->Mru1 - 8 - 1 - 1)
				{
					if (p->Eap_TlsCtx.CachedBufferSend == NULL)
					{
						p->Eap_TlsCtx.CachedBufferSend = ZeroMalloc(dataSize);
						p->Eap_TlsCtx.CachedBufferSendPntr = p->Eap_TlsCtx.CachedBufferSend;
					}
					ReadFifo(p->Eap_TlsCtx.SslPipe->RawOut->RecvFifo, p->Eap_TlsCtx.CachedBufferSend, dataSize);

					// Now send data from the cached buffer with set fragmentation flag and also total TLS Size
					tlsLength = dataSize;
					dataSize = p->Mru1 - 8 - 1 - 1 - 4; // Calculating the maximum payload size (adjusting for including TlsLength)
					flags = PPP_EAP_TLS_FLAG_TLS_LENGTH; // L flag
					flags |= PPP_EAP_TLS_FLAG_FRAGMENTED; // M flag
					p->Eap_PacketId = p->NextId++;
					lcp = BuildEAPTlsRequest(p->Eap_PacketId, dataSize, flags);
					eap = lcp->Data;
					eap->Tls.TlsDataWithLength.TlsLength = Endian32(tlsLength);
					Copy(eap->Tls.TlsDataWithLength.Data, p->Eap_TlsCtx.CachedBufferSend, dataSize);
					p->Eap_TlsCtx.CachedBufferSendPntr += dataSize;
					if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
					Debug("Sent EAP-TLS size=%i type=%i flag=%i\n", lcp->DataSize, eap->Type, eap->Tls.Flags);
					return true;
				}
				else if (dataSize > 0 || p->Eap_TlsCtx.ClientCert.X == NULL)
				{
					p->Eap_PacketId = p->NextId++;
					lcp = BuildEAPTlsRequest(p->Eap_PacketId, dataSize, 0);
					eap = lcp->Data;
					ReadFifo(p->Eap_TlsCtx.SslPipe->RawOut->RecvFifo, &(eap->Tls.TlsDataWithoutLength), dataSize);
					if (PPPSendAndRetransmitRequest(p, PPP_PROTOCOL_EAP, lcp) == false)
					{
						PPPSetStatus(p, PPP_STATUS_FAIL);
						WHERE;
						return false;
					}
					Debug("Sent EAP-TLS size=%i type=%i flag=%i\n", lcp->DataSize, eap->Type, eap->Tls.Flags);
					return true;
				}
			}

			

			// If we end up here, we got problems, send an EAP failure
			if (p->Eap_TlsCtx.SslPipe->IsDisconnected)
			{
				PPP_PACKET* pack;
				UINT identificator = p->Eap_PacketId;

				PPPSetStatus(p, PPP_STATUS_AUTH_FAIL);

				pack = ZeroMalloc(sizeof(PPP_PACKET));
				pack->IsControl = true;
				pack->Protocol = PPP_PROTOCOL_EAP;
				lcp = NewPPPLCP(PPP_EAP_CODE_FAILURE, identificator);
				pack->Lcp = lcp;
				Debug("Sent EAP-TLS size=%i FAILURE\n", lcp->DataSize);
				if (PPPSendPacketAndFree(p, pack) == false)
				{
					PPPSetStatus(p, PPP_STATUS_FAIL);
					WHERE;
					return false;
				}
				return false;
			}
		}
	}
	else
	{
		Debug("Got an EAP_TLS packet when not authenticating, ignoring...\n");
	}
	return false;
}

PPP_LCP *BuildEAPPacketEx(UCHAR code, UCHAR id, UCHAR type, UINT datasize)
{
	PPP_EAP *eap_packet;
	PPP_LCP *lcp_packet;
	UINT lcpDatasize;
	lcpDatasize = datasize + sizeof(UCHAR);
	eap_packet = ZeroMalloc(lcpDatasize);
	eap_packet->Type = type;
	lcp_packet = NewPPPLCP(code, id);
	lcp_packet->Data = eap_packet;
	lcp_packet->DataSize = lcpDatasize;
	return lcp_packet;
}

PPP_LCP *BuildEAPTlsPacketEx(UCHAR code, UCHAR id, UCHAR type, UINT datasize, UCHAR flags)
{
	PPP_LCP *lcp_packet;
	PPP_EAP *eap_packet;
	UINT tls_datasize = datasize + sizeof(UCHAR);
	if (flags & PPP_EAP_TLS_FLAG_TLS_LENGTH)
	{
		tls_datasize += sizeof(UINT);
	}
	lcp_packet = BuildEAPPacketEx(code, id, type, tls_datasize);
	eap_packet = lcp_packet->Data;
	eap_packet->Tls.Flags = flags;
	return lcp_packet;
}

PPP_LCP *BuildEAPTlsRequest(UCHAR id, UINT datasize, UCHAR flags)
{
	return BuildEAPTlsPacketEx(PPP_EAP_CODE_REQUEST, id, PPP_EAP_TYPE_TLS, datasize, flags);
}

// Other packet utilities

// Get the option value
PPP_OPTION *PPPGetOptionValue(PPP_LCP *c, UCHAR type)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(c->OptionList); i++)
	{
		PPP_OPTION *t = LIST_DATA(c->OptionList, i);

		if (t->Type == type)
		{
			return t;
		}
	}

	return NULL;
}

// Check whether the Virtual HUB with the specified name exist?
bool IsHubExistsWithLock(CEDAR *cedar, char *hubname)
{
	bool ret = false;
	// Validate arguments
	if (cedar == NULL || hubname == NULL)
	{
		return false;
	}

	LockList(cedar->HubList);
	{
		ret = IsHub(cedar, hubname);
	}
	UnlockList(cedar->HubList);

	return ret;
}

// Sets the PPP status without overwriting the FAIL status
void PPPSetStatus(PPP_SESSION *p, UINT status)
{
	if (status == PPP_STATUS_FAIL)
	{
		Debug("SETTING PPP_STATUS_FAIL!!!\n");
	}
	if (PPP_STATUS_IS_UNAVAILABLE(p->PPPStatus) == false || PPP_STATUS_IS_UNAVAILABLE(status))
	{
		p->PPPStatus = status;
	}
}


// Memory freeing functions

// Release the PPP session
void FreePPPSession(PPP_SESSION *p)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	// Release the memory
	for (i = 0; i < LIST_NUM(p->RecvPacketList); i++)
	{
		PPP_PACKET *pp = LIST_DATA(p->RecvPacketList, i);

		FreePPPPacket(pp);
	}
	ReleaseList(p->RecvPacketList);

	for (i = 0; i < LIST_NUM(p->SentReqPacketList); i++)
	{
		PPP_REQUEST_RESEND *t = LIST_DATA(p->SentReqPacketList, i);
		FreePPPPacket(t->Packet);

		Free(t);
	}

	ReleaseList(p->SentReqPacketList);

	for (i = 0; i < LIST_NUM(p->DelayedPackets); i++)
	{
		PPP_DELAYED_PACKET *t = LIST_DATA(p->DelayedPackets, i);
		FreePPPPacket(t->Packet);

		Free(t);
	}

	ReleaseList(p->DelayedPackets);

	if (p->CurrentPacket != NULL)
	{
		FreePPPPacket(p->CurrentPacket);
	}

	if (p->TubeRecv != NULL)
	{
		// Record the PPP disconnect reason code for L2TP
		p->TubeRecv->IntParam1 = p->DisconnectCauseCode;
		p->TubeRecv->IntParam2 = p->DisconnectCauseDirection;
	}

	// Freeing EAP-TLS context
	if (p->Eap_TlsCtx.CachedBufferRecv != NULL)
	{
		Free(p->Eap_TlsCtx.CachedBufferRecv);
	}
	if (p->Eap_TlsCtx.CachedBufferSend != NULL)
	{
		Free(p->Eap_TlsCtx.CachedBufferSend);
	}
	if (p->Eap_TlsCtx.SslPipe != NULL)
	{
		FreeSslPipe(p->Eap_TlsCtx.SslPipe);
	}
	if (p->Eap_TlsCtx.ClientCert.X != NULL)
	{
		FreeX(p->Eap_TlsCtx.ClientCert.X);
	}
	if (p->Eap_TlsCtx.Dh != NULL)
	{
		DhFree(p->Eap_TlsCtx.Dh);
	}


	FreeTubeFlushList(p->FlushList);

	TubeDisconnect(p->TubeRecv);
	TubeDisconnect(p->TubeSend);

	ReleaseCedar(p->Cedar);

	ReleaseTube(p->TubeRecv);
	ReleaseTube(p->TubeSend);

	if (p->Ipc != NULL)
	{
		FreeIPC(p->Ipc);
	}

	PPPFreeEapClient(p);

	Free(p);
}

// Release the LCP
void FreePPPLCP(PPP_LCP *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	FreePPPOptionList(c->OptionList);

	Free(c->Data);

	Free(c);
}

// Release the PPP options list
void FreePPPOptionList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		PPP_OPTION *t = LIST_DATA(o, i);

		Free(t);
	}

	ReleaseList(o);
}

// Release the PPP packet
void FreePPPPacket(PPP_PACKET *pp)
{
	FreePPPPacketEx(pp, false);
}

void FreePPPPacketEx(PPP_PACKET *pp, bool no_free_struct)
{
	// Validate arguments
	if (pp == NULL)
	{
		return;
	}

	FreePPPLCP(pp->Lcp);

	Free(pp->Data);

	if (no_free_struct == false)
	{
		Free(pp);
	}
}

// Free the associated EAP client
void PPPFreeEapClient(PPP_SESSION *p)
{
	if (p == NULL)
	{
		return;
	}

	if (p->EapClient != NULL)
	{
		ReleaseEapClient(p->EapClient);
		p->EapClient = NULL;
	}
}


// Utility functions used not only in PPP stack

// Separate into the user name and the Virtual HUB name by analyzing the string
bool PPPParseUsername(CEDAR *cedar, char *src_username, ETHERIP_ID *dst)
{
	UINT i, len, last_at, first_en;
	char token1[MAX_SIZE];	// username
	char token2[MAX_SIZE];	// hub_name
	char src[MAX_SIZE];
	// Validate arguments
	Zero(dst, sizeof(ETHERIP_ID));
	if (cedar == NULL || dst == NULL)
	{
		return false;
	}

	StrCpy(src, sizeof(src), src_username);
	Trim(src);

	// Search for the first "\\" in the string
	len = StrLen(src);

	first_en = SearchStrEx(src, "\\", 0, true);

	if (first_en != INFINITE && first_en >= 1 && (first_en < (len - 1)))
	{
		StrCpy(token1, sizeof(token1), src + first_en + 1);
		StrCpy(token2, sizeof(token2), src);
		token2[first_en] = 0;

		// Confirm whether the hubname exists if the virtual HUB name is
		// specified like as hubname\username
		if (IsHubExistsWithLock(cedar, token2) == false)
		{
			// If the hubname does not exist, restore to the original name
			StrCpy(token1, sizeof(token1), src);
			ClearStr(token2, sizeof(token2));
		}
	}
	else
	{
		// Search for the separator character's last position in the string
		len = StrLen(src);
		last_at = INFINITE;
		for (i = 0; i < len; i++)
		{
			char c = src[i];

			if (c == cedar->UsernameHubSeparator)
			{
				last_at = i;
			}
		}

		Zero(token1, sizeof(token1));
		Zero(token2, sizeof(token2));

		if (last_at == INFINITE)
		{
			// The separator character is not specifiedd
			StrCpy(token1, sizeof(token1), src);
		}
		else
		{
			StrCpy(token1, sizeof(token1), src);
			token1[last_at] = 0;

			StrCpy(token2, sizeof(token2), src + last_at + 1);
		}

		// Check whether such Virtual HUB exists If the virtual HUB name is specified
		if (IsEmptyStr(token2) == false)
		{
			if (IsHubExistsWithLock(cedar, token2) == false)
			{
				// Because the specified virtual HUB name doesn't exist, it's considered to be a part of the user name
				StrCpy(token1, sizeof(token1), src);

				ClearStr(token2, sizeof(token2));
			}
		}
	}

	if (IsEmptyStr(token2))
	{
		// Select the default Virtual HUB if the Virtual HUB name is not specified
		StrCpy(token2, sizeof(token2), SERVER_DEFAULT_HUB_NAME);
		if (cedar->Server != NULL && cedar->Server->IPsecServer != NULL)
		{
			Lock(cedar->Server->IPsecServer->LockSettings);
			{
				IPsecNormalizeServiceSetting(cedar->Server->IPsecServer);

				StrCpy(token2, sizeof(token2), cedar->Server->IPsecServer->Services.L2TP_DefaultHub);
			}
			Unlock(cedar->Server->IPsecServer->LockSettings);
		}

	}

	// Return the results
	StrCpy(dst->HubName, sizeof(dst->HubName), token2);
	StrCpy(dst->UserName, sizeof(dst->UserName), token1);

	return true;
}

// Generate the NT hash of the password
void GenerateNtPasswordHash(UCHAR *dst, char *password)
{
	UCHAR *tmp;
	UINT tmp_size;
	UINT i, len;
	// Validate arguments
	if (dst == NULL || password == NULL)
	{
		return;
	}

	// Generate a Unicode password
	len = StrLen(password);
	tmp_size = len * 2;

	tmp = ZeroMalloc(tmp_size);

	for (i = 0; i < len; i++)
	{
		tmp[i * 2] = password[i];
	}

	// Hashing
	HashMd4(dst, tmp, tmp_size);

	Free(tmp);
}

// Generate the MS-CHAPv2 server-side challenge
void MsChapV2Server_GenerateChallenge(UCHAR *dst)
{
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	Rand(dst, 16);
}

// Generate the MS-CHAPv2 client-side challenge
void MsChapV2Client_GenerateChallenge(UCHAR *dst)
{
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	Rand(dst, 16);
}

// Generate a 8 bytes challenge
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	char username2[MAX_SIZE];
	char domainname2[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || client_challenge == NULL || server_challenge == NULL)
	{
		return;
	}

	b = NewBuf();

	WriteBuf(b, client_challenge, 16);
	WriteBuf(b, server_challenge, 16);

	ParseNtUsername(username, username2, sizeof(username2), domainname2, sizeof(domainname2), true);

	if (IsEmptyStr(username2) == false)
	{
		WriteBuf(b, username2, StrLen(username2));
	}

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(dst, hash, 8);
}

// Generate the MS-CHAPv2 client response
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash)
{
	UCHAR password_hash_2[21];
	UCHAR key1[8], key2[8], key3[8];
	// Validate arguments
	if (dst == NULL || challenge8 == NULL || nt_password_hash == NULL)
	{
		return;
	}

	Zero(password_hash_2, sizeof(password_hash_2));
	Copy(password_hash_2, nt_password_hash, 16);

	Zero(key1, sizeof(key1));
	Zero(key2, sizeof(key2));
	Zero(key3, sizeof(key3));

	Copy(key1, password_hash_2 + 0, 7);
	Copy(key2, password_hash_2 + 7, 7);
	Copy(key3, password_hash_2 + 14, 7);

	DesEcbEncrypt(dst + 0, challenge8, key1);
	DesEcbEncrypt(dst + 8, challenge8, key2);
	DesEcbEncrypt(dst + 16, challenge8, key3);
}

// Generate a hash of the hash of the NT password
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash)
{
	// Validate arguments
	if (dst_hash == NULL || src_hash == NULL)
	{
		return;
	}

	HashMd4(dst_hash, src_hash, 16);
}

// Generate the MS-CHAPv2 server response
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8)
{
	UCHAR digest[SHA1_SIZE];
	BUF *b;
	char *magic1 = "Magic server to client signing constant";
	char *magic2 = "Pad to make it do more than one iteration";
	// Validate arguments
	if (dst == NULL || nt_password_hash_hash == NULL || client_response == NULL || challenge8 == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, nt_password_hash_hash, 16);
	WriteBuf(b, client_response, 24);
	WriteBuf(b, magic1, StrLen(magic1));
	Sha1(digest, b->Buf, b->Size);
	FreeBuf(b);

	b = NewBuf();
	WriteBuf(b, digest, sizeof(digest));
	WriteBuf(b, challenge8, 8);
	WriteBuf(b, magic2, StrLen(magic2));
	Sha1(dst, b->Buf, b->Size);
	FreeBuf(b);
}

// Verify whether the password matches one that is specified by the user in the MS-CHAPv2
bool MsChapV2VerityPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password)
{
	UCHAR ntlm_hash[MD5_SIZE];
	UCHAR challenge8[8];
	UCHAR client_response[24];
	// Validate arguments
	if (d == NULL || password == NULL)
	{
		return false;
	}

	GenerateNtPasswordHash(ntlm_hash, password);
	MsChapV2_GenerateChallenge8(challenge8, d->MsChapV2_ClientChallenge, d->MsChapV2_ServerChallenge, d->MsChapV2_PPPUsername);
	MsChapV2Client_GenerateResponse(client_response, challenge8, ntlm_hash);

	if (Cmp(client_response, d->MsChapV2_ClientResponse, 24) != 0)
	{
		return false;
	}

	return true;
}

// Estimate the password in the brute force for the request packet of MS-CHAPv2
char *MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list)
{
	UINT i;
	// Validate arguments
	if (d == NULL || password_list == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(password_list); i++)
	{
		char *s = LIST_DATA(password_list, i);
		char tmp[MAX_SIZE];
		UINT j, max;
		UINT len;

		StrCpy(tmp, sizeof(tmp), s);

		len = StrLen(tmp);
		max = Power(2, MIN(len, 9));

		for (j = 0; j < max; j++)
		{
			SetStrCaseAccordingToBits(tmp, j);
			if (MsChapV2VerityPassword(d, tmp))
			{
				return CopyStr(tmp);
			}
		}
	}

	return NULL;
}


