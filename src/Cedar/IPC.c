// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// IPC.c
// In-process VPN client module

#include "IPC.h"

#include "Admin.h"
#include "Cedar.h"
#include "Client.h"
#include "Connection.h"
#include "Hub.h"
#include "Protocol.h"
#include "Radius.h"
#include "Virtual.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

// Extract the MS-CHAP v2 authentication information by parsing the password string
bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (d == NULL || password == NULL)
	{
		return false;
	}

	Zero(d, sizeof(IPC_MSCHAP_V2_AUTHINFO));

	if (StartWith(password, IPC_PASSWORD_MSCHAPV2_TAG) == false)
	{
		return false;
	}

	t = ParseTokenWithNullStr(password, ":");

	if (t->NumTokens == 6)
	{
		BUF *b1, *b2, *b3, *b4;

		b1 = StrToBin(t->Token[2]);
		b2 = StrToBin(t->Token[3]);
		b3 = StrToBin(t->Token[4]);
		b4 = StrToBin(t->Token[5]);

		if (IsEmptyStr(t->Token[1]) == false && b1->Size == 16 && b2->Size == 16 && b3->Size == 24
		        && b4->Size == 8)
		{
			UINT64 eap_client_ptr = 0;

			StrCpy(d->MsChapV2_PPPUsername, sizeof(d->MsChapV2_PPPUsername), t->Token[1]);
			Copy(d->MsChapV2_ServerChallenge, b1->Buf, 16);
			Copy(d->MsChapV2_ClientChallenge, b2->Buf, 16);
			Copy(d->MsChapV2_ClientResponse, b3->Buf, 24);
			Copy(&eap_client_ptr, b4->Buf, 8);

			d->MsChapV2_EapClient = (EAP_CLIENT *)eap_client_ptr;

			ret = true;
		}

		FreeBuf(b1);
		FreeBuf(b2);
		FreeBuf(b3);
		FreeBuf(b4);
	}

	FreeToken(t);

	return ret;
}

// Start an IPC connection asynchronously
IPC_ASYNC *NewIPCAsync(CEDAR *cedar, IPC_PARAM *param, SOCK_EVENT *sock_event)
{
	IPC_ASYNC *a;
	// Validate arguments
	if (cedar == NULL || param == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(IPC_ASYNC));

	a->TubeForDisconnect = NewTube(0);

	a->Cedar = cedar;
	AddRef(a->Cedar->ref);

	Copy(&a->Param, param, sizeof(IPC_PARAM));

	if (param->ClientCertificate != NULL)
	{
		// Client certificate must be copied for async processing
		a->Param.ClientCertificate = CloneX(param->ClientCertificate);
	}

	if (sock_event != NULL)
	{
		a->SockEvent = sock_event;
		AddRef(a->SockEvent->ref);
	}

	a->Thread = NewThread(IPCAsyncThreadProc, a);

	return a;
}

// asynchronous IPC connection creation thread
void IPCAsyncThreadProc(THREAD *thread, void *param)
{
	IPC_ASYNC *a;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	a = (IPC_ASYNC *)param;

	// Attempt to connect
	a->Ipc = NewIPCByParam(a->Cedar, &a->Param, &a->ErrorCode);

	if (a->Ipc != NULL)
	{
		if (a->Param.IsL3Mode)
		{
			DHCP_OPTION_LIST cao;

			Zero(&cao, sizeof(cao));

			// Get an IP address from the DHCP server in the case of L3 mode
			Debug("IPCDhcpAllocateIP() start...\n");
			if (IPCDhcpAllocateIP(a->Ipc, &cao, a->TubeForDisconnect))
			{
				UINT t;
				IP ip, subnet, gw;

				Debug("IPCDhcpAllocateIP() Ok.\n");

				// Calculate the DHCP update interval
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

				// Save the options list
				Copy(&a->L3ClientAddressOption, &cao, sizeof(DHCP_OPTION_LIST));
				a->L3DhcpRenewInterval = (UINT64)t * (UINT64)1000;

				// Set the obtained IP address parameters to the IPC virtual host
				UINTToIP(&ip, cao.ClientAddress);
				UINTToIP(&subnet, cao.SubnetMask);
				UINTToIP(&gw, cao.Gateway);

				IPCSetIPv4Parameters(a->Ipc, &ip, &subnet, &gw, &cao.ClasslessRoute);

				a->L3NextDhcpRenewTick = Tick64() + a->L3DhcpRenewInterval;
			}
			else
			{
				Debug("IPCDhcpAllocateIP() Error.\n");

				a->DhcpAllocFailed = true;

				FreeIPC(a->Ipc);
				a->Ipc = NULL;
			}
		}
	}

	// Procedure complete
	a->Done = true;

	if (a->SockEvent != NULL)
	{
		SetSockEvent(a->SockEvent);
	}
}

// Release the IPC asynchronous connection object
void FreeIPCAsync(IPC_ASYNC *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	TubeDisconnect(a->TubeForDisconnect);
	WaitThread(a->Thread, INFINITE);
	ReleaseThread(a->Thread);

	if (a->Ipc != NULL)
	{
		FreeIPC(a->Ipc);
		a->Ipc = NULL;
	}

	if (a->SockEvent != NULL)
	{
		ReleaseSockEvent(a->SockEvent);
	}

	ReleaseCedar(a->Cedar);

	ReleaseTube(a->TubeForDisconnect);

	if (a->Param.ClientCertificate != NULL)
	{
		FreeX(a->Param.ClientCertificate);
	}

	Free(a);
}

// Start a new IPC connection by specifying the parameter structure
IPC *NewIPCByParam(CEDAR *cedar, IPC_PARAM *param, UINT *error_code)
{
	IPC *ipc;
	// Validate arguments
	if (cedar == NULL || param == NULL)
	{
		return NULL;
	}

	ipc = NewIPC(cedar, param->ClientName, param->Postfix, param->HubName,
	             param->UserName, param->Password, param->WgKey, error_code,
	             &param->ClientIp, param->ClientPort, &param->ServerIp, param->ServerPort,
	             param->ClientHostname, param->CryptName,
	             param->BridgeMode, param->Mss, NULL, param->ClientCertificate, param->RadiusOK,
				 param->Layer);

	return ipc;
}

// Start a new IPC connection
IPC *NewIPC(CEDAR *cedar, char *client_name, char *postfix, char *hubname, char *username, char *password, char *wg_key,
            UINT *error_code, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port,
            char *client_hostname, char *crypt_name,
            bool bridge_mode, UINT mss, EAP_CLIENT *eap_client, X *client_certificate, bool external_auth,
            UINT layer)
{
	IPC *ipc;
	HUB *hub;
	UINT dummy_int = 0;
	SOCK *a;
	SOCK *s;
	PACK *p;
	UINT err = ERR_INTERNAL_ERROR;
	char server_str[MAX_SIZE];
	char macstr[30];
	UINT server_ver, server_build;
	UCHAR unique[SHA1_SIZE];
	NODE_INFO info;
	BUF *b;
	UCHAR mschap_v2_server_response_20[20];
	UINT64 u64;
	// Validate arguments
	if (cedar == NULL || username == NULL || password == NULL || client_hostname == NULL)
	{
		return NULL;
	}
	if (IsEmptyStr(client_name))
	{
		client_name = "InProc VPN Connection";
	}
	if (IsEmptyStr(crypt_name))
	{
		crypt_name = "";
	}
	if (error_code == NULL)
	{
		error_code = &dummy_int;
	}

	Zero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));

	err = *error_code = ERR_INTERNAL_ERROR;

	a = GetInProcListeningSock(cedar);
	if (a == NULL)
	{
		return NULL;
	}

	ipc = ZeroMalloc(sizeof(IPC));

	ipc->Cedar = cedar;
	AddRef(cedar->ref);

	ipc->Layer = layer;
	if (ipc->Layer == 0)
	{
		ipc->Layer = IPC_LAYER_2;
	}

	ipc->FlushList = NewTubeFlushList();

	StrCpy(ipc->ClientHostname, sizeof(ipc->ClientHostname), client_hostname);

	// Connect the in-process socket
	s = ConnectInProc(a, client_ip, client_port, server_ip, server_port);
	if (s == NULL)
	{
		goto LABEL_ERROR;
	}

	// Protocol initialization process
	if (ClientUploadSignature(s) == false)
	{
		err = ERR_DISCONNECTED;
		goto LABEL_ERROR;
	}

	p = HttpClientRecv(s);
	if (p == NULL)
	{
		err = ERR_DISCONNECTED;
		goto LABEL_ERROR;
	}

	err = GetErrorFromPack(p);
	if (err != ERR_NO_ERROR)
	{
		FreePack(p);
		goto LABEL_ERROR;
	}

	if (GetHello(p, ipc->random, &server_ver, &server_build, server_str, sizeof(server_str)) == false)
	{
		FreePack(p);
		err = ERR_DISCONNECTED;
		goto LABEL_ERROR;
	}

	FreePack(p);

	// Upload the authentication data
	if (IsEmptyStr(wg_key) == false)
	{
		p = PackLoginWithWireGuardKey(wg_key);
	}
	else if (client_certificate != NULL)
	{
		p = PackLoginWithOpenVPNCertificate(hubname, username, client_certificate);
	}
	else if (external_auth)
	{
		p = PackLoginWithExternal(hubname, username);
	}
	else
	{
		p = PackLoginWithPlainPassword(hubname, username, password);
	}

	if (p == NULL)
	{
		err = ERR_AUTH_FAILED;
		goto LABEL_ERROR;
	}

	PackAddStr(p, "hello", client_name);
	PackAddInt(p, "client_ver", cedar->Version);
	PackAddInt(p, "client_build", cedar->Build);
	PackAddInt(p, "max_connection", 1);
	PackAddInt(p, "use_encrypt", 0);
	PackAddInt(p, "use_compress", 0);
	PackAddInt(p, "half_connection", 0);
	PackAddInt(p, "adjust_mss", mss);
	PackAddBool(p, "require_bridge_routing_mode", bridge_mode);
	PackAddBool(p, "require_monitor_mode", false);
	PackAddBool(p, "qos", false);

	if (eap_client != NULL)
	{
		UINT64 ptr = (UINT64)eap_client;
		PackAddInt64(p, "release_me_eap_client", ptr);

		AddRef(eap_client->Ref);
	}

	// Unique ID is determined by the sum of the connecting client IP address and the client_name
	b = NewBuf();
	WriteBuf(b, client_ip, sizeof(IP));
	WriteBufStr(b, client_name);
	WriteBufStr(b, crypt_name);

	Sha1(unique, b->Buf, b->Size);

	FreeBuf(b);

	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	PackAddStr(p, "inproc_postfix", postfix);
	PackAddStr(p, "inproc_cryptname", crypt_name);
	PackAddInt(p, "inproc_layer", ipc->Layer);

	// Node information
	Zero(&info, sizeof(info));
	StrCpy(info.ClientProductName, sizeof(info.ClientProductName), client_name);
	info.ClientProductVer = Endian32(cedar->Version);
	info.ClientProductBuild = Endian32(cedar->Build);
	StrCpy(info.ServerProductName, sizeof(info.ServerProductName), server_str);
	info.ServerProductVer = Endian32(server_ver);
	info.ServerProductBuild = Endian32(server_build);
	StrCpy(info.ClientOsName, sizeof(info.ClientOsName), client_name);
	StrCpy(info.ClientOsVer, sizeof(info.ClientOsVer), "-");
	StrCpy(info.ClientOsProductId, sizeof(info.ClientOsProductId), "-");
	info.ClientIpAddress = IPToUINT(&s->LocalIP);
	info.ClientPort = Endian32(s->LocalPort);
	StrCpy(info.ClientHostname, sizeof(info.ClientHostname), ipc->ClientHostname);
	IPToStr(info.ServerHostname, sizeof(info.ServerHostname), &s->RemoteIP);
	info.ServerIpAddress = IPToUINT(&s->RemoteIP);
	info.ServerPort = Endian32(s->RemotePort);
	StrCpy(info.HubName, sizeof(info.HubName), hubname);
	Copy(info.UniqueId, unique, sizeof(info.UniqueId));
	if (IsIP6(&s->LocalIP))
	{
		Copy(info.ClientIpAddress6, s->LocalIP.address, sizeof(info.ClientIpAddress6));
	}
	if (IsIP6(&s->RemoteIP))
	{
		Copy(info.ServerIpAddress6, s->RemoteIP.address, sizeof(info.ServerIpAddress6));
	}
	OutRpcNodeInfo(p, &info);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		err = ERR_DISCONNECTED;
		goto LABEL_ERROR;
	}

	FreePack(p);

	// Receive a Welcome packet
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		err = ERR_DISCONNECTED;
		goto LABEL_ERROR;
	}

	err = GetErrorFromPack(p);
	if (err != ERR_NO_ERROR)
	{
		FreePack(p);
		goto LABEL_ERROR;
	}

	if (ParseWelcomeFromPack(p, ipc->SessionName, sizeof(ipc->SessionName),
	                         ipc->ConnectionName, sizeof(ipc->ConnectionName), &ipc->Policy) == false)
	{
		err = ERR_PROTOCOL_ERROR;
		FreePack(p);
		goto LABEL_ERROR;
	}

	if (PackGetData2(p, "IpcMacAddress", ipc->MacAddress, 6) == false || IsZero(ipc->MacAddress, 6))
	{
		err = ERR_PROTOCOL_ERROR;
		FreePack(p);
		goto LABEL_ERROR;
	}

	if (PackGetData2(p, "IpcMsChapV2ServerResponse", mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20)))
	{
		Copy(ipc->MsChapV2_ServerResponse, mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));
	}

	PackGetStr(p, "IpcHubName", ipc->HubName, sizeof(ipc->HubName));
	Debug("IPC Hub Name: %s\n", ipc->HubName);

	hub = GetHub(cedar, ipc->HubName);
	if (hub != NULL)
	{
		UINTToIP(&ipc->DefaultGateway, hub->Option->DefaultGateway);
		UINTToIP(&ipc->SubnetMask, hub->Option->DefaultSubnet);
		GetBroadcastAddress4(&ipc->BroadcastAddress, &ipc->DefaultGateway, &ipc->SubnetMask);
	}
	else
	{
		ZeroIP4(&ipc->DefaultGateway);
		ZeroIP4(&ipc->SubnetMask);
		ZeroIP4(&ipc->BroadcastAddress);
	}

	ReleaseHub(hub);

	ZeroIP4(&ipc->ClientIPAddress);

	MacToStr(macstr, sizeof(macstr), ipc->MacAddress);

	Debug("IPC: Session = %s, Connection = %s, Mac = %s\n", ipc->SessionName, ipc->ConnectionName, macstr);

	u64 = PackGetInt64(p, "IpcSessionSharedBuffer");
	ipc->IpcSessionSharedBuffer = (SHARED_BUFFER *)u64;
	ipc->IpcSessionShared = ipc->IpcSessionSharedBuffer->Data;

	FreePack(p);

	ReleaseSock(a);
	ipc->Sock = s;

	Debug("NewIPC() Succeed.\n");

	ipc->Interrupt = NewInterruptManager();

	// Create an ARP table
	ipc->ArpTable = NewList(IPCCmpArpTable);

	// Create an IPv4 reception queue
	ipc->IPv4ReceivedQueue = NewQueue();
	ipc->IPv4State = IPC_PROTO_STATUS_CLOSED;

	ipc->DHCPv4Awaiter.IsAwaiting = false;
	ipc->DHCPv4Awaiter.DhcpData = NULL;

	IPCIPv6Init(ipc);

	return ipc;

LABEL_ERROR:
	Debug("NewIPC() Failed: Err = %u\n", err);
	Disconnect(s);
	ReleaseSock(s);
	ReleaseSock(a);
	FreeIPC(ipc);
	*error_code = err;
	return NULL;
}

// Create a new IPC based on SOCK
IPC *NewIPCBySock(CEDAR *cedar, SOCK *s, void *mac_address)
{
	IPC *ipc;
	// Validate arguments
	if (cedar == NULL || mac_address == NULL || s == NULL)
	{
		return NULL;
	}

	ipc = ZeroMalloc(sizeof(IPC));

	ipc->Cedar = cedar;
	AddRef(cedar->ref);

	ipc->Sock = s;
	AddRef(s->ref);

	Copy(ipc->MacAddress, mac_address, 6);

	ipc->Interrupt = NewInterruptManager();

	// Create an ARP table
	ipc->ArpTable = NewList(IPCCmpArpTable);

	// Create an IPv4 reception queue
	ipc->IPv4ReceivedQueue = NewQueue();
	ipc->IPv4State = IPC_PROTO_STATUS_CLOSED;

	ipc->DHCPv4Awaiter.IsAwaiting = false;
	ipc->DHCPv4Awaiter.DhcpData = NULL;

	ipc->FlushList = NewTubeFlushList();

	IPCIPv6Init(ipc);

	return ipc;
}

// Get whether the IPC is connected
bool IsIPCConnected(IPC *ipc)
{
	// Validate arguments
	if (ipc == NULL)
	{
		return false;
	}

	if (IsTubeConnected(ipc->Sock->RecvTube) == false || IsTubeConnected(ipc->Sock->SendTube) == false)
	{
		return false;
	}

	return true;
}

// Get to hit the SOCK_EVENT when a new data has arrived in the IPC
void IPCSetSockEventWhenRecvL2Packet(IPC *ipc, SOCK_EVENT *e)
{
	// Validate arguments
	if (ipc == NULL || e == NULL)
	{
		return;
	}

	JoinSockToSockEvent(ipc->Sock, e);
}

// End of IPC connection
void FreeIPC(IPC *ipc)
{
	UINT i;
	// Validate arguments
	if (ipc == NULL)
	{
		return;
	}

	FreeTubeFlushList(ipc->FlushList);

	Disconnect(ipc->Sock);
	ReleaseSock(ipc->Sock);

	if (ipc->Policy != NULL)
	{
		Free(ipc->Policy);
	}

	ReleaseCedar(ipc->Cedar);

	FreeInterruptManager(ipc->Interrupt);

	for (i = 0; i < LIST_NUM(ipc->ArpTable); i++)
	{
		IPC_ARP *a = LIST_DATA(ipc->ArpTable, i);
		IPCFreeARP(a);
	}

	ReleaseList(ipc->ArpTable);

	while (true)
	{
		BLOCK *b = GetNext(ipc->IPv4ReceivedQueue);
		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(ipc->IPv4ReceivedQueue);

	ReleaseSharedBuffer(ipc->IpcSessionSharedBuffer);

	FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);

	IPCIPv6Free(ipc);

	Free(ipc);
}

// Set User Class option if corresponding Virtual Hub optin is set
void IPCDhcpSetConditionalUserClass(IPC *ipc, DHCP_OPTION_LIST *req)
{
	HUB *hub;

	hub = GetHub(ipc->Cedar, ipc->HubName);
	if (hub == NULL)
	{
		return;
	}

	if (hub->Option && hub->Option->UseHubNameAsDhcpUserClassOption)
	{
		StrCpy(req->UserClass, sizeof(req->UserClass), ipc->HubName);
	}
	ReleaseHub(hub);
}

// Release the IP address from the DHCP server
void IPCDhcpFreeIP(IPC *ipc, IP *dhcp_server)
{
	DHCP_OPTION_LIST req;
	UINT tran_id = Rand32();
	// Validate arguments
	if (ipc == NULL || dhcp_server == NULL)
	{
		return;
	}

	Zero(&req, sizeof(req));
	req.Opcode = DHCP_RELEASE;
	req.ServerAddress = IPToUINT(dhcp_server);
	IPCDhcpSetConditionalUserClass(ipc, &req);

	FreeDHCPv4Data(IPCSendDhcpRequest(ipc, NULL, tran_id, &req, 0, 0, NULL));
}

// Update the IP address using the DHCP
void IPCDhcpRenewIP(IPC *ipc, IP *dhcp_server)
{
	DHCP_OPTION_LIST req;
	UINT tran_id = Rand32();
	// Validate arguments
	if (ipc == NULL || dhcp_server == NULL)
	{
		return;
	}

	// Send a DHCP Request
	Zero(&req, sizeof(req));
	req.Opcode = DHCP_REQUEST;
	StrCpy(req.Hostname, sizeof(req.Hostname), ipc->ClientHostname);
	req.RequestedIp = IPToUINT(&ipc->ClientIPAddress);
	IPCDhcpSetConditionalUserClass(ipc, &req);

	FreeDHCPv4Data(IPCSendDhcpRequest(ipc, dhcp_server, tran_id, &req, 0, 0, NULL));
}

// Get the information other than the IP address with using DHCP
bool IPCDhcpRequestInformIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube, IP *client_ip)
{
	DHCP_OPTION_LIST req;
	DHCPV4_DATA *d;
	UINT tran_id = Rand32();
	bool ok;
	// Validate arguments
	if (ipc == NULL || opt == NULL || client_ip == NULL)
	{
		return false;
	}

	// Send a DHCP Inform
	Zero(&req, sizeof(req));
	req.Opcode = DHCP_INFORM;
	req.ClientAddress = IPToUINT(client_ip);
	StrCpy(req.Hostname, sizeof(req.Hostname), ipc->ClientHostname);
	IPCDhcpSetConditionalUserClass(ipc, &req);

	d = IPCSendDhcpRequest(ipc, NULL, tran_id, &req, DHCP_ACK, IPC_DHCP_TIMEOUT, discon_poll_tube);
	if (d == NULL)
	{
		return false;
	}

	// Analyze the DHCP Ack
	ok = true;
	if (d->ParsedOptionList->SubnetMask == 0)
	{
		ok = false;
	}

	if (ok == false)
	{
		FreeDHCPv4Data(d);
		return false;
	}

	Copy(opt, d->ParsedOptionList, sizeof(DHCP_OPTION_LIST));

	FreeDHCPv4Data(d);

	return true;
}

// Make a request for IP addresses using DHCP
bool IPCDhcpAllocateIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube)
{
	DHCP_OPTION_LIST req;
	DHCPV4_DATA *d, *d2;
	UINT tran_id = Rand32();
	bool ok;
	// Validate arguments
	if (ipc == NULL || opt == NULL)
	{
		return false;
	}

	// Send a DHCP Discover
	Zero(&req, sizeof(req));
	req.RequestedIp = 0;
	req.Opcode = DHCP_DISCOVER;
	StrCpy(req.Hostname, sizeof(req.Hostname), ipc->ClientHostname);
	IPCDhcpSetConditionalUserClass(ipc, &req);

	d = IPCSendDhcpRequest(ipc, NULL, tran_id, &req, DHCP_OFFER, IPC_DHCP_TIMEOUT, discon_poll_tube);
	if (d == NULL)
	{
		return false;
	}

	// Analyze the DHCP Offer
	ok = true;
	if (IsValidUnicastIPAddressUINT4(d->ParsedOptionList->ClientAddress) == false)
	{
		ok = false;
	}
	if (IsValidUnicastIPAddressUINT4(d->ParsedOptionList->ServerAddress) == false)
	{
		ok = false;
	}
	if (d->ParsedOptionList->SubnetMask == 0)
	{
		ok = false;
	}
	if (d->ParsedOptionList->LeaseTime == 0)
	{
		d->ParsedOptionList->LeaseTime = IPC_DHCP_DEFAULT_LEASE;
	}
	if (d->ParsedOptionList->LeaseTime <= IPC_DHCP_MIN_LEASE)
	{
		d->ParsedOptionList->LeaseTime = IPC_DHCP_MIN_LEASE;
	}

	if (ok == false)
	{
		FreeDHCPv4Data(d);
		return false;
	}

	// Send a DHCP Request
	Zero(&req, sizeof(req));
	req.Opcode = DHCP_REQUEST;
	StrCpy(req.Hostname, sizeof(req.Hostname), ipc->ClientHostname);
	req.ServerAddress = d->ParsedOptionList->ServerAddress;
	req.RequestedIp = d->ParsedOptionList->ClientAddress;
	IPCDhcpSetConditionalUserClass(ipc, &req);

	d2 = IPCSendDhcpRequest(ipc, NULL, tran_id, &req, DHCP_ACK, IPC_DHCP_TIMEOUT, discon_poll_tube);
	if (d2 == NULL)
	{
		FreeDHCPv4Data(d);
		return false;
	}

	// Analyze the DHCP Ack
	ok = true;
	if (IsValidUnicastIPAddressUINT4(d2->ParsedOptionList->ClientAddress) == false)
	{
		ok = false;
	}
	if (IsValidUnicastIPAddressUINT4(d2->ParsedOptionList->ServerAddress) == false)
	{
		ok = false;
	}
	if (d2->ParsedOptionList->SubnetMask == 0)
	{
		ok = false;
	}
	if (d2->ParsedOptionList->LeaseTime == 0)
	{
		d2->ParsedOptionList->LeaseTime = IPC_DHCP_DEFAULT_LEASE;
	}
	if (d2->ParsedOptionList->LeaseTime <= IPC_DHCP_MIN_LEASE)
	{
		d2->ParsedOptionList->LeaseTime = IPC_DHCP_MIN_LEASE;
	}

	if (ok == false)
	{
		FreeDHCPv4Data(d);
		FreeDHCPv4Data(d2);
		return false;
	}

	Copy(opt, d2->ParsedOptionList, sizeof(DHCP_OPTION_LIST));

	FreeDHCPv4Data(d);
	FreeDHCPv4Data(d2);

	return true;
}

// Send out a DHCP request, and wait for a corresponding response
DHCPV4_DATA *IPCSendDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt, UINT expecting_code, UINT timeout, TUBE *discon_poll_tube)
{
	UINT resend_interval;
	UINT64 giveup_time;
	UINT64 next_send_time = 0;
	TUBE *tubes[3];
	UINT num_tubes = 0;
	// Validate arguments
	if (ipc == NULL || opt == NULL || (expecting_code != 0 && timeout == 0))
	{
		return NULL;
	}

	// Retransmission interval
	resend_interval = MAX(1, (timeout / 3) - 100);

	// Time-out time
	giveup_time = Tick64() + (UINT64)timeout;

	AddInterrupt(ipc->Interrupt, giveup_time);

	tubes[num_tubes++] = ipc->Sock->RecvTube;
	tubes[num_tubes++] = ipc->Sock->SendTube;

	if (discon_poll_tube != NULL)
	{
		tubes[num_tubes++] = discon_poll_tube;
	}

	while (true)
	{
		UINT64 now = Tick64();
		BUF *dhcp_packet;

		IPCFlushArpTable(ipc);

		// Time-out inspection
		if ((expecting_code != 0) && (now >= giveup_time))
		{
			ipc->DHCPv4Awaiter.IsAwaiting = false;
			FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
			ipc->DHCPv4Awaiter.DhcpData = NULL;
			return NULL;
		}

		// Send by building a DHCP packet periodically
		if (next_send_time == 0 || next_send_time <= now)
		{
			dhcp_packet = IPCBuildDhcpRequest(ipc, dest_ip, tran_id, opt);
			if (dhcp_packet == NULL)
			{
				ipc->DHCPv4Awaiter.IsAwaiting = false;
				FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
				ipc->DHCPv4Awaiter.DhcpData = NULL;
				return NULL;
			}

			IPCSendIPv4(ipc, dhcp_packet->Buf, dhcp_packet->Size);

			FreeBuf(dhcp_packet);

			if (expecting_code == 0)
			{
				ipc->DHCPv4Awaiter.IsAwaiting = false;
				FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
				ipc->DHCPv4Awaiter.DhcpData = NULL;
				return NULL;
			}

			next_send_time = now + (UINT64)resend_interval;

			AddInterrupt(ipc->Interrupt, next_send_time);
		}

		// Happy processing
		ipc->DHCPv4Awaiter.IsAwaiting = true;
		FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
		ipc->DHCPv4Awaiter.DhcpData = NULL;
		ipc->DHCPv4Awaiter.TransCode = tran_id;
		ipc->DHCPv4Awaiter.OpCode = expecting_code;
		IPCProcessL3Events(ipc);

		if (ipc->DHCPv4Awaiter.DhcpData != NULL)
		{
			DHCPV4_DATA *dhcp = ipc->DHCPv4Awaiter.DhcpData;
			ipc->DHCPv4Awaiter.IsAwaiting = false;
			ipc->DHCPv4Awaiter.DhcpData = NULL;
			return dhcp;
		}

		if (IsTubeConnected(ipc->Sock->RecvTube) == false || IsTubeConnected(ipc->Sock->SendTube) == false ||
		        (discon_poll_tube != NULL && IsTubeConnected(discon_poll_tube) == false))
		{
			// Session is disconnected
			ipc->DHCPv4Awaiter.IsAwaiting = false;
			FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
			ipc->DHCPv4Awaiter.DhcpData = NULL;
			return NULL;
		}

		// Keep the CPU waiting
		WaitForTubes(tubes, num_tubes, GetNextIntervalForInterrupt(ipc->Interrupt));
	}

	ipc->DHCPv4Awaiter.IsAwaiting = false;
	FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
	ipc->DHCPv4Awaiter.DhcpData = NULL;
	return NULL;
}

// Build a DHCP request packet
BUF *IPCBuildDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt)
{
	IPV4_HEADER ip;
	UDP_HEADER *udp;
	DHCPV4_HEADER dhcp;
	UINT blank_size = 128 + 64;
	BUF *ret;
	BUF *b;
	UDPV4_PSEUDO_HEADER *ph;
	UINT ph_size;
	UINT udp_size;
	UINT magic_number = Endian32(DHCP_MAGIC_COOKIE);
	USHORT checksum;
	// Validate arguments
	if (ipc == NULL || opt == NULL)
	{
		return NULL;
	}

	// DHCPv4 Options
	b = IPCBuildDhcpRequestOptions(ipc, opt);
	if (b == NULL)
	{
		return NULL;
	}

	// DHCPv4 Header
	Zero(&dhcp, sizeof(dhcp));
	dhcp.OpCode = 1;
	dhcp.HardwareType = ARP_HARDWARE_TYPE_ETHERNET;
	dhcp.HardwareAddressSize = 6;
	dhcp.Hops = 0;
	dhcp.TransactionId = Endian32(tran_id);
	dhcp.ClientIP = IPToUINT(&ipc->ClientIPAddress);
	if (dhcp.ClientIP == 0)
	{
		dhcp.ClientIP = opt->ClientAddress;
	}
	Copy(dhcp.ClientMacAddress, ipc->MacAddress, 6);

	// UDP pseudo header
	ph_size = b->Size + sizeof(dhcp) + blank_size + sizeof(UINT) + sizeof(UDPV4_PSEUDO_HEADER);
	udp_size = b->Size + sizeof(dhcp) + blank_size + sizeof(UINT) + sizeof(UDP_HEADER);

	ph = ZeroMalloc(ph_size);
	ph->SrcIP = IPToUINT(&ipc->ClientIPAddress);
	ph->DstIP = IPToUINT(dest_ip);
	ph->Protocol = IP_PROTO_UDP;
	ph->PacketLength1 = Endian16(udp_size);
	ph->SrcPort = Endian16(NAT_DHCP_CLIENT_PORT);
	ph->DstPort = Endian16(NAT_DHCP_SERVER_PORT);
	ph->PacketLength2 = Endian16(udp_size);

	Copy(((UCHAR *)(ph)) + sizeof(UDPV4_PSEUDO_HEADER), &dhcp, sizeof(dhcp));
	Copy(((UCHAR *)(ph)) + sizeof(UDPV4_PSEUDO_HEADER) + sizeof(dhcp) + blank_size, &magic_number, sizeof(UINT));
	Copy(((UCHAR *)(ph)) + sizeof(UDPV4_PSEUDO_HEADER) + sizeof(dhcp) + blank_size + sizeof(UINT),
	     b->Buf, b->Size);

	// UDP Header
	udp = (UDP_HEADER *)(((UCHAR *)ph) + 12);

	// Calculate the checksum
	checksum = IpChecksum(ph, ph_size);
	if (checksum == 0x0000)
	{
		checksum = 0xffff;
	}
	udp->Checksum = checksum;

	// IP Header
	Zero(&ip, sizeof(ip));
	IPV4_SET_VERSION(&ip, 4);
	IPV4_SET_HEADER_LEN(&ip, 5);
	ip.Identification = Rand16();
	ip.TimeToLive = 128;
	ip.Protocol = IP_PROTO_UDP;
	ip.SrcIP = IPToUINT(&ipc->ClientIPAddress);
	if (dest_ip != NULL)
	{
		ip.DstIP = IPToUINT(dest_ip);
	}
	else
	{
		ip.DstIP = Endian32(0xffffffff);
	}
	ip.TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + udp_size));
	ip.Checksum = IpChecksum(&ip, sizeof(IPV4_HEADER));

	ret = NewBuf();

	WriteBuf(ret, &ip, sizeof(IPV4_HEADER));
	WriteBuf(ret, udp, udp_size);

	FreeBuf(b);
	Free(ph);

	return ret;
}

// Build a option data in the DHCP request packet
BUF *IPCBuildDhcpRequestOptions(IPC *ipc, DHCP_OPTION_LIST *opt)
{
	LIST *o;
	UCHAR opcode;
	BUF *ret;
	// Validate arguments
	if (ipc == NULL || opt == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	// Opcode
	opcode = opt->Opcode;
	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &opcode, sizeof(opcode)));

	// Server ID
	if (opt->ServerAddress != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_SERVER_ADDRESS, &opt->ServerAddress, 4));
	}

	// Requested IP Address
	if (opt->RequestedIp != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_REQUEST_IP_ADDRESS, &opt->RequestedIp, 4));
	}

	// Hostname
	if (IsEmptyStr(opt->Hostname) == false)
	{
		UCHAR client_id[MAX_HOST_NAME_LEN + 32];
		UCHAR macstr[30];
		MacToStr(macstr, sizeof(macstr), ipc->MacAddress);

		Format(client_id, sizeof(client_id), "%s/%s", opt->Hostname, macstr);

		Add(o, NewDhcpOption(DHCP_ID_HOST_NAME, opt->Hostname, StrLen(opt->Hostname)));
		Add(o, NewDhcpOption(DHCP_ID_CLIENT_ID, client_id, StrLen(client_id)));
	}
	else // Client MAC Address
	{
		UCHAR client_id[7];
		client_id[0] = ARP_HARDWARE_TYPE_ETHERNET;
		Copy(client_id + 1, ipc->MacAddress, 6);
		Add(o, NewDhcpOption(DHCP_ID_CLIENT_ID, client_id, sizeof(client_id)));
	}

	// User Class
	if (IsEmptyStr(opt->UserClass) == false)
	{
		Add(o, NewDhcpOption(DHCP_ID_USER_CLASS, opt->UserClass, StrLen(opt->UserClass)));
	}

	// Vendor
	Add(o, NewDhcpOption(DHCP_ID_VENDOR_ID, IPC_DHCP_VENDOR_ID, StrLen(IPC_DHCP_VENDOR_ID)));

	// Parameter Request List
	if (opcode == DHCP_DISCOVER || opcode == DHCP_REQUEST || opcode == DHCP_INFORM)
	{
		UCHAR param_list[12];

		param_list[0] = 1;
		param_list[1] = 15;
		param_list[2] = 3;
		param_list[3] = 6;
		param_list[4] = 44;
		param_list[5] = 46;
		param_list[6] = 47;
		param_list[7] = 31;
		param_list[8] = 33;
		param_list[9] = 121;
		param_list[10] = 249;
		param_list[11] = 43;

		Add(o, NewDhcpOption(DHCP_ID_REQ_PARAM_LIST, param_list, sizeof(param_list)));
	}

	ret = BuildDhcpOptionsBuf(o);

	FreeDhcpOptions(o);

	return ret;
}

// Process the received ARP
void IPCProcessArp(IPC *ipc, BLOCK *b)
{
	UCHAR *dest_mac;
	UCHAR *src_mac;
	ARPV4_HEADER *arp;
	UCHAR *sender_mac;
	IP sender_ip;
	UCHAR *target_mac;
	IP target_ip;
	// Validate arguments
	if (ipc == NULL || b == NULL || b->Size < (14 + sizeof(ARPV4_HEADER)))
	{
		return;
	}

	dest_mac = b->Buf + 0;
	src_mac = b->Buf + 6;

	arp = (ARPV4_HEADER *)(b->Buf + 14);

	if (arp->HardwareType != Endian16(ARP_HARDWARE_TYPE_ETHERNET))
	{
		return;
	}
	if (arp->ProtocolType != Endian16(MAC_PROTO_IPV4))
	{
		return;
	}
	if (arp->HardwareSize != 6 || arp->ProtocolSize != 4)
	{
		return;
	}

	sender_mac = arp->SrcAddress;
	UINTToIP(&sender_ip, arp->SrcIP);

	target_mac = arp->TargetAddress;
	UINTToIP(&target_ip, arp->TargetIP);

	if (CmpIpAddr(&sender_ip, &ipc->ClientIPAddress) == 0)
	{
		// Source is myself
		return;
	}

	IPCAssociateOnArpTable(ipc, &sender_ip, sender_mac);
	IPCAssociateOnArpTable(ipc, &target_ip, target_mac);

	if (Endian16(arp->Operation) == ARP_OPERATION_REQUEST)
	{
		// Received an ARP request
		if (CmpIpAddr(&target_ip, &ipc->ClientIPAddress) == 0)
		{
			// Create a response since a request for its own IP address have received
			if (IsMacUnicast(sender_mac))
			{
				UCHAR tmp[14 + sizeof(ARPV4_HEADER)];
				ARPV4_HEADER *arp = (ARPV4_HEADER *)(tmp + 14);

				Copy(tmp + 0, sender_mac, 6);
				Copy(tmp + 6, ipc->MacAddress, 6);
				WRITE_USHORT(tmp + 12, MAC_PROTO_ARPV4);

				arp->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
				arp->ProtocolType = Endian16(MAC_PROTO_IPV4);
				arp->HardwareSize = 6;
				arp->ProtocolSize = 4;
				arp->Operation = Endian16(ARP_OPERATION_RESPONSE);

				Copy(arp->SrcAddress, ipc->MacAddress, 6);
				arp->SrcIP = IPToUINT(&ipc->ClientIPAddress);

				Copy(arp->TargetAddress, sender_mac, 6);
				arp->TargetIP = IPToUINT(&sender_ip);

				IPCSendL2(ipc, tmp, sizeof(tmp));
			}
		}
	}
}

// Associate the MAC address and IP address on the ARP table
void IPCAssociateOnArpTable(IPC *ipc, IP *ip, UCHAR *mac_address)
{
	IPC_ARP *a;
	// Validate arguments
	if (ipc == NULL || ip == NULL || IsValidUnicastIPAddress4(ip) == false || IsMacUnicast(mac_address) == false)
	{
		return;
	}
	if (CmpIpAddr(&ipc->ClientIPAddress, ip) == 0 || Cmp(ipc->MacAddress, mac_address, 6) == 0)
	{
		return;
	}
	if (IsInSameNetwork4(ip, &ipc->ClientIPAddress, &ipc->SubnetMask) == false)
	{
		// Not to learn the IP address of outside the subnet
		return;
	}

	if (CmpIpAddr(&ipc->BroadcastAddress, ip) == 0)
	{
		// Not to learn the broadcast IP address
		return;
	}

	// Search whether there is ARP table entry already
	a = IPCSearchArpTable(ipc->ArpTable, ip);
	if (a == NULL)
	{
		// Add to the ARP table
		a = IPCNewARP(ip, mac_address);

		Insert(ipc->ArpTable, a);
	}
	else
	{
		Copy(a->MacAddress, mac_address, 6);

		// There is the ARP table entry already
		if (a->Resolved == false)
		{
			a->Resolved = true;
			a->GiveupTime = 0;

			// Send all the packets that are accumulated to be sent
			while (true)
			{
				BLOCK *b = GetNext(a->PacketQueue);

				if (b == NULL)
				{
					break;
				}

				IPCSendIPv4WithDestMacAddr(ipc, b->Buf, b->Size, a->MacAddress);

				FreeBlock(b);
			}
		}

		// Extend the expiration date
		a->ExpireTime = Tick64() + (UINT64)IPC_ARP_LIFETIME;
	}
}

// Interrupt process (This is called periodically)
void IPCProcessInterrupts(IPC *ipc)
{
	// Validate arguments
	if (ipc == NULL)
	{
		return;
	}

	FlushTubeFlushList(ipc->FlushList);
}

// Process the L3 event by the IPC
void IPCProcessL3Events(IPC *ipc)
{
	IPCProcessL3EventsEx(ipc, 0);
}
void IPCProcessL3EventsIPv4Only(IPC *ipc)
{
	UINT previousStatus4 = IPC_PROTO_GET_STATUS(ipc, IPv4State);
	UINT previousStatus6 = IPC_PROTO_GET_STATUS(ipc, IPv6State);
	IPC_PROTO_SET_STATUS(ipc, IPv4State, IPC_PROTO_STATUS_OPENED);
	IPC_PROTO_SET_STATUS(ipc, IPv6State, IPC_PROTO_STATUS_CLOSED);
	IPCProcessL3Events(ipc);
	IPC_PROTO_SET_STATUS(ipc, IPv4State, previousStatus4);
	IPC_PROTO_SET_STATUS(ipc, IPv6State, previousStatus6);
}
void IPCProcessL3EventsEx(IPC *ipc, UINT64 now)
{
	// Validate arguments
	if (ipc == NULL)
	{
		return;
	}
	if (now == 0)
	{
		now = Tick64();
	}

	// Remove old ARP table entries
	IPCFlushArpTableEx(ipc, now);
	IPCIPv6FlushNDTEx(ipc, now);

	// Receive all the L2 packet
	while (true)
	{
		BLOCK *b = IPCRecvL2(ipc);
		if (b == NULL)
		{
			// All reception completed
			break;
		}

		if (b->Size >= 14)
		{
			UCHAR *dest_mac = b->Buf + 0;
			UCHAR *src_mac = b->Buf + 6;
			USHORT protocol = READ_USHORT(b->Buf + 12);

			// Confirm the destination MAC address
			// (Receive if the destination MAC address is the IPC address or a broadcast address)
			if (Cmp(dest_mac, ipc->MacAddress, 6) == 0 || IsMacBroadcast(dest_mac) || IsMacMulticast(dest_mac))
			{
				// If the source MAC address is itselves or invalid address, ignore the packet
				if (Cmp(src_mac, ipc->MacAddress, 6) != 0 && IsMacUnicast(src_mac))
				{
					if (protocol == MAC_PROTO_ARPV4)
					{
						// ARP receiving process
						IPCProcessArp(ipc, b);
					}
					else if (protocol == MAC_PROTO_IPV4)
					{
						// IPv4 receiving process
						if (b->Size >= (14 + 20))
						{
							UCHAR *data = Clone(b->Buf + 14, b->Size - 14);
							UINT size = b->Size - 14;
							IP ip_src, ip_dst;
							bool ok = false;

							// Extract the IP address portion
							UINTToIP(&ip_src, *((UINT *)(((UCHAR *)data) + 12)));
							UINTToIP(&ip_dst, *((UINT *)(((UCHAR *)data) + 16)));

							// Receive only if the IPv4 destination address is its own
							// or 255.255.255.255 or a multicast address or a broadcast address
							if (CmpIpAddr(&ip_dst, &ipc->ClientIPAddress) == 0)
							{
								ok = true;
							}
							else
							{
								const BYTE *ipv4 = IPV4(ip_dst.address);

								if (ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255)
								{
									ok = true;
								}
								else if (ipv4[0] >= 224 && ipv4[1] <= 239)
								{
									ok = true;
								}
								else if (CmpIpAddr(&ipc->BroadcastAddress, &ip_dst) == 0)
								{
									ok = true;
								}
								else if (IsZeroIP(&ipc->ClientIPAddress))
								{
									// Client IP address is undetermined
									ok = true;
								}
							}

							if (ok)
							{
								// Parse DHCP packets
								bool packetConsumed = false;
								if (ipc->DHCPv4Awaiter.IsAwaiting)
								{
									PKT *pkt;
									DHCPV4_DATA *dhcp;

									Debug("Parsing for DHCP awaiter\n");
									pkt = ParsePacketIPv4WithDummyMacHeader(data, size);
									dhcp = ParseDHCPv4Data(pkt);

									if (dhcp != NULL)
									{
										if (Endian32(dhcp->Header->TransactionId) == ipc->DHCPv4Awaiter.TransCode &&
										        dhcp->OpCode == ipc->DHCPv4Awaiter.OpCode)
										{
											FreeDHCPv4Data(ipc->DHCPv4Awaiter.DhcpData);
											ipc->DHCPv4Awaiter.DhcpData = dhcp;
											packetConsumed = true;
										}
										else
										{
											FreeDHCPv4Data(dhcp);
										}
									}

									FreePacketWithData(pkt);
								}

								IPCAssociateOnArpTable(ipc, &ip_src, src_mac);

								if (ipc->IPv4State == IPC_PROTO_STATUS_OPENED && !packetConsumed)
								{
									// Place in the reception queue
									InsertQueue(ipc->IPv4ReceivedQueue, NewBlock(data, size, 0));
								}
								else
								{
									Free(data); // We need to free the packet if we don't save it
								}

							}
							else
							{
								// This packet is discarded because it is irrelevant for me
								Free(data);
							}
						}
					}
					else if (protocol == MAC_PROTO_IPV6)
					{
						PKT *p = ParsePacketUpToICMPv6(b->Buf, b->Size);
						if (p != NULL)
						{
							IP ip_src, ip_dst;
							bool ndtProcessed = false;
							UINT size = b->Size - 14;

							UCHAR *data = Clone(b->Buf + 14, size);

							IPv6AddrToIP(&ip_src, &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
							IPv6AddrToIP(&ip_dst, &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

							if (p->IPv6HeaderPacketInfo.Protocol == IP_PROTO_ICMPV6)
							{
								IP icmpHeaderAddr;
								UINT header_size = 0;
								// We need to parse the Router Advertisement and Neighbor Advertisement messages
								// to build the Neighbor Discovery Table (aka ARP table for IPv6)
								switch (p->ICMPv6HeaderPacketInfo.Type)
								{
								case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
									// We save the router advertisement data for later use
									IPCIPv6AddRouterPrefixes(ipc, &p->ICMPv6HeaderPacketInfo.OptionList, src_mac, &ip_src);
									IPCIPv6AssociateOnNDTEx(ipc, &ip_src, src_mac, true);
									IPCIPv6AssociateOnNDTEx(ipc, &ip_src, p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer->Address, true);
									ndtProcessed = true;
									header_size = sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER);
									break;
								case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
									// We save the neighbor advertisements into NDT
									IPv6AddrToIP(&icmpHeaderAddr, &p->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader->TargetAddress);
									IPCIPv6AssociateOnNDTEx(ipc, &icmpHeaderAddr, src_mac, true);
									IPCIPv6AssociateOnNDTEx(ipc, &ip_src, src_mac, true);
									ndtProcessed = true;
									header_size = sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER);
									break;
								case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
									header_size = sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER);
									break;
								}

								// Remove link-layer address options for Windows clients (required on Windows 11)
								if (header_size > 0)
								{
									UCHAR *src = p->ICMPv6HeaderPacketInfo.Headers.HeaderPointer + header_size;
									UINT opt_size = p->ICMPv6HeaderPacketInfo.DataSize - header_size;
									UCHAR *dst = src;
									UINT removed = 0;

									while (opt_size > sizeof(ICMPV6_OPTION))
									{
										ICMPV6_OPTION *option_header;
										UINT header_total_size;

										option_header = (ICMPV6_OPTION *)src;
										// Calculate the entire header size
										header_total_size = option_header->Length * 8;
										if (header_total_size == 0)
										{
											// The size is zero
											break;
										}
										if (opt_size < header_total_size)
										{
											// Size shortage
											break;
										}

										switch (option_header->Type)
										{
										case ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER:
										case ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER:
											// Skip source or target link-layer option
											removed += header_total_size;
											break;
										default:
											// Copy options other than source link-layer
											if (src != dst)
											{
												UCHAR *tmp = Clone(src, header_total_size);
												Copy(dst, tmp, header_total_size);
												Free(tmp);
											}
											dst += header_total_size;
										}

										src += header_total_size;
										opt_size -= header_total_size;

									}

									// Recalculate length and checksum if modified
									if (removed > 0)
									{
										size -= removed;
										p->L3.IPv6Header->PayloadLength = Endian16(size - sizeof(IPV6_HEADER));
										p->L4.ICMPHeader->Checksum = 0;
										p->L4.ICMPHeader->Checksum =
											CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
												&p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
												p->L4.ICMPHeader, size - sizeof(IPV6_HEADER), 0);
										Copy(data, b->Buf + 14, size);
									}

								}
							}

							// We update the NDT only if we have an entry in it for the IP+Mac
							if (!ndtProcessed)
							{
								IPCIPv6AssociateOnNDT(ipc, &ip_src, src_mac);
							}

							/// TODO: should we or not filter Neighbor Advertisements and/or Neighbor Solicitations?
							if (ipc->IPv6State == IPC_PROTO_STATUS_OPENED)
							{
								InsertQueue(ipc->IPv6ReceivedQueue, NewBlock(data, size, 0));
							}
							else
							{
								Free(data); // We need to free the packet if we don't save it
							}

							FreePacket(p);
						}
					}
				}
			}
		}

		FreeBlock(b);
	}

	IPCProcessInterrupts(ipc);
}

// Configure IPv4 parameters
bool IPCSetIPv4Parameters(IPC *ipc, IP *ip, IP *subnet, IP *gw, DHCP_CLASSLESS_ROUTE_TABLE *rt)
{
	bool changed = false;
	// Validate arguments
	if (ipc == NULL || ip == NULL || subnet == NULL)
	{
		return false;
	}

	if (CmpIpAddr(&ipc->ClientIPAddress, ip) != 0)
	{
		changed = true;
	}
	Copy(&ipc->ClientIPAddress, ip, sizeof(IP));

	if (CmpIpAddr(&ipc->SubnetMask, subnet) != 0)
	{
		changed = true;
	}
	Copy(&ipc->SubnetMask, subnet, sizeof(IP));

	if (gw != NULL)
	{
		if (CmpIpAddr(&ipc->DefaultGateway, gw) != 0)
		{
			changed = true;
		}

		Copy(&ipc->DefaultGateway, gw, sizeof(IP));
	}
	else
	{
		if (IsZeroIP(&ipc->DefaultGateway) == false)
		{
			changed = true;
		}

		Zero(&ipc->DefaultGateway, sizeof(IP));
	}

	GetBroadcastAddress4(&ipc->BroadcastAddress, ip, subnet);

	if (rt != NULL && rt->NumExistingRoutes >= 1)
	{
		if (Cmp(&ipc->ClasslessRoute, rt, sizeof(DHCP_CLASSLESS_ROUTE_TABLE)) != 0)
		{
			changed = true;

			Copy(&ipc->ClasslessRoute, rt, sizeof(DHCP_CLASSLESS_ROUTE_TABLE));
		}
	}

	return changed;
}

// Send an IPv4 packet (client -> server)
void IPCSendIPv4(IPC *ipc, void *data, UINT size)
{
	IP ip_src, ip_dst;
	IP ip_dst_local;
	bool is_broadcast = false;
	UCHAR uc;
	DHCP_CLASSLESS_ROUTE *r = NULL;
	// Validate arguments
	if (ipc == NULL || data == NULL || size < 20 || size > 1500)
	{
		return;
	}

	uc = ((UCHAR *)data)[0];
	if (((uc >> 4) & 0x0f) != 4)
	{
		// Not an IPv4
		return;
	}

	// Extract the IP address portion
	UINTToIP(&ip_src, *((UINT *)(((UCHAR *)data) + 12)));
	UINTToIP(&ip_dst, *((UINT *)(((UCHAR *)data) + 16)));

	// Filter the source IP address
	if (CmpIpAddr(&ip_src, &ipc->ClientIPAddress) != 0)
	{
		// Cut off packets from illegal IP address
		return;
	}

	if (IsZeroIP(&ip_dst))
	{
		// Illegal destination address
		return;
	}

	if (CmpIpAddr(&ip_dst, &ipc->ClientIPAddress) == 0)
	{
		// Packet destined for myself
		return;
	}

	// Get the IP address of the relayed destination
	Copy(&ip_dst_local, &ip_dst, sizeof(IP));

	if (IsInSameNetwork4(&ip_dst, &ipc->ClientIPAddress, &ipc->SubnetMask) == false)
	{
		r = GetBestClasslessRoute(&ipc->ClasslessRoute, &ip_dst);

		if (r == NULL)
		{
			Copy(&ip_dst_local, &ipc->DefaultGateway, sizeof(IP));
		}
		else
		{
			Copy(&ip_dst_local, &r->Gateway, sizeof(IP));
		}
	}

	if (CmpIpAddr(&ipc->BroadcastAddress, &ip_dst) == 0)
	{
		// Local Broadcast
		is_broadcast = true;
	}
	else
	{
		const BYTE *ipv4 = IPV4(ip_dst.address);

		if (ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255)
		{
			// Global Broadcast
			is_broadcast = true;
		}
		else if (ipv4[0] >= 224 && ipv4[0] <= 239)
		{
			// IPv4 Multicast
			UCHAR dest[6];

			// Per RFC 1112, multicast MAC address has the form 01-00-5E-00-00-00,
			// where the lowest 23 bits are copied from the destination IP address.
			dest[0] = 0x01;
			dest[1] = 0x00;
			dest[2] = 0x5e;
			dest[3] = 0x7f & ipv4[1];
			dest[4] = ipv4[2];
			dest[5] = ipv4[3];

			// Send
			IPCSendIPv4WithDestMacAddr(ipc, data, size, dest);

			return;
		}
	}

	if (is_broadcast)
	{
		// Send a broadcast packet
		UCHAR dest[6];
		UINT i;

		// Destination
		for (i = 0; i < 6; i++)
		{
			dest[i] = 0xff;
		}

		// Send
		IPCSendIPv4WithDestMacAddr(ipc, data, size, dest);

		return;
	}

	if (IsZeroIP(&ip_dst_local))
	{
		// Unable to send
		return;
	}

	// Send a unicast packet
	IPCSendIPv4Unicast(ipc, data, size, &ip_dst_local);
}

// Send an IPv4 packet with a specified destination MAC address
void IPCSendIPv4WithDestMacAddr(IPC *ipc, void *data, UINT size, UCHAR *dest_mac_addr)
{
	UCHAR tmp[1514];
	// Validate arguments
	if (ipc == NULL || data == NULL || size < 20 || size > 1500 || dest_mac_addr == NULL)
	{
		return;
	}

	// Destination
	Copy(tmp + 0, dest_mac_addr, 6);

	// Source
	Copy(tmp + 6, ipc->MacAddress, 6);

	// Protocol number
	WRITE_USHORT(tmp + 12, MAC_PROTO_IPV4);

	// Data
	Copy(tmp + 14, data, size);

	// Send
	IPCSendL2(ipc, tmp, size + 14);
}

// Remove old ARP table entries
void IPCFlushArpTable(IPC *ipc)
{
	IPCFlushArpTableEx(ipc, 0);
}
void IPCFlushArpTableEx(IPC *ipc, UINT64 now)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (ipc == NULL)
	{
		return;
	}
	if (now == 0)
	{
		now = Tick64();
	}

	for (i = 0; i < LIST_NUM(ipc->ArpTable); i++)
	{
		IPC_ARP *a = LIST_DATA(ipc->ArpTable, i);
		bool b = false;

		if (a->Resolved && a->ExpireTime <= now)
		{
			b = true;
		}
		else if (a->Resolved == false && a->GiveupTime <= now)
		{
			b = true;
		}

		if (b)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, a);
		}
	}

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IPC_ARP *a = LIST_DATA(o, i);

			IPCFreeARP(a);

			Delete(ipc->ArpTable, a);
		}

		ReleaseList(o);
	}
}

// Send an IPv4 unicast packet
void IPCSendIPv4Unicast(IPC *ipc, void *data, UINT size, IP *next_ip)
{
	IPC_ARP *a;
	// Validate arguments
	if (ipc == NULL || data == NULL || size < 20 || size > 1500 || next_ip == NULL)
	{
		return;
	}

	a = IPCSearchArpTable(ipc->ArpTable, next_ip);

	if (a != NULL)
	{
		// ARP entry is found
		if (a->Resolved)
		{
			// Send
			a->ExpireTime = Tick64() + (UINT64)IPC_ARP_LIFETIME;

			IPCSendIPv4WithDestMacAddr(ipc, data, size, a->MacAddress);
		}
		else
		{
			// Undeliverable because of unresolved table. Accumulate in the queue
			if (a->PacketQueue->num_item < IPC_MAX_PACKET_QUEUE_LEN)
			{
				InsertQueue(a->PacketQueue, NewBlock(Clone(data, size), size, false));
			}
		}
	}
	else
	{
		ARPV4_HEADER arp;
		UCHAR tmp[14 + sizeof(ARPV4_HEADER)];
		UINT i;

		// Because there is no such ARP entry, create a new one
		a = IPCNewARP(next_ip, NULL);

		// Send an ARP request
		Zero(&arp, sizeof(arp));
		arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
		arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
		arp.HardwareSize = 6;
		arp.ProtocolSize = 4;
		arp.Operation = Endian16(ARP_OPERATION_REQUEST);
		Copy(&arp.SrcAddress, &ipc->MacAddress, 6);
		arp.SrcIP = IPToUINT(&ipc->ClientIPAddress);
		arp.TargetIP = IPToUINT(next_ip);

		for (i = 0; i < 6; i++)
		{
			tmp[i] = 0xff;
		}

		Copy(tmp + 6, ipc->MacAddress, 6);

		WRITE_USHORT(tmp + 12, MAC_PROTO_ARPV4);
		Copy(tmp + 14, &arp, sizeof(ARPV4_HEADER));

		IPCSendL2(ipc, tmp, 14 + sizeof(ARPV4_HEADER));

		// Accumulate the IP packet to be transmitted in the queue
		if (a->PacketQueue->num_item < IPC_MAX_PACKET_QUEUE_LEN)
		{
			InsertQueue(a->PacketQueue, NewBlock(Clone(data, size), size, false));
		}

		Insert(ipc->ArpTable, a);
	}
}

// Search the ARP table
IPC_ARP *IPCSearchArpTable(LIST *arpTable, IP *ip)
{
	IPC_ARP t;
	IPC_ARP *a;
	// Validate arguments
	if (arpTable == NULL || ip == NULL)
	{
		return NULL;
	}

	Copy(&t.Ip, ip, sizeof(IP));

	a = Search(arpTable, &t);

	return a;
}

// Release the ARP entry
void IPCFreeARP(IPC_ARP *a)
{
	BLOCK *b;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	while (true)
	{
		b = GetNext(a->PacketQueue);
		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(a->PacketQueue);

	Free(a);
}

// Create a new ARP entry
IPC_ARP *IPCNewARP(IP *ip, UCHAR *mac_address)
{
	IPC_ARP *a;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(IPC_ARP));

	Copy(&a->Ip, ip, sizeof(IP));
	if (mac_address != NULL)
	{
		Copy(a->MacAddress, mac_address, 6);
		a->Resolved = true;
		a->ExpireTime = Tick64() + (UINT64)IPC_ARP_LIFETIME;
	}
	else
	{
		a->GiveupTime = Tick64() + (UINT64)IPC_ARP_GIVEUPTIME;
	}

	a->PacketQueue = NewQueueFast();

	return a;
}

// Compare ARP entries
int IPCCmpArpTable(void *p1, void *p2)
{
	IPC_ARP *a1, *a2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(IPC_ARP **)p1;
	a2 = *(IPC_ARP **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&a1->Ip, &a2->Ip);
}

// Send an Ethernet packet (client -> server)
void IPCSendL2(IPC *ipc, void *data, UINT size)
{
	// Validate arguments
	if (ipc == NULL || data == NULL || size == 0)
	{
		return;
	}

	if (ipc->Sock == NULL)
	{
		return;
	}

	TubeSendEx(ipc->Sock->SendTube, data, size, NULL, true);
	AddTubeToFlushList(ipc->FlushList, ipc->Sock->SendTube);
}

// Receive an IPv4 packet (server -> client)
BLOCK *IPCRecvIPv4(IPC *ipc)
{
	BLOCK *b;
	// Validate arguments
	if (ipc == NULL)
	{
		return NULL;
	}

	b = GetNext(ipc->IPv4ReceivedQueue);

	return b;
}

// Receive an Ethernet packet (server -> client)
BLOCK *IPCRecvL2(IPC *ipc)
{
	TUBEDATA *d;
	BLOCK *b;
	// Validate arguments
	if (ipc == NULL)
	{
		return NULL;
	}

	if (ipc->Sock == NULL)
	{
		return NULL;
	}

	d = TubeRecvAsync(ipc->Sock->RecvTube);

	if (d == NULL)
	{
		return NULL;
	}

	b = NewBlock(d->Data, d->DataSize, 0);

	Free(d->Header);
	Free(d);

	return b;
}

// IPv6 stuff
// Memory management
void IPCIPv6Init(IPC *ipc)
{
	ipc->IPv6ReceivedQueue = NewQueue();
	// The NDT is basically the same as ARP Table with some slight adjustments
	ipc->IPv6NeighborTable = NewList(IPCCmpArpTable);
	ipc->IPv6RouterAdvs = NewList(NULL);

	ipc->IPv6ClientEUI = 0;
	GenerateEui64Address6((UCHAR *)&ipc->IPv6ServerEUI, ipc->MacAddress);

	ipc->IPv6State = IPC_PROTO_STATUS_CLOSED;
}
void IPCIPv6Free(IPC *ipc)
{
	UINT i;
	for (i = 0; i < LIST_NUM(ipc->IPv6NeighborTable); i++)
	{
		IPC_ARP *a = LIST_DATA(ipc->IPv6NeighborTable, i);
		IPCFreeARP(a);
	}

	ReleaseList(ipc->IPv6NeighborTable);

	for (i = 0; i < LIST_NUM(ipc->IPv6RouterAdvs); i++)
	{
		IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(ipc->IPv6RouterAdvs, i);
		Free(ra);
	}

	ReleaseList(ipc->IPv6RouterAdvs);

	while (true)
	{
		BLOCK *b = GetNext(ipc->IPv6ReceivedQueue);
		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(ipc->IPv6ReceivedQueue);
}

// NDT
void IPCIPv6AssociateOnNDT(IPC *ipc, IP *ip, UCHAR *mac_address)
{
	IPCIPv6AssociateOnNDTEx(ipc, ip, mac_address, false);
}
void IPCIPv6AssociateOnNDTEx(IPC *ipc, IP *ip, UCHAR *mac_address, bool isNeighborAdv)
{
	IPC_ARP *a;
	UINT addrType = 0;
	if (ipc == NULL || ip == NULL ||
	        IsValidUnicastIPAddress6(ip) == false ||
	        IsMacUnicast(mac_address) == false)
	{
		return;
	}

	addrType = GetIPAddrType6(ip);

	if (!(addrType & IPV6_ADDR_UNICAST))
	{
		return;
	}

	if (addrType & IPV6_ADDR_GLOBAL_UNICAST)
	{
		if (!IPCIPv6CheckUnicastFromRouterPrefix(ipc, ip, NULL))
		{
			return;
		}
	}

	a = IPCSearchArpTable(ipc->IPv6NeighborTable, ip);

	// We create a new entry only if we got a neighbor advertisement
	if (a == NULL && isNeighborAdv)
	{
		a = IPCNewARP(ip, mac_address);
		Insert(ipc->IPv6NeighborTable, a);
	}
	else if (a == NULL)
	{
		// We skip the NDT association on random packets from unknown locations
		return;
	}
	else
	{
		Copy(a->MacAddress, mac_address, 6);

		if (a->Resolved == false)
		{
			a->Resolved = true;
			a->GiveupTime = 0;
			while (true)
			{
				BLOCK *b = GetNext(a->PacketQueue);

				if (b == NULL)
				{
					break;
				}

				IPCIPv6SendWithDestMacAddr(ipc, b->Buf, b->Size, a->MacAddress);

				FreeBlock(b);
			}
		}

		a->ExpireTime = Tick64() + (UINT64)IPC_IPV6_NDT_LIFETIME;
	}
}

void IPCIPv6FlushNDT(IPC *ipc)
{
	IPCIPv6FlushNDTEx(ipc, 0);
}
void IPCIPv6FlushNDTEx(IPC *ipc, UINT64 now)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (ipc == NULL)
	{
		return;
	}
	if (now == 0)
	{
		now = Tick64();
	}

	for (i = 0; i < LIST_NUM(ipc->IPv6NeighborTable); i++)
	{
		IPC_ARP *a = LIST_DATA(ipc->IPv6NeighborTable, i);
		bool b = false;

		if (a->Resolved && a->ExpireTime <= now)
		{
			b = true;
		}
		else if (a->Resolved == false && a->GiveupTime <= now)
		{
			b = true;
		}
		/// TODO: think about adding retransmission as per RFC4861

		if (b)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, a);
		}
	}

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IPC_ARP *a = LIST_DATA(o, i);

			IPCFreeARP(a);

			Delete(ipc->IPv6NeighborTable, a);
		}

		ReleaseList(o);
	}
}

// Scan the hub IP Table to try to find the EUI-based link-local address
bool IPCIPv6CheckExistingLinkLocal(IPC *ipc, UINT64 eui)
{
	HUB t, *h;
	IP_TABLE_ENTRY i, *e;
	t.Name = ipc->HubName;

	// Construct link local from eui
	Zero(&i.Ip, sizeof(i.Ip));
	i.Ip.address[0] = 0xfe;
	i.Ip.address[1] = 0x80;
	Copy(&i.Ip.address[8], &eui, sizeof(eui));

	h = Search(ipc->Cedar->HubList, &t);

	if (h != NULL)
	{
		e = Search(h->IpTable, &i);
		if (e != NULL)
		{
			return true;
		}
	}

	return false;
}

// RA
void IPCIPv6AddRouterPrefixes(IPC *ipc, ICMPV6_OPTION_LIST *recvPrefix, UCHAR *macAddress, IP *ip)
{
	UINT i, j;
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (recvPrefix->Prefix[i] != NULL)
		{
			bool foundPrefix = false;
			for (j = 0; j < LIST_NUM(ipc->IPv6RouterAdvs); j++)
			{
				IPC_IPV6_ROUTER_ADVERTISEMENT *existingRA = LIST_DATA(ipc->IPv6RouterAdvs, j);
				if (Cmp(&recvPrefix->Prefix[i]->Prefix, &existingRA->RoutedPrefix.address, sizeof(IPV6_ADDR)) == 0)
				{
					foundPrefix = true;
					break;
				}
			}

			if (!foundPrefix)
			{
				IPC_IPV6_ROUTER_ADVERTISEMENT *newRA = Malloc(sizeof(IPC_IPV6_ROUTER_ADVERTISEMENT));
				IPv6AddrToIP(&newRA->RoutedPrefix, &recvPrefix->Prefix[i]->Prefix);
				IntToSubnetMask6(&newRA->RoutedMask, recvPrefix->Prefix[i]->SubnetLength);
				CopyIP(&newRA->RouterAddress, ip);
				Copy(newRA->RouterMacAddress, macAddress, 6);
				Copy(newRA->RouterLinkLayerAddress, recvPrefix->SourceLinkLayer->Address, 6);
				Add(ipc->IPv6RouterAdvs, newRA);
			}
		}
		else
		{
			break;
		}
	}
}

bool IPCIPv6CheckUnicastFromRouterPrefix(IPC *ipc, IP *ip, IPC_IPV6_ROUTER_ADVERTISEMENT *matchedRA)
{
	UINT i;
	IPC_IPV6_ROUTER_ADVERTISEMENT *matchingRA = NULL;
	bool isInPrefix = false;

	if (LIST_NUM(ipc->IPv6RouterAdvs) == 0)
	{
		// We have a unicast packet but we haven't got any RAs.
		// The client is probably misconfigured in IPv6. We send non-blocking RS at best effort.
		IPCSendIPv6RouterSoliciation(ipc, false);
		return false;
	}

	for (i = 0; i < LIST_NUM(ipc->IPv6RouterAdvs); i++)
	{
		IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(ipc->IPv6RouterAdvs, i);
		isInPrefix = IsInSameNetwork6(ip, &ra->RoutedPrefix, &ra->RoutedMask);
		if (isInPrefix)
		{
			matchingRA = ra;
			break;
		}
	}

	if (matchedRA != NULL && matchingRA != NULL)
	{
		Copy(matchedRA, matchingRA, sizeof(IPC_IPV6_ROUTER_ADVERTISEMENT));
	}

	return isInPrefix;
}

// Send router solicitation to find a router
bool IPCSendIPv6RouterSoliciation(IPC *ipc, bool blocking)
{
	IP destIP;
	IPV6_ADDR destV6;
	UCHAR destMacAddress[6];
	IPV6_ADDR linkLocal;
	BUF *packet;
	UINT64 giveup_time = Tick64() + (UINT64)(IPC_IPV6_RA_MAX_RETRIES * IPC_IPV6_RA_INTERVAL);
	UINT64 timeout_retry = 0;

	// If we don't have a valid client EUI, we can't generate a correct link local
	if (ipc->IPv6ClientEUI == 0)
	{
		return false;
	}

	Zero(&linkLocal, sizeof(IPV6_ADDR));

	// Generate link local from client's EUI
	linkLocal.Value[0] = 0xFE;
	linkLocal.Value[1] = 0x80;
	Copy(&linkLocal.Value[8], &ipc->IPv6ClientEUI, sizeof(UINT64));

	GetAllRouterMulticastAddress6(&destIP);

	// Generate the MAC address from the multicast address
	destMacAddress[0] = 0x33;
	destMacAddress[1] = 0x33;
	Copy(&destMacAddress[2], &destIP.address[12], sizeof(UINT));

	IPToIPv6Addr(&destV6, &destIP);

	packet = BuildICMPv6RouterSoliciation(&linkLocal, &destV6, ipc->MacAddress, 0);

	if (blocking == false) {
		IPCIPv6SendWithDestMacAddr(ipc, packet->Buf, packet->Size, destMacAddress);
		FreeBuf(packet);
		return false;
	}

	while (LIST_NUM(ipc->IPv6RouterAdvs) == 0)
	{
		UINT64 now = Tick64();
		if (now >= timeout_retry)
		{
			timeout_retry = now + (UINT64)IPC_IPV6_RA_INTERVAL;
			IPCIPv6SendWithDestMacAddr(ipc, packet->Buf, packet->Size, destMacAddress);
		}

		AddInterrupt(ipc->Interrupt, timeout_retry);

		if (Tick64() >= giveup_time)
		{
			// We failed to receive any router advertisements
			FreeBuf(packet);
			return false;
		}

		// The processing should populate the received RAs by itself
		IPCProcessL3Events(ipc);
	}

	FreeBuf(packet);
	return true;
}

// Data flow
BLOCK *IPCIPv6Recv(IPC *ipc)
{
	BLOCK *b;
	// Validate arguments
	if (ipc == NULL)
	{
		return NULL;
	}

	b = GetNext(ipc->IPv6ReceivedQueue);

	return b;
}

void IPCIPv6Send(IPC *ipc, void *data, UINT size)
{
	IP destAddr;
	UINT ipv6Type;
	UCHAR destMac[6];
	IPV6_HEADER *header = data;

	IPv6AddrToIP(&destAddr, &header->DestAddress);

	if (IsValidUnicastIPAddress6(&destAddr))
	{
		IPCIPv6SendUnicast(ipc, data, size, &destAddr);
		return;
	}

	// Here we're probably dealing with a multicast packet. But let's check it anyway
	ipv6Type = GetIPAddrType6(&destAddr);
	if (ipv6Type & IPV6_ADDR_MULTICAST)
	{
		// Constructing multicast MAC address based on destination IP address, then just fire and forget
		destMac[0] = 0x33;
		destMac[1] = 0x33;
		destMac[2] = destAddr.address[12];
		destMac[3] = destAddr.address[13];
		destMac[4] = destAddr.address[14];
		destMac[5] = destAddr.address[15];
		IPCIPv6SendWithDestMacAddr(ipc, data, size, destMac);
		return;
	}
	else
	{
		Debug("We got a weird packet with a weird type! %i\n", ipv6Type);
	}
}

void IPCIPv6SendWithDestMacAddr(IPC *ipc, void *data, UINT size, UCHAR *dest_mac_addr)
{
	UCHAR tmp[1514];

	IPV6_HEADER *header = data;


	// Validate arguments
	if (ipc == NULL || data == NULL || size < 40 || size > 1500 || dest_mac_addr == NULL)
	{
		return;
	}

	// Destination
	Copy(tmp + 0, dest_mac_addr, 6);

	// Source
	Copy(tmp + 6, ipc->MacAddress, 6);

	// Protocol number
	WRITE_USHORT(tmp + 12, MAC_PROTO_IPV6);

	// Data
	Copy(tmp + 14, data, size);

	// Parse the packet for ND ICMPv6 fixup
	if (header->NextHeader == IP_PROTO_ICMPV6)
	{
		PKT *p = ParsePacketUpToICMPv6(tmp, size + 14);
		if (p != NULL)
		{
			ICMPV6_OPTION_LINK_LAYER linkLayer;
			BUF *buf;
			BUF *optBuf;
			BUF *packet;
			UINT header_size = 0;
			// We need to rebuild the packet to
			switch (p->ICMPv6HeaderPacketInfo.Type)
			{
			case ICMPV6_TYPE_ROUTER_SOLICIATION:
				header_size = sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER);
				if (p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer == NULL)
				{
					p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer = &linkLayer;
				}
				Copy(p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer->Address, ipc->MacAddress, 6);
				break;
			case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
				header_size = sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER);
				if (p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer == NULL)
				{
					p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer = &linkLayer;
				}
				Copy(p->ICMPv6HeaderPacketInfo.OptionList.SourceLinkLayer->Address, ipc->MacAddress, 6);
				break;
			case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
				header_size = sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER);
				if (p->ICMPv6HeaderPacketInfo.OptionList.TargetLinkLayer == NULL)
				{
					p->ICMPv6HeaderPacketInfo.OptionList.TargetLinkLayer = &linkLayer;
				}
				Copy(p->ICMPv6HeaderPacketInfo.OptionList.TargetLinkLayer->Address, ipc->MacAddress, 6);
				break;
			}
			switch (p->ICMPv6HeaderPacketInfo.Type)
			{
			case ICMPV6_TYPE_ROUTER_SOLICIATION:
			case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
			case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
				optBuf = BuildICMPv6Options(&p->ICMPv6HeaderPacketInfo.OptionList);
				buf = NewBuf();
				WriteBuf(buf, p->ICMPv6HeaderPacketInfo.Headers.HeaderPointer, header_size);
				WriteBufBuf(buf, optBuf);
				packet = BuildICMPv6(&p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress,
				                     &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress,
				                     p->IPv6HeaderPacketInfo.IPv6Header->HopLimit,
				                     p->ICMPv6HeaderPacketInfo.Type,
				                     p->ICMPv6HeaderPacketInfo.Code,
				                     buf->Buf,
				                     buf->Size,
				                     0);
				Copy(tmp + 14, packet->Buf, packet->Size);
				size = packet->Size;
				FreeBuf(optBuf);
				FreeBuf(buf);
				FreeBuf(packet);
				break;
			}
		}
		FreePacket(p);
	}

	// Send
	IPCSendL2(ipc, tmp, size + 14);
}

void IPCIPv6SendUnicast(IPC *ipc, void *data, UINT size, IP *next_ip)
{
	IPC_ARP *ndtMatch;
	UCHAR *destMac = NULL;
	IPC_IPV6_ROUTER_ADVERTISEMENT ra;
	IPV6_HEADER *header = data;
	IP srcIp;
	bool isLocal = false;
	// First we need to understand if it is a local packet or we should route it through the router
	UINT addrType = GetIPAddrType6(next_ip);

	Zero(&ra, sizeof(IPC_IPV6_ROUTER_ADVERTISEMENT));
	IPv6AddrToIP(&srcIp, &header->SrcAddress);

	// Link local is always local =)
	if (addrType & IPV6_ADDR_LOCAL_UNICAST)
	{
		isLocal = true;
	}

	// If it matches any received prefix from router advertisements, it's also local
	if (!isLocal && IPCIPv6CheckUnicastFromRouterPrefix(ipc, next_ip, &ra))
	{
		isLocal = true;
	}

	// If it is a global packet, we need to get our source IP prefix to know through which router shall we route
	if (!isLocal)
	{
		if (!IPCIPv6CheckUnicastFromRouterPrefix(ipc, &srcIp, &ra))
		{
			// If we didn't find a router for the source IP, let's just try to pick the first router and try to send to it
			if (LIST_NUM(ipc->IPv6RouterAdvs) > 0)
			{
				Copy(&ra, LIST_DATA(ipc->IPv6RouterAdvs, 0), sizeof(IPC_IPV6_ROUTER_ADVERTISEMENT));
			}
			else
			{
				char tmp[MAX_SIZE];
				IPToStr6(tmp, MAX_SIZE, &srcIp);
				Debug("We couldn't find a router for the source address of %s! Trying as local.\n", tmp);
				isLocal = true;
			}
		}

		destMac = ra.RouterMacAddress;
		if (!IsMacUnicast(destMac) && !IsMacInvalid(ra.RouterMacAddress))
		{
			destMac = ra.RouterLinkLayerAddress;
		}
	}

	// If it is local it should be routed directly through the NDT
	if (isLocal)
	{
		ndtMatch = IPCSearchArpTable(ipc->IPv6NeighborTable, next_ip);
		if (ndtMatch == NULL)
		{
			// Creating a non-matched NDT entry
			ndtMatch = IPCNewARP(next_ip, NULL);
			Add(ipc->IPv6NeighborTable, ndtMatch);
		}

		if (ndtMatch->Resolved != true && LIST_NUM(ipc->IPv6RouterAdvs) > 0)
		{
			// First try to look up in router advertisements
			UINT i;
			for (i = 0; i < LIST_NUM(ipc->IPv6RouterAdvs); i++)
			{
				IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(ipc->IPv6RouterAdvs, i);
				if (CmpIpAddr(next_ip, &ra->RouterAddress) == 0)
				{
					Copy(ndtMatch->MacAddress, IsMacUnicast(ra->RouterLinkLayerAddress) ? ra->RouterLinkLayerAddress : ra->RouterMacAddress, 6);
					ndtMatch->Resolved = true;
					break;
				}
			}
		}

		if (ndtMatch->Resolved != true)
		{
			// We need to send the Neighbor Solicitation and save the packet for sending later
			// Generate the MAC address from the multicast address
			BUF *neighborSolicit;
			UCHAR destMacAddress[6];

			char tmp[MAX_SIZE];
			UCHAR *copy;
			BLOCK *blk;

			neighborSolicit = BuildICMPv6NeighborSoliciation(&header->SrcAddress, &header->DestAddress, ipc->MacAddress, 0, true);
			destMacAddress[0] = 0x33;
			destMacAddress[1] = 0x33;
			destMacAddress[2] = 0xFF;
			Copy(&destMacAddress[3], &header->DestAddress.Value[13], 3);
			IPCIPv6SendWithDestMacAddr(ipc, neighborSolicit->Buf, neighborSolicit->Size, destMacAddress);

			FreeBuf(neighborSolicit);


			copy = Clone(data, size);
			blk = NewBlock(copy, size, 0);
			InsertQueue(ndtMatch->PacketQueue, blk);
			IPToStr6(tmp, MAX_SIZE, next_ip);

			return;
		}
		destMac = ndtMatch->MacAddress;
	}

	if (destMac != NULL && !IsMacInvalid(destMac))
	{
		IPCIPv6SendWithDestMacAddr(ipc, data, size, destMac);
	}
	else
	{
		char tmp[MAX_SIZE];
		IPToStr6(tmp, MAX_SIZE, next_ip);
		Debug("We couldn't deduce the MAC address for unicast address %s, packet dropped.\n", tmp);
		/// TODO: think about sending to the all routers broadcast MAC as a last resort
	}
}
