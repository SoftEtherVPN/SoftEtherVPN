// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AzureClient.c
// VPN Azure Client

#include "AzureClient.h"

#include "Cedar.h"
#include "Command.h"
#include "Logging.h"
#include "Wpc.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/MayaType.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>

// Wait for connection request
void AcWaitForRequest(AZURE_CLIENT *ac, SOCK *s, AZURE_PARAM *param)
{
	// Validate arguments
	if (ac == NULL || s == NULL || param == NULL)
	{
		return;
	}

	while (ac->Halt == false)
	{
		UCHAR uc;

		// Receive 1 byte
		if (RecvAll(s, &uc, 1, param->UseEncryption) == 0)
		{
			break;
		}

		if (uc != 0)
		{
			// Receive a Pack
			PACK *p = RecvPackWithHash(s);

			if (p == NULL)
			{
				break;
			}
			else
			{
				// Verify contents of Pack
				char opcode[MAX_SIZE];
				char cipher_name[MAX_SIZE];
				char hostname[MAX_SIZE];

				PackGetStr(p, "opcode", opcode, sizeof(opcode));
				PackGetStr(p, "cipher_name", cipher_name, sizeof(cipher_name));
				PackGetStr(p, "hostname", hostname, sizeof(hostname));

				if (StrCmpi(opcode, "relay") == 0)
				{
					IP client_ip, server_ip;
					UINT client_port;
					UINT server_port;
					UCHAR session_id[SHA1_SIZE];
					UCHAR relay_cert_hash[SHA1_SIZE];

					if (PackGetIp(p, "client_ip", &client_ip) &&
						PackGetIp(p, "server_ip", &server_ip) &&
						PackGetData2(p, "session_id", session_id, sizeof(session_id)))
					{
						client_port = PackGetInt(p, "client_port");
						server_port = PackGetInt(p, "server_port");

						if (client_port != 0 && server_port != 0)
						{
							SOCK *ns;
							Debug("Connect Request from %r:%u\n", &client_ip, client_port);
							char ipstr[128];
							IPToStr(ipstr, sizeof(ipstr), &client_ip);
							SLog(ac->Cedar, "LS_AZURE_START", ipstr, client_port);

							// Create new socket and connect VPN Azure Server
							if (param->UseCustom)
							{
								// Get relay server info from pack
								char relay_addr[MAX_HOST_NAME_LEN + 1];
								UINT relay_port;

								relay_port = PackGetInt(p, "relay_port");

								if (PackGetStr(p, "relay_address", relay_addr, sizeof(relay_addr)) &&
									PackGetData2(p, "cert_hash", relay_cert_hash, sizeof(relay_cert_hash)) &&
									relay_port != 0)
								{
									ns = ConnectEx2(relay_addr, relay_port, 0, (bool *)&ac->Halt);
									
									if (ns != NULL)
									{
										UINT ssl_err = 0;
										Copy(&ns->SslAcceptSettings, &ac->Cedar->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));

										if (StartSSLEx3(ns, NULL, NULL, NULL, 0, relay_addr, NULL, &ssl_err) == false)
										{
											if (ssl_err != 0)
											{
												SLog(ac->Cedar, "LS_AZURE_SSL_ERROR", GetUniErrorStr(ssl_err), ssl_err);
											}

											Disconnect(ns);
											ReleaseSock(ns);
											ns = NULL;
										}
									}
								}
							}
							else
							{
								BUF *b = StrToBin(ac->DDnsStatus.AzureCertHash);
								if (b->Size == SHA1_SIZE)
								{
									Copy(relay_cert_hash, b->Buf, SHA1_SIZE);
								}
								FreeBuf(b);

								if (ac->DDnsStatusCopy.InternetSetting.ProxyType == PROXY_DIRECT)
								{
									ns = ConnectEx2(ac->DDnsStatusCopy.CurrentAzureIp, AZURE_SERVER_PORT,
										0, (bool *)&ac->Halt);
								}
								else
								{
									ns = WpcSockConnect2(ac->DDnsStatusCopy.CurrentAzureIp, AZURE_SERVER_PORT,
										&ac->DDnsStatusCopy.InternetSetting, NULL, AZURE_VIA_PROXY_TIMEOUT);
								}
							}

							if (ns == NULL)
							{
								Debug("Connect Error.\n");
							}
							else
							{
								Debug("Connected to the relay server.\n");

								SetTimeout(ns, param->DataTimeout);

								UINT ssl_err = 0;
								Copy(&ns->SslAcceptSettings, &ac->Cedar->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));

								if (StartSSLEx3(ns, NULL, NULL, NULL, 0, NULL, NULL, &ssl_err))
								{
									// Check certification
									UCHAR server_cert_hash[SHA1_SIZE];

									Zero(server_cert_hash, sizeof(server_cert_hash));
									GetXDigest(ns->RemoteX, server_cert_hash, true);

									if (Cmp(relay_cert_hash, server_cert_hash, SHA1_SIZE) == 0)
									{
										if (SendAll(ns, AZURE_PROTOCOL_DATA_SIANGTURE, 24, true))
										{
											PACK *p2 = NewPack();

											PackAddStr(p2, "hostname", hostname);
											PackAddData(p2, "session_id", session_id, sizeof(session_id));

											if (SendPackWithHash(ns, p2))
											{
												UCHAR uc;

												if (RecvAll(ns, &uc, 1, true) != false)
												{
													if (uc != 0)
													{
														SOCK *accept_sock = GetReverseListeningSock(ac->Cedar);

														if (accept_sock != NULL)
														{
															AddRef(ns->ref);

															SetTimeout(ns, INFINITE);

															Copy(&ns->Reverse_MyServerGlobalIp, &server_ip, sizeof(IP));
															ns->Reverse_MyServerPort = server_port;

															InjectNewReverseSocketToAccept(accept_sock, ns,
																&client_ip, client_port);

															ReleaseSock(accept_sock);
														}
													}
												}
											}

											FreePack(p2);
										}
									}
								}
								else
								{
									if (ssl_err != 0)
									{
										SLog(ac->Cedar, "LS_AZURE_SSL_ERROR", GetUniErrorStr(ssl_err), ssl_err);
									}
								}

								ReleaseSock(ns);
							}
						}
					}
				}

				FreePack(p);
			}
		}

		// Send 1 byte
		uc = 0;
		if (SendAll(s, &uc, 1, param->UseEncryption) == 0)
		{
			break;
		}
	}
}

// VPN Azure client main thread
void AcMainThread(THREAD *thread, void *param)
{
	AZURE_CLIENT *ac = (AZURE_CLIENT *)param;
	UINT last_ip_revision = INFINITE;
	UINT64 last_reconnect_tick = 0;
	UINT64 next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
	UINT num_reconnect_retry = 0;
	UINT64 next_ddns_retry_tick = 0;
	bool last_connect_ok = false;
	// Validate arguments
	if (ac == NULL || thread == NULL)
	{
		return;
	}

	while (ac->Halt == false)
	{
		UINT64 now = Tick64();
		bool connect_was_ok = false;
		// Wait for enabling VPN Azure function
		if (ac->IsEnabled)
		{
			// VPN Azure is enabled
			DDNS_CLIENT_STATUS st;
			bool connect_now = false;
			bool azure_ip_changed = false;
			bool use_custom_azure = false;
			bool use_encryption = false;
			char hostname[MAX_HOST_NAME_LEN + 1];
			UCHAR hashed_password[SHA1_SIZE];
			char server_address[MAX_HOST_NAME_LEN + 1];
			UINT server_port = AZURE_SERVER_PORT;
			bool add_default_ca = false;
			bool verify_server = false;
			X *server_cert = NULL;
			X *client_cert = NULL;
			K *client_key = NULL;

			Lock(ac->Lock);
			{
				if (ac->UseCustom && ac->CustomConfig != NULL)
				{
					use_custom_azure = true;
					use_encryption = true;
					StrCpy(hostname, sizeof(hostname), ac->CustomConfig->Hostname);
					Copy(hashed_password, ac->CustomConfig->HashedPassword, SHA1_SIZE);
					StrCpy(server_address, sizeof(server_address), ac->CustomConfig->ServerName);
					server_port = ac->CustomConfig->ServerPort;
					verify_server = ac->CustomConfig->VerifyServer;
					add_default_ca = ac->CustomConfig->AddDefaultCA;
					server_cert = CloneX(ac->CustomConfig->ServerCert);
					client_cert = CloneX(ac->CustomConfig->ClientX);
					client_key = CloneK(ac->CustomConfig->ClientK);
				}
				else
				{
					Copy(&st, &ac->DDnsStatus, sizeof(DDNS_CLIENT_STATUS));
					StrCpy(server_address, sizeof(server_address), st.CurrentAzureIp);
					StrCpy(hostname, sizeof(hostname), st.CurrentHostName);

					if (StrCmpi(st.CurrentAzureIp, ac->DDnsStatusCopy.CurrentAzureIp) != 0)
					{
						if (IsEmptyStr(st.CurrentAzureIp) == false)
						{
							// Destination IP address is changed
							connect_now = true;
							num_reconnect_retry = 0;
						}
					}

					if (StrCmpi(st.CurrentHostName, ac->DDnsStatusCopy.CurrentHostName) != 0)
					{
						// DDNS host name is changed
						connect_now = true;
						num_reconnect_retry = 0;
					}

					Copy(&ac->DDnsStatusCopy, &st, sizeof(DDNS_CLIENT_STATUS));
				}
			}
			Unlock(ac->Lock);

			if (last_ip_revision != ac->IpStatusRevision)
			{
				last_ip_revision = ac->IpStatusRevision;

				connect_now = true;

				num_reconnect_retry = 0;
			}

			if (last_reconnect_tick == 0 || (now >= (last_reconnect_tick + next_reconnect_interval)))
			{
				UINT r;

				last_reconnect_tick = now;
				num_reconnect_retry++;
				next_reconnect_interval = (UINT64)num_reconnect_retry * AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
				next_reconnect_interval = MIN(next_reconnect_interval, AZURE_CONNECT_MAX_RETRY_INTERVAL);

				r = (UINT)next_reconnect_interval;

				r = GenRandInterval(r / 2, r);

				next_reconnect_interval = r;

				connect_now = true;
			}

			if (IsEmptyStr(server_address) == false && IsEmptyStr(hostname) == false)
			{
				if (connect_now)
				{
					SOCK *s;
					char *host = NULL;
					UINT port;

					Debug("VPN Azure: Connecting to %s...\n", server_address);

					if (ParseHostPort(server_address, &host, &port, server_port))
					{
						if (use_custom_azure)
						{
							s = ConnectEx2(host, port, 0, (bool *)&ac->Halt);

							if (s != NULL && use_encryption)
							{
								// Enable SSL peer verification if we have a server cert or trust system CA
								SSL_VERIFY_OPTION ssl_option;
								Zero(&ssl_option, sizeof(ssl_option));
								ssl_option.VerifyPeer = verify_server;
								ssl_option.AddDefaultCA = add_default_ca;
								ssl_option.VerifyHostname = verify_server;
								ssl_option.SavedCert = server_cert;

								UINT ssl_err = 0;
								Copy(&s->SslAcceptSettings, &ac->Cedar->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));

								if (StartSSLEx3(s, client_cert, client_key, NULL, 0, server_address, &ssl_option, &ssl_err) == false)
								{
									if (ssl_err != 0)
									{
										SLog(ac->Cedar, "LS_AZURE_SSL_ERROR", GetUniErrorStr(ssl_err), ssl_err);
									}

									Disconnect(s);
									ReleaseSock(s);
									s = NULL;
								}
							}
						}
						else if (st.InternetSetting.ProxyType == PROXY_DIRECT)
						{
							s = ConnectEx2(host, port, 0, (bool *)&ac->Halt);
						}
						else
						{
							s = WpcSockConnect2(host, port, &st.InternetSetting, NULL, AZURE_VIA_PROXY_TIMEOUT);
						}

						if (s != NULL)
						{
							PACK *p;
							UINT64 established_tick = 0;

							Debug("VPN Azure: Connected.\n");

							SetTimeout(s, AZURE_PROTOCOL_CONTROL_TIMEOUT_DEFAULT);

							Lock(ac->Lock);
							{
								ac->CurrentSock = s;
								ac->IsConnected = true;
								StrCpy(ac->ConnectingAzureIp, sizeof(ac->ConnectingAzureIp), server_address);
							}
							Unlock(ac->Lock);

							SendAll(s, AZURE_PROTOCOL_CONTROL_SIGNATURE, StrLen(AZURE_PROTOCOL_CONTROL_SIGNATURE), use_encryption);

							// Receive parameter
							p = RecvPackWithHash(s);
							if (p != NULL)
							{
								UCHAR c;
								AZURE_PARAM param;
								bool hostname_changed = false;

								Zero(&param, sizeof(param));

								param.ControlKeepAlive = PackGetInt(p, "ControlKeepAlive");
								param.ControlTimeout = PackGetInt(p, "ControlTimeout");
								param.DataTimeout = PackGetInt(p, "DataTimeout");
								param.SslTimeout = PackGetInt(p, "SslTimeout");
								param.UseCustom = use_custom_azure;
								param.UseEncryption = use_encryption;

								UCHAR random[SHA1_SIZE];
								PackGetData2(p, "Random", random, sizeof(random));

								FreePack(p);

								param.ControlKeepAlive = MAKESURE(param.ControlKeepAlive, 1000, AZURE_SERVER_MAX_KEEPALIVE);
								param.ControlTimeout = MAKESURE(param.ControlTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);
								param.DataTimeout = MAKESURE(param.DataTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);
								param.SslTimeout = MAKESURE(param.SslTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);

								Lock(ac->Lock);
								{
									Copy(&ac->AzureParam, &param, sizeof(AZURE_PARAM));
								}
								Unlock(ac->Lock);

								SetTimeout(s, param.ControlTimeout);

								// Send parameter
								p = NewPack();
								PackAddStr(p, "CurrentHostName", hostname);
								PackAddStr(p, "CurrentAzureIp", server_address);

								if (use_custom_azure == false)
								{
									PackAddInt64(p, "CurrentAzureTimestamp", st.CurrentAzureTimestamp);
									PackAddStr(p, "CurrentAzureSignature", st.CurrentAzureSignature);
								}
								else
								{
									BUF *b = NewBuf();
									UCHAR hash[SHA1_SIZE];

									WriteBuf(b, hashed_password, SHA1_SIZE);
									WriteBuf(b, random, SHA1_SIZE);
									Sha1(hash, b->Buf, b->Size);
									PackAddData(p, "PasswordHash", hash, SHA1_SIZE);
									FreeBuf(b);
								}

								Lock(ac->Lock);
								{
									if (use_custom_azure == false && StrCmpi(hostname, ac->DDnsStatus.CurrentHostName) != 0)
									{
										hostname_changed = true;
									}
								}
								Unlock(ac->Lock);

								if (hostname_changed == false)
								{
									if (SendPackWithHash(s, p))
									{
										// Receive result
										if (RecvAll(s, &c, 1, use_encryption))
										{
											if (c && ac->Halt == false)
											{
												connect_was_ok = true;

												established_tick = Tick64();

												AcWaitForRequest(ac, s, &param);
											}
										}
									}
								}

								FreePack(p);
							}
							else
							{
								WHERE;
							}

							Debug("VPN Azure: Disconnected.\n");

							Lock(ac->Lock);
							{
								ac->IsConnected = false;
								ac->CurrentSock = NULL;
								ClearStr(ac->ConnectingAzureIp, sizeof(ac->ConnectingAzureIp));
							}
							Unlock(ac->Lock);

							if (established_tick != 0)
							{
								if ((established_tick + (UINT64)AZURE_CONNECT_MAX_RETRY_INTERVAL) <= Tick64())
								{
									// If the connected time exceeds the AZURE_CONNECT_MAX_RETRY_INTERVAL, reset the retry counter.
									last_reconnect_tick = 0;
									num_reconnect_retry = 0;
									next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
								}
							}

							Disconnect(s);
							ReleaseSock(s);
						}
						else
						{
							Debug("VPN Azure: Error: Connect Failed.\n");
						}

						Free(host);
					}
				}
			}

			FreeX(server_cert);
			FreeX(client_cert);
			FreeK(client_key);
		}
		else
		{
			last_reconnect_tick = 0;
			num_reconnect_retry = 0;
			next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
		}

		if (ac->Halt)
		{
			break;
		}

		if (connect_was_ok)
		{
			// If connection goes out after connected, increment connection success count to urge DDNS client query
			next_ddns_retry_tick = Tick64() + MIN((UINT64)DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF * (UINT64)(num_reconnect_retry + 1), (UINT64)DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX);
		}

		if ((next_ddns_retry_tick != 0) && (Tick64() >= next_ddns_retry_tick))
		{
			next_ddns_retry_tick = 0;

			ac->DDnsTriggerInt++;
		}

		Wait(ac->Event, rand() % 1000);
	}
}

// Enable or disable VPN Azure client
void AcSetEnable(AZURE_CLIENT *ac, bool enabled, bool use_custom)
{
	bool changed = false;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	if (ac->IsEnabled != enabled)
	{
		ac->IsEnabled = enabled;
		changed = true;
	}

	if (ac->UseCustom != use_custom)
	{
		ac->UseCustom = use_custom;
		changed = true;
	}

	if (ac->IsEnabled && ac->UseCustom == false && changed)
	{
		ac->DDnsTriggerInt++;
	}

	if (ac->IsEnabled == false)
	{
		// If VPN Azure client is disabled, disconnect current data connection
		changed = true;
	}

	AcApplyCurrentConfig(ac, NULL, NULL, changed);
}

// Set current configuration to VPN Azure client
void AcApplyCurrentConfig(AZURE_CLIENT *ac, DDNS_CLIENT_STATUS *ddns_status, AZURE_CUSTOM_CONFIG *config, bool disconnect)
{
	bool disconnect_now = disconnect;
	SOCK *disconnect_sock = NULL;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	// Get current DDNS configuration
	Lock(ac->Lock);
	{
		if (config != NULL)
		{
			if (ac->UseCustom)
			{
				disconnect_now = true;
			}

			if (ac->CustomConfig == NULL)
			{
				ac->CustomConfig = config;
			}
			else
			{
				FreeX(ac->CustomConfig->ServerCert);
				FreeX(ac->CustomConfig->ClientX);
				FreeK(ac->CustomConfig->ClientK);
				Free(ac->CustomConfig);

				ac->CustomConfig = config;
			}
		}

		if (ddns_status != NULL)
		{
			if (ac->UseCustom == false)
			{
				if (StrCmpi(ac->DDnsStatus.CurrentHostName, ddns_status->CurrentHostName) != 0)
				{
					// If host name is changed, disconnect current data connection
					disconnect_now = true;
				}

				if (Cmp(&ac->DDnsStatus.InternetSetting, &ddns_status->InternetSetting, sizeof(INTERNET_SETTING)) != 0)
				{
					// If proxy setting is changed, disconnect current data connection
					disconnect_now = true;
				}
			}

			Copy(&ac->DDnsStatus, ddns_status, sizeof(DDNS_CLIENT_STATUS));
		}

		if (disconnect_now)
		{
			if (ac->CurrentSock != NULL)
			{
				disconnect_sock = ac->CurrentSock;
				AddRef(disconnect_sock->ref);
			}
		}
	}
	Unlock(ac->Lock);

	if (disconnect_sock != NULL)
	{
		Disconnect(disconnect_sock);
		ReleaseSock(disconnect_sock);
	}

	Set(ac->Event);
}

// Free VPN Azure client
void FreeAzureClient(AZURE_CLIENT *ac)
{
	SOCK *disconnect_sock = NULL;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	ac->Halt = true;

	Lock(ac->Lock);
	{
		if (ac->CurrentSock != NULL)
		{
			disconnect_sock = ac->CurrentSock;

			AddRef(disconnect_sock->ref);
		}
	}
	Unlock(ac->Lock);

	if (disconnect_sock != NULL)
	{
		Disconnect(disconnect_sock);
		ReleaseSock(disconnect_sock);
	}

	if (ac->CustomConfig != NULL)
	{
		FreeX(ac->CustomConfig->ServerCert);
		FreeX(ac->CustomConfig->ClientX);
		FreeK(ac->CustomConfig->ClientK);
		Free(ac->CustomConfig);
	}

	Set(ac->Event);

	// Stop main thread
	WaitThread(ac->MainThread, INFINITE);
	ReleaseThread(ac->MainThread);

	ReleaseEvent(ac->Event);

	DeleteLock(ac->Lock);

	Free(ac);
}

// Create new VPN Azure client
AZURE_CLIENT *NewAzureClient(CEDAR *cedar, SERVER *server, AZURE_CUSTOM_CONFIG *config)
{
	AZURE_CLIENT *ac;
	// Validate arguments
	if (cedar == NULL || server == NULL)
	{
		return NULL;
	}

	ac = ZeroMalloc(sizeof(AZURE_CLIENT));

	ac->Cedar = cedar;

	ac->Server = server;

	ac->CustomConfig = config;

	ac->Lock = NewLock();

	ac->IsEnabled = false;

	ac->UseCustom = false;

	ac->Event = NewEvent();

	// Start main thread
	ac->MainThread = NewThread(AcMainThread, ac);

	return ac;
}

