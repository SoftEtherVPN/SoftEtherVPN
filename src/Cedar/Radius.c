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


// Radius.c
// Radius authentication module

#include "CedarPch.h"

// Attempts Radius authentication (with specifying retry interval and multiple server)
bool RadiusLogin(CONNECTION *c, char *server, UINT port, UCHAR *secret, UINT secret_size, wchar_t *username, char *password, UINT interval, UCHAR *mschap_v2_server_response_20,
				 RADIUS_LOGIN_OPTION *opt)
{
	UCHAR random[MD5_SIZE];
	UCHAR id;
	BUF *encrypted_password = NULL;
	BUF *user_name = NULL;
	//IP ip;
	bool ret = false;
	TOKEN_LIST *token;
	UINT i;
	LIST *ip_list;
	IPC_MSCHAP_V2_AUTHINFO mschap;
	bool is_mschap;
	char client_ip_str[MAX_SIZE];
	RADIUS_LOGIN_OPTION opt_dummy;
	static UINT packet_id = 0;
	// Validate arguments
	if (server == NULL || port == 0 || (secret_size != 0 && secret == NULL) || username == NULL || password == NULL)
	{
		return false;
	}

	if (opt == NULL)
	{
		Zero(&opt_dummy, sizeof(opt_dummy));

		opt = &opt_dummy;
	}

	opt->Out_VLanId = 0;

	Zero(client_ip_str, sizeof(client_ip_str));
	if (c != NULL && c->FirstSock != NULL)
	{
		IPToStr(client_ip_str, sizeof(client_ip_str), &c->FirstSock->RemoteIP);
	}

	// Parse the MS-CHAP v2 authentication data
	Zero(&mschap, sizeof(mschap));
	is_mschap = ParseAndExtractMsChapV2InfoFromPassword(&mschap, password);

	// Split the server into tokens
	token = ParseToken(server, " ,;\t");

	// Get the IP address of the server
	ip_list = NewListFast(NULL);
	for(i = 0; i < token->NumTokens; i++)
	{
		IP *tmp_ip = Malloc(sizeof(IP));
		if (GetIP(tmp_ip, token->Token[i]))
		{
			Add(ip_list, tmp_ip);
		}
		else if (GetIPEx(tmp_ip, token->Token[i], true))
		{
			Add(ip_list, tmp_ip);
		}
		else
		{
			Free(tmp_ip);
		}
	}

	FreeToken(token);

	if(LIST_NUM(ip_list) == 0)
	{
		ReleaseList(ip_list);
		return false;
	}

	// Random number generation
	Rand(random, sizeof(random));

	// ID generation
	id = (UCHAR)(packet_id % 254 + 1);
	packet_id++;

	if (is_mschap == false)
	{
		// Encrypt the password
		encrypted_password = RadiusEncryptPassword(password, random, secret, secret_size);
		if (encrypted_password == NULL)
		{
			// Encryption failure
			ReleaseList(ip_list);
			return false;
		}
	}

	// Generate the user name packet
	user_name = RadiusCreateUserName(username);

	if (user_name != NULL)
	{
		// Generate a password packet
		BUF *user_password = (is_mschap ? NULL : RadiusCreateUserPassword(encrypted_password->Buf, encrypted_password->Size));
		BUF *nas_id = RadiusCreateNasId(CEDAR_SERVER_STR);

		if (is_mschap || user_password != NULL)
		{
			UINT64 start;
			UINT64 next_send_time;
			UCHAR tmp[MAX_SIZE];
			UINT recv_buf_size = 32768;
			UCHAR *recv_buf = MallocEx(recv_buf_size, true);
			// Generate an UDP packet
			BUF *p = NewBuf();
			UCHAR type = 1;
			SOCK *sock;
			USHORT sz = 0;
			UINT pos = 0;
			BOOL *finish = ZeroMallocEx(sizeof(BOOL) * LIST_NUM(ip_list), true);

			Zero(tmp, sizeof(tmp));

			WriteBuf(p, &type, 1);
			WriteBuf(p, &id, 1);
			WriteBuf(p, &sz, 2);
			WriteBuf(p, random, 16);
			WriteBuf(p, user_name->Buf, user_name->Size);

			if (is_mschap == false)
			{
				UINT ui;
				// PAP
				WriteBuf(p, user_password->Buf, user_password->Size);
				WriteBuf(p, nas_id->Buf, nas_id->Size);

				// Service-Type
				ui = Endian32(2);
				RadiusAddValue(p, 6, 0, 0, &ui, sizeof(ui));

				// NAS-Port-Type
				ui = Endian32(5);
				RadiusAddValue(p, 61, 0, 0, &ui, sizeof(ui));

				// Tunnel-Type
				ui = Endian32(1);
				RadiusAddValue(p, 64, 0, 0, &ui, sizeof(ui));

				// Tunnel-Medium-Type
				ui = Endian32(1);
				RadiusAddValue(p, 65, 0, 0, &ui, sizeof(ui));

				// Calling-Station-Id
				RadiusAddValue(p, 31, 0, 0, client_ip_str, StrLen(client_ip_str));

				// Tunnel-Client-Endpoint
				RadiusAddValue(p, 66, 0, 0, client_ip_str, StrLen(client_ip_str));
			}
			else
			{
				// MS-CHAP v2
				static UINT session_id = 0;
				USHORT us;
				UINT ui;
				char *ms_ras_version = "MSRASV5.20";
				UCHAR ms_chapv2_response[50];

				// Acct-Session-Id
				us = Endian16(session_id % 254 + 1);
				session_id++;
				RadiusAddValue(p, 44, 0, 0, &us, sizeof(us));

				// NAS-IP-Address
				if (c != NULL && c->FirstSock != NULL && c->FirstSock->IPv6 == false)
				{
					ui = IPToUINT(&c->FirstSock->LocalIP);
					RadiusAddValue(p, 4, 0, 0, &ui, sizeof(ui));
				}

				// Service-Type
				ui = Endian32(2);
				RadiusAddValue(p, 6, 0, 0, &ui, sizeof(ui));

				// MS-RAS-Vendor
				ui = Endian32(311);
				RadiusAddValue(p, 26, 311, 9, &ui, sizeof(ui));

				// MS-RAS-Version
				RadiusAddValue(p, 26, 311, 18, ms_ras_version, StrLen(ms_ras_version));

				// NAS-Port-Type
				ui = Endian32(5);
				RadiusAddValue(p, 61, 0, 0, &ui, sizeof(ui));

				// Tunnel-Type
				ui = Endian32(1);
				RadiusAddValue(p, 64, 0, 0, &ui, sizeof(ui));

				// Tunnel-Medium-Type
				ui = Endian32(1);
				RadiusAddValue(p, 65, 0, 0, &ui, sizeof(ui));

				// Calling-Station-Id
				RadiusAddValue(p, 31, 0, 0, client_ip_str, StrLen(client_ip_str));

				// Tunnel-Client-Endpoint
				RadiusAddValue(p, 66, 0, 0, client_ip_str, StrLen(client_ip_str));

				// MS-RAS-Client-Version
				RadiusAddValue(p, 26, 311, 35, ms_ras_version, StrLen(ms_ras_version));

				// MS-RAS-Client-Name
				RadiusAddValue(p, 26, 311, 34, client_ip_str, StrLen(client_ip_str));

				// MS-CHAP-Challenge
				RadiusAddValue(p, 26, 311, 11, mschap.MsChapV2_ServerChallenge, sizeof(mschap.MsChapV2_ServerChallenge));

				// MS-CHAP2-Response
				Zero(ms_chapv2_response, sizeof(ms_chapv2_response));
				Copy(ms_chapv2_response + 2, mschap.MsChapV2_ClientChallenge, 16);
				Copy(ms_chapv2_response + 2 + 16 + 8, mschap.MsChapV2_ClientResponse, 24);
				RadiusAddValue(p, 26, 311, 25, ms_chapv2_response, sizeof(ms_chapv2_response));

				// NAS-ID
				WriteBuf(p, nas_id->Buf, nas_id->Size);
			}

			SeekBuf(p, 0, 0);

			WRITE_USHORT(((UCHAR *)p->Buf) + 2, (USHORT)p->Size);

			// Create a socket
			sock = NewUDPEx(0, IsIP6(LIST_DATA(ip_list, pos)));

			// Transmission process start
			start = Tick64();
			if(interval < RADIUS_RETRY_INTERVAL)
			{
				interval = RADIUS_RETRY_INTERVAL;
			}
			else if(interval > RADIUS_RETRY_TIMEOUT)
			{
				interval = RADIUS_RETRY_TIMEOUT;
			}
			next_send_time = start + (UINT64)interval;

			while (true)
			{
				UINT server_port;
				UINT recv_size;
				//IP server_ip;
				SOCKSET set;
				UINT64 now;

SEND_RETRY:
				//SendTo(sock, &ip, port, p->Buf, p->Size);
				SendTo(sock, LIST_DATA(ip_list, pos), port, p->Buf, p->Size);

				Debug("send to host:%u\n", pos);

				next_send_time = Tick64() + (UINT64)interval;

RECV_RETRY:
				now = Tick64();
				if (next_send_time <= now)
				{
					// Switch the host to refer
					pos++;
					pos = pos % LIST_NUM(ip_list);

					goto SEND_RETRY;
				}

				if ((start + RADIUS_RETRY_TIMEOUT) < now)
				{
					// Time-out
					break;
				}

				InitSockSet(&set);
				AddSockSet(&set, sock);
				Select(&set, (UINT)(next_send_time - now), NULL, NULL);

				recv_size = RecvFrom(sock, LIST_DATA(ip_list, pos), &server_port, recv_buf, recv_buf_size);

				if (recv_size == 0)
				{
					Debug("Radius recv_size 0\n");
					finish[pos] = TRUE;
					for(i = 0; i < LIST_NUM(ip_list); i++)
					{
						if(finish[i] == FALSE)
						{
							// Switch the host to refer
							pos++;
							pos = pos % LIST_NUM(ip_list);
							goto SEND_RETRY;
						}
					}
					// Failure
					break;
				}
				else if (recv_size == SOCK_LATER)
				{
					// Waiting
					goto RECV_RETRY;
				}
				else
				{
					// Check such as the IP address
					if (/*Cmp(&server_ip, &ip, sizeof(IP)) != 0 || */server_port != port)
					{
						goto RECV_RETRY;
					}
					// Success
					if (recv_buf[0] == 2)
					{
						ret = true;

						if (is_mschap && mschap_v2_server_response_20 != NULL)
						{
							// Cutting corners Zurukko
							UCHAR signature[] = {0x1A, 0x33, 0x00, 0x00, 0x01, 0x37, 0x1A, 0x2D, 0x00, 0x53, 0x3D, };
							UINT i = SearchBin(recv_buf, 0, recv_buf_size, signature, sizeof(signature));

							if (i == INFINITE || ((i + sizeof(signature) + 40) > recv_buf_size))
							{
								ret = false;
							}
							else
							{
								char tmp[MAX_SIZE];
								BUF *b;

								Zero(tmp, sizeof(tmp));
								Copy(tmp, recv_buf + i + sizeof(signature), 40);

								b = StrToBin(tmp);

								if (b != NULL && b->Size == 20)
								{
									WHERE;
									Copy(mschap_v2_server_response_20, b->Buf, 20);
								}
								else
								{
									WHERE;
									ret = false;
								}

								FreeBuf(b);
							}
						}

						if (opt->In_CheckVLanId)
						{
							BUF *buf = NewBufFromMemory(recv_buf, recv_size);
							LIST *o = RadiusParseOptions(buf);

							if (o != NULL)
							{
								DHCP_OPTION *vlan_option = GetDhcpOption(o, RADIUS_ATTRIBUTE_VLAN_ID);

								if (vlan_option != NULL)
								{
									UINT vlan_id = 0;
									char tmp[32];

									Zero(tmp, sizeof(tmp));

									Copy(tmp, vlan_option->Data, MIN(vlan_option->Size, sizeof(tmp) - 1));

									vlan_id = ToInt(tmp);

									opt->Out_VLanId = vlan_id;
								}
							}

							FreeBuf(buf);
							FreeDhcpOptions(o);
						}
					}
					break;
				}
			}

			Free(finish);

			// Release the socket
			ReleaseSock(sock);

			FreeBuf(p);
			FreeBuf(user_password);

			Free(recv_buf);
		}

		FreeBuf(nas_id);
		FreeBuf(user_name);
	}

	// Release the ip_list
	for(i = 0; i < LIST_NUM(ip_list); i++)
	{
		IP *tmp_ip = LIST_DATA(ip_list, i);
		Free(tmp_ip);
	}
	ReleaseList(ip_list);

	// Release the memory
	FreeBuf(encrypted_password);

	return ret;
}

// Parse RADIUS attributes
LIST *RadiusParseOptions(BUF *b)
{
	LIST *o;
	UCHAR code;
	UCHAR id;
	USHORT len;
	UCHAR auth[16];
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	o = NewList(NULL);

	ReadBuf(b, &code, 1);
	ReadBuf(b, &id, 1);
	len = 0;
	ReadBuf(b, &len, 2);
	len = Endian16(len);
	ReadBuf(b, auth, 16);

	while (true)
	{
		UCHAR attribute_id;
		UCHAR size;
		UCHAR data[256];
		DHCP_OPTION *d;

		if (ReadBuf(b, &attribute_id, 1) != 1)
		{
			break;
		}

		if (ReadBuf(b, &size, 1) != 1)
		{
			break;
		}

		if (size <= 2)
		{
			break;
		}

		size -= 2;
		if (ReadBuf(b, data, size) != size)
		{
			break;
		}

		d = ZeroMalloc(sizeof(DHCP_OPTION));
		d->Id = attribute_id;
		d->Size = size;
		d->Data = Clone(data, d->Size);

		Add(o, d);
	}

	return o;
}

// Adding Attributes
void RadiusAddValue(BUF *b, UCHAR t, UINT v, UCHAR vt, void *data, UINT size)
{
	UINT len;
	// Validate arguments
	if (b == NULL || (data == NULL && size != 0))
	{
		return;
	}

	// type
	WriteBufChar(b, t);

	// length
	len = 2 + size;
	if (t == 26)
	{
		len += 6;
	}
	WriteBufChar(b, (UCHAR)len);

	if (t != 26)
	{
		// value
		WriteBuf(b, data, size);
	}
	else
	{
		// vendor
		WriteBufInt(b, v);

		// vendor type
		WriteBufChar(b, vt);

		// length2
		len = size + 2;
		WriteBufChar(b, (UCHAR)len);

		// value
		WriteBuf(b, data, size);
	}
}

// Create a password attribute for Radius
BUF *RadiusCreateUserPassword(void *data, UINT size)
{
	BUF *b;
	UCHAR code, sz;
	// Validate arguments
	if (size != 0 && data == NULL || size >= 253)
	{
		return NULL;
	}

	b = NewBuf();
	code = 2;
	sz = 2 + (UCHAR)size;
	WriteBuf(b, &code, 1);
	WriteBuf(b, &sz, 1);
	WriteBuf(b, data, size);

	return b;
}

// Generate an ID attribute of Nas
BUF *RadiusCreateNasId(char *name)
{
	BUF *b;
	UCHAR code, size;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}
	if (StrLen(name) == 0 || StrLen(name) >= 128)
	{
		return NULL;
	}

	b = NewBuf();
	code = 32;
	size = 2 + (UCHAR)StrLen(name);
	WriteBuf(b, &code, 1);
	WriteBuf(b, &size, 1);
	WriteBuf(b, name, StrLen(name));

	return b;
}

// Create a user name attribute for Radius
BUF *RadiusCreateUserName(wchar_t *username)
{
	BUF *b;
	UCHAR code, size;
	UCHAR utf8[254];
	// Validate arguments
	if (username == NULL)
	{
		return NULL;
	}

	// Convert the user name to a Unicode string
	UniToStr(utf8, sizeof(utf8), username);
	utf8[253] = 0;

	b = NewBuf();
	code = 1;
	size = 2 + (UCHAR)StrLen(utf8);
	WriteBuf(b, &code, 1);
	WriteBuf(b, &size, 1);
	WriteBuf(b, utf8, StrLen(utf8));

	return b;
}

// Encrypt the password for the Radius
BUF *RadiusEncryptPassword(char *password, UCHAR *random, UCHAR *secret, UINT secret_size)
{
	UINT n, i;
	BUF *buf;
	UCHAR c[16][16];		// Result
	UCHAR b[16][16];		// Result
	UCHAR p[16][16];		// Password
	// Validate arguments
	if (password == NULL || random == NULL || (secret_size != 0 && secret == NULL))
	{
		return NULL;
	}
	if (StrLen(password) > 256)
	{
		// Password is too long
		return NULL;
	}

	// Initialize
	Zero(c, sizeof(c));
	Zero(p, sizeof(p));
	Zero(b, sizeof(b));

	// Divide the password per 16 characters
	Copy(p, password, StrLen(password));
	// Calculate the number of blocks
	n = StrLen(password) / 16;
	if ((StrLen(password) % 16) != 0)
	{
		n++;
	}

	// Encryption processing
	for (i = 0;i < n;i++)
	{
		// Calculation of b[i]
		UINT j;
		BUF *tmp = NewBuf();
		WriteBuf(tmp, secret, secret_size);
		if (i == 0)
		{
			WriteBuf(tmp, random, 16);
		}
		else
		{
			WriteBuf(tmp, c[i - 1], 16);
		}
		Hash(b[i], tmp->Buf, tmp->Size, false);
		FreeBuf(tmp);

		// Calculation of c[i]
		for (j = 0;j < 16;j++)
		{
			c[i][j] = p[i][j] ^ b[i][j];
		}
	}

	// Return the results
	buf = NewBuf();
	WriteBuf(buf, c, n * 16);
	return buf;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
