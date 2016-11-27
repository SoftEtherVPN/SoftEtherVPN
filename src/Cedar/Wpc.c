// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2016 Daiyuu Nobori.
// Copyright (c) 2012-2016 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2016 SoftEther Corporation.
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


// Wpc.c
// RPC over HTTP

#include <GlobalConst.h>

#include "CedarPch.h"

// Get whether the proxy server is specified by a private IP
bool IsProxyPrivateIp(INTERNET_SETTING *s)
{
	IP ip;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->ProxyType == PROXY_DIRECT)
	{
		return false;
	}

	if (GetIP(&ip, s->ProxyHostName) == false)
	{
		return false;
	}

	if (IsIPPrivate(&ip))
	{
		return true;
	}

	if (IsIPMyHost(&ip))
	{
		return true;
	}

	if (IsLocalHostIP(&ip))
	{
		return true;
	}

	return false;
}

// Call
PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash)
{
	return WpcCallEx(url, setting, timeout_connect, timeout_comm, function_name, pack, cert, key,
		sha1_cert_hash, NULL, 0, NULL, NULL);
}
PACK *WpcCallEx(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value)
{
	return WpcCallEx2(url, setting, timeout_connect, timeout_comm, function_name, pack,
		cert, key, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, additional_header_name, additional_header_value, NULL);
}
PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value, char *sni_string)
{
	URL_DATA data;
	BUF *b, *recv;
	UINT error;
	WPC_PACKET packet;
	// Validate arguments
	if (function_name == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	if (ParseUrl(&data, url, true, NULL) == false)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	PackAddStr(pack, "function", function_name);

	b = WpcGeneratePacket(pack, cert, key);
	if (b == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	SeekBuf(b, b->Size, 0);
	WriteBufInt(b, 0);
	SeekBuf(b, 0, 0);

	if (IsEmptyStr(additional_header_name) == false && IsEmptyStr(additional_header_value) == false)
	{
		StrCpy(data.AdditionalHeaderName, sizeof(data.AdditionalHeaderName), additional_header_name);
		StrCpy(data.AdditionalHeaderValue, sizeof(data.AdditionalHeaderValue), additional_header_value);
	}

	if (sni_string != NULL && IsEmptyStr(sni_string) == false)
	{
		StrCpy(data.SniString, sizeof(data.SniString), sni_string);
	}

	recv = HttpRequestEx3(&data, setting, timeout_connect, timeout_comm, &error,
		false, b->Buf, NULL, NULL, sha1_cert_hash, num_hashes, cancel, max_recv_size,
		NULL, NULL);

	FreeBuf(b);

	if (recv == NULL)
	{
		return PackError(error);
	}

	if (WpcParsePacket(&packet, recv) == false)
	{
		FreeBuf(recv);
		return PackError(ERR_PROTOCOL_ERROR);
	}

	FreeBuf(recv);

	FreeX(packet.Cert);

	return packet.Pack;
}

// Release the packet
void WpcFreePacket(WPC_PACKET *packet)
{
	// Validate arguments
	if (packet == NULL)
	{
		return;
	}

	FreePack(packet->Pack);
	FreeX(packet->Cert);
}

// Parse the packet
bool WpcParsePacket(WPC_PACKET *packet, BUF *buf)
{
	LIST *o;
	BUF *b;
	bool ret = false;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (packet == NULL || buf == NULL)
	{
		return false;
	}

	Zero(packet, sizeof(WPC_PACKET));

	o = WpcParseDataEntry(buf);

	b = WpcDataEntryToBuf(WpcFindDataEntry(o, "PACK"));
	if (b != NULL)
	{
		HashSha1(hash, b->Buf, b->Size);

		packet->Pack = BufToPack(b);
		FreeBuf(b);

		if (packet->Pack != NULL)
		{
			BUF *b;

			ret = true;

			b = WpcDataEntryToBuf(WpcFindDataEntry(o, "HASH"));

			if (b != NULL)
			{
				if (b->Size != SHA1_SIZE || Cmp(b->Buf, hash, SHA1_SIZE) != 0)
				{
					ret = false;
					FreePack(packet->Pack);
				}
				else
				{
					BUF *b;

					Copy(packet->Hash, hash, SHA1_SIZE);

					b = WpcDataEntryToBuf(WpcFindDataEntry(o, "CERT"));

					if (b != NULL)
					{
						X *cert = BufToX(b, false);
						if (cert == NULL)
						{
							ret = false;
							FreePack(packet->Pack);
						}
						else
						{
							BUF *b = WpcDataEntryToBuf(WpcFindDataEntry(o, "SIGN"));

							if (b == NULL || (b->Size != 128))
							{
								ret = false;
								FreeX(cert);
								FreePack(packet->Pack);
							}
							else
							{
								K *k = GetKFromX(cert);

								if (RsaVerify(hash, SHA1_SIZE, b->Buf, k) == false)
								{
									ret = false;
									FreeX(cert);
									FreePack(packet->Pack);
								}
								else
								{
									packet->Cert = cert;
									Copy(packet->Sign, b->Buf, 128);
								}

								FreeK(k);
							}

							FreeBuf(b);
						}
						FreeBuf(b);
					}
				}
				FreeBuf(b);
			}
		}
	}

	WpcFreeDataEntryList(o);

	return ret;
}

// Generate the packet
BUF *WpcGeneratePacket(PACK *pack, X *cert, K *key)
{
	UCHAR hash[SHA1_SIZE];
	BUF *pack_data;
	BUF *cert_data = NULL;
	BUF *sign_data = NULL;
	BUF *b;
	// Validate arguments
	if (pack == NULL)
	{
		return NULL;
	}

	pack_data = PackToBuf(pack);
	HashSha1(hash, pack_data->Buf, pack_data->Size);

	if (cert != NULL && key != NULL)
	{
		UCHAR sign[128];
		cert_data = XToBuf(cert, false);

		RsaSign(sign, hash, sizeof(hash), key);

		sign_data = NewBuf();
		WriteBuf(sign_data, sign, sizeof(sign));
		SeekBuf(sign_data, 0, 0);
	}

	b = NewBuf();

	WpcAddDataEntryBin(b, "PACK", pack_data->Buf, pack_data->Size);
	WpcAddDataEntryBin(b, "HASH", hash, sizeof(hash));

	if (cert_data != NULL)
	{
		WpcAddDataEntryBin(b, "CERT", cert_data->Buf, cert_data->Size);
		WpcAddDataEntryBin(b, "SIGN", sign_data->Buf, sign_data->Size);
	}

	FreeBuf(pack_data);
	FreeBuf(cert_data);
	FreeBuf(sign_data);

	SeekBuf(b, 0, 0);

	return b;
}

// Decode the buffer from WPC_ENTRY
BUF *WpcDataEntryToBuf(WPC_ENTRY *e)
{
	void *data;
	UINT data_size;
	UINT size;
	BUF *b;
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}

	data_size = e->Size + 4096;
	data = Malloc(data_size);
	size = DecodeSafe64(data, e->Data, e->Size);

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	Free(data);

	return b;
}

// Search for the data entry
WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name)
{
	UINT i;
	char name_str[WPC_DATA_ENTRY_SIZE];
	// Validate arguments
	if (o == NULL || name == NULL)
	{
		return NULL;
	}

	WpcFillEntryName(name_str, name);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WPC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->EntryName, name_str, WPC_DATA_ENTRY_SIZE) == 0)
		{
			return e;
		}
	}

	return NULL;
}

// Release the data entry list
void WpcFreeDataEntryList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WPC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Parse the data entry
LIST *WpcParseDataEntry(BUF *b)
{
	char entry_name[WPC_DATA_ENTRY_SIZE];
	char size_str[11];
	LIST *o;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	SeekBuf(b, 0, 0);

	o = NewListFast(NULL);

	while (true)
	{
		UINT size;
		WPC_ENTRY *e;

		if (ReadBuf(b, entry_name, WPC_DATA_ENTRY_SIZE) != WPC_DATA_ENTRY_SIZE)
		{
			break;
		}

		Zero(size_str, sizeof(size_str));
		if (ReadBuf(b, size_str, 10) != 10)
		{
			break;
		}

		size = ToInt(size_str);
		if ((b->Size - b->Current) < size)
		{
			break;
		}

		e = ZeroMalloc(sizeof(WPC_ENTRY));
		e->Data = (UCHAR *)b->Buf + b->Current;
		Copy(e->EntryName, entry_name, WPC_DATA_ENTRY_SIZE);
		e->Size = size;

		SeekBuf(b, size, 1);

		Add(o, e);
	}

	return o;
}

// Generate a entry name
void WpcFillEntryName(char *dst, char *name)
{
	UINT i, len;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), name);
	StrUpper(tmp);
	len = StrLen(tmp);

	for (i = 0;i < WPC_DATA_ENTRY_SIZE;i++)
	{
		dst[i] = ' ';
	}

	if (len <= WPC_DATA_ENTRY_SIZE)
	{
		Copy(dst, tmp, len);
	}
	else
	{
		Copy(dst, tmp, WPC_DATA_ENTRY_SIZE);
	}
}

// Add the data entry (binary)
void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size)
{
	char *str;
	// Validate arguments
	if (b == NULL || name == NULL || (data == NULL && size != 0))
	{
		return;
	}

	str = Malloc(size * 2 + 64);

	EncodeSafe64(str, data, size);

	WpcAddDataEntry(b, name, str, StrLen(str));

	Free(str);
}


// Add the data entry
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size)
{
	char entry_name[WPC_DATA_ENTRY_SIZE];
	char size_str[11];
	// Validate arguments
	if (b == NULL || name == NULL || (data == NULL && size != 0))
	{
		return;
	}

	WpcFillEntryName(entry_name, name);
	WriteBuf(b, entry_name, WPC_DATA_ENTRY_SIZE);

	Format(size_str, sizeof(size_str), "%010u", size);
	WriteBuf(b, size_str, 10);

	WriteBuf(b, data, size);
}

// Get the empty INTERNET_SETTING
INTERNET_SETTING *GetNullInternetSetting()
{
	static INTERNET_SETTING ret;

	Zero(&ret, sizeof(ret));

	return &ret;
}

// Socket connection
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout)
{
	return WpcSockConnectEx(param, error_code, timeout, NULL);
}
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel)
{
	CONNECTION c;
	SOCK *sock;
	UINT err = ERR_NO_ERROR;
	// Validate arguments
	if (param == NULL)
	{
		return NULL;
	}

	Zero(&c, sizeof(c));

	sock = NULL;
	err = ERR_INTERNAL_ERROR;

	switch (param->ProxyType)
	{
	case PROXY_DIRECT:
		sock = TcpConnectEx3(param->HostName, param->Port, timeout, cancel, NULL, true, NULL, false, false, NULL);
		if (sock == NULL)
		{
			err = ERR_CONNECT_FAILED;
		}
		break;

	case PROXY_HTTP:
		sock = ProxyConnectEx2(&c, param->ProxyHostName, param->ProxyPort,
			param->HostName, param->Port,
			param->ProxyUsername, param->ProxyPassword, false, cancel, NULL, timeout);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;

	case PROXY_SOCKS:
		sock = SocksConnectEx2(&c, param->ProxyHostName, param->ProxyPort,
			param->HostName, param->Port,
			param->ProxyUsername, false, cancel, NULL, timeout, NULL);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;
	}

	if (error_code != NULL)
	{
		*error_code = err;
	}

	return sock;
}
SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout)
{
	// Validate arguments
	INTERNET_SETTING t2;
	WPC_CONNECT c;
	if (t == NULL)
	{
		Zero(&t2, sizeof(t2));

		t = &t2;
	}

	Zero(&c, sizeof(c));
	StrCpy(c.HostName, sizeof(c.HostName), hostname);
	c.Port = port;
	c.ProxyType = t->ProxyType;
	StrCpy(c.ProxyHostName, sizeof(c.HostName), t->ProxyHostName);
	c.ProxyPort = t->ProxyPort;
	StrCpy(c.ProxyUsername, sizeof(c.ProxyUsername), t->ProxyUsername);
	StrCpy(c.ProxyPassword, sizeof(c.ProxyPassword), t->ProxyPassword);

	return WpcSockConnect(&c, error_code, timeout);
}

// Handle the HTTP request
BUF *HttpRequest(URL_DATA *data, INTERNET_SETTING *setting,
				 UINT timeout_connect, UINT timeout_comm,
				 UINT *error_code, bool check_ssl_trust, char *post_data,
				 WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash)
{
	return HttpRequestEx(data, setting, timeout_connect, timeout_comm,
		error_code, check_ssl_trust, post_data,
		recv_callback, recv_callback_param, sha1_cert_hash, NULL, 0);
}
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size)
{
	return HttpRequestEx2(data, setting, timeout_connect, timeout_comm, error_code,
		check_ssl_trust, post_data, recv_callback, recv_callback_param, sha1_cert_hash,
		cancel, max_recv_size, NULL, NULL);
}
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	return HttpRequestEx3(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value);
}
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	WPC_CONNECT con;
	SOCK *s;
	HTTP_HEADER *h;
	bool use_http_proxy = false;
	char target[MAX_SIZE * 4];
	char *send_str;
	BUF *send_buf;
	BUF *recv_buf;
	UINT http_error_code;
	char len_str[100];
	UINT content_len;
	void *socket_buffer;
	UINT socket_buffer_size = WPC_RECV_BUF_SIZE;
	UINT num_continue = 0;
	INTERNET_SETTING wt_setting;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}
	if (setting == NULL)
	{
		Zero(&wt_setting, sizeof(wt_setting));
		setting = &wt_setting;
	}
	if (error_code == NULL)
	{
		static UINT ret = 0;
		error_code = &ret;
	}
	if (timeout_comm == 0)
	{
		timeout_comm = WPC_TIMEOUT;
	}
	if (sha1_cert_hash == NULL)
	{
		num_hashes = 0;
	}
	if (num_hashes == 0)
	{
		sha1_cert_hash = NULL;
	}

	// Connection
	Zero(&con, sizeof(con));
	StrCpy(con.HostName, sizeof(con.HostName), data->HostName);
	con.Port = data->Port;
	con.ProxyType = setting->ProxyType;
	StrCpy(con.ProxyHostName, sizeof(con.ProxyHostName), setting->ProxyHostName);
	con.ProxyPort = setting->ProxyPort;
	StrCpy(con.ProxyUsername, sizeof(con.ProxyUsername), setting->ProxyUsername);
	StrCpy(con.ProxyPassword, sizeof(con.ProxyPassword), setting->ProxyPassword);

	if (setting->ProxyType != PROXY_HTTP || data->Secure)
	{
		use_http_proxy = false;
		StrCpy(target, sizeof(target), data->Target);
	}
	else
	{
		use_http_proxy = true;
		CreateUrl(target, sizeof(target), data);
	}

	if (use_http_proxy == false)
	{
		// If the connection is not via HTTP Proxy, or is a SSL connection even via HTTP Proxy
		s = WpcSockConnectEx(&con, error_code, timeout_connect, cancel);
	}
	else
	{
		// If the connection is not SSL via HTTP Proxy
		s = TcpConnectEx3(con.ProxyHostName, con.ProxyPort, timeout_connect, cancel, NULL, true, NULL, false, false, NULL);
		if (s == NULL)
		{
			*error_code = ERR_PROXY_CONNECT_FAILED;
		}
	}

	if (s == NULL)
	{
		return NULL;
	}

	if (data->Secure)
	{
		// Start the SSL communication
		if (StartSSLEx(s, NULL, NULL, true, 0, (IsEmptyStr(data->SniString) ? NULL : data->SniString)) == false)
		{
			// SSL connection failed
			*error_code = ERR_PROTOCOL_ERROR;
			Disconnect(s);
			ReleaseSock(s);
			return NULL;
		}

		if (sha1_cert_hash != NULL && num_hashes >= 1)
		{
			UCHAR hash[SHA1_SIZE];
			UINT i;
			bool ok = false;

			Zero(hash, sizeof(hash));
			GetXDigest(s->RemoteX, hash, true);

			for (i = 0;i < num_hashes;i++)
			{
				UCHAR *a = (UCHAR *)sha1_cert_hash;
				a += (SHA1_SIZE * i);

				if (Cmp(hash, a, SHA1_SIZE) == 0)
				{
					ok = true;
					break;
				}
			}

			if (ok == false)
			{
				// Destination certificate hash mismatch
				*error_code = ERR_CERT_NOT_TRUSTED;
				Disconnect(s);
				ReleaseSock(s);
				return NULL;
			}
		}
	}

	// Timeout setting
	SetTimeout(s, timeout_comm);

	// Generate a request
	h = NewHttpHeader(data->Method, target, use_http_proxy ? "HTTP/1.0" : "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Accept-Language", "ja"));
	AddHttpValue(h, NewHttpValue("User-Agent", WPC_USER_AGENT));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
	AddHttpValue(h, NewHttpValue("Host", data->HeaderHostName));

	if (IsEmptyStr(header_name) == false && IsEmptyStr(header_value) == false)
	{
		AddHttpValue(h, NewHttpValue(header_name, header_value));
	}

	if (IsEmptyStr(data->Referer) == false)
	{
		AddHttpValue(h, NewHttpValue("Referer", data->Referer));
	}

	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		ToStr(len_str, StrLen(post_data));
		AddHttpValue(h, NewHttpValue("Content-Type", "application/x-www-form-urlencoded"));
		AddHttpValue(h, NewHttpValue("Content-Length", len_str));
	}

	if (IsEmptyStr(data->AdditionalHeaderName) == false && IsEmptyStr(data->AdditionalHeaderValue) == false)
	{
		AddHttpValue(h, NewHttpValue(data->AdditionalHeaderName, data->AdditionalHeaderValue));
	}

	if (use_http_proxy)
	{
		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));

		if (IsEmptyStr(setting->ProxyUsername) == false || IsEmptyStr(setting->ProxyPassword) == false)
		{
			char auth_tmp_str[MAX_SIZE], auth_b64_str[MAX_SIZE * 2];
			char basic_str[MAX_SIZE * 2];

			// Generate the authentication string
			Format(auth_tmp_str, sizeof(auth_tmp_str), "%s:%s",
				setting->ProxyUsername, setting->ProxyPassword);

			// Base64 encode
			Zero(auth_b64_str, sizeof(auth_b64_str));
			Encode64(auth_b64_str, auth_tmp_str);
			Format(basic_str, sizeof(basic_str), "Basic %s", auth_b64_str);

			AddHttpValue(h, NewHttpValue("Proxy-Authorization", basic_str));
		}
	}

	send_str = HttpHeaderToStr(h);
	FreeHttpHeader(h);

	send_buf = NewBuf();
	WriteBuf(send_buf, send_str, StrLen(send_str));
	Free(send_str);

	// Append to the sending data in the case of POST
	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		WriteBuf(send_buf, post_data, StrLen(post_data));
	}

	// Send
	if (SendAll(s, send_buf->Buf, send_buf->Size, s->SecureMode) == false)
	{
		Disconnect(s);
		ReleaseSock(s);
		FreeBuf(send_buf);

		*error_code = ERR_DISCONNECTED;

		return NULL;
	}

	FreeBuf(send_buf);

CONT:
	// Receive
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);

		*error_code = ERR_DISCONNECTED;

		return NULL;
	}

	http_error_code = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			http_error_code = ToInt(h->Target);
		}
	}

	*error_code = ERR_NO_ERROR;

	switch (http_error_code)
	{
	case 401:
	case 407:
		// Proxy authentication error
		*error_code = ERR_PROXY_AUTH_FAILED;
		break;

	case 404:
		// 404 File Not Found
		*error_code = ERR_OBJECT_NOT_FOUND;
		break;

	case 100:
		// Continue
		num_continue++;
		if (num_continue >= 10)
		{
			goto DEF;
		}
		FreeHttpHeader(h);
		goto CONT;

	case 200:
		// Success
		break;

	default:
		// Protocol error
DEF:
		*error_code = ERR_PROTOCOL_ERROR;
		break;
	}

	if (*error_code != ERR_NO_ERROR)
	{
		// An error has occured
		Disconnect(s);
		ReleaseSock(s);
		FreeHttpHeader(h);
		return NULL;
	}

	// Get the length of the content
	content_len = GetContentLength(h);
	if (max_recv_size != 0)
	{
		content_len = MIN(content_len, max_recv_size);
	}

	FreeHttpHeader(h);

	socket_buffer = Malloc(socket_buffer_size);

	// Receive the content
	recv_buf = NewBuf();

	while (true)
	{
		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);
		UINT size;

		if (recv_callback != NULL)
		{
			if (recv_callback(recv_callback_param,
				content_len, recv_buf->Size, recv_buf) == false)
			{
				// Cancel the reception
				*error_code = ERR_USER_CANCEL;
				goto RECV_CANCEL;
			}
		}

		if (recvsize == 0)
		{
			break;
		}

		size = Recv(s, socket_buffer, recvsize, s->SecureMode);
		if (size == 0)
		{
			// Disconnected
			*error_code = ERR_DISCONNECTED;

RECV_CANCEL:
			FreeBuf(recv_buf);
			Free(socket_buffer);
			Disconnect(s);
			ReleaseSock(s);

			return NULL;
		}

		WriteBuf(recv_buf, socket_buffer, size);
	}

	SeekBuf(recv_buf, 0, 0);
	Free(socket_buffer);

	Disconnect(s);
	ReleaseSock(s);

	// Transmission
	return recv_buf;
}

// Get the proxy server settings from the registry string of IE
bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type)
{
#ifdef	OS_WIN32
	TOKEN_LIST *t;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (name == NULL || port == NULL || str == NULL || server_type == NULL)
	{
		return false;
	}

	t = ParseToken(str, ";");

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];
		UINT i;

		Trim(s);

		i = SearchStrEx(s, "=", 0, false);
		if (i != INFINITE)
		{
			char tmp[MAX_PATH];

			StrCpy(name, name_size, s);
			name[i] = 0;

			if (StrCmpi(name, server_type) == 0)
			{
				char *host;
				StrCpy(tmp, sizeof(tmp), s + i + 1);

				if (ParseHostPort(tmp, &host, port, 0))
				{
					StrCpy(name, name_size, host);
					Free(host);

					if (*port != 0)
					{
						ret = true;
					}
					break;
				}
			}
		}
	}

	FreeToken(t);

	return ret;
#else	// OS_WIN32
	return true;
#endif	// OS_WIN32
}

// Get the internet connection settings of the system
void GetSystemInternetSetting(INTERNET_SETTING *setting)
{
#ifdef	OS_WIN32
	bool use_proxy;
	// Validate arguments
	if (setting == NULL)
	{
		return;
	}

	Zero(setting, sizeof(INTERNET_SETTING));

	use_proxy = MsRegReadInt(REG_CURRENT_USER,
		"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
		"ProxyEnable");

	if (use_proxy)
	{
		char *str = MsRegReadStr(REG_CURRENT_USER,
			"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			"ProxyServer");
		if (str != NULL)
		{
			char name[MAX_HOST_NAME_LEN + 1];
			UINT port;

			if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "https"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "http"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "socks"))
			{
				setting->ProxyType = PROXY_SOCKS;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else
			{
				if (SearchStrEx(str, "=", 0, false) == INFINITE)
				{
					char *host;
					UINT port;
					if (ParseHostPort(str, &host, &port, 0))
					{
						if (port != 0)
						{
							setting->ProxyType = PROXY_HTTP;
							StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), host);
							setting->ProxyPort = port;
						}
						Free(host);
					}
				}
			}

			Free(str);
		}
	}
#else	// OS_WIN32
	Zero(setting, sizeof(INTERNET_SETTING));
#endif	// OS_WIN32
}

// Generate the URL
void CreateUrl(char *url, UINT url_size, URL_DATA *data)
{
	char *protocol;
	// Validate arguments
	if (url == NULL || data == NULL)
	{
		return;
	}

	if (data->Secure == false)
	{
		protocol = "http://";
	}
	else
	{
		protocol = "https://";
	}

	Format(url, url_size, "%s%s%s", protocol, data->HeaderHostName, data->Target);
}


// Parse the URL
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer)
{
	char tmp[MAX_SIZE * 3];
	char server_port[MAX_HOST_NAME_LEN + 16];
	char *s = NULL;
	char *host;
	UINT port;
	UINT i;
	// Validate arguments
	if (data == NULL || str == NULL)
	{
		return false;
	}

	Zero(data, sizeof(URL_DATA));

	if (is_post)
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_POST_NAME);
	}
	else
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_GET_NAME);
	}

	if (referrer != NULL)
	{
		StrCpy(data->Referer, sizeof(data->Referer), referrer);
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	// Determine the protocol
	if (StartWith(tmp, "http://"))
	{
		data->Secure = false;
		s = &tmp[7];
	}
	else if (StartWith(tmp, "https://"))
	{
		data->Secure = true;
		s = &tmp[8];
	}
	else
	{
		if (SearchStrEx(tmp, "://", 0, false) != INFINITE)
		{
			return false;
		}
		data->Secure = false;
		s = &tmp[0];
	}

	// Get the "server name:port number"
	StrCpy(server_port, sizeof(server_port), s);
	i = SearchStrEx(server_port, "/", 0, false);
	if (i != INFINITE)
	{
		server_port[i] = 0;
		s += StrLen(server_port);
		StrCpy(data->Target, sizeof(data->Target), s);
	}
	else
	{
		StrCpy(data->Target, sizeof(data->Target), "/");
	}

	if (ParseHostPort(server_port, &host, &port, data->Secure ? 443 : 80) == false)
	{
		return false;
	}

	StrCpy(data->HostName, sizeof(data->HostName), host);
	data->Port = port;

	Free(host);

	if ((data->Secure && data->Port == 443) || (data->Secure == false && data->Port == 80))
	{
		StrCpy(data->HeaderHostName, sizeof(data->HeaderHostName), data->HostName);
	}
	else
	{
		Format(data->HeaderHostName, sizeof(data->HeaderHostName),
			"%s:%u", data->HostName, data->Port);
	}

	return true;
}

// String replacement
void Base64ToSafe64(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		switch (str[i])
		{
		case '=':
			str[i] = '(';
			break;

		case '+':
			str[i] = ')';
			break;

		case '/':
			str[i] = '_';
			break;
		}
	}
}
void Safe64ToBase64(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		switch (str[i])
		{
		case '(':
			str[i] = '=';
			break;

		case ')':
			str[i] = '+';
			break;

		case '_':
			str[i] = '/';
			break;
		}
	}
}

// Decode from Safe64
UINT DecodeSafe64(void *dst, char *src, UINT src_strlen)
{
	char *tmp;
	UINT ret;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	if (src_strlen == 0)
	{
		src_strlen = StrLen(src);
	}

	tmp = Malloc(src_strlen + 1);
	Copy(tmp, src, src_strlen);
	tmp[src_strlen] = 0;
	Safe64ToBase64(tmp);

	ret = B64_Decode(dst, tmp, src_strlen);
	Free(tmp);

	return ret;
}

// Encode to Safe64
void EncodeSafe64(char *dst, void *src, UINT src_size)
{
	UINT size;
	if (dst == NULL || src == NULL)
	{
		return;
	}

	size = B64_Encode(dst, src, src_size);
	dst[size] = 0;

	Base64ToSafe64(dst);
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
