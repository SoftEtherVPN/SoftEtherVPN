// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Admin.c
// RPC Module for Management

#include "CedarPch.h"

// Macro for RPC function declaration
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		free_rpc(t);													\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	CHECK_RIGHT														\
	if (a->ServerAdmin == false && (StrCmpi(a->HubName, t->HubName) != 0))	\
		return ERR_NOT_ENOUGH_RIGHT;	\
	if (IsEmptyStr(t->HubName))			\
		return ERR_INVALID_PARAMETER;
#define	SERVER_ADMIN_ONLY												\
	if (a->ServerAdmin == false)										\
		return ERR_NOT_ENOUGH_RIGHT;
#define	NO_SUPPORT_FOR_BRIDGE											\
	if (a->Server->Cedar->Bridge)										\
		return ERR_NOT_SUPPORTED;

// Get server Caps (Guessing from the build number if failed to get Caps)
CAPSLIST *ScGetCapsEx(RPC *rpc)
{
	RPC_SERVER_INFO info;
	CAPSLIST *t;
	bool is_bridge = false;
	// Validate arguments
	if (rpc == NULL)
	{
		return NULL;
	}

	Zero(&info, sizeof(info));
	ScGetServerInfo(rpc, &info);

	t = ZeroMalloc(sizeof(CAPSLIST));

	// Try to get Caps by RPC
	if (ScGetCaps(rpc, t) != ERR_NO_ERROR)
	{
		UINT build;

		Free(t);
		t = NewCapsList();

		// Since acquisition of Caps went wrong, get build number
		build = info.ServerBuildInt;

		is_bridge = (SearchStrEx(info.ServerProductName, "bridge", 0, false) == INFINITE) ? false : true;

		AddCapsInt(t, "i_max_packet_size", 1514);

		if (is_bridge == false)
		{
			AddCapsInt(t, "i_max_hubs", 4096);
			AddCapsInt(t, "i_max_sessions", 4096);

			if (info.ServerType != SERVER_TYPE_FARM_MEMBER)
			{
				AddCapsInt(t, "i_max_users_per_hub", 10000);
				AddCapsInt(t, "i_max_groups_per_hub", 10000);
				AddCapsInt(t, "i_max_access_lists", 4096);
			}
			else
			{
				AddCapsInt(t, "i_max_users_per_hub", 0);
				AddCapsInt(t, "i_max_groups_per_hub", 0);
				AddCapsInt(t, "i_max_access_lists", 0);
			}
		}
		else
		{
			AddCapsInt(t, "i_max_hubs", 0);
			AddCapsInt(t, "i_max_sessions", 0);
			AddCapsInt(t, "i_max_users_per_hub", 0);
			AddCapsInt(t, "i_max_groups_per_hub", 0);
			AddCapsInt(t, "i_max_access_lists", 0);
		}

		AddCapsInt(t, "i_max_mac_tables", 10000);
		AddCapsInt(t, "i_max_ip_tables", 10000);

		if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_support_securenat", (build >= 3600) ? true : false);
			AddCapsInt(t, "i_max_secnat_tables", 4096);
		}
		else
		{
			AddCapsBool(t, "b_support_securenat", false);
			AddCapsInt(t, "i_max_secnat_tables", 0);
		}

		if (is_bridge)
		{
			AddCapsBool(t, "b_bridge", true);
		}
		else if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_standalone", true);
		}
		else if (info.ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			AddCapsBool(t, "b_cluster_controller", true);
		}
		else
		{
			AddCapsBool(t, "b_cluster_member", true);
		}

		AddCapsBool(t, "b_support_config_hub", info.ServerType != SERVER_TYPE_FARM_MEMBER &&
			is_bridge == false);

		AddCapsBool(t, "b_vpn_client_connect", is_bridge == false ? true : false);

		AddCapsBool(t, "b_support_radius", info.ServerType != SERVER_TYPE_FARM_MEMBER &&
			is_bridge == false);

		if (build >= 3600)
		{
			RPC_BRIDGE_SUPPORT b;
			Zero(&b, sizeof(b));
			if (ScGetBridgeSupport(rpc, &b) == ERR_NO_ERROR)
			{
				AddCapsBool(t, "b_local_bridge", b.IsBridgeSupportedOs);
				AddCapsBool(t, "b_must_install_pcap", b.IsWinPcapNeeded);
			}
			else
			{
				AddCapsBool(t, "b_local_bridge", false);
				AddCapsBool(t, "b_must_install_pcap", false);
			}
		}
		else
		{
			AddCapsBool(t, "b_local_bridge", false);
			AddCapsBool(t, "b_must_install_pcap", false);
		}

		AddCapsBool(t, "b_tap_supported", false);

		if (info.ServerType == SERVER_TYPE_STANDALONE)
		{
			AddCapsBool(t, "b_support_cascade", true);
		}
		else
		{
			AddCapsBool(t, "b_support_cascade", false);
		}

		AddCapsBool(t, "b_support_cascade_cert", false);
		AddCapsBool(t, "b_support_config_log", info.ServerType != SERVER_TYPE_FARM_MEMBER);
		AddCapsBool(t, "b_support_autodelete", false);
	}
	else
	{
		// Success getting Caps
		if (info.ServerBuildInt <= 4350)
		{
			if (is_bridge == false)
			{
				// b_support_cluster should be true for build 4300 or earlier
				CAPS *caps = GetCaps(t, "b_support_cluster");
				if (caps == NULL)
				{
					AddCapsBool(t, "b_support_cluster", true);
				}
				else
				{
					caps->Value = 1;
				}
			}
		}
	}

	if (true)
	{
		TOKEN_LIST *names;

		// Fill items that doesn't exist in server-side as false
		names = GetTableNameStartWith("CT_b_");
		if (names != NULL)
		{
			UINT i;
			for (i = 0;i < names->NumTokens;i++)
			{
				char *name = names->Token[i] + 3;

				if (GetCaps(t, name) == NULL)
				{
					AddCapsBool(t, name, false);
				}
			}

			FreeToken(names);
		}
	}

	FreeRpcServerInfo(&info);

	return t;
}



// Process server side include
BUF *AdminWebProcessServerSideInclude(BUF *src_txt, char *filename, UINT depth)
{
	char *src_str;
	UINT src_str_size;
	UINT i, len;
	BUF *ret = NULL;
	UINT pos = 0;
	char dirname[MAX_PATH];
	if (src_txt == NULL || filename == NULL || depth >= 4)
	{
		return CloneBuf(src_txt);
	}
	if (EndWith(filename, ".html") == false)
	{
		// We process only .html files
		return CloneBuf(src_txt);
	}

	GetDirNameFromFilePath(dirname, sizeof(dirname), filename);

	src_str_size = src_txt->Size + 1;
	src_str = ZeroMalloc(src_str_size);

	Copy(src_str, src_txt->Buf, src_txt->Size);

	len = StrLen(src_str);

	ret = NewBuf();

	for (i = 0;i < len;i++)
	{
		char *start_tag = "<!--#include file=";
		bool is_ssi = false;

		if (StartWith(src_str + i, start_tag))
		{
			UINT a = i + StrLen(start_tag);

			if (src_str[a] == '\"' || src_str[a] == '\'')
			{
				char delimier = src_str[a];
				char delimier_str[2];
				UINT b;

				delimier_str[0] = delimier;
				delimier_str[1] = 0;
				b = SearchStrEx(src_str, delimier_str, i + StrLen(start_tag) + 1, true);

				if ((b != INFINITE) && (b >= i + StrLen(start_tag) + 1) && ((b - (i + StrLen(start_tag) + 1)) < 32))
				{
					char inc_filename[MAX_PATH];
					char *end_tag = "-->";
					UINT x;

					Zero(inc_filename, sizeof(inc_filename));

					StrCpy(inc_filename, sizeof(inc_filename), src_str + i + StrLen(start_tag) + 1);
					inc_filename[b - (i + StrLen(start_tag) + 1)] = 0;

					x = SearchStrEx(src_str, end_tag, b + 1, true);

					if ((x != INFINITE) && (x >= (b + 1)))
					{
						BUF *inc_buf;
						char full_inc_filename[MAX_PATH];

						if (StartWith(inc_filename, "/"))
						{
							Format(full_inc_filename, sizeof(full_inc_filename), "|wwwroot/%s", inc_filename + 1);
						}
						else
						{
							StrCpy(full_inc_filename, sizeof(full_inc_filename), dirname);
							StrCat(full_inc_filename, sizeof(full_inc_filename), "/");
							StrCat(full_inc_filename, sizeof(full_inc_filename), inc_filename);
						}

						Debug("dirname = %s, full_inc_filename (src) = %s\n\n", dirname, full_inc_filename);
						NormalizePath(full_inc_filename, sizeof(full_inc_filename), full_inc_filename);

						if (StartWith(full_inc_filename, "|wwwroot/") == false
							&& StartWith(full_inc_filename, "|wwwroot\\") == false)
						{
							char tmp[MAX_PATH];
							Format(tmp, sizeof(tmp), "|wwwroot/%s", full_inc_filename);
							StrCpy(full_inc_filename, sizeof(full_inc_filename), tmp);
						}

						Debug("inc_filename = %s\nfull_inc_filename = %s\n\n", inc_filename, full_inc_filename);

						inc_buf = ReadDump(full_inc_filename);

						if (inc_buf != NULL)
						{
							BUF *inc_buf2;

							inc_buf2 = AdminWebProcessServerSideInclude(inc_buf, full_inc_filename, depth + 1);

							BufSkipUtf8Bom(inc_buf2);
							WriteBufBufWithOffset(ret, inc_buf2);

							FreeBuf(inc_buf);
							FreeBuf(inc_buf2);
						}
						else
						{
							Debug("Loading SSI '%s' error.\n", inc_buf);
						}

						i = (x + StrLen(end_tag) - 1);

						is_ssi = true;
					}
				}
			}
		}

		if (is_ssi == false)
		{
			WriteBufChar(ret, src_str[i]);
		}
	}

	Free(src_str);

	return ret;
}

// Handle the file request
bool AdminWebHandleFileRequest(ADMIN *a, CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_src, char *query_string, char *virtual_root_dir, char *physical_root_dir)
{
	bool ret = false;
	char url[MAX_PATH];
	UINT i, len;
	if (a == NULL || c == NULL || s == NULL || h == NULL || query_string == NULL ||
		virtual_root_dir == NULL || physical_root_dir == NULL)
	{
		return false;
	}

	StrCpy(url, sizeof(url), url_src);

	len = StrLen(url);
	for (i = 0;i < len;i++)
	{
		if (url[i] == '\\')
		{
			url[i] = '/';
		}
	}

	// Is dangerous URL?
	if (InStr(url, "..") || InStr(url, "//") || InStr(url, "\\\\") || InStr(url, "/\\") || InStr(url, "\\/"))
	{
		ret = AdminWebSend404Error(s, h);
	}
	else
	{
		char filename[MAX_PATH];
		bool is_index_file = false;

		BUF *b = AdminWebTryFindAndReadFile(virtual_root_dir, physical_root_dir, url,
			filename, sizeof(filename), &is_index_file);

		if (b == NULL)
		{
			ret = AdminWebSend404Error(s, h);
		}
		else
		{
			if (is_index_file && EndWith(url, "/") == false)
			{
				char url2[MAX_PATH];
				StrCpy(url2, sizeof(url2), url);
				StrCat(url2, sizeof(url2), "/");
				ret = AdminWebSend302Redirect(s, url2, query_string, h);
			}
			else if (is_index_file == false && EndWith(url, "/"))
			{
				char url2[MAX_PATH];
				TrimEndWith(url2, sizeof(url2), url, "/");
				ret = AdminWebSend302Redirect(s, url2, query_string, h);
			}
			else
			{
				BUF *b2 = AdminWebProcessServerSideInclude(b, filename, 0);
				char *mime = GetMimeTypeFromFileName(filename);

				if (mime == NULL)
				{
					mime = "application/octet-stream";
				}

				ret = AdminWebSendBody(s, 200, "OK", b2->Buf, b2->Size, mime, NULL, NULL, h);

				FreeBuf(b2);
			}
			FreeBuf(b);
		}
	}

	return ret;
}

// Try to find a file, and if exists return the file contents
BUF *AdminWebTryFindAndReadFile(char *vroot, char *proot, char *url, char *ret_filename, UINT ret_filename_size, bool *is_index_html)
{
	char tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	UINT vroot_len;
	UINT url_len;
	char relative_path[MAX_PATH];
	BUF *b;
	if (vroot == NULL || proot == NULL || url == NULL || ret_filename == NULL || is_index_html == NULL)
	{
		return NULL;
	}

	*is_index_html = false;

	if (StartWith(url, vroot) == false)
	{
		return NULL;
	}

	vroot_len = StrLen(vroot);
	url_len = StrLen(url);

	StrCpy(relative_path, sizeof(relative_path), url + vroot_len);

	if (StartWith(relative_path, "/"))
	{
		char tmp3[MAX_PATH];

		StrCpy(tmp3, sizeof(tmp3), relative_path + 1);
		StrCpy(relative_path, sizeof(relative_path), tmp3);
	}

	CombinePath(tmp, sizeof(tmp), proot, relative_path);

	// index.html
	CombinePath(tmp2, sizeof(tmp2), tmp, "index.html");
	b = AdminWebTryOneFile(tmp2, ret_filename, ret_filename_size);
	if (b != NULL)
	{
		*is_index_html = true;
		return b;
	}

	// dirname/filename
	StrCpy(tmp2, sizeof(tmp2), tmp);
	b = AdminWebTryOneFile(tmp2, ret_filename, ret_filename_size);
	if (b != NULL)
	{
		return b;
	}

	return NULL;
}
BUF *AdminWebTryOneFile(char *filename, char *ret_filename, UINT ret_filename_size)
{
	BUF *b;
	if (filename == NULL || ret_filename == NULL)
	{
		return NULL;
	}

	b = ReadDump(filename);
	if (b == NULL)
	{
		return NULL;
	}

	StrCpy(ret_filename, ret_filename_size, filename);

	return b;
}

// Send a 401 Unauthorized error
bool AdminWebSendUnauthorized(SOCK *s, HTTP_HEADER *http_request_headers)
{
	char *http_401_str = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<html><head>\r\n<title>401 Unauthorized</title>\r\n</head><body>\r\n<h1>" CEDAR_SERVER_STR ": Administrative authentication required.</h1>\r\n<p>This VPN Server could not verify that you are authorized to access to the \r\nserver in administrative mode.</p>\r\n<p><strong>For web browser logins:<br></strong>You must supply the HTTP basic \r\nauthentication credential as following.</p>\r\n<ul>\r\n\t<li>To login to the VPN server as the entire server administrator, specify empty or &quot;administrator&quot; as the username field, and specify the server administrative \r\n\tpassword as the password field.<br></li>\r\n\t<li>To login to a particular Virtual Hub as the hub administrator, specify \r\n\tthe hub name as the username field, and specify the hub administrative \r\n\tpassword as the password field.</li>\r\n</ul>\r\n<p><strong>For JSON-RPC client logins:<br></strong>Instead to HTTP basic \r\nauthentication, you can also specify the HTTP header parameters as following.</p>\r\n<ul>\r\n\t<li>X-VPNADMIN-HUBNAME: Empty to login to the VPN Server as the entire \r\n\tserver administrator, or specify the target Virtual Hub name as the hub \r\n\tadministrator.</li>\r\n\t<li>X-VPNADMIN-PASSWORD: Specify the administrative password.</li>\r\n</ul>\r\n</body></html>\r\n";
	bool ret;
	// Validate arguments
	if (s == NULL || http_request_headers == NULL)
	{
		return false;
	}

	// Creating a Data
	ret = AdminWebSendBody(s, 401, "Unauthorized", http_401_str, StrLen(http_401_str), HTTP_CONTENT_TYPE,
		"WWW-Authenticate",
		"Basic realm=\"Username 'administrator' for entire VPN Server privilege, or specify Virtual Hub name as the username for specified Virtual Hub administrative privilege.\"",
		http_request_headers);

	return ret;
}

// Send reply
bool AdminWebSendBody(SOCK *s, UINT status_code, char *status_string, UCHAR *data, UINT data_size, char *content_type, char *add_header_name, char *add_header_value,
					  HTTP_HEADER *request_headers)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char error_code_str[16];
	bool ret = false;
	HTTP_VALUE *origin;
	if (s == NULL || status_string == NULL || (data_size != 0 && data == NULL) || request_headers == NULL)
	{
		return false;
	}
	if (content_type == NULL)
	{
		content_type = "text/html; charset=utf-8";
	}

	ToStr(error_code_str, status_code);
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", error_code_str, status_string);

	if (StrCmpi(request_headers->Method, "OPTIONS") == 0)
	{
		AddHttpValue(h, NewHttpValue("Allow", "OPTIONS, GET, POST"));
	}

	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
	AddHttpValue(h, NewHttpValue("Content-Type", content_type));
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Methods", "OPTIONS,GET,POST"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Headers", "X-VPNADMIN-HUBNAME,X-VPNADMIN-PASSWORD"));
	AddHttpValue(h, NewHttpValue("Access-Control-Allow-Credentials", "true"));

	origin = GetHttpValue(request_headers, "Origin");
	if (origin != NULL)
	{
		AddHttpValue(h, NewHttpValue("Access-Control-Allow-Origin", origin->Data));
	}

	if (add_header_name != NULL && add_header_value != NULL)
	{
		AddHttpValue(h, NewHttpValue(add_header_name, add_header_value));
	}

	ret = PostHttp(s, h, data, data_size);

	FreeHttpHeader(h);

	return ret;
}

// Send 404 error
bool AdminWebSend404Error(SOCK *s, HTTP_HEADER *request_headers)
{
	char *body = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\r\n";
	if (s == NULL || request_headers == NULL)
	{
		return false;
	}

	return AdminWebSendBody(s, 404, "Not Found", body, StrLen(body), NULL, NULL, NULL, request_headers);
}

// Send 302 redirect
bool AdminWebSend302Redirect(SOCK *s, char *url, char *query_string, HTTP_HEADER *request_headers)
{
	bool ret = false;
	char *txt;
	UINT txt_size;
	char *url2;
	UINT url2_size;
	char *body = "<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"$URL$\">here</a>.</h2>\r\n</body></html>";
	if (s == NULL || url == NULL || request_headers == NULL)
	{
		return false;
	}

	url2_size = (StrSize(url) + StrSize(query_string) + MAX_SIZE) * 2;
	url2 = ZeroMalloc(url2_size);

	StrCpy(url2, url2_size, url);
	if (IsEmptyStr(query_string) == false)
	{
		StrCat(url2, url2_size, "?");
		StrCat(url2, url2_size, query_string);
	}

	txt_size = (StrSize(body) + StrSize(url2) + MAX_SIZE) * 2;
	txt = ZeroMalloc(txt_size);

	ReplaceStrEx(txt, txt_size, body, "$URL$", url2, false);

	ret = AdminWebSendBody(s, 302, "Found", txt, StrLen(txt), NULL, "Location", url2, request_headers);

	Free(txt);

	Free(url2);

	return ret;
}

// "/admin" web page POST handler
void AdminWebProcPost(CONNECTION *c, SOCK *s, HTTP_HEADER *h, UINT post_data_size, char *url_target)
{
	ADMIN *a;
	UCHAR *data;
	char url[MAX_PATH];
	char query_string[MAX_SIZE];
	UINT i;
	if (c == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return;
	}

	a = JsonRpcAuthLogin(c->Cedar, s, h);
	if (a == NULL)
	{
		RecvAllWithDiscard(s, post_data_size, s->SecureMode);
		AdminWebSendUnauthorized(s, h);
		return;
	}

	if (post_data_size > a->MaxJsonRpcRecvSize)
	{
		Disconnect(s);
		return;
	}

	data = ZeroMalloc(post_data_size + 1);

	if (RecvAll(s, data, post_data_size, s->SecureMode))
	{
		c->JsonRpcAuthed = true;
#ifndef	GC_SOFTETHER_OSS
		RemoveDosEntry(c->Listener, s);
#endif	// GC_SOFTETHER_OSS

		// Divide url_target into URL and query string
		StrCpy(url, sizeof(url), url_target);
		Zero(query_string, sizeof(query_string));
		i = SearchStr(url, "?", 0);
		if (i != INFINITE)
		{
			StrCpy(query_string, sizeof(query_string), url + i + 1);
			url[i] = 0;
		}

		AdminWebHandleFileRequest(a, c, s, h, url, query_string, "/admin", "|wwwroot/admin");
	}

	Free(data);
	Free(a);
}

// "/admin" web page GET handler
void AdminWebProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target)
{
	ADMIN *a;
	char url[MAX_PATH];
	char query_string[MAX_SIZE];
	UINT i;
	if (c == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return;
	}

	a = JsonRpcAuthLogin(c->Cedar, s, h);
	if (a == NULL)
	{
		AdminWebSendUnauthorized(s, h);
		return;
	}

	c->JsonRpcAuthed = true;
#ifndef	GC_SOFTETHER_OSS
	RemoveDosEntry(c->Listener, s);
#endif	// GC_SOFTETHER_OSS

	// Divide url_target into URL and query string
	StrCpy(url, sizeof(url), url_target);
	Zero(query_string, sizeof(query_string));
	i = SearchStr(url, "?", 0);
	if (i != INFINITE)
	{
		StrCpy(query_string, sizeof(query_string), url + i + 1);
		url[i] = 0;
	}

	AdminWebHandleFileRequest(a, c, s, h, url, query_string, "/admin", "|wwwroot/admin");

	Free(a);
}

// New JSON-RPC Result
JSON_VALUE *JsonRpcNewResponse(PACK *p)
{
	JSON_VALUE *jv;
	JSON_OBJECT *jo;
	JSON_VALUE *jv2;

	if (p == NULL)
	{
		return NULL;
	}

	jv = JsonNewObject();
	jo = JsonValueGetObject(jv);

	jv2 = PackToJson(p);

	JsonSet(jo, "result", jv2);

	return jv;
}

// New JSON-RPC Error
JSON_VALUE *JsonRpcNewError(int code, wchar_t *message)
{
	wchar_t msg[MAX_PATH];
	JSON_VALUE *jv;
	JSON_OBJECT *jo;
	JSON_VALUE *jv2;
	JSON_OBJECT *jo2;

	if (UniIsEmptyStr(message))
	{
		UniFormat(msg, sizeof(msg), L"Error code %u", code);
	}
	else
	{
		UniFormat(msg, sizeof(msg), L"Error code %u: %s", code, message);
	}

	jv = JsonNewObject();
	jo = JsonValueGetObject(jv);

	jv2 = JsonNewObject();
	jo2 = JsonValueGetObject(jv2);

	JsonSet(jo, "error", jv2);

	JsonSetNumber(jo2, "code", (UINT64)code);
	JsonSetUniStr(jo2, "message", msg);

	return jv;
}

// JSON-RPC process request object
JSON_VALUE *JsonRpcProcRequestObject(ADMIN *admin, CONNECTION *c, SOCK *s, JSON_VALUE *json_req, char *method_name)
{
	PACK *pack_request;
	JSON_VALUE *ret = NULL;
	if (c == NULL || s == NULL || json_req == NULL || admin == NULL)
	{
		return NULL;
	}

	pack_request = JsonToPack(json_req);

	PackAddStr(pack_request, "function_name", method_name);

	if (pack_request != NULL)
	{
		RPC *rpc;
		PACK *pack_response;
		UINT err;

		// RPC Server
		rpc = StartRpcServer(s, AdminDispatch, admin);

		admin->Rpc = rpc;

		pack_response = CallRpcDispatcher(rpc, pack_request);

		if (pack_response == NULL)
		{
			pack_response = PackError(ERR_NOT_SUPPORTED);
		}

		RpcFreeEx(rpc, true);

		FreePack(pack_request);

		// Construct response object
		err = GetErrorFromPack(pack_response);
		if (err != 0)
		{
			// Return the error
			ret = JsonRpcNewError(err, _E(err));
		}
		else
		{
			// Return the PACK
			ret = JsonRpcNewResponse(pack_response);
		}

		SLog(admin->Server->Cedar, "LS_API_RPC_CALL",
			&s->RemoteIP, s->RemotePort, s->RemoteHostname,
			method_name, err, _E(err));

		FreePack(pack_response);
	}

	return ret;
}

// JSON-RPC HTTP user authentication
bool HttpParseBasicAuthHeader(HTTP_HEADER *h, char *username, UINT username_size, char *password, UINT password_size)
{
	bool ret = false;
	HTTP_VALUE *auth_value;
	HTTP_VALUE *vpnadmin_hubname;
	HTTP_VALUE *vpnadmin_password;
	if (h == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	auth_value = GetHttpValue(h, "Authorization");
	vpnadmin_hubname = GetHttpValue(h, "X-VPNADMIN-HUBNAME");
	vpnadmin_password = GetHttpValue(h, "X-VPNADMIN-PASSWORD");

	if (vpnadmin_password != NULL)
	{
		if (vpnadmin_hubname == NULL)
		{
			StrCpy(username, username_size, "");
		}
		else
		{
			StrCpy(username, username_size, vpnadmin_hubname->Data);
		}

		StrCpy(password, password_size, vpnadmin_password->Data);

		ret = true;
	}

	if (ret == false && auth_value != NULL)
	{
		char key[32], value[MAX_SIZE];

		if (GetKeyAndValue(auth_value->Data, key, sizeof(key), value, sizeof(value), " \t"))
		{
			if (StrCmpi(key, "Basic") == 0 && IsEmptyStr(value) == false)
			{
				UINT b64_dest_size = StrSize(value) * 2 + 256;
				char *b64_dest = ZeroMalloc(b64_dest_size);

				Decode64(b64_dest, value);

				if (IsEmptyStr(b64_dest) == false)
				{
					if (b64_dest[0] == ':')
					{
						// Empty username
						StrCpy(username, username_size, "");
						StrCpy(password, password_size, b64_dest + 1);
						ret = true;
					}
					else
					{
						if (GetKeyAndValue(b64_dest, username, username_size, password, password_size, ":"))
						{
							ret = true;
						}
					}
				}

				Free(b64_dest);
			}
		}
	}

	return ret;
}

// JSON-RPC Login
ADMIN *JsonRpcAuthLogin(CEDAR *c, SOCK *sock, HTTP_HEADER *h)
{
	ADMIN *a = NULL;
	char username[MAX_HUBNAME_LEN + 1];
	char password[MAX_PASSWORD_LEN + 1];
	SERVER *s;
	char empty_pw_hash[SHA1_SIZE];

	if (c == NULL || h == NULL || sock == NULL)
	{
		return NULL;
	}

	s = c->Server;

	HashAdminPassword(empty_pw_hash, "");

	Zero(username, sizeof(username));
	Zero(password, sizeof(password));

	if (HttpParseBasicAuthHeader(h, username, sizeof(username), password, sizeof(password)))
	{
		char pw_hash[SHA1_SIZE];
		bool is_server_admin = false;
		bool is_hub_admin = false;
		char hub_name[MAX_HUBNAME_LEN + 1];

		HashAdminPassword(pw_hash, password);

		Zero(hub_name, sizeof(hub_name));

		// Check if the server administrator password is empty. If yes, login always success.
		if (Cmp(s->HashedPassword, empty_pw_hash, SHA1_SIZE) == 0)
		{
			is_server_admin = true;
		}
		else
		{
			if (IsEmptyStr(username) || StrCmpi(username, ADMINISTRATOR_USERNAME) == 0)
			{
				// If the username is empty or 'administrator', verify with the server admin password.
				if (Cmp(s->HashedPassword, pw_hash, SHA1_SIZE) == 0)
				{
					is_server_admin = true;
				}
			}
		}

		if (is_server_admin == false)
		{
			HUB *h;
			// Hub admin mode
			LockHubList(c);
			{
				h = GetHub(c, username);
			}
			UnlockHubList(c);

			if (h != NULL)
			{
				Lock(h->lock);
				{
					if (Cmp(h->HashedPassword, empty_pw_hash, SHA1_SIZE) != 0 && IsZero(h->HashedPassword, sizeof(h->HashedPassword)) == false)
					{
						if (Cmp(pw_hash, h->HashedPassword, SHA1_SIZE) == 0)
						{
							is_hub_admin = true;

							StrCpy(hub_name, sizeof(hub_name), h->Name);
						}
					}
				}
				Unlock(h->lock);

				ReleaseHub(h);
			}
		}

		if (is_server_admin || is_hub_admin)
		{
			if (CheckAdminSourceAddress(sock, hub_name))
			{
				a = ZeroMalloc(sizeof(ADMIN));

				a->Server = s;
				a->ServerAdmin = is_server_admin;
				a->ClientBuild = c->Build;

				if (is_hub_admin)
				{
					StrCpy(a->dummy1, sizeof(a->dummy1), hub_name);
					a->HubName = a->dummy1;
				}
			}
		}
	}

	if (a != NULL)
	{
		char admin_mode[256];
		if (a->ServerAdmin)
		{
			a->MaxJsonRpcRecvSize = ADMIN_RPC_MAX_POST_SIZE_BY_SERVER_ADMIN;
		}
		else
		{
			a->MaxJsonRpcRecvSize = ADMIN_RPC_MAX_POST_SIZE_BY_HUB_ADMIN;
		}

		if (IsEmptyStr(a->HubName))
		{
			StrCpy(admin_mode, sizeof(admin_mode),
				"Entire VPN Server Admin Mode");
		}
		else
		{
			Format(admin_mode, sizeof(admin_mode),
				"Virtual Hub Admin Mode for '%s'",
				a->HubName);
		}

		SLog(s->Cedar, "LS_API_AUTH_OK",
			&sock->RemoteIP, sock->RemotePort, sock->RemoteHostname,
			admin_mode, username, h->Method, h->Target);
	}
	else
	{
		SLog(s->Cedar, "LS_API_AUTH_ERROR",
			&sock->RemoteIP, sock->RemotePort, sock->RemoteHostname,
			username, h->Method, h->Target);
	}


	return a;
}

// Query string to JSON list value
JSON_VALUE *QueryStringToJsonListValue(char *qs)
{
	TOKEN_LIST *t;
	UINT i;
	LIST *distinct_list = NULL;
	JSON_VALUE *v = NULL;
	JSON_OBJECT *o = NULL;
	if (qs == NULL)
	{
		return NULL;
	}

	t = ParseTokenWithoutNullStr(qs, "&");
	if (t == NULL)
	{
		return NULL;
	}

	distinct_list = NewStrList();

	v = JsonNewObject();
	o = JsonValueGetObject(v);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *token = t->Token[i];
		UINT pos;

		pos = SearchStr(token, "=", 0);
		if (pos != INFINITE)
		{
			char *key_decoded;
			char *value_decoded;
			char *key = CopyStr(token);
			char *value = CopyStr(token + pos + 1);

			key[pos] = 0;
			key_decoded = UrlDecode(key);
			value_decoded = UrlDecode(value);

			if (key_decoded != NULL && value_decoded != NULL)
			{
				if (AddStrToStrListDistinct(distinct_list, key_decoded))
				{
					JsonSetStr(o, key_decoded, value_decoded);
				}
			}

			Free(value_decoded);
			Free(key_decoded);
			Free(key);
			Free(value);
		}
	}

	FreeToken(t);

	FreeStrList(distinct_list);

	return v;
}

// Construct new JSON-RPC dummy request
JSON_VALUE *ConstructDummyJsonRpcRequest(char *method_name, JSON_VALUE *p)
{
	JSON_VALUE *ret;
	JSON_OBJECT *ret_object;
	UCHAR rand[16];
	char id_str[64];

	Rand(rand, sizeof(rand));

	BinToStr(id_str, sizeof(id_str), rand, sizeof(rand));

	ret = JsonNewObject();
	ret_object = JsonObject(ret);

	JsonSetStr(ret_object, "jsonrpc", "2.0");
	JsonSetStr(ret_object, "method", method_name);
	JsonSet(ret_object, "params", p);
	JsonSetStr(ret_object, "id", id_str);

	return ret;
}

// JSON-RPC Options Dispatch
void JsonRpcProcOptions(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target)
{
	if (c == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return;
	}

	c->JsonRpcAuthed = true;

#ifndef	GC_SOFTETHER_OSS
	RemoveDosEntry(c->Listener, s);
#endif	// GC_SOFTETHER_OSS

	AdminWebSendBody(s, 200, "OK", NULL, 0, NULL, NULL, NULL, h);
}

// JSON-RPC GET Dispatch
void JsonRpcProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target)
{
	ADMIN *a;
	char url[MAX_PATH];
	char query_string[MAX_SIZE];
	UINT i;
	bool reply_sent = false;
	if (c == NULL || s == NULL || h == NULL || url_target == NULL)
	{
		return;
	}

	a = JsonRpcAuthLogin(c->Cedar, s, h);
	if (a == NULL)
	{
		AdminWebSendUnauthorized(s, h);
		return;
	}

	c->JsonRpcAuthed = true;

#ifndef	GC_SOFTETHER_OSS
	RemoveDosEntry(c->Listener, s);
#endif	// GC_SOFTETHER_OSS

	// Divide url_target into URL and query string
	StrCpy(url, sizeof(url), url_target);
	Zero(query_string, sizeof(query_string));
	i = SearchStr(url, "?", 0);
	if (i != INFINITE)
	{
		StrCpy(query_string, sizeof(query_string), url + i + 1);
		url[i] = 0;
	}

	if (StartWith(url, "/api/"))
	{
		// Call a method
		JSON_VALUE *params_value = NULL;
		JSON_OBJECT *params_object = NULL;
		UINT i;
		char method_name[MAX_PATH];

		StrCpy(method_name, sizeof(method_name), url + 5);

		i = SearchStr(method_name, "/", 0);
		if (i != INFINITE)
		{
			method_name[i] = 0;
		}

		if (IsEmptyStr(method_name) == false)
		{
			// Call a method
			params_value = QueryStringToJsonListValue(query_string);

			if (params_value != NULL)
			{
				JSON_VALUE *json_ret = NULL;
				char id[96];
				char *ret_str = NULL;

				GetDateTimeStrMilli64(id, sizeof(id), LocalTime64());

				params_object = JsonObject(params_value);

				// Process the request
				json_ret = JsonRpcProcRequestObject(a, c, s, params_value, method_name);

				if (json_ret == NULL)
				{
					json_ret = JsonRpcNewError(ERR_INTERNAL_ERROR, L"Internal error");
				}

				JsonSetStr(JsonObject(json_ret), "jsonrpc", "2.0");
				JsonSetStr(JsonObject(json_ret), "id", id);

				ret_str = JsonToStr(json_ret);

				AdminWebSendBody(s, 200, "OK", ret_str, StrLen(ret_str), "text/plain; charset=UTF-8", NULL, NULL, h);

				Free(ret_str);
				JsonFree(json_ret);
				JsonFree(params_value);
			}
		}
	}


	if (reply_sent == false)
	{
		BUF *html_buf = ReadDump("|vpnserver_api_doc.html");

		if (html_buf != NULL)
		{
			AdminWebSendBody(s, 200, "OK", html_buf->Buf, html_buf->Size, "text/html; charset=UTF-8", NULL, NULL, h);

			FreeBuf(html_buf);
		}
		else
		{
			AdminWebSend404Error(s, h);
		}
	}

	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}
	Free(a);
}

// JSON-RPC POST Dispatch
void JsonRpcProcPost(CONNECTION *c, SOCK *s, HTTP_HEADER *h, UINT post_data_size)
{
	ADMIN *a;
	UCHAR *data;
	if (c == NULL || s == NULL || h == NULL)
	{
		return;
	}

	a = JsonRpcAuthLogin(c->Cedar, s, h);
	if (a == NULL)
	{
		RecvAllWithDiscard(s, post_data_size, s->SecureMode);
		AdminWebSendUnauthorized(s, h);
		return;
	}

	if (post_data_size > a->MaxJsonRpcRecvSize)
	{
		Disconnect(s);
		return;
	}

	data = ZeroMalloc(post_data_size + 1);

	if (RecvAll(s, data, post_data_size, s->SecureMode))
	{
		// Parse JSON
		JSON_VALUE *json_req = StrToJson(data);
		JSON_OBJECT *json_req_object = JsonObject(json_req);
		JSON_VALUE *json_ret = NULL;
		char *res = NULL;
		char *request_id = NULL;
		char *method_name = NULL;

		c->JsonRpcAuthed = true;

#ifndef	GC_SOFTETHER_OSS
		RemoveDosEntry(c->Listener, s);
#endif	// GC_SOFTETHER_OSS

		if (json_req == NULL || json_req_object == NULL)
		{
			// Parse error
			json_ret = JsonRpcNewError(ERR_INVALID_PARAMETER, L"Parameter is invalid: JSON-RPC Parse Error");
		}
		else
		{
			// check the JSON-RPC version
			char *ver_str = JsonGetStr(json_req_object, "jsonrpc");
			if (StrCmpi(ver_str, "2.0") != 0)
			{
				// Invalid version
				json_ret = JsonRpcNewError(ERR_INVALID_PARAMETER, L"JSON-RPC version is invalid");
			}
			else
			{
				JSON_VALUE *params_value = NULL;
				JSON_OBJECT *params_object = NULL;

				// Get Request ID
				request_id = JsonGetStr(json_req_object, "id");

				// Get method name
				method_name = JsonGetStr(json_req_object, "method");

				// Get parameters
				params_value = JsonGet(json_req_object, "params");
				params_object = JsonObject(params_value);

				if (IsEmptyStr(method_name))
				{
					// method is empty
					json_ret = JsonRpcNewError(ERR_INVALID_PARAMETER, L"JSON-RPC method name is empty");
				}
				else if (params_value == NULL || params_object == NULL)
				{
					// params is empty
					json_ret = JsonRpcNewError(ERR_INVALID_PARAMETER, L"JSON-RPC parameter is empty");
				}
				else
				{
					// Process the request
					json_ret = JsonRpcProcRequestObject(a, c, s, params_value, method_name);
				}
			}
		}

		if (json_ret == NULL)
		{
			json_ret = JsonRpcNewError(ERR_INTERNAL_ERROR, L"Internal error");
		}

		JsonSetStr(JsonObject(json_ret), "jsonrpc", "2.0");
		if (request_id == NULL)
		{
			request_id = "0";
		}
		JsonSetStr(JsonObject(json_ret), "id", request_id);

		res = JsonToStr(json_ret);

		AdminWebSendBody(s, 200, "OK", res, StrLen(res), "application/json", NULL, NULL, h);

		Free(res);

		JsonFree(json_ret);
		JsonFree(json_req);
	}

	Free(data);

	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}
	Free(a);
}

// Dispatch routine for Administration RPC 
PACK *AdminDispatch(RPC *rpc, char *name, PACK *p)
{
	ADMIN *a;
	PACK *ret;
	UINT err;
	SERVER *server = NULL;
	CEDAR *cedar = NULL;
	bool ok = false;
	// Validate arguments
	if (rpc == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;

	// Administration structure
	a = (ADMIN *)rpc->Param;
	if (a == NULL)
	{
		FreePack(ret);
		return NULL;
	}

	server = a->Server;

	if (server == NULL)
	{
		return NULL;
	}

	cedar = server->Cedar;
	Lock(cedar->CedarSuperLock);

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Entering RPC [%s]...",
			rpc_id, ip, name);

		SiDebugLog(a->Server, tmp);
	}

	if (0) {}

	// RPC function declaration: from here
	DECLARE_RPC_EX("Test", RPC_TEST, StTest, InRpcTest, OutRpcTest, FreeRpcTest)
	DECLARE_RPC_EX("GetServerInfo", RPC_SERVER_INFO, StGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
	DECLARE_RPC("GetServerStatus", RPC_SERVER_STATUS, StGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
	DECLARE_RPC("CreateListener", RPC_LISTENER, StCreateListener, InRpcListener, OutRpcListener)
	DECLARE_RPC_EX("EnumListener", RPC_LISTENER_LIST, StEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
	DECLARE_RPC("DeleteListener", RPC_LISTENER, StDeleteListener, InRpcListener, OutRpcListener)
	DECLARE_RPC("EnableListener", RPC_LISTENER, StEnableListener, InRpcListener, OutRpcListener)
	DECLARE_RPC_EX("SetPortsUDP", RPC_PORTS, StSetPortsUDP, InRpcPorts, OutRpcPorts, FreeRpcPorts)
	DECLARE_RPC_EX("GetPortsUDP", RPC_PORTS, StGetPortsUDP, InRpcPorts, OutRpcPorts, FreeRpcPorts)
	DECLARE_RPC_EX("SetProtoOptions", RPC_PROTO_OPTIONS, StSetProtoOptions, InRpcProtoOptions, OutRpcProtoOptions, FreeRpcProtoOptions)
	DECLARE_RPC_EX("GetProtoOptions", RPC_PROTO_OPTIONS, StGetProtoOptions, InRpcProtoOptions, OutRpcProtoOptions, FreeRpcProtoOptions)
	DECLARE_RPC("SetServerPassword", RPC_SET_PASSWORD, StSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
	DECLARE_RPC_EX("SetFarmSetting", RPC_FARM, StSetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
	DECLARE_RPC_EX("GetFarmSetting", RPC_FARM, StGetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
	DECLARE_RPC_EX("GetFarmInfo", RPC_FARM_INFO, StGetFarmInfo, InRpcFarmInfo, OutRpcFarmInfo, FreeRpcFarmInfo)
	DECLARE_RPC_EX("EnumFarmMember", RPC_ENUM_FARM, StEnumFarmMember, InRpcEnumFarm, OutRpcEnumFarm, FreeRpcEnumFarm)
	DECLARE_RPC("GetFarmConnectionStatus", RPC_FARM_CONNECTION_STATUS, StGetFarmConnectionStatus, InRpcFarmConnectionStatus, OutRpcFarmConnectionStatus)
	DECLARE_RPC_EX("SetServerCert", RPC_KEY_PAIR, StSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCert", RPC_KEY_PAIR, StGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCipherList", RPC_STR, StGetServerCipherList, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC_EX("GetServerCipher", RPC_STR, StGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC_EX("SetServerCipher", RPC_STR, StSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC("CreateHub", RPC_CREATE_HUB, StCreateHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("SetHub", RPC_CREATE_HUB, StSetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("GetHub", RPC_CREATE_HUB, StGetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC_EX("EnumHub", RPC_ENUM_HUB, StEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
	DECLARE_RPC("DeleteHub", RPC_DELETE_HUB, StDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
	DECLARE_RPC("GetHubRadius", RPC_RADIUS, StGetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPC("SetHubRadius", RPC_RADIUS, StSetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPC_EX("EnumConnection", RPC_ENUM_CONNECTION, StEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnection)
	DECLARE_RPC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, StDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
	DECLARE_RPC("GetConnectionInfo", RPC_CONNECTION_INFO, StGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
	DECLARE_RPC("SetHubOnline", RPC_SET_HUB_ONLINE, StSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
	DECLARE_RPC("GetHubStatus", RPC_HUB_STATUS, StGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
	DECLARE_RPC("SetHubLog", RPC_HUB_LOG, StSetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC("GetHubLog", RPC_HUB_LOG, StGetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC_EX("AddCa", RPC_HUB_ADD_CA, StAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
	DECLARE_RPC_EX("EnumCa", RPC_HUB_ENUM_CA, StEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
	DECLARE_RPC_EX("GetCa", RPC_HUB_GET_CA, StGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
	DECLARE_RPC("DeleteCa", RPC_HUB_DELETE_CA, StDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
	DECLARE_RPC("SetLinkOnline", RPC_LINK, StSetLinkOnline, InRpcLink, OutRpcLink)
	DECLARE_RPC("SetLinkOffline", RPC_LINK, StSetLinkOffline, InRpcLink, OutRpcLink)
	DECLARE_RPC("DeleteLink", RPC_LINK, StDeleteLink, InRpcLink, OutRpcLink)
	DECLARE_RPC("RenameLink", RPC_RENAME_LINK, StRenameLink, InRpcRenameLink, OutRpcRenameLink)
	DECLARE_RPC_EX("CreateLink", RPC_CREATE_LINK, StCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("GetLink", RPC_CREATE_LINK, StGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("SetLink", RPC_CREATE_LINK, StSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("EnumLink", RPC_ENUM_LINK, StEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
	DECLARE_RPC_EX("GetLinkStatus", RPC_LINK_STATUS, StGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
	DECLARE_RPC("AddAccess", RPC_ADD_ACCESS, StAddAccess, InRpcAddAccess, OutRpcAddAccess)
	DECLARE_RPC("DeleteAccess", RPC_DELETE_ACCESS, StDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
	DECLARE_RPC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, StEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, StSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("CreateUser", RPC_SET_USER, StCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("SetUser", RPC_SET_USER, StSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("GetUser", RPC_SET_USER, StGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC("DeleteUser", RPC_DELETE_USER, StDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumUser", RPC_ENUM_USER, StEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
	DECLARE_RPC_EX("CreateGroup", RPC_SET_GROUP, StCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("SetGroup", RPC_SET_GROUP, StSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("GetGroup", RPC_SET_GROUP, StGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC("DeleteGroup", RPC_DELETE_USER, StDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumGroup", RPC_ENUM_GROUP, StEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
	DECLARE_RPC_EX("EnumSession", RPC_ENUM_SESSION, StEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
	DECLARE_RPC_EX("GetSessionStatus", RPC_SESSION_STATUS, StGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
	DECLARE_RPC("DeleteSession", RPC_DELETE_SESSION, StDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
	DECLARE_RPC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, StEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
	DECLARE_RPC("DeleteMacTable", RPC_DELETE_TABLE, StDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, StEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
	DECLARE_RPC("DeleteIpTable", RPC_DELETE_TABLE, StDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC("SetKeep", RPC_KEEP, StSetKeep, InRpcKeep, OutRpcKeep)
	DECLARE_RPC("GetKeep", RPC_KEEP, StGetKeep, InRpcKeep, OutRpcKeep)
	DECLARE_RPC("EnableSecureNAT", RPC_HUB, StEnableSecureNAT, InRpcHub, OutRpcHub)
	DECLARE_RPC("DisableSecureNAT", RPC_HUB, StDisableSecureNAT, InRpcHub, OutRpcHub)
	DECLARE_RPC("SetSecureNATOption", VH_OPTION, StSetSecureNATOption, InVhOption, OutVhOption)
	DECLARE_RPC("GetSecureNATOption", VH_OPTION, StGetSecureNATOption, InVhOption, OutVhOption)
	DECLARE_RPC_EX("EnumNAT", RPC_ENUM_NAT, StEnumNAT, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
	DECLARE_RPC_EX("EnumDHCP", RPC_ENUM_DHCP, StEnumDHCP, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
	DECLARE_RPC("GetSecureNATStatus", RPC_NAT_STATUS, StGetSecureNATStatus, InRpcNatStatus, OutRpcNatStatus)
	DECLARE_RPC_EX("EnumEthernet", RPC_ENUM_ETH, StEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
	DECLARE_RPC("AddLocalBridge", RPC_LOCALBRIDGE, StAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC("DeleteLocalBridge", RPC_LOCALBRIDGE, StDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, StEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
	DECLARE_RPC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, StGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
	DECLARE_RPC("RebootServer", RPC_TEST, StRebootServer, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetCaps", CAPSLIST, StGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
	DECLARE_RPC_EX("GetConfig", RPC_CONFIG, StGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("SetConfig", RPC_CONFIG, StSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("GetDefaultHubAdminOptions", RPC_ADMIN_OPTION, StGetDefaultHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, StGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, StSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, StGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, StSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC("AddL3Switch", RPC_L3SW, StAddL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("DelL3Switch", RPC_L3SW, StDelL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC_EX("EnumL3Switch", RPC_ENUM_L3SW, StEnumL3Switch, InRpcEnumL3Sw, OutRpcEnumL3Sw, FreeRpcEnumL3Sw)
	DECLARE_RPC("StartL3Switch", RPC_L3SW, StStartL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("StopL3Switch", RPC_L3SW, StStopL3Switch, InRpcL3Sw, OutRpcL3Sw)
	DECLARE_RPC("AddL3If", RPC_L3IF, StAddL3If, InRpcL3If, OutRpcL3If)
	DECLARE_RPC("DelL3If", RPC_L3IF, StDelL3If, InRpcL3If, OutRpcL3If)
	DECLARE_RPC_EX("EnumL3If", RPC_ENUM_L3IF, StEnumL3If, InRpcEnumL3If, OutRpcEnumL3If, FreeRpcEnumL3If)
	DECLARE_RPC("AddL3Table", RPC_L3TABLE, StAddL3Table, InRpcL3Table, OutRpcL3Table)
	DECLARE_RPC("DelL3Table", RPC_L3TABLE, StDelL3Table, InRpcL3Table, OutRpcL3Table)
	DECLARE_RPC_EX("EnumL3Table", RPC_ENUM_L3TABLE, StEnumL3Table, InRpcEnumL3Table, OutRpcEnumL3Table, FreeRpcEnumL3Table)
	DECLARE_RPC_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPC_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetCrl", RPC_CRL, StSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, StEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
	DECLARE_RPC_EX("ReadLogFile", RPC_READ_LOG_FILE, StReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
	DECLARE_RPC("AddLicenseKey", RPC_TEST, StAddLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC("DelLicenseKey", RPC_TEST, StDelLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, StEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
	DECLARE_RPC("GetLicenseStatus", RPC_LICENSE_STATUS, StGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
	DECLARE_RPC("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, StEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
	DECLARE_RPC("SetEnableEthVLan", RPC_TEST, StSetEnableEthVLan, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("SetHubMsg", RPC_MSG, StSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC_EX("GetHubMsg", RPC_MSG, StGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Crash", RPC_TEST, StCrash, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetAdminMsg", RPC_MSG, StGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Flush", RPC_TEST, StFlush, InRpcTest, OutRpcTest)
	DECLARE_RPC("Debug", RPC_TEST, StDebug, InRpcTest, OutRpcTest)
	DECLARE_RPC("SetIPsecServices", IPSEC_SERVICES, StSetIPsecServices, InIPsecServices, OutIPsecServices)
	DECLARE_RPC("GetIPsecServices", IPSEC_SERVICES, StGetIPsecServices, InIPsecServices, OutIPsecServices)
	DECLARE_RPC("AddEtherIpId", ETHERIP_ID, StAddEtherIpId, InEtherIpId, OutEtherIpId)
	DECLARE_RPC("GetEtherIpId", ETHERIP_ID, StGetEtherIpId, InEtherIpId, OutEtherIpId)
	DECLARE_RPC("DeleteEtherIpId", ETHERIP_ID, StDeleteEtherIpId, InEtherIpId, OutEtherIpId)
	DECLARE_RPC_EX("EnumEtherIpId", RPC_ENUM_ETHERIP_ID, StEnumEtherIpId, InRpcEnumEtherIpId, OutRpcEnumEtherIpId, FreeRpcEnumEtherIpId)
	DECLARE_RPC("SetOpenVpnSstpConfig", OPENVPN_SSTP_CONFIG, StSetOpenVpnSstpConfig, InOpenVpnSstpConfig, OutOpenVpnSstpConfig)
	DECLARE_RPC("GetOpenVpnSstpConfig", OPENVPN_SSTP_CONFIG, StGetOpenVpnSstpConfig, InOpenVpnSstpConfig, OutOpenVpnSstpConfig)
	DECLARE_RPC("GetDDnsClientStatus", DDNS_CLIENT_STATUS, StGetDDnsClientStatus, InDDnsClientStatus, OutDDnsClientStatus)
	DECLARE_RPC("ChangeDDnsClientHostname", RPC_TEST, StChangeDDnsClientHostname, InRpcTest, OutRpcTest)
	DECLARE_RPC("RegenerateServerCert", RPC_TEST, StRegenerateServerCert, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("MakeOpenVpnConfigFile", RPC_READ_LOG_FILE, StMakeOpenVpnConfigFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
	DECLARE_RPC("SetSpecialListener", RPC_SPECIAL_LISTENER, StSetSpecialListener, InRpcSpecialListener, OutRpcSpecialListener)
	DECLARE_RPC("GetSpecialListener", RPC_SPECIAL_LISTENER, StGetSpecialListener, InRpcSpecialListener, OutRpcSpecialListener)
	DECLARE_RPC("GetAzureStatus", RPC_AZURE_STATUS, StGetAzureStatus, InRpcAzureStatus, OutRpcAzureStatus)
	DECLARE_RPC("SetAzureStatus", RPC_AZURE_STATUS, StSetAzureStatus, InRpcAzureStatus, OutRpcAzureStatus)
	DECLARE_RPC("GetDDnsInternetSettng", INTERNET_SETTING, StGetDDnsInternetSetting, InRpcInternetSetting, OutRpcInternetSetting)
	DECLARE_RPC("SetDDnsInternetSettng", INTERNET_SETTING, StSetDDnsInternetSetting, InRpcInternetSetting, OutRpcInternetSetting)
	// RPC function declaration: till here


	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	if (err != ERR_NO_ERROR)
	{
		PackAddInt(ret, "error", err);
	}

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Leaving RPC [%s] (Error: %u).",
			rpc_id, ip, name, err);

		SiDebugLog(a->Server, tmp);
	}

	Unlock(cedar->CedarSuperLock);

	return ret;
}

// RPC call function declaration: from here
DECLARE_SC_EX("Test", RPC_TEST, ScTest, InRpcTest, OutRpcTest, FreeRpcTest)
DECLARE_SC_EX("GetServerInfo", RPC_SERVER_INFO, ScGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
DECLARE_SC("GetServerStatus", RPC_SERVER_STATUS, ScGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
DECLARE_SC("CreateListener", RPC_LISTENER, ScCreateListener, InRpcListener, OutRpcListener)
DECLARE_SC_EX("EnumListener", RPC_LISTENER_LIST, ScEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
DECLARE_SC("DeleteListener", RPC_LISTENER, ScDeleteListener, InRpcListener, OutRpcListener)
DECLARE_SC("EnableListener", RPC_LISTENER, ScEnableListener, InRpcListener, OutRpcListener)
DECLARE_SC_EX("SetPortsUDP", RPC_PORTS, ScSetPortsUDP, InRpcPorts, OutRpcPorts, FreeRpcPorts)
DECLARE_SC_EX("GetPortsUDP", RPC_PORTS, ScGetPortsUDP, InRpcPorts, OutRpcPorts, FreeRpcPorts)
DECLARE_SC_EX("SetProtoOptions", RPC_PROTO_OPTIONS, ScSetProtoOptions, InRpcProtoOptions, OutRpcProtoOptions, FreeRpcProtoOptions)
DECLARE_SC_EX("GetProtoOptions", RPC_PROTO_OPTIONS, ScGetProtoOptions, InRpcProtoOptions, OutRpcProtoOptions, FreeRpcProtoOptions)
DECLARE_SC("SetServerPassword", RPC_SET_PASSWORD, ScSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
DECLARE_SC_EX("SetFarmSetting", RPC_FARM, ScSetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
DECLARE_SC_EX("GetFarmSetting", RPC_FARM, ScGetFarmSetting, InRpcFarm, OutRpcFarm, FreeRpcFarm)
DECLARE_SC_EX("GetFarmInfo", RPC_FARM_INFO, ScGetFarmInfo, InRpcFarmInfo, OutRpcFarmInfo, FreeRpcFarmInfo)
DECLARE_SC_EX("EnumFarmMember", RPC_ENUM_FARM, ScEnumFarmMember, InRpcEnumFarm, OutRpcEnumFarm, FreeRpcEnumFarm)
DECLARE_SC("GetFarmConnectionStatus", RPC_FARM_CONNECTION_STATUS, ScGetFarmConnectionStatus, InRpcFarmConnectionStatus, OutRpcFarmConnectionStatus)
DECLARE_SC_EX("SetServerCert", RPC_KEY_PAIR, ScSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCert", RPC_KEY_PAIR, ScGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCipherList", RPC_STR, ScGetServerCipherList, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC_EX("GetServerCipher", RPC_STR, ScGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC_EX("SetServerCipher", RPC_STR, ScSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC("CreateHub", RPC_CREATE_HUB, ScCreateHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("SetHub", RPC_CREATE_HUB, ScSetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("GetHub", RPC_CREATE_HUB, ScGetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC_EX("EnumHub", RPC_ENUM_HUB, ScEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
DECLARE_SC("DeleteHub", RPC_DELETE_HUB, ScDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
DECLARE_SC("GetHubRadius", RPC_RADIUS, ScGetHubRadius, InRpcRadius, OutRpcRadius)
DECLARE_SC("SetHubRadius", RPC_RADIUS, ScSetHubRadius, InRpcRadius, OutRpcRadius)
DECLARE_SC_EX("EnumConnection", RPC_ENUM_CONNECTION, ScEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnection)
DECLARE_SC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, ScDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
DECLARE_SC("GetConnectionInfo", RPC_CONNECTION_INFO, ScGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
DECLARE_SC("SetHubOnline", RPC_SET_HUB_ONLINE, ScSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
DECLARE_SC("GetHubStatus", RPC_HUB_STATUS, ScGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
DECLARE_SC("SetHubLog", RPC_HUB_LOG, ScSetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC("GetHubLog", RPC_HUB_LOG, ScGetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC_EX("AddCa", RPC_HUB_ADD_CA, ScAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
DECLARE_SC_EX("EnumCa", RPC_HUB_ENUM_CA, ScEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
DECLARE_SC_EX("GetCa", RPC_HUB_GET_CA, ScGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
DECLARE_SC("DeleteCa", RPC_HUB_DELETE_CA, ScDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
DECLARE_SC_EX("CreateLink", RPC_CREATE_LINK, ScCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetLink", RPC_CREATE_LINK, ScGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("SetLink", RPC_CREATE_LINK, ScSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("EnumLink", RPC_ENUM_LINK, ScEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
DECLARE_SC_EX("GetLinkStatus", RPC_LINK_STATUS, ScGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
DECLARE_SC("SetLinkOnline", RPC_LINK, ScSetLinkOnline, InRpcLink, OutRpcLink)
DECLARE_SC("SetLinkOffline", RPC_LINK, ScSetLinkOffline, InRpcLink, OutRpcLink)
DECLARE_SC("DeleteLink", RPC_LINK, ScDeleteLink, InRpcLink, OutRpcLink)
DECLARE_SC("RenameLink", RPC_RENAME_LINK, ScRenameLink, InRpcRenameLink, OutRpcRenameLink)
DECLARE_SC("AddAccess", RPC_ADD_ACCESS, ScAddAccess, InRpcAddAccess, OutRpcAddAccess)
DECLARE_SC("DeleteAccess", RPC_DELETE_ACCESS, ScDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
DECLARE_SC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, ScEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, ScSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("CreateUser", RPC_SET_USER, ScCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("SetUser", RPC_SET_USER, ScSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("GetUser", RPC_SET_USER, ScGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC("DeleteUser", RPC_DELETE_USER, ScDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumUser", RPC_ENUM_USER, ScEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
DECLARE_SC_EX("CreateGroup", RPC_SET_GROUP, ScCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("SetGroup", RPC_SET_GROUP, ScSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("GetGroup", RPC_SET_GROUP, ScGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC("DeleteGroup", RPC_DELETE_USER, ScDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumGroup", RPC_ENUM_GROUP, ScEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
DECLARE_SC_EX("EnumSession", RPC_ENUM_SESSION, ScEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
DECLARE_SC_EX("GetSessionStatus", RPC_SESSION_STATUS, ScGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
DECLARE_SC("DeleteSession", RPC_DELETE_SESSION, ScDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
DECLARE_SC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, ScEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
DECLARE_SC("DeleteMacTable", RPC_DELETE_TABLE, ScDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, ScEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
DECLARE_SC("DeleteIpTable", RPC_DELETE_TABLE, ScDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC("SetKeep", RPC_KEEP, ScSetKeep, InRpcKeep, OutRpcKeep)
DECLARE_SC("GetKeep", RPC_KEEP, ScGetKeep, InRpcKeep, OutRpcKeep)
DECLARE_SC("EnableSecureNAT", RPC_HUB, ScEnableSecureNAT, InRpcHub, OutRpcHub)
DECLARE_SC("DisableSecureNAT", RPC_HUB, ScDisableSecureNAT, InRpcHub, OutRpcHub)
DECLARE_SC("SetSecureNATOption", VH_OPTION, ScSetSecureNATOption, InVhOption, OutVhOption)
DECLARE_SC("GetSecureNATOption", VH_OPTION, ScGetSecureNATOption, InVhOption, OutVhOption)
DECLARE_SC_EX("EnumNAT", RPC_ENUM_NAT, ScEnumNAT, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
DECLARE_SC_EX("EnumDHCP", RPC_ENUM_DHCP, ScEnumDHCP, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
DECLARE_SC("GetSecureNATStatus", RPC_NAT_STATUS, ScGetSecureNATStatus, InRpcNatStatus, OutRpcNatStatus)
DECLARE_SC_EX("EnumEthernet", RPC_ENUM_ETH, ScEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
DECLARE_SC("AddLocalBridge", RPC_LOCALBRIDGE, ScAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC("DeleteLocalBridge", RPC_LOCALBRIDGE, ScDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, ScEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
DECLARE_SC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, ScGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
DECLARE_SC("RebootServer", RPC_TEST, ScRebootServer, InRpcTest, OutRpcTest)
DECLARE_SC_EX("GetCaps", CAPSLIST, ScGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
DECLARE_SC_EX("GetConfig", RPC_CONFIG, ScGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("SetConfig", RPC_CONFIG, ScSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, ScGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, ScSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, ScGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, ScSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("GetDefaultHubAdminOptions", RPC_ADMIN_OPTION, ScGetDefaultHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC("AddL3Switch", RPC_L3SW, ScAddL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("DelL3Switch", RPC_L3SW, ScDelL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC_EX("EnumL3Switch", RPC_ENUM_L3SW, ScEnumL3Switch, InRpcEnumL3Sw, OutRpcEnumL3Sw, FreeRpcEnumL3Sw)
DECLARE_SC("StartL3Switch", RPC_L3SW, ScStartL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("StopL3Switch", RPC_L3SW, ScStopL3Switch, InRpcL3Sw, OutRpcL3Sw)
DECLARE_SC("AddL3If", RPC_L3IF, ScAddL3If, InRpcL3If, OutRpcL3If)
DECLARE_SC("DelL3If", RPC_L3IF, ScDelL3If, InRpcL3If, OutRpcL3If)
DECLARE_SC_EX("EnumL3If", RPC_ENUM_L3IF, ScEnumL3If, InRpcEnumL3If, OutRpcEnumL3If, FreeRpcEnumL3If)
DECLARE_SC("AddL3Table", RPC_L3TABLE, ScAddL3Table, InRpcL3Table, OutRpcL3Table)
DECLARE_SC("DelL3Table", RPC_L3TABLE, ScDelL3Table, InRpcL3Table, OutRpcL3Table)
DECLARE_SC_EX("EnumL3Table", RPC_ENUM_L3TABLE, ScEnumL3Table, InRpcEnumL3Table, OutRpcEnumL3Table, FreeRpcEnumL3Table)
DECLARE_SC_EX("EnumCrl", RPC_ENUM_CRL, ScEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
DECLARE_SC_EX("AddCrl", RPC_CRL, ScAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("DelCrl", RPC_CRL, ScDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("GetCrl", RPC_CRL, ScGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("SetCrl", RPC_CRL, ScSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("SetAcList", RPC_AC_LIST, ScSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("GetAcList", RPC_AC_LIST, ScGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, ScEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
DECLARE_SC_EX("ReadLogFile", RPC_READ_LOG_FILE, ScReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
DECLARE_SC("AddLicenseKey", RPC_TEST, ScAddLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC("DelLicenseKey", RPC_TEST, ScDelLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, ScEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
DECLARE_SC("GetLicenseStatus", RPC_LICENSE_STATUS, ScGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
DECLARE_SC("SetSysLog", SYSLOG_SETTING, ScSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("GetSysLog", SYSLOG_SETTING, ScGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, ScEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
DECLARE_SC("SetEnableEthVLan", RPC_TEST, ScSetEnableEthVLan, InRpcTest, OutRpcTest)
DECLARE_SC_EX("SetHubMsg", RPC_MSG, ScSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC_EX("GetHubMsg", RPC_MSG, ScGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC("Crash", RPC_TEST, ScCrash, InRpcTest, OutRpcTest)
DECLARE_SC_EX("GetAdminMsg", RPC_MSG, ScGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
DECLARE_SC("Flush", RPC_TEST, ScFlush, InRpcTest, OutRpcTest)
DECLARE_SC("Debug", RPC_TEST, ScDebug, InRpcTest, OutRpcTest)
DECLARE_SC("SetIPsecServices", IPSEC_SERVICES, ScSetIPsecServices, InIPsecServices, OutIPsecServices)
DECLARE_SC("GetIPsecServices", IPSEC_SERVICES, ScGetIPsecServices, InIPsecServices, OutIPsecServices)
DECLARE_SC("AddEtherIpId", ETHERIP_ID, ScAddEtherIpId, InEtherIpId, OutEtherIpId)
DECLARE_SC("GetEtherIpId", ETHERIP_ID, ScGetEtherIpId, InEtherIpId, OutEtherIpId)
DECLARE_SC("DeleteEtherIpId", ETHERIP_ID, ScDeleteEtherIpId, InEtherIpId, OutEtherIpId)
DECLARE_SC_EX("EnumEtherIpId", RPC_ENUM_ETHERIP_ID, ScEnumEtherIpId, InRpcEnumEtherIpId, OutRpcEnumEtherIpId, FreeRpcEnumEtherIpId)
DECLARE_SC("SetOpenVpnSstpConfig", OPENVPN_SSTP_CONFIG, ScSetOpenVpnSstpConfig, InOpenVpnSstpConfig, OutOpenVpnSstpConfig)
DECLARE_SC("GetOpenVpnSstpConfig", OPENVPN_SSTP_CONFIG, ScGetOpenVpnSstpConfig, InOpenVpnSstpConfig, OutOpenVpnSstpConfig)
DECLARE_SC("GetDDnsClientStatus", DDNS_CLIENT_STATUS, ScGetDDnsClientStatus, InDDnsClientStatus, OutDDnsClientStatus)
DECLARE_SC("ChangeDDnsClientHostname", RPC_TEST, ScChangeDDnsClientHostname, InRpcTest, OutRpcTest)
DECLARE_SC("RegenerateServerCert", RPC_TEST, ScRegenerateServerCert, InRpcTest, OutRpcTest)
DECLARE_SC_EX("MakeOpenVpnConfigFile", RPC_READ_LOG_FILE, ScMakeOpenVpnConfigFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
DECLARE_SC("SetSpecialListener", RPC_SPECIAL_LISTENER, ScSetSpecialListener, InRpcSpecialListener, OutRpcSpecialListener)
DECLARE_SC("GetSpecialListener", RPC_SPECIAL_LISTENER, ScGetSpecialListener, InRpcSpecialListener, OutRpcSpecialListener)
DECLARE_SC("GetAzureStatus", RPC_AZURE_STATUS, ScGetAzureStatus, InRpcAzureStatus, OutRpcAzureStatus)
DECLARE_SC("SetAzureStatus", RPC_AZURE_STATUS, ScSetAzureStatus, InRpcAzureStatus, OutRpcAzureStatus)
DECLARE_SC("GetDDnsInternetSettng", INTERNET_SETTING, ScGetDDnsInternetSetting, InRpcInternetSetting, OutRpcInternetSetting)
DECLARE_SC("SetDDnsInternetSettng", INTERNET_SETTING, ScSetDDnsInternetSetting, InRpcInternetSetting, OutRpcInternetSetting)
// RPC call function declaration: till here

// Setting VPN Gate Server Configuration
UINT StSetVgsConfig(ADMIN *a, VGS_CONFIG *t)
{
	return ERR_NOT_SUPPORTED;
}

// Get VPN Gate configuration
UINT StGetVgsConfig(ADMIN *a, VGS_CONFIG *t)
{
	return ERR_NOT_SUPPORTED;
}

// Get DDNS proxy configuration
UINT StGetDDnsInternetSetting(ADMIN *a, INTERNET_SETTING *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->DDnsClient == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	Zero(t, sizeof(INTERNET_SETTING));

	DCGetInternetSetting(s->DDnsClient, t);

	return ret;
}

// Set DDNS proxy configuration
UINT StSetDDnsInternetSetting(ADMIN *a, INTERNET_SETTING *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->DDnsClient == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	DCSetInternetSetting(s->DDnsClient, t);

	IncrementServerConfigRevision(s);

	return ret;
}

// Get Azure status
UINT StGetAzureStatus(ADMIN *a, RPC_AZURE_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	AZURE_CLIENT *ac;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (SiIsAzureSupported(s) == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	ac = s->AzureClient;
	if (ac == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	Zero(t, sizeof(RPC_AZURE_STATUS));

	Lock(ac->Lock);
	{
		t->IsConnected = ac->IsConnected;
		t->IsEnabled = ac->IsEnabled;
	}
	Unlock(ac->Lock);

	return ERR_NO_ERROR;
}

// Set Azure status
UINT StSetAzureStatus(ADMIN *a, RPC_AZURE_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (SiIsAzureSupported(s) == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	SiSetAzureEnable(s, t->IsEnabled);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get special listener status
UINT StGetSpecialListener(ADMIN *a, RPC_SPECIAL_LISTENER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	Zero(t, sizeof(RPC_SPECIAL_LISTENER));
	t->VpnOverDnsListener = s->EnableVpnOverDns;
	t->VpnOverIcmpListener = s->EnableVpnOverIcmp;

	return ERR_NO_ERROR;
}

// Set special listener status
UINT StSetSpecialListener(ADMIN *a, RPC_SPECIAL_LISTENER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	// Check ports
	if (t->VpnOverDnsListener && (MAKEBOOL(s->EnableVpnOverDns) != MAKEBOOL(t->VpnOverDnsListener)))
	{
		if (SiCanOpenVpnOverDnsPort() == false)
		{
			return ERR_SPECIAL_LISTENER_DNS_ERROR;
		}
	}

	if (t->VpnOverIcmpListener && (MAKEBOOL(s->EnableVpnOverIcmp) != MAKEBOOL(t->VpnOverIcmpListener)))
	{
		if (SiCanOpenVpnOverIcmpPort() == false)
		{
			return ERR_SPECIAL_LISTENER_ICMP_ERROR;
		}
	}

	s->EnableVpnOverDns = t->VpnOverDnsListener;
	s->EnableVpnOverIcmp = t->VpnOverIcmpListener;

	SiApplySpecialListenerStatus(s);

	ALog(a, NULL, "LA_SET_SPECIAL_LISTENER");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Set configurations for OpenVPN and SSTP
UINT StSetOpenVpnSstpConfig(ADMIN *a, OPENVPN_SSTP_CONFIG *t)
{
	PROTO *proto = a->Server->Proto;
	PROTO_CONTAINER *container, tmp_c;
	PROTO_OPTION *option, tmp_o;
	UINT ret = ERR_NO_ERROR;
	bool changed = false;

	SERVER_ADMIN_ONLY;

	if (proto == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	tmp_o.Name = PROTO_OPTION_TOGGLE_NAME;
	tmp_c.Name = "OpenVPN";

	container = Search(proto->Containers, &tmp_c);
	if (container != NULL)
	{
		option = Search(container->Options, &tmp_o);
		if (option != NULL)
		{
			if (option->Type == PROTO_OPTION_BOOL)
			{
				option->Bool = t->EnableOpenVPN;
				changed = true;
			}
			else
			{
				ret = ERR_INVALID_PARAMETER;
			}
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	else
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}

	tmp_c.Name = "SSTP";

	container = Search(proto->Containers, &tmp_c);
	if (container != NULL)
	{
		option = Search(container->Options, &tmp_o);
		if (option != NULL)
		{
			if (option->Type == PROTO_OPTION_BOOL)
			{
				option->Bool = t->EnableSSTP;
				changed = true;
			}
			else
			{
				ret = ERR_INVALID_PARAMETER;
			}
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	else
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}

	if (changed)
	{
		ALog(a, NULL, "LA_SET_OVPN_SSTP_CONFIG");
		IncrementServerConfigRevision(a->Server);
	}

	return ret;
}

// Get configurations for OpenVPN and SSTP
UINT StGetOpenVpnSstpConfig(ADMIN *a, OPENVPN_SSTP_CONFIG *t)
{
	PROTO *proto = a->Server->Proto;
	if (proto == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	t->EnableOpenVPN = ProtoEnabled(proto, "OpenVPN");
	t->EnableSSTP = ProtoEnabled(proto, "SSTP");

	return ERR_NO_ERROR;
}

// Get status of DDNS client
UINT StGetDDnsClientStatus(ADMIN *a, DDNS_CLIENT_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->DDnsClient == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	Zero(t, sizeof(DDNS_CLIENT_STATUS));
	DCGetStatus(s->DDnsClient, t);

	return ERR_NO_ERROR;
}

// Change host-name for DDNS client
UINT StChangeDDnsClientHostname(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->DDnsClient == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	ret = DCChangeHostName(s->DDnsClient, t->StrValue);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, NULL, "LA_DDNS_HOSTNAME_CHANGED", t->StrValue);
	}

	IncrementServerConfigRevision(s);

	return ret;
}

// Regenerate server certification
UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	X *x;
	K *k;

	SERVER_ADMIN_ONLY;

	SiGenerateDefaultCertEx(&x, &k, t->StrValue);

	SetCedarCert(c, x, k);

	ALog(a, NULL, "LA_REGENERATE_SERVER_CERT", t->StrValue);

	IncrementServerConfigRevision(s);

	FreeX(x);
	FreeK(k);

	return ERR_NO_ERROR;
}

// Generate OpenVPN configuration files
UINT StMakeOpenVpnConfigFile(ADMIN *a, RPC_READ_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	ZIP_PACKER *p;
	FIFO *f;
	BUF *readme_buf;
	BUF *readme_pdf_buf;
	BUF *sample_buf;
	LIST *port_list;
	char my_hostname[MAX_SIZE];

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (ProtoEnabled(s->Proto, "OpenVPN") == false)
	{
		return ERR_OPENVPN_IS_NOT_ENABLED;
	}

	port_list = s->PortsUDP;

	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	p = NewZipPacker();

	// readme.txt
	readme_buf = ReadDump("|openvpn_readme.txt");

	// readme.pdf
	readme_pdf_buf = ReadDump("|openvpn_readme.pdf");

	// sample.ovpn
	sample_buf = ReadDump("|openvpn_sample.ovpn");

	// host name
	GetMachineHostName(my_hostname, sizeof(my_hostname));
	my_hostname[16] = 0;

	if (readme_buf == NULL || sample_buf == NULL || readme_pdf_buf == NULL)
	{
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		BUF *config_l3_buf, *config_l2_buf;
		X *x = NULL;
		BUF *x_buf;
		char protocol[MAX_SIZE];
		UINT port = OPENVPN_UDP_PORT;
		char port_str[MAX_SIZE];
		char hostname[MAX_SIZE];
		char tag_before_hostname[MAX_SIZE];
		DDNS_CLIENT_STATUS ddns;
		UCHAR *zero_buffer;
		UINT zero_buffer_size = 128 * 1024;
		char name_tmp[MAX_SIZE];

		zero_buffer = ZeroMalloc(zero_buffer_size);


		if (x == NULL)
		{
			Lock(c->lock);
			{
				x = CloneX(c->ServerX);
			}
			Unlock(c->lock);

			if (x != NULL)
			{
				// Get the root certificate
				if (x->root_cert == false)
				{
					X *root_x = NULL;
					LIST *cert_list = NewCertList(true);

					if (TryGetRootCertChain(cert_list, x, true, &root_x))
					{
						FreeX(x);
						x = root_x;
					}

					FreeCertList(cert_list);
				}
			}
		}

		x_buf = XToBuf(x, true);

		SeekBufToEnd(x_buf);
		WriteBufChar(x_buf, 0);
		SeekBufToBegin(x_buf);

		FreeX(x);
		Zero(hostname, sizeof(hostname));
		Zero(tag_before_hostname, sizeof(tag_before_hostname));

		Zero(&ddns, sizeof(ddns));
		if (s->DDnsClient != NULL)
		{
			DCGetStatus(s->DDnsClient, &ddns);

			if (IsEmptyStr(ddns.CurrentHostName) == false && IsEmptyStr(ddns.DnsSuffix) == false &&
				ddns.Err_IPv4 == ERR_NO_ERROR)
			{
				StrCpy(tag_before_hostname, sizeof(tag_before_hostname),
					"# Note: The below hostname is came from the Dynamic DNS Client function\r\n"
					"#       which is running on the VPN Server. If you don't want to use\r\n"
					"#       the Dynamic DNS hostname, replace it to either IP address or\r\n"
					"#       other domain's hostname.\r\n\r\n");

				Format(hostname, sizeof(hostname), "%s.v4%s", ddns.CurrentHostName, ddns.DnsSuffix);
			}
		}

		if (IsEmptyStr(hostname))
		{
			IP myip;

			Zero(&myip, sizeof(myip));
			GetCurrentGlobalIP(&myip, false);

			if (IsZeroIP(&myip))
			{
				GetCurrentGlobalIPGuess(&myip, false);
			}

			IPToStr(hostname, sizeof(hostname), &myip);
		}

		SeekBuf(sample_buf, sample_buf->Size, 0);
		WriteBuf(sample_buf, zero_buffer, zero_buffer_size);

		config_l3_buf = CloneBuf(sample_buf);
		config_l2_buf = CloneBuf(sample_buf);

		// Generate contents of configuration
		if (LIST_NUM(port_list) >= 1)
		{
			StrCpy(protocol, sizeof(protocol), "udp");

			if (IsIntInList(port_list, OPENVPN_UDP_PORT))
			{
				port = OPENVPN_UDP_PORT;
			}
			else
			{
				port = *((UINT *)(LIST_DATA(port_list, 0)));
			}
		}
		else
		{
			RPC_LISTENER_LIST tt;
			UINT i;

			port = 0;

			StrCpy(protocol, sizeof(protocol), "tcp");

			Zero(&tt, sizeof(tt));

			StEnumListener(a, &tt);

			for (i = 0;i < tt.NumPort;i++)
			{
				if (tt.Enables[i] && tt.Errors[i] == false)
				{
					port = tt.Ports[i];
					break;
				}
			}

			FreeRpcListenerList(&tt);

			if (port == 0)
			{
				StrCpy(protocol, sizeof(protocol), "udp");
				port = OPENVPN_UDP_PORT;
			}
		}

		ToStr(port_str, port);

		if (IsEmptyStr(my_hostname) == false)
		{
			StrCat(my_hostname, sizeof(my_hostname), "_");

			StrLower(my_hostname);
		}

		ZipAddFileSimple(p, "readme.txt", LocalTime64(), 0, readme_buf->Buf, readme_buf->Size);
		ZipAddFileSimple(p, "readme.pdf", LocalTime64(), 0, readme_pdf_buf->Buf, readme_pdf_buf->Size);

		ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
			"$TAG_TUN_TAP$", "tun", false);
		ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
			"$TAG_PROTO$", protocol, false);
		ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
			"$TAG_HOSTNAME$", hostname, false);
		ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
			"$TAG_BEFORE_REMOTE$", tag_before_hostname, false);
		ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
			"$TAG_PORT$", port_str, false);

		if (x_buf != NULL)
		{
			ReplaceStrEx((char *)config_l3_buf->Buf, config_l3_buf->Size, (char *)config_l3_buf->Buf,
				"$CA$", x_buf->Buf, false);
		}

		Format(name_tmp, sizeof(name_tmp), "%sopenvpn_remote_access_l3.ovpn", my_hostname);
		ZipAddFileSimple(p, name_tmp, LocalTime64(), 0, config_l3_buf->Buf, StrLen(config_l3_buf->Buf));

		ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
			"$TAG_TUN_TAP$", "tap", false);
		ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
			"$TAG_PROTO$", protocol, false);
		ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
			"$TAG_HOSTNAME$", hostname, false);
		ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
			"$TAG_BEFORE_REMOTE$", tag_before_hostname, false);
		ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
			"$TAG_PORT$", port_str, false);

		if (x_buf != NULL)
		{
			ReplaceStrEx((char *)config_l2_buf->Buf, config_l2_buf->Size, (char *)config_l2_buf->Buf,
				"$CA$", x_buf->Buf, false);
		}

		Format(name_tmp, sizeof(name_tmp), "%sopenvpn_site_to_site_bridge_l2.ovpn", my_hostname);
		ZipAddFileSimple(p, name_tmp, LocalTime64(), 0, config_l2_buf->Buf, StrLen(config_l2_buf->Buf));

		FreeBuf(config_l3_buf);
		FreeBuf(config_l2_buf);

		f = ZipFinish(p);

		if (f != NULL)
		{
			t->Buffer = NewBuf();
			WriteBuf(t->Buffer, FifoPtr(f), FifoSize(f));
			SeekBuf(t->Buffer, 0, 0);
		}

		FreeBuf(readme_buf);
		FreeBuf(sample_buf);
		FreeBuf(readme_pdf_buf);
		FreeBuf(x_buf);

		Free(zero_buffer);
	}

	FreeZipPacker(p);

	return ERR_NO_ERROR;
}

// Set IPsec service configuration
UINT StSetIPsecServices(ADMIN *a, IPSEC_SERVICES *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	IPsecServerSetServices(s->IPsecServer, t);

	ALog(a, NULL, "LA_SET_IPSEC_CONFIG");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get IPsec service configuration
UINT StGetIPsecServices(ADMIN *a, IPSEC_SERVICES *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	Zero(t, sizeof(IPSEC_SERVICES));
	IPsecServerGetServices(s->IPsecServer, t);

	return ERR_NO_ERROR;
}

// Add EtherIP ID setting
UINT StAddEtherIpId(ADMIN *a, ETHERIP_ID *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	AddEtherIPId(s->IPsecServer, t);

	ALog(a, NULL, "LA_ADD_ETHERIP_ID", t->Id);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get EtherIP ID setting
UINT StGetEtherIpId(ADMIN *a, ETHERIP_ID *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char id[MAX_SIZE];

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(id, sizeof(id), t->Id);

	Zero(t, sizeof(ETHERIP_ID));
	if (SearchEtherIPId(s->IPsecServer, t, id) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	return ERR_NO_ERROR;
}

// Delete EtherIP ID setting
UINT StDeleteEtherIpId(ADMIN *a, ETHERIP_ID *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char id[MAX_SIZE];

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(id, sizeof(id), t->Id);

	if (DeleteEtherIPId(s->IPsecServer, id) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, NULL, "LA_DEL_ETHERIP_ID", id);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Enumerate EtherIP ID settings
UINT StEnumEtherIpId(ADMIN *a, RPC_ENUM_ETHERIP_ID *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;
	if (GetServerCapsBool(s, "b_support_ipsec") == false || s->IPsecServer == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcEnumEtherIpId(t);
	Zero(t, sizeof(RPC_ENUM_ETHERIP_ID));

	Lock(s->IPsecServer->LockSettings);
	{
		UINT i;
		UINT num;

		num = LIST_NUM(s->IPsecServer->EtherIPIdList);

		t->NumItem = num;
		t->IdList = ZeroMalloc(sizeof(ETHERIP_ID) * num);

		for (i = 0;i < num;i++)
		{
			ETHERIP_ID *d = &t->IdList[i];
			ETHERIP_ID *src = LIST_DATA(s->IPsecServer->EtherIPIdList, i);

			Copy(d, src, sizeof(ETHERIP_ID));
		}
	}
	Unlock(s->IPsecServer->LockSettings);

	return ERR_NO_ERROR;
}

// Set message of today on hub
UINT StSetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_msg") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			SetHubMsg(h, t->Msg);
		}

		ReleaseHub(h);
	}

	IncrementServerConfigRevision(s);

	return ret;
}

// Get message of today on hub
UINT StGetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		FreeRpcMsg(t);
		Zero(t, sizeof(RPC_MSG));

		t->Msg = GetHubMsg(h);

		ReleaseHub(h);
	}

	return ret;
}

// Do debug function
UINT StDebug(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_TEST t2;

	SERVER_ADMIN_ONLY;

	Zero(&t2, sizeof(t2));

	ret = SiDebug(s, &t2, t->IntValue, t->StrValue);

	if (ret == ERR_NO_ERROR)
	{
		Copy(t, &t2, sizeof(RPC_TEST));
	}
	else
	{
		Zero(t, sizeof(RPC_TEST));
	}

	return ret;
}

// Flush configuration file
UINT StFlush(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	UINT size;

	SERVER_ADMIN_ONLY;

	size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

// Do Crash
UINT StCrash(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	MsSetEnableMinidump(false);
#endif	// OS_WIN32

	CrashNow();

	return ERR_NO_ERROR;
}

// Get message for administrators
UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_WINVER server_ver;
	RPC_WINVER client_ver;
	wchar_t winver_msg_client[3800];
	wchar_t winver_msg_server[3800];
	UINT tmpsize;
	wchar_t *tmp;

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	// Check for Windows version
	GetWinVer(&server_ver);
	Copy(&client_ver, &a->ClientWinVer, sizeof(RPC_WINVER));

	Zero(winver_msg_client, sizeof(winver_msg_client));
	Zero(winver_msg_server, sizeof(winver_msg_server));

	if (IsSupportedWinVer(&client_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_LOCAL"),
			client_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_LOCAL"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	if (IsSupportedWinVer(&server_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_REMOTE"),
			server_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_REMOTE"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + 10000;

	tmp = ZeroMalloc(tmpsize);

	if (
		c->Bridge == false)
	{
		if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
		{
			UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
		}
	}

	UniStrCat(tmp, tmpsize, winver_msg_client);
	UniStrCat(tmp, tmpsize, winver_msg_server);

	t->Msg = tmp;

	return ERR_NO_ERROR;
}

// Enumerate VLAN tag transparent setting
UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else
	{
		FreeRpcEnumEthVLan(t);
		Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

		if (EnumEthVLanWin32(t) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}
#else	// OS_WIN32
	ret = ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ret;
}

// Set VLAN tag transparent setting
UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

#ifdef	OS_WIN32
	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else if (MsIsAdmin() == false)
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
	}
	else
	{
		if (SetVLanEnableStatus(t->StrValue, MAKEBOOL(t->IntValue)) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}
#else	// OS_WIN32
	ret = ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ret;
}

// Get license status
UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t)
{
	return ERR_NOT_SUPPORTED;
}

// Enumerate license key
UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t)
{
	return ERR_NOT_SUPPORTED;
}

// Add new license key
UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// Delete a license key
UINT StDelLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

// Download a log file
BUF *DownloadFileFromServer(RPC *r, char *server_name, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param)
{
	UINT offset;
	BUF *buf;
	// Validate arguments
	if (r == NULL || filepath == NULL)
	{
		return NULL;
	}

	if (server_name == NULL)
	{
		server_name = "";
	}

	offset = 0;

	buf = NewBuf();

	while (true)
	{
		DOWNLOAD_PROGRESS g;
		RPC_READ_LOG_FILE t;
		UINT ret;

		Zero(&t, sizeof(t));
		StrCpy(t.FilePath, sizeof(t.FilePath), filepath);
		t.Offset = offset;
		StrCpy(t.ServerName, sizeof(t.ServerName), server_name);

		ret = ScReadLogFile(r, &t);

		if (ret != ERR_NO_ERROR)
		{
			// Failed
			FreeRpcReadLogFile(&t);
			FreeBuf(buf);
			return NULL;
		}

		if (t.Buffer == NULL)
		{
			// read to the end
			break;
		}

		// Update current progress
		offset += t.Buffer->Size;
		Zero(&g, sizeof(g));
		g.Param = param;
		g.CurrentSize = offset;
		g.TotalSize = MAX(total_size, offset);
		g.ProgressPercent = (UINT)(MAKESURE((UINT64)g.CurrentSize * 100ULL / (UINT64)(MAX(g.TotalSize, 1)), 0, 100ULL));

		WriteBuf(buf, t.Buffer->Buf, t.Buffer->Size);

		FreeRpcReadLogFile(&t);

		if (proc != NULL)
		{
			if (proc(&g) == false)
			{
				// Canceled by user
				FreeBuf(buf);
				return NULL;
			}
		}
	}

	if (buf->Size == 0)
	{
		// Downloading failed
		FreeBuf(buf);
		return NULL;
	}

	return buf;
}

// Read a log file
UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	char logfilename[MAX_PATH];
	char servername[MAX_HOST_NAME_LEN + 1];
	UINT offset;
	bool local = true;

	if (IsEmptyStr(t->FilePath))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(logfilename, sizeof(logfilename), t->FilePath);
	StrCpy(servername, sizeof(servername), t->ServerName);
	offset = t->Offset;

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		GetMachineName(servername, sizeof(servername));
	}

	// Check the permission to read the log file
	if (a->LogFileList == NULL)
	{
		// Enum the log files first
		RPC_ENUM_LOG_FILE elf;
		UINT elf_ret;

		Zero(&elf, sizeof(elf));

		elf_ret = StEnumLogFile(a, &elf);

		FreeRpcEnumLogFile(&elf);

		if (elf_ret != ERR_NO_ERROR)
		{
			return elf_ret;
		}
	}
	if (CheckLogFileNameFromEnumList(a->LogFileList, logfilename, servername) == false)
	{
		// There is no such file in the log file list
		return ERR_OBJECT_NOT_FOUND;
	}

	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;

		// When the host name in request is a cluster member, redirect the request
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					if (StrCmpi(f->hostname, servername) == 0)
					{
						RPC_READ_LOG_FILE tt;

						Zero(&tt, sizeof(tt));
						local = false;

						StrCpy(tt.ServerName, sizeof(tt.ServerName), servername);
						StrCpy(tt.FilePath, sizeof(tt.FilePath), logfilename);
						tt.Offset = offset;

						if (SiCallReadLogFile(s, f, &tt))
						{
							if (tt.Buffer != NULL && tt.Buffer->Size > 0)
							{
								t->Buffer = NewBuf();
								WriteBuf(t->Buffer, tt.Buffer->Buf, tt.Buffer->Size);
							}
						}

						FreeRpcReadLogFile(&tt);

						break;
					}
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	// Read a local file
	if (local)
	{
		SiReadLocalLogFile(s, logfilename, offset, t);
	}

	if (offset == 0)
	{
		ALog(a, NULL, "LA_READ_LOG_FILE", servername, logfilename);
	}

	StrCpy(t->FilePath, sizeof(t->FilePath), logfilename);
	StrCpy(t->ServerName, sizeof(t->ServerName), servername);
	t->Offset = offset;

	return ERR_NO_ERROR;
}

// Enumerate log files
UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;
	bool no_access = false;

	HUB *h;

	if (a->ServerAdmin == false)
	{
		h = GetHub(c, a->HubName);

		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_read_log_file") != 0)
		{
			no_access = true;
		}

		ReleaseHub(h);
	}
	else
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// Since Management session will become unstable if log files are
			// enumerated on a cluster controller, it forbids. 
			return ERR_NOT_SUPPORTED;
		}
	}

	if (no_access)
	{
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	// Enumerate local log files
	SiEnumLocalLogFileList(s, a->ServerAdmin ? NULL : a->HubName, t);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;
		LIST *tt_list = NewListFast(NULL);

		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					// Enumerate log files on other cluster members.
					RPC_ENUM_LOG_FILE *tt;
					tt = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE));

					if (SiCallEnumLogFileList(s, f, tt, a->ServerAdmin ? "" : a->HubName))
					{
						UINT i;
						for (i = 0;i < tt->NumItem;i++)
						{
							RPC_ENUM_LOG_FILE_ITEM *e = &tt->Items[i];

							StrCpy(e->ServerName, sizeof(e->ServerName), f->hostname);
						}

						Add(tt_list, tt);
					}
					else
					{
						Free(tt);
					}
				}
			}
		}
		UnlockList(s->FarmMemberList);

		for (i = 0;i < LIST_NUM(tt_list);i++)
		{
			RPC_ENUM_LOG_FILE *tt = LIST_DATA(tt_list, i);

			AdjoinRpcEnumLogFile(t, tt);
			FreeRpcEnumLogFile(tt);

			Free(tt);
		}

		ReleaseList(tt_list);
	}

	// Cache the last list of log files on RPC session
	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	a->LogFileList = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		f->UpdatedTime = e->UpdatedTime;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);

		Insert(a->LogFileList, f);
	}

	return ERR_NO_ERROR;
}


// Get access control list
UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}


	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcAcList(t);
	Zero(t, sizeof(RPC_AC_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			HUBDB *db = h->HubDb;

			LockList(db->AcList);
			{
				t->o = NewAcList();

				SetAcList(t->o, db->AcList);
			}
			UnlockList(db->AcList);
		}
		ReleaseHub(h);
	}

	return ret;
}

// Set access control list
UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];


	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0 && LIST_NUM(t->o) >= 1)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_control_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				HUBDB *db = h->HubDb;

				LockList(db->AcList);
				{
					SetAcList(db->AcList, t->o);

					{
						ALog(a, h, "LA_SET_AC_LIST", LIST_NUM(t->o));

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(db->AcList);
			}
		}
		ReleaseHub(h);
	}

	return ret;
}

// Set CRL (Certificate Revocation List) entry
UINT StSetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						CRL *new_crl = CopyCrl(t->Crl);
						if (ReplaceListPointer(h->HubDb->CrlList, crl, new_crl))
						{
							ALog(a, h, "LA_ADD_CRL");
							FreeCrl(crl);

							IncrementServerConfigRevision(s);
						}
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Get CRL (Certificate Revocation List) entry
UINT StGetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcCrl(t);
	Zero(t, sizeof(RPC_CRL));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	t->Key = key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

				if (crl == NULL)
				{
					ret = ERR_OBJECT_NOT_FOUND;
				}
				else
				{
					t->Crl = CopyCrl(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

// Delete CRL (Certificate Revocation List) entry
UINT StDelCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						ALog(a, h, "LA_DEL_CRL");
						FreeCrl(crl);
						Delete(h->HubDb->CrlList, crl);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Add new CRL (Certificate Revocation List) entry
UINT StAddCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					if (LIST_NUM(h->HubDb->CrlList) < MAX_HUB_CRLS)
					{
						CRL *crl = CopyCrl(t->Crl);

						Insert(h->HubDb->CrlList, crl);

						ALog(a, h, "LA_SET_CRL");

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Get CRL (Certificate Revocation List) index
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumCrl(t);
	Zero(t, sizeof(RPC_ENUM_CRL));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				UINT i;

				t->NumItem = LIST_NUM(h->HubDb->CrlList);
				t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);

				for (i = 0;i < LIST_NUM(h->HubDb->CrlList);i++)
				{
					CRL *crl = LIST_DATA(h->HubDb->CrlList, i);
					wchar_t *info = GenerateCrlStr(crl);

					UniStrCpy(t->Items[i].CrlInfo, sizeof(t->Items[i].CrlInfo), info);
					Free(info);

					t->Items[i].Key = POINTER_TO_KEY(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

// Get routing table on virtual L3 switch
UINT StEnumL3Table(ADMIN *a, RPC_ENUM_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;
	char name[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(name, sizeof(name), t->Name);
	FreeRpcEnumL3Table(t);
	Zero(t, sizeof(RPC_ENUM_L3TABLE));
	StrCpy(t->Name, sizeof(t->Name), name);

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		UINT i;

		Lock(sw->lock);
		{
			t->NumItem = LIST_NUM(sw->TableList);
			t->Items = ZeroMalloc(sizeof(RPC_L3TABLE) * t->NumItem);

			for (i = 0;i < t->NumItem;i++)
			{
				L3TABLE *tbl = LIST_DATA(sw->TableList, i);
				RPC_L3TABLE *e = &t->Items[i];

				StrCpy(e->Name, sizeof(e->Name), name);
				e->NetworkAddress = tbl->NetworkAddress;
				e->SubnetMask = tbl->SubnetMask;
				e->GatewayAddress = tbl->GatewayAddress;
				e->Metric = tbl->Metric;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Delete routing table entry on virtual L3 switch
UINT StDelL3Table(ADMIN *a, RPC_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	SERVER_ADMIN_ONLY;

	NO_SUPPORT_FOR_BRIDGE;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3TABLE tbl;

		Zero(&tbl, sizeof(tbl));
		tbl.NetworkAddress = t->NetworkAddress;
		tbl.SubnetMask = t->SubnetMask;
		tbl.GatewayAddress = t->GatewayAddress;
		tbl.Metric = t->Metric;

		if (L3DelTable(sw, &tbl) == false)
		{
			ret = ERR_LAYER3_TABLE_DEL_FAILED;
		}
		else
		{
			char tmp[MAX_SIZE];
			IPToStr32(tmp, sizeof(tmp), tbl.NetworkAddress);
			ALog(a, NULL, "LA_DEL_L3_TABLE", tmp, t->Name);

			IncrementServerConfigRevision(s);
		}

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Add new routing table entry on virtual L3 switch
UINT StAddL3Table(ADMIN *a, RPC_L3TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsNetworkAddress32(t->NetworkAddress, t->SubnetMask) == false ||
		IsHostIPAddress32(t->GatewayAddress) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	NO_SUPPORT_FOR_BRIDGE;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3TABLE tbl;

		Zero(&tbl, sizeof(tbl));
		tbl.NetworkAddress = t->NetworkAddress;
		tbl.SubnetMask = t->SubnetMask;
		tbl.GatewayAddress = t->GatewayAddress;
		tbl.Metric = t->Metric;

		if (L3AddTable(sw, &tbl) == false)
		{
			ret = ERR_LAYER3_TABLE_ADD_FAILED;
		}
		else
		{
			char tmp[MAX_SIZE];
			IPToStr32(tmp, sizeof(tmp), tbl.NetworkAddress);
			ALog(a, NULL, "LA_ADD_L3_TABLE", tmp, t->Name);

			IncrementServerConfigRevision(s);
		}

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Enumerate virtual interfaces on virtual L3 switch
UINT StEnumL3If(ADMIN *a, RPC_ENUM_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;
	char name[MAX_HUBNAME_LEN + 1];

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(name, sizeof(name), t->Name);

	FreeRpcEnumL3If(t);
	Zero(t, sizeof(RPC_ENUM_L3IF));

	StrCpy(t->Name, sizeof(t->Name), name);

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			UINT i;

			t->NumItem = LIST_NUM(sw->IfList);
			t->Items = ZeroMalloc(sizeof(RPC_L3IF) * t->NumItem);

			for (i = 0;i < t->NumItem;i++)
			{
				L3IF *f = LIST_DATA(sw->IfList, i);
				RPC_L3IF *e = &t->Items[i];

				StrCpy(e->Name, sizeof(e->Name), sw->Name);
				StrCpy(e->HubName, sizeof(e->HubName), f->HubName);
				e->IpAddress = f->IpAddress;
				e->SubnetMask = f->SubnetMask;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Delete a virtual interface on virtual L3 switch
UINT StDelL3If(ADMIN *a, RPC_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		if (L3DelIf(sw, t->HubName) == false)
		{
			ret = ERR_LAYER3_IF_DEL_FAILED;
		}
		else
		{
			ALog(a, NULL, "LA_DEL_L3_IF", t->HubName, t->Name);

			IncrementServerConfigRevision(s);
		}
		ReleaseL3Sw(sw);
	}

	return ret;
}

// Add new virtual interface on virtual L3 switch
UINT StAddL3If(ADMIN *a, RPC_L3IF *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;


	if (IsSubnetMask32(t->SubnetMask) == false || IsHostIPAddress32(t->IpAddress) == false)
	{
		return ERR_INVALID_PARAMETER;
	}
	if ((t->IpAddress & (~t->SubnetMask)) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			if (L3SearchIf(sw, t->HubName) != NULL)
			{
				// Already exists
				ret = ERR_LAYER3_IF_EXISTS;
			}
			else
			{
				if (L3AddIf(sw, t->HubName, t->IpAddress, t->SubnetMask) == false)
				{
					ret = ERR_LAYER3_IF_ADD_FAILED;
				}
				else
				{
					ALog(a, NULL, "LA_ADD_L3_IF", t->HubName, t->Name);

					IncrementServerConfigRevision(s);
				}
			}
		}
		Unlock(sw->lock);
		ReleaseL3Sw(sw);
	}

	return ret;
}

// Stop a virtual layer-3 switch
UINT StStopL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		L3SwStop(sw);
		ALog(a, NULL, "LA_STOP_L3_SW", sw->Name);
		ReleaseL3Sw(sw);

		IncrementServerConfigRevision(s);
	}

	return ret;
}

// Start a virtual layer-3 switch
UINT StStartL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	sw = L3GetSw(c, t->Name);

	if (sw == NULL)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		Lock(sw->lock);
		{
			// Count the registered virtual interfaces 
			if (LIST_NUM(sw->IfList) >= 1)
			{
				L3SwStart(sw);

				ALog(a, NULL, "LA_START_L3_SW", sw->Name);

				IncrementServerConfigRevision(s);
			}
			else
			{
				ret = ERR_LAYER3_CANT_START_SWITCH;
			}
		}
		Unlock(sw->lock);

		ReleaseL3Sw(sw);
	}

	return ret;
}

// Enumerate virtual layer-3 switches
UINT StEnumL3Switch(ADMIN *a, RPC_ENUM_L3SW *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	NO_SUPPORT_FOR_BRIDGE;

	FreeRpcEnumL3Sw(t);
	Zero(t, sizeof(RPC_ENUM_L3SW));

	LockList(c->L3SwList);
	{
		t->NumItem = LIST_NUM(c->L3SwList);
		t->Items = ZeroMalloc(sizeof(RPC_ENUM_L3SW_ITEM) * t->NumItem);
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *sw = LIST_DATA(c->L3SwList, i);
			RPC_ENUM_L3SW_ITEM *e = &t->Items[i];

			Lock(sw->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), sw->Name);
				e->NumInterfaces = LIST_NUM(sw->IfList);
				e->NumTables = LIST_NUM(sw->TableList);
				e->Active = sw->Active;
				e->Online = sw->Online;
			}
			Unlock(sw->lock);
		}
	}
	UnlockList(c->L3SwList);

	return ret;
}

// Delete a virtual layer-3 switch
UINT StDelL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	if (L3DelSw(c, t->Name) == false)
	{
		ret = ERR_LAYER3_SW_NOT_FOUND;
	}
	else
	{
		ALog(a, NULL, "LA_DEL_L3_SW", t->Name);

		IncrementServerConfigRevision(s);
	}

	return ret;
}

// Add a new virtual layer-3 switch
UINT StAddL3Switch(ADMIN *a, RPC_L3SW *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	L3SW *sw;

	NO_SUPPORT_FOR_BRIDGE;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	// Duplication check
	sw = L3GetSw(c, t->Name);
	if (sw != NULL)
	{
		// Already exists
		ReleaseL3Sw(sw);
		ret = ERR_LAYER3_SW_EXISTS;
	}
	else
	{
		LockList(c->L3SwList);
		{
			if (LIST_NUM(c->L3SwList) >= GetServerCapsInt(s, "i_max_l3_sw"))
			{
				// No more virtual interfaces
				sw = NULL;
			}
			else
			{
				// Create
				sw = L3AddSw(c, t->Name);

				if (sw != NULL)
				{
					ALog(a, NULL, "LA_ADD_L3_SW", t->Name);

					IncrementServerConfigRevision(s);
				}
			}
		}
		UnlockList(c->L3SwList);

		if (sw == NULL)
		{
			// Failed
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			// Success
			ReleaseL3Sw(sw);
		}
	}

	return ret;
}

// Set hub extended options
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;

	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}


	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "deny_hub_admin_change_ext_option") && not_server_admin)
	{
		// Insufficient permission
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	// Update setting
	Lock(h->lock);
	{
		DataToHubOptionStruct(h->Option, t);
	}
	Unlock(h->lock);

	ALog(a, NULL, "LA_SET_HUB_EXT_OPTION", h->Name);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub extended options
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	// Get options
	Lock(h->lock);
	{
		HubOptionStructToData(t, h->Option, h->Name);
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Set hub administration options
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;


	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "allow_hub_admin_change_option") == false
		&& not_server_admin)
	{
		// Insufficient permission
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->AdminOptionList);
	{
		DeleteAllHubAdminOption(h, false);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *e = &t->Items[i];
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}

		AddHubAdminOptionsDefaults(h, false);
	}
	UnlockList(h->AdminOptionList);

	ALog(a, NULL, "LA_SET_HUB_ADMIN_OPTION", h->Name);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub administration options
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	LockList(h->AdminOptionList);
	{
		t->NumItem = LIST_NUM(h->AdminOptionList);
		t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);
			ADMIN_OPTION *e = &t->Items[i];

			StrCpy(e->Name, sizeof(e->Name), a->Name);
			e->Value = a->Value;
			UniStrCpy(e->Descrption, sizeof(e->Descrption), GetHubAdminOptionHelpString(e->Name));
		}
	}
	UnlockList(h->AdminOptionList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get default hub administration options
UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;

	NO_SUPPORT_FOR_BRIDGE;
	if (a->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	t->NumItem = num_admin_options;
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *a = &t->Items[i];

		StrCpy(a->Name, sizeof(a->Name), admin_options[i].Name);
		a->Value = admin_options[i].Value;
		UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));
	}

	return ERR_NO_ERROR;
}

// Get configuration file stream
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;

	SERVER_ADMIN_ONLY;

	FreeRpcConfig(t);
	Zero(t, sizeof(RPC_CONFIG));

	s = a->Server;

	ALog(a, NULL, "LA_GET_CONFIG");

	if (s->CfgRw != NULL)
	{
		FOLDER *f = SiWriteConfigurationToCfg(s);
		BUF *b = CfgFolderToBuf(f, true);

		StrCpy(t->FileName, sizeof(t->FileName), s->CfgRw->FileName + (s->CfgRw->FileName[0] == '@' ? 1 : 0));

		t->FileData = ZeroMalloc(b->Size + 1);
		Copy(t->FileData, b->Buf, b->Size);

		CfgDeleteFolder(f);
		FreeBuf(b);

		return ERR_NO_ERROR;
	}
	else
	{
		return ERR_INTERNAL_ERROR;
	}
}

// Overwrite configuration file by specified data
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;
	IO *o;
	char filename[MAX_PATH];

	SERVER_ADMIN_ONLY;

	s = a->Server;
	if (s->CfgRw == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Write new configuration file
	Format(filename, sizeof(filename), "%s.new", s->CfgRw->FileName);

	o = FileCreate(filename);

	FileWrite(o, t->FileData, StrLen(t->FileData));

	FileClose(o);

	IncrementServerConfigRevision(s);

	ALog(a, NULL, "LA_SET_CONFIG");

	// Reboot server itself
	SiRebootServer(s->Cedar->Bridge);

	return ERR_NO_ERROR;
}

// Get capabilities
UINT StGetCaps(ADMIN *a, CAPSLIST *t)
{
	FreeRpcCapsList(t);
	Zero(t, sizeof(CAPSLIST));

	GetServerCapsMain(a->Server, t);

	return ERR_NO_ERROR;
}

// Reboot server itself
UINT StRebootServer(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(a->Server->Cedar->Bridge, t->IntValue);

	return ERR_NO_ERROR;
}

// Get availability to localbridge function
UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t)
{
	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = IsBridgeSupported();
	t->IsWinPcapNeeded = IsNeedWinPcap();

	return ERR_NO_ERROR;
}

// Enumerate Ethernet devices
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t)
{
	TOKEN_LIST *o;
	UINT i;
	char tmp[MAX_SIZE];
	bool unix_support = false;

	SERVER_ADMIN_ONLY;

#ifdef	OS_UNIX
	unix_support = EthIsInterfaceDescriptionSupportedUnix();
#endif	// OS_UNIX

	o = GetEthList();
	if (o == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcEnumEth(t);
	Zero(t, sizeof(RPC_ENUM_ETH));

	t->NumItem = o->NumTokens;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];

		StrCpy(e->DeviceName, sizeof(e->DeviceName), o->Token[i]);

		StrCpy(tmp, sizeof(tmp), e->DeviceName);

#ifdef OS_WIN32
		GetEthNetworkConnectionName(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), e->DeviceName);
#else
		if (unix_support == false)
		{
			StrCpy(tmp, sizeof(tmp), "");
		}
		else
		{
			if (EthGetInterfaceDescriptionUnix(e->DeviceName, tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), e->DeviceName);
			}
		}

		StrToUni(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), tmp);
#endif
	}

	FreeToken(o);

	return ERR_NO_ERROR;
}

// Add a new local bridge
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;


	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

#ifdef	OS_WIN32
	if (true)
	{
		char tmp[MAX_SIZE];
		UINT id = Win32EthGetNameAndIdFromCombinedName(tmp, sizeof(tmp), t->DeviceName);

		if (id == 0)
		{
			// If a ID is not specified in Win32, adding will fail
			return ERR_OBJECT_NOT_FOUND;
		}
	}
#endif	// OS_WIN32

	ALog(a, NULL, "LA_ADD_BRIDGE", t->HubName, t->DeviceName);

	AddLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName, false, false, t->TapMode, NULL, false);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Delete a local bridge
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_DELETE_BRIDGE", t->HubName, t->DeviceName);

	if (DeleteLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Enumerate local bridges
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	CEDAR *c;

	if (IsEthSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	FreeRpcEnumLocalBridge(t);
	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));

	c = a->Server->Cedar;

	LockList(c->LocalBridgeList);
	{
		t->NumItem = LIST_NUM(c->LocalBridgeList);
		t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_LOCALBRIDGE *e = &t->Items[i];
			LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

			if (br->Bridge == false)
			{
				e->Online = e->Active = false;
			}
			else
			{
				e->Online = true;
				if (br->Bridge->Active)
				{
					e->Active = true;
				}
				else
				{
					e->Active = false;
				}
			}
			StrCpy(e->DeviceName, sizeof(e->DeviceName), br->DeviceName);
			StrCpy(e->HubName, sizeof(e->HubName), br->HubName);

			e->TapMode = br->TapMode;
		}
	}
	UnlockList(c->LocalBridgeList);

	return ERR_NO_ERROR;
}

// Set syslog function setting
UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0 && t->SaveType != SYSLOG_NONE)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	if (GetServerCapsBool(s, "b_support_syslog") == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	SiSetSysLogSetting(s, t);

	IncrementServerConfigRevision(s);
	ALog(a, NULL, "LA_SET_SYSLOG");

	return ERR_NO_ERROR;
}

// Get syslog function setting
UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SiGetSysLogSetting(s, t);

	if (a->ServerAdmin == false)
	{
		// Hide server name for non-administrator
		if (t->SaveType == SYSLOG_NONE)
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "");
			t->Port = 0;
		}
		else
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "Secret");
			t->Port = 0;
		}
	}

	return ERR_NO_ERROR;
}

// Set keep-alive function setting
UINT StSetKeep(ADMIN *a, RPC_KEEP *t)
{
	SERVER *s = a->Server;

	if (t->UseKeepConnect)
	{
		if (IsEmptyStr(t->KeepConnectHost) ||
			t->KeepConnectPort == 0 ||
			t->KeepConnectPort >= 65536)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	SERVER_ADMIN_ONLY;

	Lock(s->Keep->lock);
	{
		KEEP *keep = s->Keep;
		keep->Enable = t->UseKeepConnect;
		keep->Server = true;
		StrCpy(keep->ServerName, sizeof(keep->ServerName), t->KeepConnectHost);
		keep->ServerPort = t->KeepConnectPort;
		keep->UdpMode = t->KeepConnectProtocol;
		keep->Interval = t->KeepConnectInterval * 1000;
		if (keep->Interval < 5000)
		{
			keep->Interval = 5000;
		}
		else if (keep->Interval > 600000)
		{
			keep->Interval = 600000;
		}
	}
	Unlock(s->Keep->lock);

	ALog(a, NULL, "LA_SET_KEEP");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get keep-alive function setting
UINT StGetKeep(ADMIN *a, RPC_KEEP *t)
{
	SERVER *s = a->Server;

	Zero(t, sizeof(RPC_KEEP));

	Lock(s->Keep->lock);
	{
		KEEP *k = s->Keep;
		t->UseKeepConnect = k->Enable;
		StrCpy(t->KeepConnectHost, sizeof(t->KeepConnectHost), k->ServerName);
		t->KeepConnectPort = k->ServerPort;
		t->KeepConnectProtocol = k->UdpMode;
		t->KeepConnectInterval = k->Interval / 1000;
	}
	Unlock(s->Keep->lock);

	return ERR_NO_ERROR;
}

// Delete IP address table entry
UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_iptable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->IpTable);
	{
		if (IsInListKey(h->IpTable, t->Key))
		{
			IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, t->Key);
			Free(e);
			Delete(h->IpTable, e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->IpTable);

	if (ret == ERR_OBJECT_NOT_FOUND)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						SiCallDeleteIpTable(s, f, t->HubName, t->Key);
						ret = ERR_NO_ERROR;
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	return ret;
}

// Get local IP address table
UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	// Validate arguments
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->IpTable);
	{
		t->NumIpTable = LIST_NUM(h->IpTable);
		t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

		for (i = 0;i < t->NumIpTable;i++)
		{
			RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];
			IP_TABLE_ENTRY *table = LIST_DATA(h->IpTable, i);

			e->Key = POINTER_TO_KEY(table);
			StrCpy(e->SessionName, sizeof(e->SessionName), table->Session->Name);
			e->Ip = IPToUINT(&table->Ip);
			Copy(&e->IpV6, &table->Ip, sizeof(IP));
			Copy(&e->IpAddress, &table->Ip, sizeof(IP));
			e->DhcpAllocated = table->DhcpAllocated;
			e->CreatedTime = TickToTime(table->CreatedTime);
			e->UpdatedTime = TickToTime(table->UpdatedTime);

			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get IP address table
UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	// Get local IP address table
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumIpTable(t);
	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	ret = SiEnumIpTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Get remote IP address table
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					RPC_ENUM_IP_TABLE tmp;

					Zero(&tmp, sizeof(tmp));

					SiCallEnumIpTable(s, f, hubname, &tmp);

					AdjoinRpcEnumIpTable(t, &tmp);
					FreeRpcEnumIpTable(&tmp);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ret;
}

// Delete MAC address table entry
UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_mactable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockHashList(h->MacHashTable);
	{
		if (IsInHashListKey(h->MacHashTable, t->Key))
		{
			MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, t->Key);
			DeleteHash(h->MacHashTable, e);
			Free(e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockHashList(h->MacHashTable);

	if (ret == ERR_OBJECT_NOT_FOUND)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						SiCallDeleteMacTable(s, f, t->HubName, t->Key);
						ret = ERR_NO_ERROR;
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	return ret;
}

// Get local MAC address table
UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	// Validate arguments
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockHashList(h->MacHashTable);
	{
		MAC_TABLE_ENTRY **pp = (MAC_TABLE_ENTRY **)HashListToArray(h->MacHashTable, &t->NumMacTable);
		t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

		for (i = 0;i < t->NumMacTable;i++)
		{
			RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];
			MAC_TABLE_ENTRY *mac = pp[i];

			e->Key = POINTER_TO_KEY(mac);
			StrCpy(e->SessionName, sizeof(e->SessionName), mac->Session->Name);
			Copy(e->MacAddress, mac->MacAddress, sizeof(e->MacAddress));
			e->CreatedTime = TickToTime(mac->CreatedTime);
			e->UpdatedTime = TickToTime(mac->UpdatedTime);
			e->VlanId = mac->VlanId;

			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}

		Free(pp);
	}
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get MAC address table
UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	// Get local MAC address table
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumMacTable(t);
	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));

	ret = SiEnumMacTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Get remote MAC address table
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me == false)
				{
					RPC_ENUM_MAC_TABLE tmp;

					Zero(&tmp, sizeof(tmp));

					SiCallEnumMacTable(s, f, hubname, &tmp);

					AdjoinRpcEnumMacTable(t, &tmp);
					FreeRpcEnumMacTable(&tmp);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ret;
}

// Delete a session
UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_disconnect_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	sess = GetSessionByName(h, name);

	if (sess == NULL)
	{
		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// Cluster controller
			UINT i;
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						// Try to disconnect
						SiCallDeleteSession(s, f, t->HubName, t->Name);
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	else
	{
		if (sess->LinkModeServer)
		{
			ret = ERR_LINK_CANT_DISCONNECT;
		}
		else if (sess->SecureNATMode)
		{
			ret = ERR_SNAT_CANT_DISCONNECT;
		}
		else if (sess->BridgeMode)
		{
			ret = ERR_BRIDGE_CANT_DISCONNECT;
		}
		else if (sess->L3SwitchMode)
		{
			ret = ERR_LAYER3_CANT_DISCONNECT;
		}
		else
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	if (ret != ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_SESSION", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

// Get session status
UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_query_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	sess = GetSessionByName(h, t->Name);

	if (sess == NULL)
	{
		if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
		{
			// Session is not found
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			UINT i;
			// Try to find the session on other cluster member
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_SESSION_STATUS tmp;
						Zero(&tmp, sizeof(tmp));
						StrCpy(tmp.HubName, sizeof(tmp.HubName), t->HubName);
						StrCpy(tmp.Name, sizeof(tmp.Name), t->Name);

						if (SiCallGetSessionStatus(s, f, &tmp))
						{
							if (StrLen(tmp.HubName) != 0)
							{
								// Success to get session status
								Copy(t, &tmp, sizeof(RPC_SESSION_STATUS));
								break;
							}
							else
							{
								FreeRpcSessionStatus(&tmp);
							}
						}
					}
				}

				if (i == LIST_NUM(s->FarmMemberList))
				{
					// not found after all
					// 
					ret = ERR_OBJECT_NOT_FOUND;
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}
	else
	{
		SESSION *s = sess;

		Lock(s->lock);
		{
			StrCpy(t->Username, sizeof(t->Username), s->Username);
			StrCpy(t->RealUsername, sizeof(t->RealUsername), s->UserNameReal);
			StrCpy(t->GroupName, sizeof(t->GroupName), s->GroupName);
			Copy(&t->NodeInfo, &s->NodeInfo, sizeof(NODE_INFO));

			if (s->Connection != NULL)
			{
				t->ClientIp = IPToUINT(&s->Connection->ClientIp);
				if (IsIP6(&s->Connection->ClientIp))
				{
					Copy(&t->ClientIp6, &s->Connection->ClientIp.ipv6_addr, sizeof(t->ClientIp6));
				}

				CopyIP(&t->ClientIpAddress, &s->Connection->ClientIp);

				StrCpy(t->ClientHostName, sizeof(t->ClientHostName), s->Connection->ClientHostname);
			}
		}
		Unlock(s->lock);

		CiGetSessionStatus(&t->Status, s);

		ReleaseSession(s);
	}

	ReleaseHub(h);

	return ret;
}

// Main routine of session enumeration
void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT ret = ERR_NO_ERROR;
	UINT num;
	UINT i;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcEnumSession(t);
	Zero(t, sizeof(RPC_ENUM_SESSION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	// Local session enumeration
	num = 0;
	SiEnumLocalSession(s, hubname, t);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		LIST *fm_list;

		fm_list = NewListFast(NULL);

		// Remote session enumeration
		LockList(s->FarmMemberList);
		{
			while (true)
			{
				bool escape = true;

				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

					if (IsInList(fm_list, f) == false)
					{
						Add(fm_list, f);
						escape = false;

						if (f->Me == false)
						{
							RPC_ENUM_SESSION tmp;

							Zero(&tmp, sizeof(tmp));

							SiCallEnumSession(s, f, hubname, &tmp);

							AdjoinRpcEnumSession(t, &tmp);
							FreeRpcEnumSession(&tmp);
						}

						break;
					}
				}

				if (escape)
				{
					break;
				}

				UnlockList(s->FarmMemberList);
				LockList(s->FarmMemberList);
			}
		}
		UnlockList(s->FarmMemberList);

		ReleaseList(fm_list);
	}
}

// Enumerate sessions
UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_enum_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	SiEnumSessionMain(s, t);

	ReleaseHub(h);

	return ret;
}

// Enumerate groups
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		UINT i, j;

		FreeRpcEnumGroup(t);
		Zero(t, sizeof(RPC_ENUM_GROUP));
		StrCpy(t->HubName, sizeof(t->HubName), hubname);

		t->NumGroup = LIST_NUM(h->HubDb->GroupList);
		t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

		for (i = 0;i < t->NumGroup;i++)
		{
			RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];
			USERGROUP *g = LIST_DATA(h->HubDb->GroupList, i);

			Lock(g->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), g->Name);
				UniStrCpy(e->Realname, sizeof(e->Realname), g->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), g->Note);
				if (g->Policy != NULL)
				{
					if (g->Policy->Access == false)
					{
						e->DenyAccess = true;
					}
				}
			}
			Unlock(g->lock);

			e->NumUsers = 0;


			LockList(h->HubDb->UserList);
			{
				for (j = 0;j < LIST_NUM(h->HubDb->UserList);j++)
				{
					USER *u = LIST_DATA(h->HubDb->UserList, j);

					Lock(u->lock);
					{
						if (u->Group == g)
						{
							e->NumUsers++;
						}
					}
					Unlock(u->lock);
				}
			}
			UnlockList(h->HubDb->UserList);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Delete a group
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcDeleteGroup(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_GROUP", t->Name);
	}

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Get group information
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);

		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			FreeRpcSetGroup(t);
			Zero(t, sizeof(RPC_SET_GROUP));

			StrCpy(t->HubName, sizeof(t->HubName), hubname);

			Lock(g->lock);
			{
				StrCpy(t->Name, sizeof(t->Name), g->Name);
				UniStrCpy(t->Realname, sizeof(t->Realname), g->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), g->Note);
				Copy(&t->Traffic, g->Traffic, sizeof(TRAFFIC));
			}
			Unlock(g->lock);

			t->Policy = GetGroupPolicy(g);

			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

// Set group setting
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);
		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(g->lock);
			{
				Free(g->RealName);
				Free(g->Note);
				g->RealName = UniCopyStr(t->Realname);
				g->Note = UniCopyStr(t->Note);
			}
			Unlock(g->lock);

			SetGroupPolicy(g, t->Policy);

			ReleaseGroup(g);

			ALog(a, h, "LA_SET_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Create a group
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcIsGroup(h, t->Name))
		{
			ret = ERR_GROUP_ALREADY_EXISTS;
		}
		else
		{
			USERGROUP *g = NewGroup(t->Name, t->Realname, t->Note);
			SetGroupPolicy(g, t->Policy);

			if ((LIST_NUM(h->HubDb->GroupList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
				((GetHubAdminOption(h, "max_groups") != 0) && (LIST_NUM(h->HubDb->GroupList) >= GetHubAdminOption(h, "max_groups"))))
			{
				ret = ERR_TOO_MANY_GROUP;
			}
			else
			{
				AcAddGroup(h, g);
			}

			ReleaseGroup(g);

			ALog(a, h, "LA_CREATE_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Enumerate users
UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i, num;

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcEnumUser(t);

	StrCpy(hubname, sizeof(hubname), t->HubName);

	Zero(t, sizeof(RPC_ENUM_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->HubDb->UserList);
	{
		num = LIST_NUM(h->HubDb->UserList);

		t->NumUser = num;
		t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * num);

		for (i = 0;i < num;i++)
		{
			USER *u = LIST_DATA(h->HubDb->UserList, i);

			Lock(u->lock);
			{
				RPC_ENUM_USER_ITEM *e = &t->Users[i];

				StrCpy(e->Name, sizeof(e->Name), u->Name);
				StrCpy(e->GroupName, sizeof(e->GroupName), u->GroupName);
				UniStrCpy(e->Realname, sizeof(e->Realname), u->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), u->Note);
				e->AuthType = u->AuthType;
				e->LastLoginTime = u->LastLoginTime;
				e->NumLogin = u->NumLogin;

				if (u->Policy != NULL)
				{
					e->DenyAccess = u->Policy->Access ? false : true;
				}

				Copy(&e->Traffic, u->Traffic, sizeof(TRAFFIC));
				e->IsTrafficFilled = true;

				e->Expires = u->ExpireTime;
				e->IsExpiresFilled = true;
			}
			Unlock(u->lock);
		}
	}
	UnlockList(h->HubDb->UserList);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Delete a user
UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DELETE_USER", t->Name);

	AcLock(h);
	{
		if (AcDeleteUser(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Get user setting
UINT StGetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;
	char name[MAX_USERNAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	StrCpy(name, sizeof(name), t->Name);
	StrCpy(hubname, sizeof(hubname), t->HubName);

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcSetUser(t);
	Zero(t, sizeof(RPC_SET_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		u = AcGetUser(h, name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				StrCpy(t->GroupName, sizeof(t->GroupName), u->GroupName);
				UniStrCpy(t->Realname, sizeof(t->Realname), u->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), u->Note);
				t->CreatedTime = u->CreatedTime;
				t->UpdatedTime = u->UpdatedTime;
				t->ExpireTime = u->ExpireTime;

				t->AuthType = u->AuthType;
				t->AuthData = CopyAuthData(u->AuthData, t->AuthType);
				t->NumLogin = u->NumLogin;
				Copy(&t->Traffic, u->Traffic, sizeof(TRAFFIC));
				if (u->Policy != NULL)
				{
					t->Policy = ClonePolicy(u->Policy);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

// Set user setting
UINT StSetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_RADIUS || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_RADIUS && t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		u = AcGetUser(h, t->Name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				if (StrLen(t->GroupName) != 0)
				{
					g = AcGetGroup(h, t->GroupName);

					if (g != NULL)
					{
						JoinUserToGroup(u, g);
						ReleaseGroup(g);
					}
					else
					{
						ret = ERR_GROUP_NOT_FOUND;
					}
				}
				else
				{
					JoinUserToGroup(u, NULL);
				}

				if (ret != ERR_GROUP_NOT_FOUND)
				{
					Free(u->RealName);
					Free(u->Note);
					u->RealName = UniCopyStr(t->Realname);
					u->Note = UniCopyStr(t->Note);
					SetUserAuthData(u, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
					u->ExpireTime = t->ExpireTime;
					u->UpdatedTime = SystemTime64();

					SetUserPolicy(u, t->Policy);
				}
			}
			Unlock(u->lock);

			IncrementServerConfigRevision(s);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_USER", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

// Create a user
UINT StCreateUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_RADIUS || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_RADIUS && t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	u = NewUser(t->Name, t->Realname, t->Note, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
	if (u == NULL)
	{
		ReleaseHub(h);
		return ERR_INTERNAL_ERROR;
	}

	u->ExpireTime = t->ExpireTime;

	SetUserPolicy(u, t->Policy);

	AcLock(h);
	{
		if ((LIST_NUM(h->HubDb->UserList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
			((GetHubAdminOption(h, "max_users") != 0) && (LIST_NUM(h->HubDb->UserList) >= GetHubAdminOption(h, "max_users"))))
		{
			ret = ERR_TOO_MANY_USER;
		}
		else if (SiTooManyUserObjectsInServer(s, false))
		{
			ret = ERR_TOO_MANY_USERS_CREATED;
			ALog(a, h, "ERR_128");
		}
		else if (AcIsUser(h, t->Name))
		{
			ret = ERR_USER_ALREADY_EXISTS;
		}
		else
		{
			if (StrLen(t->GroupName) != 0)
			{
				g = AcGetGroup(h, t->GroupName);
				if (g == NULL)
				{
					ret = ERR_GROUP_NOT_FOUND;
				}
			}

			if (ret != ERR_GROUP_NOT_FOUND)
			{
				if (g != NULL)
				{
					JoinUserToGroup(u, g);
					ReleaseGroup(g);
				}

				AcAddUser(h, u);
				ALog(a, h, "LA_CREATE_USER", t->Name);

				IncrementServerConfigRevision(s);
			}
		}
	}
	AcUnlock(h);

	ReleaseUser(u);

	ReleaseHub(h);

	return ret;
}

// Get access list
UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumAccessList(t);
	Zero(t, sizeof(RPC_ENUM_ACCESS_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->AccessList);
	{
		t->NumAccess = LIST_NUM(h->AccessList);
		t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);

		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = &t->Accesses[i];
			Copy(a, LIST_DATA(h->AccessList, i), sizeof(ACCESS));
			a->UniqueId = HashPtrToUINT(LIST_DATA(h->AccessList, i));
		}
	}
	UnlockList(h->AccessList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Delete access list entry
UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool exists;


	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	exists = false;

	LockList(h->AccessList);
	{
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);

			if ((t->Id < MAX_ACCESSLISTS && access->Id == t->Id) ||
				(t->Id >= MAX_ACCESSLISTS && HashPtrToUINT(access) == t->Id))
			{
				Free(access);
				Delete(h->AccessList, access);
				exists = true;

				break;
			}
		}
	}
	UnlockList(h->AccessList);

	if (exists == false)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_ACCESS");

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Set access list
UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool no_jitter = false;
	bool no_include = false;
	UINT ret = ERR_NO_ERROR;


	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (t->NumAccess > GetServerCapsInt(a->Server, "i_max_access_lists"))
	{
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "max_accesslists") != 0 &&
		t->NumAccess > GetHubAdminOption(h, "max_accesslists"))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockList(h->AccessList);
	{
		UINT i;

		if (a->ClientBuild != 0)
		{
			// Confirm whether the access list of form which cannot handle by the old client already exists
			if (a->ClientBuild < 6560)
			{
				for (i = 0;i < LIST_NUM(h->AccessList);i++)
				{
					ACCESS *access = LIST_DATA(h->AccessList, i);
					if (access->IsIPv6 ||
						access->Jitter != 0 || access->Loss != 0 || access->Delay != 0)
					{
						ret = ERR_VERSION_INVALID;
						break;
					}
				}
			}

			if (a->ClientBuild < 8234)
			{
				for (i = 0;i < LIST_NUM(h->AccessList);i++)
				{
					ACCESS *access = LIST_DATA(h->AccessList, i);

					if (IsEmptyStr(access->RedirectUrl) == false)
					{
						ret = ERR_VERSION_INVALID;
						break;
					}
				}
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			// Delete whole access list
			for (i = 0;i < LIST_NUM(h->AccessList);i++)
			{
				ACCESS *access = LIST_DATA(h->AccessList, i);
				Free(access);
			}

			DeleteAll(h->AccessList);
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_ACCESS_LIST", t->NumAccess);

		// Add whole access list
		for (i = 0;i < t->NumAccess;i++)
		{
			ACCESS *a = &t->Accesses[i];

			if (no_jitter)
			{
				a->Jitter = a->Loss = a->Delay = 0;
			}

			if (no_include)
			{
				if (StartWith(a->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->SrcUsername, sizeof(a->SrcUsername));
				}

				if (StartWith(a->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->DestUsername, sizeof(a->DestUsername));
				}
			}

			if (i == (t->NumAccess - 1))
			{
				Sort(h->AccessList);
			}

			AddAccessListEx(h, a, ((i != (t->NumAccess - 1)) ? true : false), ((i != (t->NumAccess - 1)) ? true : false));
		}

		UnlockList(h->AccessList);

		IncrementServerConfigRevision(s);

		h->CurrentVersion++;
		SiHubUpdateProc(h);
	}
	else
	{
		UnlockList(h->AccessList);
	}

	ReleaseHub(h);

	return ret;
}

// Add access list entry
UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	bool no_jitter = false;
	bool no_include = false;


	NO_SUPPORT_FOR_BRIDGE;
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if ((LIST_NUM(h->AccessList) >= GetServerCapsInt(a->Server, "i_max_access_lists") ||
		(GetHubAdminOption(h, "max_accesslists") != 0) && (LIST_NUM(h->AccessList) >= GetHubAdminOption(h, "max_accesslists"))))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	ALog(a, h, "LA_ADD_ACCESS");

	if (no_jitter)
	{
		t->Access.Jitter = t->Access.Delay = t->Access.Loss = 0;
	}

	if (no_include)
	{
		if (StartWith(t->Access.SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.SrcUsername, sizeof(t->Access.SrcUsername));
		}

		if (StartWith(t->Access.DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.DestUsername, sizeof(t->Access.DestUsername));
		}
	}

	AddAccessList(h, &t->Access);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Rename link (cascade connection)
UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	LINK *k;
	bool exists = false;

	if (UniIsEmptyStr(t->OldAccountName) || UniIsEmptyStr(t->NewAccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (UniStrCmpi(t->NewAccountName, t->OldAccountName) == 0)
	{
		// Noop if new name is same to old name
		return ERR_NO_ERROR;
	}

	h = GetHub(c, t->HubName);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// Find specified link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->OldAccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}

		exists = false;

		if (k != NULL)
		{
			// Check whether the new link name is same to other links 
			for (i = 0;i < LIST_NUM(h->LinkList);i++)
			{
				LINK *kk = LIST_DATA(h->LinkList, i);
				Lock(kk->lock);
				{
					if (UniStrCmpi(kk->Option->AccountName, t->NewAccountName) == 0)
					{
						// duplicated
						exists = true;
					}
				}
				Unlock(kk->lock);
			}

			if (exists)
			{
				// Already same name exists
				ret = ERR_LINK_ALREADY_EXISTS;
			}
			else
			{
				// Do rename
				UniStrCpy(k->Option->AccountName, sizeof(k->Option->AccountName), t->NewAccountName);

				ALog(a, h, "LA_RENAME_LINK", t->OldAccountName, t->NewAccountName);

				IncrementServerConfigRevision(s);
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// specified link is not found
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ReleaseLink(k);

	ReleaseHub(h);

	return ret;
}

// Delete a link
UINT StDeleteLink(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// Find specified link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// Specified link is not found
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	k->NoOnline = true;

	ALog(a, h, "LA_DELETE_LINK", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	DelLink(h, k);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// Make a link into off-line
UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// Find specified link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// Link is not found
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_OFFLINE", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// Make a link into on-line
UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	// Find specified link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// Specified link is not found
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_ONLINE", t->AccountName);

	SetLinkOnline(k);

	ReleaseLink(k);
	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Get link status
UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;
	SESSION *sess;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	FreeRpcLinkStatus(t);
	Zero(t, sizeof(RPC_LINK_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	UniStrCpy(t->AccountName, sizeof(t->AccountName), accountname);

	k = NULL;

	// Find the link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// Specified link is not found
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	// Get status information from session
	Lock(k->lock);
	{
		sess = k->ClientSession;
		if (sess != NULL)
		{
			AddRef(sess->ref);
		}
	}
	Unlock(k->lock);

	if (sess != NULL && k->Offline == false)
	{
		CiGetSessionStatus(&t->Status, sess);
	}
	else
	{
		ret = ERR_LINK_IS_OFFLINE;
	}
	ReleaseSession(sess);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// Enumerate links
UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumLink(t);
	Zero(t, sizeof(RPC_ENUM_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->LinkList);
	{
		t->NumLink = LIST_NUM(h->LinkList);
		t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			RPC_ENUM_LINK_ITEM *e = &t->Links[i];

			Lock(k->lock);
			{
				UniStrCpy(e->AccountName, sizeof(e->AccountName), k->Option->AccountName);
				StrCpy(e->Hostname, sizeof(e->Hostname), k->Option->Hostname);
				StrCpy(e->HubName, sizeof(e->HubName), k->Option->HubName);
				e->Online = k->Offline ? false : true;

				if (e->Online)
				{
					if (k->ClientSession != NULL)
					{
						e->ConnectedTime = TickToTime(k->ClientSession->CurrentConnectionEstablishTime);
						e->Connected = (k->ClientSession->ClientStatus == CLIENT_STATUS_ESTABLISHED);
						e->LastError = k->ClientSession->Err;
					}
				}
			}
			Unlock(k->lock);
		}
	}
	UnlockList(h->LinkList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get link configuration
UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	char hubname[MAX_SIZE];
	LINK *k;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	k = NULL;

	// Find the link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// The link is not found
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcCreateLink(t);
	Zero(t, sizeof(RPC_CREATE_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	Lock(k->lock);
	{
		// Get configuration
		t->Online = k->Offline ? false : true;
		t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(t->ClientOption, k->Option, sizeof(CLIENT_OPTION));
		t->ClientAuth = CopyClientAuth(k->Auth);
		Copy(&t->Policy, k->Policy, sizeof(POLICY));

		t->CheckServerCert = k->CheckServerCert;
		t->ServerCert = CloneX(k->ServerCert);
	}
	Unlock(k->lock);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// Set link configuration
UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;


	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// Find the link
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		// The link is not found
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK", t->ClientOption->AccountName);

	Lock(k->lock);
	{
		// Update the configuration of the link
		if (k->ServerCert != NULL)
		{
			FreeX(k->ServerCert);
			k->ServerCert = NULL;
		}

		Copy(k->Option, t->ClientOption, sizeof(CLIENT_OPTION));
		StrCpy(k->Option->DeviceName, sizeof(k->Option->DeviceName), LINK_DEVICE_NAME);
		k->Option->NumRetry = INFINITE;
		k->Option->RetryInterval = 10;
		k->Option->NoRoutingTracking = true;
		CiFreeClientAuth(k->Auth);
		k->Auth = CopyClientAuth(t->ClientAuth);

		if (t->Policy.Ver3 == false)
		{
			Copy(k->Policy, &t->Policy, sizeof(UINT) * NUM_POLICY_ITEM_FOR_VER2);
		}
		else
		{
			Copy(k->Policy, &t->Policy, sizeof(POLICY));
		}

		k->Option->RequireBridgeRoutingMode = true;	// Enable Bridge / Routing mode
		k->Option->RequireMonitorMode = false;	// Disable monitor mode

		k->CheckServerCert = t->CheckServerCert;
		k->ServerCert = CloneX(t->ServerCert);
	}
	Unlock(k->lock);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

// Create a new link(cascade)
UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;

	CHECK_RIGHT;


	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		return ERR_LINK_CANT_CREATE_ON_FARM;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	// Check for existing a link which has same name
	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k != NULL)
	{
		// There is a link which has same name
		ReleaseLink(k);
		ReleaseHub(h);
		return ERR_LINK_ALREADY_EXISTS;
	}

	ALog(a, h, "LA_CREATE_LINK", t->ClientOption->AccountName);

	// Create a new link
	k = NewLink(c, h, t->ClientOption, t->ClientAuth, &t->Policy);

	if (k == NULL)
	{
		// Link creation failed
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		// setting of verifying server certification
		// 
		k->CheckServerCert = t->CheckServerCert;
		k->ServerCert = CloneX(t->ServerCert);

		// stay this off-line
		k->Offline = false;
		SetLinkOffline(k);
		ReleaseLink(k);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ret;
}

// Delete a CA(Certificate Authority) setting from the hub
UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, t->Key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, t->Key);
			Delete(h->HubDb->RootCertList, x);
			FreeX(x);

			ALog(a, h, "LA_DELETE_CA");

			IncrementServerConfigRevision(s);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

// Get CA(Certificate Authority) setting from the hub
UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT key;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcHubGetCa(t);
	Zero(t, sizeof(RPC_HUB_GET_CA));
	t->Key = key;
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, key);

			t->Cert = CloneX(x);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

// Enumerate CA(Certificate Authority) in the hub
UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcHubEnumCa(t);
	Zero(t, sizeof(RPC_HUB_ENUM_CA));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	if (h->HubDb->RootCertList != NULL)
	{
		LockList(h->HubDb->RootCertList);
		{
			t->NumCa = LIST_NUM(h->HubDb->RootCertList);
			t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

			for (i = 0;i < t->NumCa;i++)
			{
				RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];
				X *x = LIST_DATA(h->HubDb->RootCertList, i);

				e->Key = POINTER_TO_KEY(x);
				GetAllNameFromNameEx(e->SubjectName, sizeof(e->SubjectName), x->subject_name);
				GetAllNameFromNameEx(e->IssuerName, sizeof(e->IssuerName), x->issuer_name);
				e->Expires = x->notAfter;
			}
		}
		UnlockList(h->HubDb->RootCertList);
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Add CA(Certificate Authority) into the hub
UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (t->Cert == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (t->Cert->is_compatible_bit == false)
	{
		return ERR_NOT_RSA_1024;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_ADD_CA");

	AddRootCert(h, t->Cert);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get logging configuration of the hub
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	GetHubLogSetting(h, &t->LogSetting);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Set logging configuration into the hub
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_config") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_SET_HUB_LOG");

	SetHubLogSettingEx(h, &t->LogSetting,
		(a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_switch_type") != 0));

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub status
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_STATUS));

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->HubType = h->Type;
		t->Online = h->Offline ? false : true;
		t->NumSessions = LIST_NUM(h->SessionList);
		t->NumSessionsClient = Count(h->NumSessionsClient);
		t->NumSessionsBridge = Count(h->NumSessionsBridge);
		t->NumAccessLists = LIST_NUM(h->AccessList);

		if (h->HubDb != NULL)
		{
			t->NumUsers = LIST_NUM(h->HubDb->UserList);
			t->NumGroups = LIST_NUM(h->HubDb->GroupList);
		}

		t->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
		t->NumIpTables = LIST_NUM(h->IpTable);

		Lock(h->TrafficLock);
		{
			Copy(&t->Traffic, h->Traffic, sizeof(TRAFFIC));
		}
		Unlock(h->TrafficLock);

		t->NumLogin = h->NumLogin;
		t->LastCommTime = h->LastCommTime;
		t->LastLoginTime = h->LastLoginTime;
		t->CreatedTime = h->CreatedTime;
	}
	Unlock(h->lock);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i;
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				UINT k;
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (f->Me == false)
				{
					LockList(f->HubList);
					{
						for (k = 0;k < LIST_NUM(f->HubList);k++)
						{
							HUB_LIST *h = LIST_DATA(f->HubList, k);

							if (StrCmpi(h->Name, t->HubName) == 0)
							{
								t->NumSessions += h->NumSessions;
								t->NumSessionsClient += h->NumSessionsClient;
								t->NumSessionsBridge += h->NumSessionsBridge;
								t->NumMacTables += h->NumMacTables;
								t->NumIpTables += h->NumIpTables;
							}
						}
					}
					UnlockList(f->HubList);
				}
			}
		}
		UnlockList(s->FarmMemberList);
	}

	if (h->Type != HUB_TYPE_FARM_STATIC)
	{
		t->SecureNATEnabled = h->EnableSecureNAT;
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Enable SecureNAT function of the hub
UINT StEnableSecureNAT(ADMIN *a, RPC_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_ENABLE_SNAT");

	EnableSecureNAT(h, true);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Disable the SecureNAT function of the hub
UINT StDisableSecureNAT(ADMIN *a, RPC_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DISABLE_SNAT");

	EnableSecureNAT(h, false);

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Enumerate NAT entries of the SecureNAT
UINT StEnumNAT(ADMIN *a, RPC_ENUM_NAT *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtEnumNatList(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// Get status of remote SecureNAT
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_ENUM_NAT tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallEnumNat(s, f, hubname, &tmp);

						if (tmp.NumItem >= 1)
						{
							FreeRpcEnumNat(t);
							Copy(t, &tmp, sizeof(RPC_ENUM_NAT));
							ret = ERR_NO_ERROR;
							break;
						}
						else
						{
							FreeRpcEnumNat(&tmp);
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	ret = ERR_NO_ERROR;

	return ret;
}

// Get status of the SecureNAT
UINT StGetSecureNATStatus(ADMIN *a, RPC_NAT_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtGetStatus(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// Get status of remote secureNAT
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_NAT_STATUS tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallGetNatStatus(s, f, hubname, &tmp);

						if (tmp.NumDhcpClients == 0 && tmp.NumTcpSessions == 0 && tmp.NumUdpSessions == 0)
						{
						}
						else
						{
							Copy(t, &tmp, sizeof(RPC_NAT_STATUS));
							ret = ERR_NO_ERROR;
							break;
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	ret = ERR_NO_ERROR;

	return ret;
}

// Enumerate DHCP entries
UINT StEnumDHCP(ADMIN *a, RPC_ENUM_DHCP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT == NULL)
		{
			ret = ERR_SNAT_NOT_RUNNING;
		}
		else
		{
			NtEnumDhcpList(h->SecureNAT->Nat, t);
		}
	}
	Unlock(h->lock_online);

	if (h->Type == HUB_TYPE_FARM_DYNAMIC)
	{
		if (ret == ERR_SNAT_NOT_RUNNING)
		{
			// Get status of remote DHCP service
			LockList(s->FarmMemberList);
			{
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
					if (f->Me == false)
					{
						RPC_ENUM_DHCP tmp;

						Zero(&tmp, sizeof(tmp));

						SiCallEnumDhcp(s, f, hubname, &tmp);

						if (tmp.NumItem >= 1)
						{
							FreeRpcEnumDhcp(t);
							Copy(t, &tmp, sizeof(RPC_ENUM_DHCP));
							ret = ERR_NO_ERROR;
							break;
						}
						else
						{
							FreeRpcEnumDhcp(&tmp);
						}
					}
				}
			}
			UnlockList(s->FarmMemberList);
		}
	}

	ReleaseHub(h);

	ret = ERR_NO_ERROR;

	return ret;
}

// Set SecureNAT options
UINT StSetSecureNATOption(ADMIN *a, VH_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char push_routes_str_old[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];


	if (IsZero(t->MacAddress, sizeof(t->MacAddress)) ||
		IsHostIPAddress4(&t->Ip) == false ||
		IsSubnetMask4(&t->Mask) == false)
	{
		return ERR_INVALID_PARAMETER;
	}
	if ((IPToUINT(&t->Ip) & (~(IPToUINT(&t->Mask)))) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (GetServerCapsBool(s, "b_support_securenat") == false)
	{
		t->ApplyDhcpPushRoutes = false;
	}
	if (t->ApplyDhcpPushRoutes)
	{
		if (NormalizeClasslessRouteTableStr(t->DhcpPushRoutes, sizeof(t->DhcpPushRoutes), t->DhcpPushRoutes) == false)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (h->SecureNATOption->UseNat == false && t->UseNat)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat_enablenat") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	if (h->SecureNATOption->UseDhcp == false && t->UseDhcp)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_securenat_enabledhcp") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	StrCpy(push_routes_str_old, sizeof(push_routes_str_old), h->SecureNATOption->DhcpPushRoutes);
	Copy(h->SecureNATOption, t, sizeof(VH_OPTION));
	if (t->ApplyDhcpPushRoutes == false)
	{
		StrCpy(h->SecureNATOption->DhcpPushRoutes, sizeof(h->SecureNATOption->DhcpPushRoutes), push_routes_str_old);
	}

	if (h->Type != HUB_TYPE_STANDALONE && h->Cedar != NULL && h->Cedar->Server != NULL &&
		h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption, false);
	}

	Lock(h->lock_online);
	{
		if (h->SecureNAT != NULL)
		{
			SetVirtualHostOption(h->SecureNAT->Nat->Virtual, t);
		}
	}
	Unlock(h->lock_online);

	ALog(a, h, "LA_SET_SNAT_OPTION");

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get SecureNAT options
UINT StGetSecureNATOption(ADMIN *a, VH_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type == HUB_TYPE_FARM_STATIC || GetServerCapsBool(s, "b_support_securenat") == false)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}
	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		ReleaseHub(h);
		return ERR_NOT_FARM_CONTROLLER;
	}

	Zero(t, sizeof(VH_OPTION));
	Copy(t, h->SecureNATOption, sizeof(VH_OPTION));
	StrCpy(t->HubName, sizeof(t->HubName), h->Name);
	t->ApplyDhcpPushRoutes = true;

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Make a hub on-line or off-line
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}


	NO_SUPPORT_FOR_BRIDGE;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && t->Online && GetHubAdminOption(h, "no_online") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && t->Online == false && GetHubAdminOption(h, "no_offline") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (t->Online)
	{
		ALog(a, h, "LA_SET_HUB_ONLINE");
		SetHubOnline(h);
	}
	else
	{
		ALog(a, h, "LA_SET_HUB_OFFLINE");
		SetHubOffline(h);
	}

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get connection information
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;
	char name[MAX_CONNECTION_NAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;
		StrCpy(name, sizeof(name), t->Name);

		connection = Search(c->ConnectionList, &tt);

		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	StrCpy(t->Name, sizeof(t->Name), name);

	Lock(connection->lock);
	{
		SOCK *s = connection->FirstSock;

		if (s != NULL)
		{
			t->Ip = IPToUINT(&s->RemoteIP);
			t->Port = s->RemotePort;
			StrCpy(t->Hostname, sizeof(t->Hostname), s->RemoteHostname);
		}

		StrCpy(t->Name, sizeof(t->Name), connection->Name);
		t->ConnectedTime = TickToTime(connection->ConnectedTick);
		t->Type = connection->Type;

		StrCpy(t->ServerStr, sizeof(t->ServerStr), connection->ServerStr);
		StrCpy(t->ClientStr, sizeof(t->ClientStr), connection->ClientStr);
		t->ServerVer = connection->ServerVer;
		t->ServerBuild = connection->ServerBuild;
		t->ClientVer = connection->ClientVer;
		t->ClientBuild = connection->ClientBuild;
	}
	Unlock(connection->lock);

	ReleaseConnection(connection);

	return ERR_NO_ERROR;
}

// Disconnect a connection
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);
		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	StopConnection(connection, true);

	ReleaseConnection(connection);

	ALog(a, NULL, "LA_DISCONNECT_CONN", t->Name);

	return ERR_NO_ERROR;
}

// Enumerate connections
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumConnection(t);
	Zero(t, sizeof(RPC_ENUM_CONNECTION));

	LockList(c->ConnectionList);
	{
		UINT i;
		t->NumConnection = LIST_NUM(c->ConnectionList);
		t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);
		
		for (i = 0;i < t->NumConnection;i++)
		{
			RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];
			CONNECTION *connection = LIST_DATA(c->ConnectionList, i);

			Lock(connection->lock);
			{
				SOCK *s = connection->FirstSock;

				if (s != NULL)
				{
					e->Ip = IPToUINT(&s->RemoteIP);
					e->Port = s->RemotePort;
					StrCpy(e->Hostname, sizeof(e->Hostname), s->RemoteHostname);
				}

				StrCpy(e->Name, sizeof(e->Name), connection->Name);
				e->ConnectedTime = TickToTime(connection->ConnectedTick);
				e->Type = connection->Type;
			}
			Unlock(connection->lock);
		}
	}
	UnlockList(c->ConnectionList);

	return ERR_NO_ERROR;
}

// Set Radius options of the hub
UINT StSetHubRadius(ADMIN *a, RPC_RADIUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0 && IsEmptyStr(t->RadiusServerName) == false)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	//SetRadiusServer(h, t->RadiusServerName, t->RadiusPort, t->RadiusSecret);
	SetRadiusServerEx(h, t->RadiusServerName, t->RadiusPort, t->RadiusSecret, t->RadiusRetryInterval);

	ALog(a, h, "LA_SET_HUB_RADIUS");

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get Radius options of the hub
UINT StGetHubRadius(ADMIN *a, RPC_RADIUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	CHECK_RIGHT;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_SUPPORTED;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_RADIUS));
	//GetRadiusServer(h, t->RadiusServerName, sizeof(t->RadiusServerName),
	//	&t->RadiusPort, t->RadiusSecret, sizeof(t->RadiusSecret));
	GetRadiusServerEx(h, t->RadiusServerName, sizeof(t->RadiusServerName),
		&t->RadiusPort, t->RadiusSecret, sizeof(t->RadiusSecret), &t->RadiusRetryInterval);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Delete a hub
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}


	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StopHub(h);

	IncrementServerConfigRevision(s);

	DelHub(c, h);
	ReleaseHub(h);

	ALog(a, NULL, "LA_DELETE_HUB", t->HubName);

	return ERR_NO_ERROR;
}

// Enumerate hubs
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	FreeRpcEnumHub(t);

	Zero(t, sizeof(RPC_ENUM_HUB));

	LockHubList(c);
	{
		UINT i, num, j;

		num = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);

			Lock(h->lock);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// This hub is not listed
			}
			else
			{
				// This hub is listed
				num++;
			}
		}

		t->NumHub = num;

		t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * num);

		i = 0;
		for (j = 0;j < LIST_NUM(c->HubList);j++)
		{
			HUB *h = LIST_DATA(c->HubList, j);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// This hub is not listed
			}
			else
			{
				// This hub is listed
				RPC_ENUM_HUB_ITEM *e = &t->Hubs[i++];

				StrCpy(e->HubName, sizeof(e->HubName), h->Name);
				e->Online = h->Offline ? false : true;
				e->HubType = h->Type;

				e->NumSessions = LIST_NUM(h->SessionList);

				LockHashList(h->MacHashTable);
				{
					e->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
				}
				UnlockHashList(h->MacHashTable);

				LockList(h->IpTable);
				{
					e->NumIpTables = LIST_NUM(h->IpTable);
				}
				UnlockList(h->IpTable);

				if (h->HubDb != NULL)
				{
					LockList(h->HubDb->UserList);
					{
						e->NumUsers = LIST_NUM(h->HubDb->UserList);
					}
					UnlockList(h->HubDb->UserList);

					LockList(h->HubDb->GroupList);
					{
						e->NumGroups = LIST_NUM(h->HubDb->GroupList);
					}
					UnlockList(h->HubDb->GroupList);
				}

				e->LastCommTime = h->LastCommTime;
				e->LastLoginTime = h->LastLoginTime;
				e->NumLogin = h->NumLogin;
				e->CreatedTime = h->CreatedTime;

				Lock(h->TrafficLock);
				{
					Copy(&e->Traffic, h->Traffic, sizeof(TRAFFIC));
				}
				Unlock(h->TrafficLock);

				e->IsTrafficFilled = true;
			}

			Unlock(h->lock);
		}
	}
	UnlockHubList(c);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UINT i, j, k;
		LockList(s->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				LockList(f->HubList);
				{
					if (f->Me == false)
					{
						for (j = 0;j < LIST_NUM(f->HubList);j++)
						{
							HUB_LIST *o = LIST_DATA(f->HubList, j);

							for (k = 0;k < t->NumHub;k++)
							{
								RPC_ENUM_HUB_ITEM *e = &t->Hubs[k];

								if (StrCmpi(e->HubName, o->Name) == 0)
								{
									e->NumIpTables += o->NumIpTables;
									e->NumMacTables += o->NumMacTables;
									e->NumSessions += o->NumSessions;
								}
							}
						}
					}
				}
				UnlockList(f->HubList);
			}
		}
		UnlockList(s->FarmMemberList);
	}

	return ERR_NO_ERROR;
}

// Get hub configuration
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	HUB *h;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	Zero(t, sizeof(RPC_CREATE_HUB));

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->HubOption.MaxSession = h->Option->MaxSession;
		t->HubOption.NoEnum = h->Option->NoEnum;
		t->HubType = h->Type;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ret;
}

// Set hub configuration
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}


	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		if (t->HubType != HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (t->HubType == HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (h->Type != t->HubType)
	{
		ReleaseHub(h);
		return ERR_NOT_SUPPORTED;
	}

	// For JSON-RPC
	if (StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_admin_password") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	// Is the password to be set blank
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		HashPassword(hash1, ADMINISTRATOR_USERNAME, "");
		Sha0(hash2, "", 0);

		if (Cmp(t->HashedPassword, hash2, SHA1_SIZE) == 0 || Cmp(t->SecurePassword, hash1, SHA1_SIZE) == 0)
		{
			if (a->ServerAdmin == false && a->Rpc->Sock->RemoteIP.addr[0] != 127)
			{
				// Refuse to set a blank password to hub admin from remote host
				ReleaseHub(h);
				return ERR_INVALID_PARAMETER;
			}
		}
	}

	Lock(h->lock);
	{
		if (a->ServerAdmin == false && h->Type != t->HubType)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			h->Type = t->HubType;
			h->Option->MaxSession = t->HubOption.MaxSession;
			h->Option->NoEnum = t->HubOption.NoEnum;
			if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
				IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
			{
				Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
				Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);
			}
		}
	}
	Unlock(h->lock);

	if (t->Online)
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_online") == 0)
		{
			SetHubOnline(h);
		}
	}
	else
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_offline") == 0)
		{
			SetHubOffline(h);
		}
	}

	if (h->Type == HUB_TYPE_FARM_STATIC)
	{
		EnableSecureNAT(h, false);
	}

	h->CurrentVersion++;
	SiHubUpdateProc(h);

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_SET_HUB");

	ReleaseHub(h);

	return ret;
}

// Create a hub
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	HUB_OPTION o;
	UINT current_hub_num;
	bool b;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}



	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	SERVER_ADMIN_ONLY;

	Trim(t->HubName);
	if (StrLen(t->HubName) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (StartWith(t->HubName, ".") || EndWith(t->HubName, "."))
	{
		return ERR_INVALID_PARAMETER;
	}

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		if (t->HubType != HUB_TYPE_STANDALONE)
		{
			return ERR_INVALID_PARAMETER;
		}
	}
	else if (t->HubType != HUB_TYPE_FARM_DYNAMIC && t->HubType != HUB_TYPE_FARM_STATIC)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Create a hub object
	Zero(&o, sizeof(o));
	o.MaxSession = t->HubOption.MaxSession;
	o.NoEnum = t->HubOption.NoEnum;

	// Default setting for hub admin options
	SiSetDefaultHubOption(&o);

	LockList(c->HubList);
	{
		current_hub_num = LIST_NUM(c->HubList);
	}
	UnlockList(c->HubList);

	if (current_hub_num > GetServerCapsInt(a->Server, "i_max_hubs"))
	{
		return ERR_TOO_MANY_HUBS;
	}

	LockList(c->HubList);
	{
		b = IsHub(c, t->HubName);
	}
	UnlockList(c->HubList);

	if (b)
	{
		return ERR_HUB_ALREADY_EXISTS;
	}

	ALog(a, NULL, "LA_CREATE_HUB", t->HubName);

	// For JSON-RPC
	if ((IsZero(t->HashedPassword, sizeof(t->HashedPassword)) &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword))) ||
		StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	h = NewHub(c, t->HubName, &o);
	Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
	Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);

	h->Type = t->HubType;

	AddHub(c, h);

	if (t->Online)
	{
		h->Offline = true;
		SetHubOnline(h);
	}
	else
	{
		h->Offline = false;
		SetHubOffline(h);
	}

	h->CreatedTime = SystemTime64();

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Set cipher for SSL to the server
UINT StSetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	if (IsEmptyStr(t->String))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	StrUpper(t->String);

	ALog(a, NULL, "LA_SET_SERVER_CIPHER", t->String);

	Lock(c->lock);
	{
		SetCedarCipherList(c, t->String);
	}
	Unlock(c->lock);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get cipher for SSL
UINT StGetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		t->String = CopyStr(c->CipherList);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

// Get list of available ciphers for SSL
UINT StGetServerCipherList(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		UINT i;
		TOKEN_LIST *ciphers = GetCipherList();
		if (ciphers->NumTokens > 0)
		{
			UINT size = StrSize(ciphers->Token[0]);
			t->String = Malloc(size);
			StrCpy(t->String, size, ciphers->Token[0]);
			i = 1;

			for (; i < ciphers->NumTokens; i++)
			{
				// We use StrSize() because we need the extra space for ';'
				size += StrSize(ciphers->Token[i]);
				t->String = ReAlloc(t->String, size);
				StrCat(t->String, size, ";");
				StrCat(t->String, size, ciphers->Token[i]);
			}
		}

		FreeToken(ciphers);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

// Get the server certification
UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	bool admin;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	bool is_vgs_cert = false;

	admin = a->ServerAdmin;

	FreeRpcKeyPair(t);
	Zero(t, sizeof(RPC_KEY_PAIR));

	Lock(c->lock);
	{

		t->Cert = CloneX(c->ServerX);
		if (admin && is_vgs_cert == false)
		{
			t->Key = CloneK(c->ServerK);
		}
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

// Set the server certification
UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	if (t->Cert == NULL || t->Key == NULL)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (t->Cert->is_compatible_bit == false)
	{
		return ERR_NOT_RSA_1024;
	}

	if (CheckXandK(t->Cert, t->Key) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	t->Flag1 = 1;
	if (t->Cert->root_cert == false)
	{
		if (DownloadAndSaveIntermediateCertificatesIfNecessary(t->Cert) == false)
		{
			t->Flag1 = 0;
		}
	}

	SetCedarCert(c, t->Cert, t->Key);

	ALog(a, NULL, "LA_SET_SERVER_CERT");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get status of connection to cluster controller
UINT StGetFarmConnectionStatus(ADMIN *a, RPC_FARM_CONNECTION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	FARM_CONTROLLER *fc;

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
	{
		return ERR_NOT_FARM_MEMBER;
	}

	Zero(t, sizeof(RPC_FARM_CONNECTION_STATUS));

	fc = s->FarmController;

	Lock(fc->lock);
	{
		if (fc->Sock != NULL)
		{
			t->Ip = IPToUINT(&fc->Sock->RemoteIP);
			t->Port = fc->Sock->RemotePort;
		}

		t->Online = fc->Online;
		t->LastError = ERR_NO_ERROR;

		if (t->Online == false)
		{
			t->LastError = fc->LastError;
		}
		else
		{
			t->CurrentConnectedTime = fc->CurrentConnectedTime;
		}

		t->StartedTime = fc->StartedTime;
		t->FirstConnectedTime = fc->FirstConnectedTime;

		t->NumConnected = fc->NumConnected;
		t->NumTry = fc->NumTry;
		t->NumFailed = fc->NumFailed;
	}
	Unlock(fc->lock);

	return ERR_NO_ERROR;
}

// Enumerate cluster members
UINT StEnumFarmMember(ADMIN *a, RPC_ENUM_FARM *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;

	FreeRpcEnumFarm(t);
	Zero(t, sizeof(RPC_ENUM_FARM));

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	Zero(t, sizeof(RPC_ENUM_FARM));

	LockList(s->FarmMemberList);
	{
		t->NumFarm = LIST_NUM(s->FarmMemberList);
		t->Farms = ZeroMalloc(sizeof(RPC_ENUM_FARM_ITEM) * t->NumFarm);

		for (i = 0;i < t->NumFarm;i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

			e->Id = POINTER_TO_KEY(f);
			e->Controller = f->Me;

			if (e->Controller)
			{
				e->ConnectedTime = TickToTime(c->CreatedTick);
				e->Ip = 0x0100007f;
				GetMachineName(e->Hostname, sizeof(e->Hostname));
				e->Point = f->Point;
				e->NumSessions = Count(c->CurrentSessions);
				e->NumTcpConnections = Count(c->CurrentTcpConnections);

				e->AssignedBridgeLicense = Count(c->AssignedBridgeLicense);
				e->AssignedClientLicense = Count(c->AssignedClientLicense);
			}
			else
			{
				e->ConnectedTime = f->ConnectedTime;
				e->Ip = f->Ip;
				StrCpy(e->Hostname, sizeof(e->Hostname), f->hostname);
				e->Point = f->Point;
				e->NumSessions = f->NumSessions;
				e->NumTcpConnections = f->NumTcpConnections;

				e->AssignedBridgeLicense = f->AssignedBridgeLicense;
				e->AssignedClientLicense = f->AssignedClientLicense;
			}
			e->NumHubs = LIST_NUM(f->HubList);
		}
	}
	UnlockList(s->FarmMemberList);

	return ERR_NO_ERROR;
}

// Get cluster member information
UINT StGetFarmInfo(ADMIN *a, RPC_FARM_INFO *t)
{
	SERVER *s = a->Server;
	UINT id = t->Id;
	UINT i;
	UINT ret = ERR_NO_ERROR;

	FreeRpcFarmInfo(t);
	Zero(t, sizeof(RPC_FARM_INFO));

	if (s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return ERR_NOT_FARM_CONTROLLER;
	}

	LockList(s->FarmMemberList);
	{
		if (IsInListKey(s->FarmMemberList, id))
		{
			FARM_MEMBER *f = ListKeyToPointer(s->FarmMemberList, id);

			t->Id = id;
			t->Controller = f->Me;
			t->Weight = f->Weight;

			LockList(f->HubList);
			{
				t->NumFarmHub = LIST_NUM(f->HubList);
				t->FarmHubs = ZeroMalloc(sizeof(RPC_FARM_HUB) * t->NumFarmHub);

				for (i = 0;i < t->NumFarmHub;i++)
				{
					RPC_FARM_HUB *h = &t->FarmHubs[i];
					HUB_LIST *hh = LIST_DATA(f->HubList, i);

					h->DynamicHub = hh->DynamicHub;
					StrCpy(h->HubName, sizeof(h->HubName), hh->Name);
				}
			}
			UnlockList(f->HubList);

			if (t->Controller)
			{
				t->ConnectedTime = TickToTime(s->Cedar->CreatedTick);
				t->Ip = 0x0100007f;
				GetMachineName(t->Hostname, sizeof(t->Hostname));
				t->Point = f->Point;

				LockList(s->ServerListenerList);
				{
					UINT i, n;
					t->NumPort = 0;
					for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
					{
						SERVER_LISTENER *o = LIST_DATA(s->ServerListenerList, i);
						if (o->Enabled)
						{
							t->NumPort++;
						}
					}
					t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
					n = 0;
					for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
					{
						SERVER_LISTENER *o = LIST_DATA(s->ServerListenerList, i);
						if (o->Enabled)
						{
							t->Ports[n++] = o->Port;
						}
					}
				}
				UnlockList(s->ServerListenerList);

				t->ServerCert = CloneX(s->Cedar->ServerX);
				t->NumSessions = Count(s->Cedar->CurrentSessions);
				t->NumTcpConnections = Count(s->Cedar->CurrentTcpConnections);
			}
			else
			{
				t->ConnectedTime = f->ConnectedTime;
				t->Ip = f->Ip;
				StrCpy(t->Hostname, sizeof(t->Hostname), f->hostname);
				t->Point = f->Point;
				t->NumPort = f->NumPort;
				t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
				Copy(t->Ports, f->Ports, sizeof(UINT) * t->NumPort);
				t->ServerCert = CloneX(f->ServerCert);
				t->NumSessions = f->NumSessions;
				t->NumTcpConnections = f->NumTcpConnections;
			}
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(s->FarmMemberList);

	return ret;
}

// Get clustering configuration
UINT StGetFarmSetting(ADMIN *a, RPC_FARM *t)
{
	SERVER *s;
	FreeRpcFarm(t);
	Zero(t, sizeof(RPC_FARM));

	s = a->Server;
	t->ServerType = s->ServerType;
	t->ControllerOnly = s->ControllerOnly;
	t->Weight = s->Weight;

	if (t->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		t->NumPort = s->NumPublicPort;
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		Copy(t->Ports, s->PublicPorts, sizeof(UINT) * t->NumPort);
		t->PublicIp = s->PublicIp;
		StrCpy(t->ControllerName, sizeof(t->ControllerName), s->ControllerName);
		t->ControllerPort = s->ControllerPort;
	}
	else
	{
		t->NumPort = 0;
		t->Ports = ZeroMalloc(0);
	}

	return ERR_NO_ERROR;
}

// Set clustering configuration
UINT StSetFarmSetting(ADMIN *a, RPC_FARM *t)
{
	bool cluster_allowed = false;

	SERVER_ADMIN_ONLY;
	NO_SUPPORT_FOR_BRIDGE;


	cluster_allowed = GetServerCapsInt(a->Server, "b_support_cluster");

	if (t->ServerType != SERVER_TYPE_STANDALONE && cluster_allowed == false)
	{
		// When clustering function is disabled, deny turning into clustering mode
		return ERR_NOT_SUPPORTED;
	}

	if (IsZero(t->MemberPassword, sizeof(t->MemberPassword)))
	{
		if (IsEmptyStr(t->MemberPasswordPlaintext) == false)
		{
			// For JSON-RPC
			HashAdminPassword(t->MemberPassword, t->MemberPasswordPlaintext);
		}
	}

	ALog(a, NULL, "LA_SET_FARM_SETTING");

	IncrementServerConfigRevision(a->Server);

	SiSetServerType(a->Server, t->ServerType, t->PublicIp, t->NumPort, t->Ports,
		t->ControllerName, t->ControllerPort, t->MemberPassword, t->Weight, t->ControllerOnly);

	return ERR_NO_ERROR;
}

// Set server password
UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t)
{
	SERVER_ADMIN_ONLY;

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)))
	{
		// For JSON-RPC
		HashAdminPassword(t->HashedPassword, t->PlainTextPassword);
	}

	Copy(a->Server->HashedPassword, t->HashedPassword, SHA1_SIZE);

	ALog(a, NULL, "LA_SET_SERVER_PASSWORD");

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Enable / Disable listener
UINT StEnableListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
	{
		if (t->Enable)
		{
			if (SiEnableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_ENABLE_LISTENER", t->Port);
			}
		}
		else
		{
			if (SiDisableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_DISABLE_LISTENER", t->Port);
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	IncrementServerConfigRevision(a->Server);

	SleepThread(250);

	return ret;
}

// Delete a listener
UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
	{
		if (SiDeleteListener(a->Server, t->Port) == false)
		{
			ret = ERR_LISTENER_NOT_FOUND;
		}
		else
		{
			ALog(a, NULL, "LA_DELETE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ret;
}

// Enumerating listeners
UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t)
{
	CEDAR *c = a->Server->Cedar;
	UINT i;

	FreeRpcListenerList(t);
	Zero(t, sizeof(RPC_LISTENER_LIST));

	LockList(a->Server->ServerListenerList);
	{
		t->NumPort = LIST_NUM(a->Server->ServerListenerList);
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
		t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);

		for (i = 0;i < t->NumPort;i++)
		{
			SERVER_LISTENER *o = LIST_DATA(a->Server->ServerListenerList, i);

			t->Ports[i] = o->Port;
			t->Enables[i] = o->Enabled;
			if (t->Enables[i])
			{
				if (o->Listener->Status == LISTENER_STATUS_TRYING)
				{
					t->Errors[i] = true;
				}
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ERR_NO_ERROR;
}

// Create a listener
UINT StCreateListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;
	CEDAR *c = a->Server->Cedar;

	if (t->Port == 0 || t->Port > 65535)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
	{
		if (SiAddListener(a->Server, t->Port, t->Enable) == false)
		{
			ret = ERR_LISTENER_ALREADY_EXISTS;
		}
		else
		{
			ALog(a, NULL, "LA_CREATE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	SleepThread(250);

	return ret;
}

// Set UDP ports the server should listen on
UINT StSetPortsUDP(ADMIN *a, RPC_PORTS *t)
{
	UINT i;
	LIST *ports, *server_ports;

	SERVER_ADMIN_ONLY;

	ports = NewIntList(true);

	for (i = 0; i < t->Num; ++i)
	{
		const UINT port = t->Ports[i];
		if (port < 1 || port > 65535)
		{
			ReleaseIntList(ports);
			return ERR_INVALID_PARAMETER;
		}

		AddIntDistinct(ports, port);
	}

	server_ports = a->Server->PortsUDP;

	LockList(server_ports);
	{
		char tmp[MAX_SIZE];
		wchar_t str[MAX_SIZE];

		for (i = 0; i < LIST_NUM(server_ports); ++i)
		{
			Free(LIST_DATA(server_ports, i));
		}
		DeleteAll(server_ports);

		for (i = 0; i < LIST_NUM(ports); ++i)
		{
			const UINT port = *(UINT *)LIST_DATA(ports, i);
			AddInt(server_ports, port);
		}

		ProtoSetUdpPorts(a->Server->Proto, server_ports);

		IntListToStr(tmp, sizeof(tmp), server_ports, ", ");
		StrToUni(str, sizeof(str), tmp);
		ALog(a, NULL, "LA_SET_PORTS_UDP", str);
	}
	UnlockList(server_ports);

	ReleaseIntList(ports);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// List UDP ports the server is listening on
UINT StGetPortsUDP(ADMIN *a, RPC_PORTS *t)
{
	LIST *ports = a->Server->PortsUDP;

	FreeRpcPorts(t);

	LockList(ports);
	{
		t->Num = LIST_NUM(ports);
		t->Ports = t->Num > 0 ? Malloc(sizeof(UINT) * t->Num) : NULL;
		if (t->Ports != NULL)
		{
			UINT i;
			for (i = 0; i < t->Num; ++i)
			{
				const UINT port = *(UINT *)LIST_DATA(ports, i);
				t->Ports[i] = port;
			}
		}
	}
	UnlockList(ports);

	return ERR_NO_ERROR;
}

UINT StGetProtoOptions(ADMIN *a, RPC_PROTO_OPTIONS *t)
{
	PROTO *proto = a->Server->Proto;
	PROTO_CONTAINER *container, tmp;
	UINT ret = ERR_NO_ERROR;
	LIST *options;

	if (proto == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	tmp.Name = t->Protocol;

	container = Search(proto->Containers, &tmp);
	if (container == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	options = container->Options;
	LockList(options);
	{
		UINT i;

		t->Num = LIST_NUM(options);
		t->Options = Malloc(sizeof(PROTO_OPTION) * t->Num);

		for (i = 0; i < t->Num; ++i)
		{
			const PROTO_OPTION *option = LIST_DATA(options, i);
			PROTO_OPTION *rpc_option = &t->Options[i];

			switch (option->Type)
			{
			case PROTO_OPTION_BOOL:
				rpc_option->Bool = option->Bool;
				break;
			case PROTO_OPTION_STRING:
				rpc_option->String = CopyStr(option->String);
				break;
			default:
				Debug("StGetProtoOptions(): unhandled option type %u!\n", option->Type);
				ret = ERR_INTERNAL_ERROR;
			}

			if (ret == ERR_NO_ERROR)
			{
				rpc_option->Name = CopyStr(option->Name);
				rpc_option->Type = option->Type;
			}
			else
			{
				break;
			}
		}
	}
	UnlockList(options);

	return ret;
}

UINT StSetProtoOptions(ADMIN *a, RPC_PROTO_OPTIONS *t)
{
	PROTO *proto = a->Server->Proto;
	PROTO_CONTAINER *container, tmp;
	UINT ret = ERR_NO_ERROR;
	bool changed = false;
	LIST *options;

	SERVER_ADMIN_ONLY;

	if (proto == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	tmp.Name = t->Protocol;

	container = Search(proto->Containers, &tmp);
	if (container == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	options = container->Options;
	LockList(options);
	{
		UINT i;
		for (i = 0; i < t->Num; ++i)
		{
			PROTO_OPTION *rpc_option = &t->Options[i];
			PROTO_OPTION *option = Search(options, rpc_option);
			if (option == NULL || rpc_option->Type != option->Type)
			{
				ret = ERR_INVALID_PARAMETER;
				break;
			}

			switch (option->Type)
			{
				case PROTO_OPTION_BOOL:
					option->Bool = rpc_option->Bool;
					break;
				case PROTO_OPTION_STRING:
					Free(option->String);
					option->String = CopyStr(rpc_option->String);
					break;
				default:
					Debug("StSetProtoOptions(): unhandled option type %u!\n", option->Type);
					ret = ERR_INTERNAL_ERROR;
			}

			if (ret == ERR_NO_ERROR)
			{
				changed = true;
			}
			else
			{
				break;
			}
		}
	}
	UnlockList(options);

	if (changed)
	{
		ALog(a, NULL, "LA_SET_PROTO_OPTIONS", t->Protocol);
		IncrementServerConfigRevision(a->Server);
	}

	return ret;
}

// Get server status
UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t)
{
	CEDAR *c;
	UINT i;

	c = a->Server->Cedar;

	Zero(t, sizeof(RPC_SERVER_STATUS));

	Lock(c->TrafficLock);
	{
		Copy(&t->Traffic, c->Traffic, sizeof(TRAFFIC));
	}
	Unlock(c->TrafficLock);

	GetMemInfo(&t->MemInfo);

	t->ServerType = a->Server->ServerType;
	t->NumTcpConnections = t->NumTcpConnectionsLocal = t->NumTcpConnectionsRemote = 0;
	t->NumSessionsTotal = t->NumSessionsLocal = t->NumSessionsRemote = 0;

	t->NumTcpConnectionsLocal = Count(c->CurrentTcpConnections);

	if (a->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		LockList(a->Server->FarmMemberList);
		{
			for (i = 0;i < LIST_NUM(a->Server->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(a->Server->FarmMemberList, i);

				if (f->Me == false)
				{
					t->NumTcpConnectionsRemote += f->NumTcpConnections;
					t->NumSessionsRemote += f->NumSessions;
					AddTraffic(&t->Traffic, &f->Traffic);
				}
			}
		}
		UnlockList(a->Server->FarmMemberList);
	}

	t->NumMacTables = t->NumIpTables = t->NumUsers = t->NumGroups = 0;

	// The number of hubs
	LockList(c->HubList);
	{
		t->NumHubTotal = LIST_NUM(c->HubList);

		t->NumHubStandalone = t->NumHubDynamic = t->NumHubStatic = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				switch (h->Type)
				{
				case HUB_TYPE_STANDALONE:
					t->NumHubStandalone++;
					break;

				case HUB_TYPE_FARM_STATIC:
					t->NumHubStatic++;
					break;

				case HUB_TYPE_FARM_DYNAMIC:
					t->NumHubDynamic++;
					break;
				}
			}

			t->NumMacTables += HASH_LIST_NUM(h->MacHashTable);
			t->NumIpTables += LIST_NUM(h->IpTable);

			if (h->HubDb != NULL)
			{
				t->NumUsers += LIST_NUM(h->HubDb->UserList);
				t->NumGroups += LIST_NUM(h->HubDb->GroupList);
			}

			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	// The number of sessions
	t->NumSessionsLocal = Count(c->CurrentSessions);
	t->NumSessionsTotal = t->NumSessionsLocal + t->NumSessionsRemote;
	t->NumTcpConnections = t->NumTcpConnectionsLocal + t->NumTcpConnectionsRemote;

	t->AssignedBridgeLicenses = Count(c->AssignedBridgeLicense);
	t->AssignedClientLicenses = Count(c->AssignedClientLicense);

	t->AssignedBridgeLicensesTotal = a->Server->CurrentAssignedBridgeLicense;
	t->AssignedClientLicensesTotal = a->Server->CurrentAssignedClientLicense;

	t->CurrentTick = Tick64();
	t->CurrentTime = SystemTime64();

	t->StartTime = a->Server->StartTime;

	return ERR_NO_ERROR;
}

// Get server information
UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t)
{
	CEDAR *c;
	OS_INFO *info;
	SYSTEMTIME st;
	// Validate arguments
	if (a == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	FreeRpcServerInfo(t);
	Zero(t, sizeof(RPC_SERVER_INFO));

	c = a->Server->Cedar;

	GetServerProductName(a->Server, t->ServerProductName, sizeof(t->ServerProductName));

	StrCpy(t->ServerVersionString, sizeof(t->ServerVersionString), c->VerString);
	StrCpy(t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString), c->BuildInfo);
	t->ServerVerInt = c->Version;
	t->ServerBuildInt = c->Build;
	GetMachineName(t->ServerHostName, sizeof(t->ServerHostName));
	t->ServerType = c->Server->ServerType;

	Zero(&st, sizeof(st));
	st.wYear = BUILD_DATE_Y;
	st.wMonth = BUILD_DATE_M;
	st.wDay = BUILD_DATE_D;
	st.wHour = BUILD_DATE_HO;
	st.wMinute = BUILD_DATE_MI;
	st.wSecond = BUILD_DATE_SE;

	t->ServerBuildDate = SystemToUINT64(&st);
	StrCpy(t->ServerFamilyName, sizeof(t->ServerFamilyName), UPDATE_FAMILY_NAME);

	info = GetOsInfo();
	if (info != NULL)
	{
		CopyOsInfo(&t->OsInfo, info);
	}

	return ERR_NO_ERROR;
}

// Copy OS_INFO
void CopyOsInfo(OS_INFO *dst, OS_INFO *info)
{
	// Validate arguments
	if (info == NULL || dst == NULL)
	{
		return;
	}

	dst->OsType = info->OsType;
	dst->OsServicePack = info->OsServicePack;
	dst->OsSystemName = CopyStr(info->OsSystemName);
	dst->OsProductName = CopyStr(info->OsProductName);
	dst->OsVendorName = CopyStr(info->OsVendorName);
	dst->OsVersion = CopyStr(info->OsVersion);
	dst->KernelName = CopyStr(info->KernelName);
	dst->KernelVersion = CopyStr(info->KernelVersion);
}

// OPENVPN_SSTP_CONFIG
void InOpenVpnSstpConfig(OPENVPN_SSTP_CONFIG *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(OPENVPN_SSTP_CONFIG));

	t->EnableOpenVPN = PackGetBool(p, "EnableOpenVPN");
	t->EnableSSTP = PackGetBool(p, "EnableSSTP");
}
void OutOpenVpnSstpConfig(PACK *p, OPENVPN_SSTP_CONFIG *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "EnableOpenVPN", t->EnableOpenVPN);
	PackAddBool(p, "EnableSSTP", t->EnableSSTP);
}

// DDNS_CLIENT_STATUS
void InDDnsClientStatus(DDNS_CLIENT_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(DDNS_CLIENT_STATUS));

	t->Err_IPv4 = PackGetInt(p, "Err_IPv4");
	t->Err_IPv6 = PackGetInt(p, "Err_IPv6");

	PackGetStr(p, "CurrentHostName", t->CurrentHostName, sizeof(t->CurrentHostName));
	PackGetStr(p, "CurrentFqdn", t->CurrentFqdn, sizeof(t->CurrentFqdn));
	PackGetStr(p, "DnsSuffix", t->DnsSuffix, sizeof(t->DnsSuffix));
	PackGetStr(p, "CurrentIPv4", t->CurrentIPv4, sizeof(t->CurrentIPv4));
	PackGetStr(p, "CurrentIPv6", t->CurrentIPv6, sizeof(t->CurrentIPv6));
	PackGetUniStr(p, "ErrStr_IPv4", t->ErrStr_IPv4, sizeof(t->ErrStr_IPv4));
	PackGetUniStr(p, "ErrStr_IPv6", t->ErrStr_IPv6, sizeof(t->ErrStr_IPv6));
}
void OutDDnsClientStatus(PACK *p, DDNS_CLIENT_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Err_IPv4", t->Err_IPv4);
	PackAddInt(p, "Err_IPv6", t->Err_IPv6);
	PackAddStr(p, "CurrentHostName", t->CurrentHostName);
	PackAddStr(p, "CurrentFqdn", t->CurrentFqdn);
	PackAddStr(p, "DnsSuffix", t->DnsSuffix);
	PackAddStr(p, "CurrentIPv4", t->CurrentIPv4);
	PackAddStr(p, "CurrentIPv6", t->CurrentIPv6);
	PackAddUniStr(p, "ErrStr_IPv4", t->ErrStr_IPv4);
	PackAddUniStr(p, "ErrStr_IPv6", t->ErrStr_IPv6);
}

// INTERNET_SETTING
void InRpcInternetSetting(INTERNET_SETTING *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->ProxyType = PackGetInt(p, "ProxyType");
	PackGetStr(p, "ProxyHostName", t->ProxyHostName, sizeof(t->ProxyHostName));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
	PackGetStr(p, "ProxyUsername", t->ProxyUsername, sizeof(t->ProxyUsername));
	PackGetStr(p, "ProxyPassword", t->ProxyPassword, sizeof(t->ProxyPassword));
	PackGetStr(p, "CustomHttpHeader", t->CustomHttpHeader, sizeof(t->CustomHttpHeader));
}
void OutRpcInternetSetting(PACK *p, INTERNET_SETTING *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ProxyType", t->ProxyType);
	PackAddStr(p, "ProxyHostName", t->ProxyHostName);
	PackAddInt(p, "ProxyPort", t->ProxyPort);
	PackAddStr(p, "ProxyUsername", t->ProxyUsername);
	PackAddStr(p, "ProxyPassword", t->ProxyPassword);
	PackAddStr(p, "CustomHttpHeader", t->CustomHttpHeader);
}

// RPC_AZURE_STATUS
void InRpcAzureStatus(RPC_AZURE_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_AZURE_STATUS));

	t->IsConnected = PackGetBool(p, "IsConnected");
	t->IsEnabled = PackGetBool(p, "IsEnabled");
}
void OutRpcAzureStatus(PACK *p, RPC_AZURE_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "IsConnected", t->IsConnected);
	PackAddBool(p, "IsEnabled", t->IsEnabled);
}

// RPC_SPECIAL_LISTENER
void InRpcSpecialListener(RPC_SPECIAL_LISTENER *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SPECIAL_LISTENER));

	t->VpnOverIcmpListener = PackGetBool(p, "VpnOverIcmpListener");
	t->VpnOverDnsListener = PackGetBool(p, "VpnOverDnsListener");
}
void OutRpcSpecialListener(PACK *p, RPC_SPECIAL_LISTENER *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "VpnOverIcmpListener", t->VpnOverIcmpListener);
	PackAddBool(p, "VpnOverDnsListener", t->VpnOverDnsListener);
}


// ETHERIP_ID
void InEtherIpId(ETHERIP_ID *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(ETHERIP_ID));

	PackGetStr(p, "Id", t->Id, sizeof(t->Id));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "UserName", t->UserName, sizeof(t->UserName));
	PackGetStr(p, "Password", t->Password, sizeof(t->Password));
}
void OutEtherIpId(PACK *p, ETHERIP_ID *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Id", t->Id);
	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "UserName", t->UserName);
	PackAddStr(p, "Password", t->Password);
}

// RPC_ENUM_ETHERIP_ID
void InRpcEnumEtherIpId(RPC_ENUM_ETHERIP_ID *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETHERIP_ID));

	t->NumItem = PackGetInt(p, "NumItem");
	t->IdList = ZeroMalloc(sizeof(ETHERIP_ID) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		ETHERIP_ID *e = &t->IdList[i];

		PackGetStrEx(p, "Id", e->Id, sizeof(e->Id), i);
		PackGetStrEx(p, "HubName", e->HubName, sizeof(e->HubName), i);
		PackGetStrEx(p, "UserName", e->UserName, sizeof(e->UserName), i);
		PackGetStrEx(p, "Password", e->Password, sizeof(e->Password), i);
	}
}
void OutRpcEnumEtherIpId(PACK *p, RPC_ENUM_ETHERIP_ID *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "Settings");
	for (i = 0;i < t->NumItem;i++)
	{
		ETHERIP_ID *e = &t->IdList[i];

		PackAddStrEx(p, "Id", e->Id, i, t->NumItem);
		PackAddStrEx(p, "HubName", e->HubName, i, t->NumItem);
		PackAddStrEx(p, "UserName", e->UserName, i, t->NumItem);
		PackAddStrEx(p, "Password", e->Password, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumEtherIpId(RPC_ENUM_ETHERIP_ID *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->IdList);
}

// IPSEC_SERVICES
void InIPsecServices(IPSEC_SERVICES *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(IPSEC_SERVICES));

	t->L2TP_Raw = PackGetBool(p, "L2TP_Raw");
	t->L2TP_IPsec = PackGetBool(p, "L2TP_IPsec");
	t->EtherIP_IPsec = PackGetBool(p, "EtherIP_IPsec");

	PackGetStr(p, "IPsec_Secret", t->IPsec_Secret, sizeof(t->IPsec_Secret));
	PackGetStr(p, "L2TP_DefaultHub", t->L2TP_DefaultHub, sizeof(t->L2TP_DefaultHub));
}
void OutIPsecServices(PACK *p, IPSEC_SERVICES *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "L2TP_Raw", t->L2TP_Raw);
	PackAddBool(p, "L2TP_IPsec", t->L2TP_IPsec);
	PackAddBool(p, "EtherIP_IPsec", t->EtherIP_IPsec);

	PackAddStr(p, "IPsec_Secret", t->IPsec_Secret);
	PackAddStr(p, "L2TP_DefaultHub", t->L2TP_DefaultHub);
}

// RPC_WINVER
void InRpcWinVer(RPC_WINVER *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_WINVER));

	t->IsWindows = PackGetBool(p, "V_IsWindows");
	t->IsNT = PackGetBool(p, "V_IsNT");
	t->IsServer = PackGetBool(p, "V_IsServer");
	t->IsBeta = PackGetBool(p, "V_IsBeta");
	t->VerMajor = PackGetInt(p, "V_VerMajor");
	t->VerMinor = PackGetInt(p, "V_VerMinor");
	t->Build = PackGetInt(p, "V_Build");
	t->ServicePack = PackGetInt(p, "V_ServicePack");
	PackGetStr(p, "V_Title", t->Title, sizeof(t->Title));
}
void OutRpcWinVer(PACK *p, RPC_WINVER *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "V_IsWindows", t->IsWindows);
	PackAddBool(p, "V_IsNT", t->IsNT);
	PackAddBool(p, "V_IsServer", t->IsServer);
	PackAddBool(p, "V_IsBeta", t->IsBeta);
	PackAddInt(p, "V_VerMajor", t->VerMajor);
	PackAddInt(p, "V_VerMinor", t->VerMinor);
	PackAddInt(p, "V_Build", t->Build);
	PackAddInt(p, "V_ServicePack", t->ServicePack);
	PackAddStr(p, "V_Title", t->Title);
}

// RPC_MSG
void InRpcMsg(RPC_MSG *t, PACK *p)
{
	UINT size;
	char *utf8;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_MSG));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	size = PackGetDataSize(p, "Msg");
	utf8 = ZeroMalloc(size + 8);
	PackGetData(p, "Msg", utf8);
	t->Msg = CopyUtfToUni(utf8);
	Free(utf8);
}
void OutRpcMsg(PACK *p, RPC_MSG *t)
{
	UINT size;
	char *utf8;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	utf8 = CopyUniToUtf(t->Msg);
	size = StrLen(utf8);
	PackAddData(p, "Msg", utf8, size);
	Free(utf8);
}
void FreeRpcMsg(RPC_MSG *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Msg);
}

// RPC_ENUM_ETH_VLAN
void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	t->NumItem = PackGetIndexCount(p, "DeviceName");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "Guid", e->Guid, sizeof(e->Guid), i);
		PackGetStrEx(p, "DeviceInstanceId", e->DeviceInstanceId, sizeof(e->DeviceInstanceId), i);
		PackGetStrEx(p, "DriverName", e->DriverName, sizeof(e->DriverName), i);
		PackGetStrEx(p, "DriverType", e->DriverType, sizeof(e->DriverType), i);
		e->Support = PackGetBoolEx(p, "Support", i);
		e->Enabled = PackGetBoolEx(p, "Enabled", i);
	}
}
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "Devices");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "Guid", e->Guid, i, t->NumItem);
		PackAddStrEx(p, "DeviceInstanceId", e->DeviceInstanceId, i, t->NumItem);
		PackAddStrEx(p, "DriverName", e->DriverName, i, t->NumItem);
		PackAddStrEx(p, "DriverType", e->DriverType, i, t->NumItem);
		PackAddBoolEx(p, "Support", e->Support, i, t->NumItem);
		PackAddBoolEx(p, "Enabled", e->Enabled, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_LOG_FILE
void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "FilePath", e->FilePath, sizeof(e->FilePath), i);
		PackGetStrEx(p, "ServerName", e->ServerName, sizeof(e->ServerName), i);
		e->FileSize = PackGetIntEx(p, "FileSize", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
	}
}
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "LogFiles");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "FilePath", e->FilePath, i, t->NumItem);
		PackAddStrEx(p, "ServerName", e->ServerName, i, t->NumItem);
		PackAddIntEx(p, "FileSize", e->FileSize, i, t->NumItem);
		PackAddTime64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}
void AdjoinRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, RPC_ENUM_LOG_FILE *src)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (t == NULL || src == NULL)
	{
		return;
	}

	o = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);
		f->UpdatedTime = e->UpdatedTime;

		Add(o, f);
	}

	for (i = 0;i < src->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &src->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);
		StrCpy(f->ServerName, sizeof(f->ServerName), e->ServerName);
		f->UpdatedTime = e->UpdatedTime;

		Add(o, f);
	}

	FreeRpcEnumLogFile(t);

	Sort(o);

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));
	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		StrCpy(e->ServerName, sizeof(e->ServerName), f->ServerName);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}

// RPC_READ_LOG_FILE
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));
	PackGetStr(p, "FilePath", t->FilePath, sizeof(t->FilePath));
	PackGetStr(p, "ServerName", t->ServerName, sizeof(t->ServerName));
	t->Offset = PackGetInt(p, "Offset");

	t->Buffer = PackGetBuf(p, "Buffer");
}
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "FilePath", t->FilePath);
	PackAddStr(p, "ServerName", t->ServerName);
	PackAddInt(p, "Offset", t->Offset);

	if (t->Buffer != NULL)
	{
		PackAddBuf(p, "Buffer", t->Buffer);
	}
}
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->Buffer != NULL)
	{
		FreeBuf(t->Buffer);
	}
}

// RPC_AC_LIST
void InRpcAcList(RPC_AC_LIST *t, PACK *p)
{
	UINT i;
	LIST *o;
	UINT num;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_AC_LIST));
	o = NewAcList();

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	num = PackGetIndexCount(p, "IpAddress");

	for (i = 0;i < num;i++)
	{
		AC *ac = ZeroMalloc(sizeof(AC));

		ac->Id = PackGetIntEx(p, "Id", i);
		ac->Deny = PackGetBoolEx(p, "Deny", i);
		PackGetIpEx(p, "IpAddress", &ac->IpAddress, i);
		ac->Masked = PackGetBoolEx(p, "Masked", i);

		if (ac->Masked)
		{
			PackGetIpEx(p, "SubnetMask", &ac->SubnetMask, i);
		}

		ac->Priority = PackGetIntEx(p, "Priority", i);

		AddAc(o, ac);

		Free(ac);
	}

	t->o = o;
}
void OutRpcAcList(PACK *p, RPC_AC_LIST *t)
{
	UINT i, num;
	LIST *o;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	o = t->o;
	num = LIST_NUM(o);

	PackAddInt(p, "NumItem", num);

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "ACList");
	for (i = 0;i < num;i++)
	{
		AC *ac = LIST_DATA(o, i);

		PackAddIntEx(p, "Id", ac->Id, i, num);
		PackAddBoolEx(p, "Deny", ac->Deny, i, num);
		PackAddIpEx(p, "IpAddress", &ac->IpAddress, i, num);
		PackAddBoolEx(p, "Masked", ac->Masked, i, num);

		PackAddIpEx(p, "SubnetMask", &ac->SubnetMask, i, num);

		PackAddIntEx(p, "Priority", ac->Priority, i, num);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcAcList(RPC_AC_LIST *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeAcList(t->o);
}

// RPC_INT
void InRpcInt(RPC_INT *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_INT));
	t->IntValue = PackGetInt(p, "IntValue");
}
void OutRpcInt(PACK *p, RPC_INT *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "IntValue", t->IntValue);
}

// RPC_ENUM_CRL
void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumItem = PackGetInt(p, "NumItem");

	t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "CrlInfo", e->CrlInfo, sizeof(e->CrlInfo), i);
	}
}
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "CRLList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumItem);
		PackAddUniStrEx(p, "CrlInfo", e->CrlInfo, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumCrl(RPC_ENUM_CRL *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_CRL
void InRpcCrl(RPC_CRL *t, PACK *p)
{
	BUF *b;
	NAME *n;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	b = PackGetBuf(p, "Serial");
	t->Crl = ZeroMalloc(sizeof(CRL));
	if (b != NULL)
	{
		t->Crl->Serial = NewXSerial(b->Buf, b->Size);
		FreeBuf(b);
	}
	t->Crl->Name = ZeroMalloc(sizeof(NAME));
	n = t->Crl->Name;
	if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
	{
		n->CommonName = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Organization", tmp, sizeof(tmp)))
	{
		n->Organization = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Unit", tmp, sizeof(tmp)))
	{
		n->Unit = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Country", tmp, sizeof(tmp)))
	{
		n->Country = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "State", tmp, sizeof(tmp)))
	{
		n->State = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Local", tmp, sizeof(tmp)))
	{
		n->Local = CopyUniStr(tmp);
	}
	if (PackGetDataSize(p, "DigestMD5") == MD5_SIZE)
	{
		PackGetData(p, "DigestMD5", t->Crl->DigestMD5);
	}
	if (PackGetDataSize(p, "DigestSHA1") == SHA1_SIZE)
	{
		PackGetData(p, "DigestSHA1", t->Crl->DigestSHA1);
	}
}
void OutRpcCrl(PACK *p, RPC_CRL *t)
{
	NAME *n;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);

	if (t->Crl == NULL)
	{
		return;
	}

	if (t->Crl->Serial != NULL)
	{
		PackAddData(p, "Serial", t->Crl->Serial->data, t->Crl->Serial->size);
	}
	n = t->Crl->Name;
	if (n->CommonName != NULL)
	{
		PackAddUniStr(p, "CommonName", n->CommonName);
	}
	if (n->Organization != NULL)
	{
		PackAddUniStr(p, "Organization", n->Organization);
	}
	if (n->Unit != NULL)
	{
		PackAddUniStr(p, "Unit", n->Unit);
	}
	if (n->Country != NULL)
	{
		PackAddUniStr(p, "Country", n->Country);
	}
	if (n->State != NULL)
	{
		PackAddUniStr(p, "State", n->State);
	}
	if (n->Local != NULL)
	{
		PackAddUniStr(p, "Local", n->Local);
	}
	if (IsZero(t->Crl->DigestMD5, MD5_SIZE) == false)
	{
		PackAddData(p, "DigestMD5", t->Crl->DigestMD5, MD5_SIZE);
	}
	if (IsZero(t->Crl->DigestSHA1, SHA1_SIZE) == false)
	{
		PackAddData(p, "DigestSHA1", t->Crl->DigestSHA1, SHA1_SIZE);
	}
}
void FreeRpcCrl(RPC_CRL *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeCrl(t->Crl);
}

// RPC_ENUM_L3TABLE
void InRpcEnumL3Table(RPC_ENUM_L3TABLE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3TABLE));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Items = ZeroMalloc(sizeof(RPC_L3TABLE) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3TABLE *e = &t->Items[i];

		e->NetworkAddress = PackGetIp32Ex(p, "NetworkAddress", i);
		e->SubnetMask = PackGetIp32Ex(p, "SubnetMask", i);
		e->GatewayAddress = PackGetIp32Ex(p, "GatewayAddress", i);
		e->Metric = PackGetIntEx(p, "Metric", i);
	}
}
void OutRpcEnumL3Table(PACK *p, RPC_ENUM_L3TABLE *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "Name", t->Name);

	PackSetCurrentJsonGroupName(p, "L3Table");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3TABLE *e = &t->Items[i];

		PackAddIp32Ex(p, "NetworkAddress", e->NetworkAddress, i, t->NumItem);
		PackAddIp32Ex(p, "SubnetMask", e->SubnetMask, i, t->NumItem);
		PackAddIp32Ex(p, "GatewayAddress", e->GatewayAddress, i, t->NumItem);
		PackAddIntEx(p, "Metric", e->Metric, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumL3Table(RPC_ENUM_L3TABLE *t)
{
	Free(t->Items);
}

// RPC_L3TABLE
void InRpcL3Table(RPC_L3TABLE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3TABLE));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->NetworkAddress = PackGetIp32(p, "NetworkAddress");
	t->SubnetMask = PackGetIp32(p, "SubnetMask");
	t->GatewayAddress = PackGetIp32(p, "GatewayAddress");
	t->Metric = PackGetInt(p, "Metric");
}
void OutRpcL3Table(PACK *p, RPC_L3TABLE *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddIp32(p, "NetworkAddress", t->NetworkAddress);
	PackAddIp32(p, "SubnetMask", t->SubnetMask);
	PackAddIp32(p, "GatewayAddress", t->GatewayAddress);
	PackAddInt(p, "Metric", t->Metric);
}

// RPC_ENUM_L3IF
void InRpcEnumL3If(RPC_ENUM_L3IF *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3IF));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Items = ZeroMalloc(sizeof(RPC_L3IF) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3IF *f = &t->Items[i];

		PackGetStrEx(p, "HubName", f->HubName, sizeof(f->HubName), i);
		f->IpAddress = PackGetIp32Ex(p, "IpAddress", i);
		f->SubnetMask = PackGetIp32Ex(p, "SubnetMask", i);
	}
}
void OutRpcEnumL3If(PACK *p, RPC_ENUM_L3IF *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "Name", t->Name);

	PackSetCurrentJsonGroupName(p, "L3IFList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_L3IF *f = &t->Items[i];

		PackAddStrEx(p, "HubName", f->HubName, i, t->NumItem);
		PackAddIp32Ex(p, "IpAddress", f->IpAddress, i, t->NumItem);
		PackAddIp32Ex(p, "SubnetMask", f->SubnetMask, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumL3If(RPC_ENUM_L3IF *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_L3IF
void InRpcL3If(RPC_L3IF *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3IF));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->IpAddress = PackGetIp32(p, "IpAddress");
	t->SubnetMask = PackGetIp32(p, "SubnetMask");
}
void OutRpcL3If(PACK *p, RPC_L3IF *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "HubName", t->HubName);
	PackAddIp32(p, "IpAddress", t->IpAddress);
	PackAddIp32(p, "SubnetMask", t->SubnetMask);
}

// RPC_L3SW
void InRpcL3Sw(RPC_L3SW *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_L3SW));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcL3Sw(PACK *p, RPC_L3SW *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_L3SW
void InRpcEnumL3Sw(RPC_ENUM_L3SW *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_L3SW));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_L3SW_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *s = &t->Items[i];

		PackGetStrEx(p, "Name", s->Name, sizeof(s->Name), i);
		s->NumInterfaces = PackGetIntEx(p, "NumInterfaces", i);
		s->NumTables = PackGetIntEx(p, "NumTables", i);
		s->Active = PackGetBoolEx(p, "Active", i);
		s->Online = PackGetBoolEx(p, "Online", i);
	}
}
void OutRpcEnumL3Sw(PACK *p, RPC_ENUM_L3SW *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "L3SWList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *s = &t->Items[i];

		PackAddStrEx(p, "Name", s->Name, i, t->NumItem);
		PackAddIntEx(p, "NumInterfaces", s->NumInterfaces, i, t->NumItem);
		PackAddIntEx(p, "NumTables", s->NumTables, i, t->NumItem);
		PackAddBoolEx(p, "Active", s->Active, i, t->NumItem);
		PackAddBoolEx(p, "Online", s->Online, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumL3Sw(RPC_ENUM_L3SW *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_ETH
void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetUniStrEx(p, "NetworkConnectionName", e->NetworkConnectionName, sizeof(e->NetworkConnectionName), i);
	}
}
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "EthList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddUniStrEx(p, "NetworkConnectionName", e->NetworkConnectionName, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumEth(RPC_ENUM_ETH *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_LOCALBRIDGE
void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LOCALBRIDGE));
	PackGetStr(p, "DeviceName", t->DeviceName, sizeof(t->DeviceName));
	PackGetStr(p, "HubNameLB", t->HubName, sizeof(t->HubName));
	t->TapMode = PackGetBool(p, "TapMode");
}
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
	PackAddStr(p, "HubNameLB", t->HubName);
	PackAddBool(p, "TapMode", t->TapMode);
}

// RPC_ENUM_LOCALBRIDGE
void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "HubNameLB", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->Active = PackGetBoolEx(p, "Active", i);
		e->TapMode = PackGetBoolEx(p, "TapMode", i);
	}
}
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "LocalBridgeList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "HubNameLB", e->HubName, i, t->NumItem);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumItem);
		PackAddBoolEx(p, "Active", e->Active, i, t->NumItem);
		PackAddBoolEx(p, "TapMode", e->TapMode, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}
	Free(t->Items);
}

// MEMINFO
void InRpcMemInfo(MEMINFO *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(MEMINFO));
	t->TotalMemory = PackGetInt64(p, "TotalMemory");
	t->UsedMemory = PackGetInt64(p, "UsedMemory");
	t->FreeMemory = PackGetInt64(p, "FreeMemory");
	t->TotalPhys = PackGetInt64(p, "TotalPhys");
	t->UsedPhys = PackGetInt64(p, "UsedPhys");
	t->FreePhys = PackGetInt64(p, "FreePhys");
}
void OutRpcMemInfo(PACK *p, MEMINFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64(p, "TotalMemory", t->TotalMemory);
	PackAddInt64(p, "UsedMemory", t->UsedMemory);
	PackAddInt64(p, "FreeMemory", t->FreeMemory);
	PackAddInt64(p, "TotalPhys", t->TotalPhys);
	PackAddInt64(p, "UsedPhys", t->UsedPhys);
	PackAddInt64(p, "FreePhys", t->FreePhys);
}

// OS_INFO
void InRpcOsInfo(OS_INFO *t, PACK *p)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(OS_INFO));
	t->OsType = PackGetInt(p, "OsType");
	t->OsServicePack = PackGetInt(p, "OsServicePack");
	if (PackGetStr(p, "OsSystemName", tmp, sizeof(tmp)))
	{
		t->OsSystemName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsProductName", tmp, sizeof(tmp)))
	{
		t->OsProductName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVendorName", tmp, sizeof(tmp)))
	{
		t->OsVendorName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVersion", tmp, sizeof(tmp)))
	{
		t->OsVersion = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelName", tmp, sizeof(tmp)))
	{
		t->KernelName = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelVersion", tmp, sizeof(tmp)))
	{
		t->KernelVersion = CopyStr(tmp);
	}
}
void OutRpcOsInfo(PACK *p, OS_INFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "OsType", t->OsType);
	PackAddInt(p, "OsServicePack", t->OsServicePack);
	PackAddStr(p, "OsSystemName", t->OsSystemName);
	PackAddStr(p, "OsProductName", t->OsProductName);
	PackAddStr(p, "OsVendorName", t->OsVendorName);
	PackAddStr(p, "OsVersion", t->OsVersion);
	PackAddStr(p, "KernelName", t->KernelName);
	PackAddStr(p, "KernelVersion", t->KernelVersion);
}
void FreeRpcOsInfo(OS_INFO *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->OsSystemName);
	Free(t->OsProductName);
	Free(t->OsVendorName);
	Free(t->OsVersion);
	Free(t->KernelName);
	Free(t->KernelVersion);
}

// Read a local log file
void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t)
{
	char exe_dir[MAX_PATH], full_path[MAX_PATH];
	IO *o;
	// Validate arguments
	if (s == NULL || t == NULL || filepath == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));

	GetLogDir(exe_dir, sizeof(exe_dir));
	Format(full_path, sizeof(full_path), "%s/%s", exe_dir, filepath);

	// Read file
	o = FileOpenEx(full_path, false, false);
	if (o != NULL)
	{
		UINT filesize = FileSize(o);

		if (offset < filesize)
		{
			UINT readsize = MIN(filesize - offset, FTP_BLOCK_SIZE);
			void *buf = ZeroMalloc(readsize);

			FileSeek(o, FILE_BEGIN, offset);
			FileRead(o, buf, readsize);

			t->Buffer = NewBuf();
			WriteBuf(t->Buffer, buf, readsize);
			Free(buf);
		}

		FileClose(o);
	}
}

// Enumerate local log files
void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	o = EnumLogFile(hubname);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		StrCpy(e->ServerName, sizeof(e->ServerName), f->ServerName);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}

// Enumerate local sessions
void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t)
{
	HUB *h;
	UINT64 now = Tick64();
	UINT64 dormant_interval = 0;
	// Validate arguments
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	LockHubList(s->Cedar);
	h = GetHub(s->Cedar, hubname);
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		t->NumSession = 0;
		t->Sessions = ZeroMalloc(0);
		return;
	}

	if (h->Option != NULL)
	{
		dormant_interval = h->Option->DetectDormantSessionInterval * (UINT64)1000;
	}

	LockList(h->SessionList);
	{
		UINT i;
		t->NumSession = LIST_NUM(h->SessionList);
		t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

		for (i = 0;i < t->NumSession;i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);
			RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];
			Lock(s->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), s->Name);
				StrCpy(e->Username, sizeof(e->Username), s->Username);
				e->Ip = IPToUINT(&s->Connection->ClientIp);
				CopyIP(&e->ClientIP, &s->Connection->ClientIp);
				StrCpy(e->Hostname, sizeof(e->Hostname), s->Connection->ClientHostname);
				e->MaxNumTcp = s->MaxConnection;
				e->CreatedTime = Tick64ToTime64(s->CreatedTime);
				e->LastCommTime = Tick64ToTime64(s->LastCommTime);
				e->LinkMode = s->LinkModeServer;
				e->SecureNATMode = s->SecureNATMode;
				e->BridgeMode = s->BridgeMode;
				e->Layer3Mode = s->L3SwitchMode;
				e->VLanId = s->VLanId;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					e->CurrentNumTcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);
				Lock(s->TrafficLock);
				{
					e->PacketSize = GetTrafficPacketSize(s->Traffic);
					e->PacketNum = GetTrafficPacketNum(s->Traffic);
				}
				Unlock(s->TrafficLock);
				e->Client_BridgeMode = s->IsBridgeMode;
				e->Client_MonitorMode = s->IsMonitorMode;
				Copy(e->UniqueId, s->NodeInfo.UniqueId, 16);

				if (s->NormalClient)
				{
					e->IsDormantEnabled = (dormant_interval == 0 ? false : true);
					if (e->IsDormantEnabled)
					{
						if (s->LastCommTimeForDormant == 0)
						{
							e->LastCommDormant = (UINT64)0x7FFFFFFF;
						}
						else
						{
							e->LastCommDormant = now - s->LastCommTimeForDormant;
						}
						if (s->LastCommTimeForDormant == 0)
						{
							e->IsDormant = true;
						}
						else
						{
							if ((s->LastCommTimeForDormant + dormant_interval) < now)
							{
								e->IsDormant = true;
							}
						}
					}
				}
			}
			Unlock(s->lock);

			GetMachineName(e->RemoteHostname, sizeof(e->RemoteHostname));
		}
	}
	UnlockList(h->SessionList);

	ReleaseHub(h);
}

// RPC_ENUM_LICENSE_KEY
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LICENSE_KEY));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LICENSE_KEY_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		PackGetStrEx(p, "LicenseKey", e->LicenseKey, sizeof(e->LicenseKey), i);
		PackGetStrEx(p, "LicenseId", e->LicenseId, sizeof(e->LicenseId), i);
		PackGetStrEx(p, "LicenseName", e->LicenseName, sizeof(e->LicenseName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
		e->Status = PackGetIntEx(p, "Status", i);
		e->ProductId = PackGetIntEx(p, "ProductId", i);
		e->SystemId = PackGetInt64Ex(p, "SystemId", i);
		e->SerialId = PackGetIntEx(p, "SerialId", i);
	}
}
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackSetCurrentJsonGroupName(p, "LicenseKeyList");
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddStrEx(p, "LicenseKey", e->LicenseKey, i, t->NumItem);
		PackAddStrEx(p, "LicenseId", e->LicenseId, i, t->NumItem);
		PackAddStrEx(p, "LicenseName", e->LicenseName, i, t->NumItem);
		PackAddTime64Ex(p, "Expires", e->Expires, i, t->NumItem);
		PackAddIntEx(p, "Status", e->Status, i, t->NumItem);
		PackAddIntEx(p, "ProductId", e->ProductId, i, t->NumItem);
		PackAddInt64Ex(p, "SystemId", e->SystemId, i, t->NumItem);
		PackAddIntEx(p, "SerialId", e->SerialId, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_LICENSE_STATUS
void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LICENSE_STATUS));

	t->EditionId = PackGetInt(p, "EditionId");
	PackGetStr(p, "EditionStr", t->EditionStr, sizeof(t->EditionStr) );
	t->SystemId = PackGetInt64(p, "SystemId");
	t->SystemExpires = PackGetInt64(p, "SystemExpires");
	t->NumClientConnectLicense = PackGetInt(p, "NumClientConnectLicense");
	t->NumBridgeConnectLicense = PackGetInt(p, "NumBridgeConnectLicense");

	// v3.0
	t->NeedSubscription = PackGetBool(p, "NeedSubscription");
	t->AllowEnterpriseFunction = PackGetBool(p, "AllowEnterpriseFunction");
	t->SubscriptionExpires = PackGetInt64(p, "SubscriptionExpires");
	t->IsSubscriptionExpired = PackGetBool(p, "IsSubscriptionExpired");
	t->NumUserCreationLicense = PackGetInt(p, "NumUserCreationLicense");
	t->ReleaseDate = PackGetInt64(p, "ReleaseDate");
}
void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "EditionId", t->EditionId);
	PackAddStr(p, "EditionStr", t->EditionStr);
	PackAddInt64(p, "SystemId", t->SystemId);
	PackAddTime64(p, "SystemExpires", t->SystemExpires);
	PackAddInt(p, "NumClientConnectLicense", t->NumClientConnectLicense);
	PackAddInt(p, "NumBridgeConnectLicense", t->NumBridgeConnectLicense);

	// v3.0
	PackAddBool(p, "NeedSubscription", t->NeedSubscription);
	PackAddBool(p, "AllowEnterpriseFunction", t->AllowEnterpriseFunction);
	PackAddTime64(p, "SubscriptionExpires", t->SubscriptionExpires);
	PackAddBool(p, "IsSubscriptionExpired", t->IsSubscriptionExpired);
	PackAddInt(p, "NumUserCreationLicense", t->NumUserCreationLicense);
	PackAddTime64(p, "ReleaseDate", t->ReleaseDate);
}

// RPC_ADMIN_OPTION
void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADMIN_OPTION));
	t->NumItem = PackGetIndexCount(p, "Name");
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackGetStrEx(p, "Name", o->Name, sizeof(o->Name), i);
		o->Value = PackGetIntEx(p, "Value", i);
		PackGetUniStrEx(p, "Descrption", o->Descrption, sizeof(o->Descrption), i);
	}
}
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "AdminOptionList");
	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackAddStrEx(p, "Name", o->Name, i, t->NumItem);
		PackAddIntEx(p, "Value", o->Value, i, t->NumItem);
		PackAddUniStrEx(p, "Descrption", o->Descrption, i, t->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_CONFIG
void InRpcConfig(RPC_CONFIG *t, PACK *p)
{
	UINT size;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONFIG));
	PackGetStr(p, "FileName", t->FileName, sizeof(t->FileName));
	size = PackGetDataSize(p, "FileData");
	t->FileData = ZeroMalloc(size + 1);
	PackGetData(p, "FileData", t->FileData);
}
void OutRpcConfig(PACK *p, RPC_CONFIG *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "FileName", t->FileName);
	PackAddData(p, "FileData", t->FileData, StrLen(t->FileData));
}
void FreeRpcConfig(RPC_CONFIG *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->FileData);
}

// RPC_BRIDGE_SUPPORT
void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = PackGetBool(p, "IsBridgeSupportedOs");
	t->IsWinPcapNeeded = PackGetBool(p, "IsWinPcapNeeded");
}
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddBool(p, "IsBridgeSupportedOs", t->IsBridgeSupportedOs);
	PackAddBool(p, "IsWinPcapNeeded",t->IsWinPcapNeeded);
}

// RPC_ADD_ACCESS
void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADD_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	InRpcAccess(&t->Access, p);
}
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	OutRpcAccess(p, &t->Access);
}

// RPC_DELETE_ACCESS
void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Id = PackGetInt(p, "Id");
}
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Id", t->Id);
}


// RPC_SERVER_INFO
void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_INFO));

	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ServerVersionString", t->ServerVersionString, sizeof(t->ServerVersionString));
	PackGetStr(p, "ServerBuildInfoString", t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString));
	t->ServerVerInt = PackGetInt(p, "ServerVerInt");
	t->ServerBuildInt = PackGetInt(p, "ServerBuildInt");
	PackGetStr(p, "ServerHostName", t->ServerHostName, sizeof(t->ServerHostName));
	t->ServerType = PackGetInt(p, "ServerType");
	t->ServerBuildDate = PackGetInt64(p, "ServerBuildDate");
	PackGetStr(p, "ServerFamilyName", t->ServerFamilyName, sizeof(t->ServerFamilyName));
	InRpcOsInfo(&t->OsInfo, p);
}
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ServerVersionString", t->ServerVersionString);
	PackAddStr(p, "ServerBuildInfoString", t->ServerBuildInfoString);
	PackAddInt(p, "ServerVerInt", t->ServerVerInt);
	PackAddInt(p, "ServerBuildInt", t->ServerBuildInt);
	PackAddStr(p, "ServerHostName", t->ServerHostName);
	PackAddInt(p, "ServerType", t->ServerType);
	PackAddTime64(p, "ServerBuildDate", t->ServerBuildDate);
	PackAddStr(p, "ServerFamilyName", t->ServerFamilyName);
	OutRpcOsInfo(p, &t->OsInfo);
}
void FreeRpcServerInfo(RPC_SERVER_INFO *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeRpcOsInfo(&t->OsInfo);
}

// RPC_SERVER_STATUS
void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_STATUS));
	t->ServerType = PackGetInt(p, "ServerType");
	t->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	t->NumTcpConnectionsLocal = PackGetInt(p, "NumTcpConnectionsLocal");
	t->NumTcpConnectionsRemote = PackGetInt(p, "NumTcpConnectionsRemote");
	t->NumHubTotal = PackGetInt(p, "NumHubTotal");
	t->NumHubStandalone = PackGetInt(p, "NumHubStandalone");
	t->NumHubStatic = PackGetInt(p, "NumHubStatic");
	t->NumHubDynamic = PackGetInt(p, "NumHubDynamic");
	t->NumSessionsTotal = PackGetInt(p, "NumSessionsTotal");
	t->NumSessionsLocal = PackGetInt(p, "NumSessionsLocal");
	t->NumSessionsRemote = PackGetInt(p, "NumSessionsRemote");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->CurrentTime = PackGetInt64(p, "CurrentTime");
	t->CurrentTick = PackGetInt64(p, "CurrentTick");
	t->AssignedBridgeLicenses = PackGetInt(p, "AssignedBridgeLicenses");
	t->AssignedClientLicenses = PackGetInt(p, "AssignedClientLicenses");
	t->AssignedBridgeLicensesTotal = PackGetInt(p, "AssignedBridgeLicensesTotal");
	t->AssignedClientLicensesTotal = PackGetInt(p, "AssignedClientLicensesTotal");
	t->StartTime = PackGetInt64(p, "StartTime");

	InRpcTraffic(&t->Traffic, p);

	InRpcMemInfo(&t->MemInfo, p);
}
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ServerType", t->ServerType);
	PackAddInt(p, "NumHubTotal", t->NumHubTotal);
	PackAddInt(p, "NumHubStandalone", t->NumHubStandalone);
	PackAddInt(p, "NumHubStatic", t->NumHubStatic);
	PackAddInt(p, "NumHubDynamic", t->NumHubDynamic);
	PackAddInt(p, "NumSessionsTotal", t->NumSessionsTotal);
	PackAddInt(p, "NumSessionsLocal", t->NumSessionsLocal);
	PackAddInt(p, "NumSessionsRemote", t->NumSessionsRemote);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsLocal", t->NumTcpConnectionsLocal);
	PackAddInt(p, "NumTcpConnectionsRemote", t->NumTcpConnectionsRemote);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddTime64(p, "CurrentTime", t->CurrentTime);
	PackAddInt64(p, "CurrentTick", t->CurrentTick);
	PackAddInt(p, "AssignedBridgeLicenses", t->AssignedBridgeLicenses);
	PackAddInt(p, "AssignedClientLicenses", t->AssignedClientLicenses);
	PackAddInt(p, "AssignedBridgeLicensesTotal", t->AssignedBridgeLicensesTotal);
	PackAddInt(p, "AssignedClientLicensesTotal", t->AssignedClientLicensesTotal);
	PackAddTime64(p, "StartTime", t->StartTime);

	OutRpcTraffic(p, &t->Traffic);

	OutRpcMemInfo(p, &t->MemInfo);
}

// RPC_LISTENER
void InRpcListener(RPC_LISTENER *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER));
	t->Port = PackGetInt(p, "Port");
	t->Enable = PackGetBool(p, "Enable");
}
void OutRpcListener(PACK *p, RPC_LISTENER *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Enable", t->Enable);
}

// RPC_LISTENER_LIST
void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER_LIST));
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
		t->Enables[i] = PackGetBoolEx(p, "Enables", i);
		t->Errors[i] = PackGetBoolEx(p, "Errors", i);
	}
}
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "ListenerList");
	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
		PackAddBoolEx(p, "Enables", t->Enables[i], i, t->NumPort);
		PackAddBoolEx(p, "Errors", t->Errors[i], i, t->NumPort);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcListenerList(RPC_LISTENER_LIST *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
	Free(t->Enables);
	Free(t->Errors);
}

// RPC_PORTS
void InRpcPorts(RPC_PORTS *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Num = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->Num);

	for (i = 0; i < t->Num; ++i)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
	}
}
void OutRpcPorts(PACK *p, RPC_PORTS *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0; i < t->Num; ++i)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->Num);
	}
}
void FreeRpcPorts(RPC_PORTS *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
}

// RPC_STR
void InRpcStr(RPC_STR *t, PACK *p)
{
	UINT size = 65536;
	char *tmp = Malloc(size);
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_STR));
	if (PackGetStr(p, "String", tmp, size) == false)
	{
		t->String = CopyStr("");
	}
	else
	{
		t->String = CopyStr(tmp);
	}
	Free(tmp);
}
void OutRpcStr(PACK *p, RPC_STR *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "String", t->String);
}
void FreeRpcStr(RPC_STR *t)
{
	// Validate arguments
	if (t == NULL )
	{
		return;
	}

	Free(t->String);
}

// RPC_PROTO_OPTIONS
void InRpcProtoOptions(RPC_PROTO_OPTIONS *t, PACK *p)
{
	UINT i, size;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_PROTO_OPTIONS));

	size = PackGetStrSize(p, "Protocol");
	if (size > 0)
	{
		t->Protocol = Malloc(size);

		if (PackGetStr(p, "Protocol", t->Protocol, size) == false)
		{
			Zero(t->Protocol, size);
		}
	}

	t->Num = PackGetIndexCount(p, "Name");
	if (t->Num == 0)
	{
		return;
	}

	t->Options = ZeroMalloc(sizeof(PROTO_OPTION) * t->Num);

	for (i = 0; i < t->Num; ++i)
	{
		PROTO_OPTION *option = &t->Options[i];

		size = PackGetStrSizeEx(p, "Name", i);
		if (size > 0)
		{
			option->Name = Malloc(size);
			if (PackGetStrEx(p, "Name", option->Name, size, i) == false)
			{
				Zero(option->Name, size);
			}
		}

		option->Type = PackGetIntEx(p, "Type", i);
		switch (option->Type)
		{
		case PROTO_OPTION_STRING:
			size = PackGetDataSizeEx(p, "Value", i);
			if (size > 0)
			{
				option->String = Malloc(size);
				if (PackGetDataEx2(p, "Value", option->String, size, i) == false)
				{
					Zero(option->String, size);
				}
			}
			break;
		case PROTO_OPTION_BOOL:
			PackGetDataEx2(p, "Value", &option->Bool, sizeof(option->Bool), i);
			break;
		default:
			Debug("InRpcProtoOptions(): unhandled type %u!\n", option->Type);
		}
	}
}
void OutRpcProtoOptions(PACK *p, RPC_PROTO_OPTIONS *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Protocol", t->Protocol);

	for (i = 0; i < t->Num; ++i)
	{
		PROTO_OPTION *option = &t->Options[i];

		PackAddStrEx(p, "Name", option->Name, i, t->Num);
		PackAddIntEx(p, "Type", option->Type, i, t->Num);

		switch (option->Type)
		{
		case PROTO_OPTION_STRING:
			PackAddDataEx(p, "Value", option->String, StrLen(option->String) + 1, i, t->Num);
			break;
		case PROTO_OPTION_BOOL:
			PackAddDataEx(p, "Value", &option->Bool, sizeof(option->Bool), i, t->Num);
			break;
		default:
			Debug("OutRpcProtoOptions(): unhandled type %u!\n", option->Type);
		}
	}
}
void FreeRpcProtoOptions(RPC_PROTO_OPTIONS *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Protocol);

	for (i = 0; i < t->Num; ++i)
	{
		PROTO_OPTION *option = &t->Options[i];

		Free(option->Name);

		if (option->Type == PROTO_OPTION_STRING)
		{
			Free(option->String);
		}
	}

	Free(t->Options);
}

// RPC_SET_PASSWORD
void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_PASSWORD));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetStr(p, "PlainTextPassword", t->PlainTextPassword, sizeof(t->PlainTextPassword));
}
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddStr(p, "PlainTextPassword", t->PlainTextPassword);
}

// RPC_FARM
void InRpcFarm(RPC_FARM *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM));
	t->ServerType = PackGetInt(p, "ServerType");
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
	}
	t->PublicIp = PackGetIp32(p, "PublicIp");
	PackGetStr(p, "ControllerName", t->ControllerName, sizeof(t->ControllerName));
	t->ControllerPort = PackGetInt(p, "ControllerPort");
	PackGetData2(p, "MemberPassword", t->MemberPassword, sizeof(t->MemberPassword));
	PackGetStr(p, "MemberPasswordPlaintext", t->MemberPasswordPlaintext, sizeof(t->MemberPasswordPlaintext));
	t->Weight = PackGetInt(p, "Weight");
	t->ControllerOnly = PackGetBool(p, "ControllerOnly");
}
void OutRpcFarm(PACK *p, RPC_FARM *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ServerType", t->ServerType);
	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
	}
	PackAddIp32(p, "PublicIp", t->PublicIp);
	PackAddStr(p, "ControllerName", t->ControllerName);
	PackAddInt(p, "ControllerPort", t->ControllerPort);
	PackAddData(p, "MemberPassword", t->MemberPassword, sizeof(t->MemberPassword));
	PackAddStr(p, "MemberPasswordPlaintext", t->MemberPasswordPlaintext);
	PackAddInt(p, "Weight", t->Weight);
	PackAddBool(p, "ControllerOnly", t->ControllerOnly);
}
void FreeRpcFarm(RPC_FARM *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
}

// RPC_FARM_HUB
void InRpcFarmHub(RPC_FARM_HUB *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->DynamicHub = PackGetBool(p, "DynamicHub");
}
void OutRpcFarmHub(PACK *p, RPC_FARM_HUB *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "DynamicHub", t->DynamicHub);
}

// RPC_FARM_INFO
void InRpcFarmInfo(RPC_FARM_INFO *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_FARM_INFO));
	t->Id = PackGetInt(p, "Id");
	t->Controller = PackGetBool(p, "Controller");
	t->ConnectedTime = PackGetInt64(p, "ConnectedTime");
	t->Ip = PackGetIp32(p, "Ip");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
	t->Point = PackGetInt(p, "Point");
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
	}
	t->ServerCert = PackGetX(p, "ServerCert");
	t->NumFarmHub = PackGetIndexCount(p, "HubName");
	t->FarmHubs = ZeroMalloc(sizeof(RPC_FARM_HUB) * t->NumFarmHub);
	for (i = 0;i < t->NumFarmHub;i++)
	{
		PackGetStrEx(p, "HubName", t->FarmHubs[i].HubName, sizeof(t->FarmHubs[i].HubName), i);
		t->FarmHubs[i].DynamicHub = PackGetBoolEx(p, "DynamicHub", i);
	}
	t->NumSessions = PackGetInt(p, "NumSessions");
	t->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	t->Weight = PackGetInt(p, "Weight");
}
void OutRpcFarmInfo(PACK *p, RPC_FARM_INFO *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Id", t->Id);
	PackAddBool(p, "Controller", t->Controller);
	PackAddTime64(p, "ConnectedTime", t->ConnectedTime);
	PackAddIp32(p, "Ip", t->Ip);
	PackAddStr(p, "Hostname", t->Hostname);
	PackAddInt(p, "Point", t->Point);
	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
	}
	PackAddX(p, "ServerCert", t->ServerCert);

	PackSetCurrentJsonGroupName(p, "HubsList");
	for (i = 0;i < t->NumFarmHub;i++)
	{
		PackAddStrEx(p, "HubName", t->FarmHubs[i].HubName, i, t->NumFarmHub);
		PackAddBoolEx(p, "DynamicHub", t->FarmHubs[i].DynamicHub, i, t->NumFarmHub);
	}
	PackSetCurrentJsonGroupName(p, NULL);

	PackAddInt(p, "NumSessions", t->NumSessions);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "Weight", t->Weight);
}
void FreeRpcFarmInfo(RPC_FARM_INFO *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
	Free(t->FarmHubs);
	FreeX(t->ServerCert);
}

void InRpcEnumFarm(RPC_ENUM_FARM *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_FARM));
	t->NumFarm = PackGetIndexCount(p, "Id");
	t->Farms = ZeroMalloc(sizeof(RPC_ENUM_FARM_ITEM) * t->NumFarm);

	for (i = 0;i < t->NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->Controller = PackGetBoolEx(p, "Controller", i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Ip = PackGetIp32Ex(p, "Ip", i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->Point = PackGetIntEx(p, "Point", i);
		e->NumSessions = PackGetIntEx(p, "NumSessions", i);
		e->NumTcpConnections = PackGetIntEx(p, "NumTcpConnections", i);
		e->NumHubs = PackGetIntEx(p, "NumHubs", i);
		e->AssignedClientLicense = PackGetIntEx(p, "AssignedClientLicense", i);
		e->AssignedBridgeLicense = PackGetIntEx(p, "AssignedBridgeLicense", i);
	}
}
void OutRpcEnumFarm(PACK *p, RPC_ENUM_FARM *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "FarmMemberList");
	for (i = 0;i < t->NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t->Farms[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumFarm);
		PackAddBoolEx(p, "Controller", e->Controller, i, t->NumFarm);
		PackAddTime64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumFarm);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumFarm);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumFarm);
		PackAddIntEx(p, "Point", e->Point, i, t->NumFarm);
		PackAddIntEx(p, "NumSessions", e->NumSessions, i, t->NumFarm);
		PackAddIntEx(p, "NumTcpConnections", e->NumTcpConnections, i, t->NumFarm);
		PackAddIntEx(p, "NumHubs", e->NumHubs, i, t->NumFarm);
		PackAddIntEx(p, "AssignedClientLicense", e->AssignedClientLicense, i, t->NumFarm);
		PackAddIntEx(p, "AssignedBridgeLicense", e->AssignedBridgeLicense, i, t->NumFarm);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumFarm(RPC_ENUM_FARM *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Farms);
}

// RPC_FARM_CONNECTION_STATUS
void InRpcFarmConnectionStatus(RPC_FARM_CONNECTION_STATUS *t, PACK *p)
{
	Zero(t, sizeof(RPC_FARM_CONNECTION_STATUS));
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Ip = PackGetIp32(p, "Ip");
	t->Port = PackGetInt(p, "Port");
	t->Online = PackGetBool(p, "Online");
	t->LastError = PackGetInt(p, "LastError");
	t->StartedTime = PackGetInt64(p, "StartedTime");
	t->CurrentConnectedTime = PackGetInt64(p, "CurrentConnectedTime");
	t->FirstConnectedTime = PackGetInt64(p, "FirstConnectedTime");
	t->NumConnected = PackGetInt(p, "NumConnected");
	t->NumTry = PackGetInt(p, "NumTry");
	t->NumFailed = PackGetInt(p, "NumFailed");
}
void OutRpcFarmConnectionStatus(PACK *p, RPC_FARM_CONNECTION_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddIp32(p, "Ip", t->Ip);
	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Online", t->Online);
	PackAddInt(p, "LastError", t->LastError);
	PackAddTime64(p, "StartedTime", t->StartedTime);
	PackAddTime64(p, "CurrentConnectedTime", t->CurrentConnectedTime);
	PackAddTime64(p, "FirstConnectedTime", t->FirstConnectedTime);
	PackAddInt(p, "NumConnected", t->NumConnected);
	PackAddInt(p, "NumTry", t->NumTry);
	PackAddInt(p, "NumFailed", t->NumFailed);
}

// RPC_HUB_OPTION
void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_OPTION));
	t->MaxSession = PackGetInt(p, "MaxSession");
	t->NoEnum = PackGetBool(p, "NoEnum");
}
void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "MaxSession", t->MaxSession);
	PackAddBool(p, "NoEnum", t->NoEnum);
}

// RPC_RADIUS
void InRpcRadius(RPC_RADIUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_RADIUS));
	PackGetStr(p, "RadiusServerName", t->RadiusServerName, sizeof(t->RadiusServerName));
	t->RadiusPort = PackGetInt(p, "RadiusPort");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "RadiusSecret", t->RadiusSecret, sizeof(t->RadiusSecret));
	t->RadiusRetryInterval = PackGetInt(p, "RadiusRetryInterval");
}
void OutRpcRadius(PACK *p, RPC_RADIUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "RadiusServerName", t->RadiusServerName);
	PackAddInt(p, "RadiusPort", t->RadiusPort);
	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "RadiusSecret", t->RadiusSecret);
	PackAddInt(p, "RadiusRetryInterval", t->RadiusRetryInterval);
}

// RPC_HUB
void InRpcHub(RPC_HUB *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcHub(PACK *p, RPC_HUB *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

// RPC_CREATE_HUB
void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetData2(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	PackGetStr(p, "AdminPasswordPlainText", t->AdminPasswordPlainText, sizeof(t->AdminPasswordPlainText));
	t->Online = PackGetBool(p, "Online");
	InRpcHubOption(&t->HubOption, p);
	t->HubType = PackGetInt(p, "HubType");
}
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddData(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	PackAddBool(p, "Online", t->Online);
	PackAddStr(p, "AdminPasswordPlainText", t->AdminPasswordPlainText);
	OutRpcHubOption(p, &t->HubOption);
	PackAddInt(p, "HubType", t->HubType);
}

// RPC_ENUM_HUB
void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_HUB));
	t->NumHub = PackGetIndexCount(p, "HubName");
	t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * t->NumHub);

	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackGetStrEx(p, "HubName", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->HubType = PackGetIntEx(p, "HubType", i);
		e->NumSessions = PackGetIntEx(p, "NumSessions", i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
		e->NumGroups = PackGetIntEx(p, "NumGroups", i);
		e->NumMacTables = PackGetIntEx(p, "NumMacTables", i);
		e->NumIpTables = PackGetIntEx(p, "NumIpTables", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);
		e->IsTrafficFilled = PackGetBoolEx(p, "IsTrafficFilled", i);

		InRpcTrafficEx(&e->Traffic, p, i);
	}
}
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "HubList");
	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackAddStrEx(p, "HubName", e->HubName, i, t->NumHub);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumHub);
		PackAddIntEx(p, "HubType", e->HubType, i, t->NumHub);
		PackAddIntEx(p, "NumSessions", e->NumSessions, i, t->NumHub);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumHub);
		PackAddIntEx(p, "NumGroups", e->NumGroups, i, t->NumHub);
		PackAddIntEx(p, "NumMacTables", e->NumMacTables, i, t->NumHub);
		PackAddIntEx(p, "NumIpTables", e->NumIpTables, i, t->NumHub);
		PackAddTime64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumHub);
		PackAddTime64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumHub);
		PackAddTime64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumHub);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumHub);
		PackAddBoolEx(p, "IsTrafficFilled", e->IsTrafficFilled, i, t->NumHub);

		OutRpcTrafficEx(&e->Traffic, p, i, t->NumHub);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumHub(RPC_ENUM_HUB *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Hubs);
}

// RPC_DELETE_HUB
void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

// RPC_ENUM_CONNECTION
void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CONNECTION));
	t->NumConnection = PackGetIndexCount(p, "Name");
	t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);

	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		e->Ip = PackGetIp32Ex(p, "Ip", i);
		e->Port = PackGetIntEx(p, "Port", i);
		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Type = PackGetIntEx(p, "Type", i);
	}
}
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "ConnectionList");
	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumConnection);
		PackAddIntEx(p, "Port", e->Port, i, t->NumConnection);
		PackAddStrEx(p, "Name", e->Name, i, t->NumConnection);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumConnection);
		PackAddTime64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumConnection);
		PackAddIntEx(p, "Type", e->Type, i, t->NumConnection);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Connections);
}

// RPC_DISCONNECT_CONNECTION
void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DISCONNECT_CONNECTION));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

// RPC_CONNECTION_INFO
void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Ip = PackGetIp32(p, "Ip");
	t->Port = PackGetInt(p, "Port");
	t->ConnectedTime = PackGetInt64(p, "ConnectedTime");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
	PackGetStr(p, "ServerStr", t->ServerStr, sizeof(t->ServerStr));
	PackGetStr(p, "ClientStr", t->ClientStr, sizeof(t->ClientStr));
	t->ServerVer = PackGetInt(p, "ServerVer");
	t->ServerBuild = PackGetInt(p, "ServerBuild");
	t->ClientVer = PackGetInt(p, "ClientVer");
	t->ClientBuild = PackGetInt(p, "ClientBuild");
	t->Type = PackGetInt(p, "Type");
}
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddIp32(p, "Ip", t->Ip);
	PackAddInt(p, "Port", t->Port);
	PackAddTime64(p, "ConnectedTime", t->ConnectedTime);
	PackAddStr(p, "Hostname", t->Hostname);
	PackAddStr(p, "ServerStr", t->ServerStr);
	PackAddStr(p, "ClientStr", t->ClientStr);
	PackAddInt(p, "ServerVer", t->ServerVer);
	PackAddInt(p, "ServerBuild", t->ServerBuild);
	PackAddInt(p, "ClientVer", t->ClientVer);
	PackAddInt(p, "ClientBuild", t->ClientBuild);
	PackAddInt(p, "Type", t->Type);
}

// RPC_SET_HUB_ONLINE
void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_HUB_ONLINE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
}
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
}

// RPC_HUB_STATUS
void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p)
{
	Zero(t, sizeof(RPC_HUB_STATUS));
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->HubType = PackGetInt(p, "HubType");
	t->NumSessions = PackGetInt(p, "NumSessions");
	t->NumSessionsClient = PackGetInt(p, "NumSessionsClient");
	t->NumSessionsBridge = PackGetInt(p, "NumSessionsBridge");
	t->NumAccessLists = PackGetInt(p, "NumAccessLists");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	t->SecureNATEnabled = PackGetBool(p, "SecureNATEnabled");
	InRpcTraffic(&t->Traffic, p);
	t->LastCommTime = PackGetInt64(p, "LastCommTime");
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->LastLoginTime = PackGetInt64(p, "LastLoginTime");
	t->NumLogin = PackGetInt(p, "NumLogin");
}
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
	PackAddInt(p, "HubType", t->HubType);
	PackAddInt(p, "NumSessions", t->NumSessions);
	PackAddInt(p, "NumSessionsClient", t->NumSessionsClient);
	PackAddInt(p, "NumSessionsBridge", t->NumSessionsBridge);
	PackAddInt(p, "NumAccessLists", t->NumAccessLists);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	PackAddBool(p, "SecureNATEnabled", t->SecureNATEnabled);
	OutRpcTraffic(p, &t->Traffic);
	PackAddTime64(p, "LastCommTime", t->LastCommTime);
	PackAddTime64(p, "CreatedTime", t->CreatedTime);
	PackAddTime64(p, "LastLoginTime", t->LastLoginTime);
	PackAddInt(p, "NumLogin", t->NumLogin);
}

// RPC_HUB_LOG
void InRpcHubLog(RPC_HUB_LOG *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_LOG));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->LogSetting.SaveSecurityLog = PackGetBool(p, "SaveSecurityLog");
	t->LogSetting.SecurityLogSwitchType = PackGetInt(p, "SecurityLogSwitchType");
	t->LogSetting.SavePacketLog = PackGetBool(p, "SavePacketLog");
	t->LogSetting.PacketLogSwitchType = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		t->LogSetting.PacketLogConfig[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
}
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "SaveSecurityLog", t->LogSetting.SaveSecurityLog);
	PackAddInt(p, "SecurityLogSwitchType", t->LogSetting.SecurityLogSwitchType);
	PackAddBool(p, "SavePacketLog", t->LogSetting.SavePacketLog);
	PackAddInt(p, "PacketLogSwitchType", t->LogSetting.PacketLogSwitchType);
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", t->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
}

// RPC_HUB_ADD_CA
void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ADD_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

// RPC_HUB_ENUM_CA
void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumCa = PackGetIndexCount(p, "Key");
	t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "SubjectName", e->SubjectName, sizeof(e->SubjectName), i);
		PackGetUniStrEx(p, "IssuerName", e->IssuerName, sizeof(e->IssuerName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "CAList");
	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumCa);
		PackAddUniStrEx(p, "SubjectName", e->SubjectName, i, t->NumCa);
		PackAddUniStrEx(p, "IssuerName", e->IssuerName, i, t->NumCa);
		PackAddTime64Ex(p, "Expires", e->Expires, i, t->NumCa);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Ca);
}

// RPC_HUB_GET_CA
void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_GET_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

// RPC_HUB_DELETE_CA
void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_DELETE_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

// RPC_CREATE_LINK
void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_LINK));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	InRpcClientOption(t->ClientOption, p);
	t->ClientAuth  = ZeroMalloc(sizeof(CLIENT_AUTH));
	InRpcClientAuth(t->ClientAuth, p);
	InRpcPolicy(&t->Policy, p);

	t->CheckServerCert = PackGetBool(p, "CheckServerCert");
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		t->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}
}
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex",t->HubName);
	PackAddBool(p, "Online", t->Online);
	OutRpcClientOption(p, t->ClientOption);
	OutRpcClientAuth(p, t->ClientAuth);
	OutRpcPolicy(p, &t->Policy);

	PackAddBool(p, "CheckServerCert", t->CheckServerCert);
	if (t->ServerCert != NULL)
	{
		BUF *b;
		b = XToBuf(t->ServerCert, false);
		PackAddBuf(p, "ServerCert", b);
		FreeBuf(b);
	}
}
void FreeRpcCreateLink(RPC_CREATE_LINK *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->ServerCert != NULL)
	{
		FreeX(t->ServerCert);
	}
	Free(t->ClientOption);
	CiFreeClientAuth(t->ClientAuth);
}

// RPC_ENUM_LINK
void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumLink = PackGetIndexCount(p, "AccountName");
	t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackGetUniStrEx(p, "AccountName", e->AccountName, sizeof(e->AccountName), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		PackGetStrEx(p, "ConnectedHubName", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Connected = PackGetBoolEx(p, "Connected", i);
		e->LastError = PackGetIntEx(p, "LastError", i);
		PackGetStrEx(p, "LinkHubName", e->HubName, sizeof(e->HubName), i);
	}
}
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "LinkList");
	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackAddUniStrEx(p, "AccountName", e->AccountName, i, t->NumLink);
		PackAddStrEx(p, "ConnectedHubName", e->HubName, i, t->NumLink);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumLink);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumLink);
		PackAddTime64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumLink);
		PackAddBoolEx(p, "Connected", e->Connected, i, t->NumLink);
		PackAddIntEx(p, "LastError", e->LastError, i, t->NumLink);
		PackAddStrEx(p, "TargetHubName", e->HubName, i, t->NumLink);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumLink(RPC_ENUM_LINK *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Links);
}

// RPC_LINK_STATUS
void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK_STATUS));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
	InRpcClientGetConnectionStatus(&t->Status, p);
}
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
	OutRpcClientGetConnectionStatus(p, &t->Status);
}
void FreeRpcLinkStatus(RPC_LINK_STATUS *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

// RPC_LINK
void InRpcLink(RPC_LINK *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
}
void OutRpcLink(PACK *p, RPC_LINK *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
}

// RPC_RENAME_LINK
void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_RENAME_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "OldAccountName", t->OldAccountName, sizeof(t->OldAccountName));
	PackGetUniStr(p, "NewAccountName", t->NewAccountName, sizeof(t->NewAccountName));
}
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "OldAccountName", t->OldAccountName);
	PackAddUniStr(p, "NewAccountName", t->NewAccountName);
}

// ACCESS
void InRpcAccessEx(ACCESS *a, PACK *p, UINT index)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(ACCESS));
	a->Id = PackGetIntEx(p, "Id", index);
	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), index);
	a->Active = PackGetBoolEx(p, "Active", index);
	a->Priority = PackGetIntEx(p, "Priority", index);
	a->Discard = PackGetBoolEx(p, "Discard", index);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", index);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", index);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", index);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", index);
	a->Protocol = PackGetIntEx(p, "Protocol", index);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", index);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", index);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", index);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", index);
	//a->SrcUsernameHash = PackGetIntEx(p, "SrcUsernameHash", index);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), index);
	//a->DestUsernameHash = PackGetIntEx(p, "DestUsernameHash", index);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), index);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", index);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", index);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", index);
	a->Established = PackGetBoolEx(p, "Established", index);
	a->Delay = PackGetIntEx(p, "Delay", index);
	a->Jitter = PackGetIntEx(p, "Jitter", index);
	a->Loss = PackGetIntEx(p, "Loss", index);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", index);
	a->UniqueId = PackGetIntEx(p, "UniqueId", index);
	PackGetStrEx(p, "RedirectUrl", a->RedirectUrl, sizeof(a->RedirectUrl), index);
	if (a->IsIPv6)
	{
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index);
	}
}
void InRpcAccess(ACCESS *a, PACK *p)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	InRpcAccessEx(a, p, 0);
}
void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddIntEx(p, "Id", a->Id, index, total);
	PackAddUniStrEx(p, "Note", a->Note, index, total);
	PackAddBoolEx(p, "Active", a->Active, index, total);
	PackAddIntEx(p, "Priority", a->Priority, index, total);
	PackAddBoolEx(p, "Discard", a->Discard, index, total);
	if (a->IsIPv6)
	{
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, index, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, index, total);
	}
	else
	{
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, index, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, index, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, index, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, index, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, index, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, index, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, index, total);
	//PackAddIntEx(p, "SrcUsernameHash", a->SrcUsernameHash, index, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, index, total);
	//PackAddIntEx(p, "DestUsernameHash", a->DestUsernameHash, index, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, index, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, index, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, index, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, index, total);
	PackAddBoolEx(p, "Established", a->Established, index, total);
	PackAddIntEx(p, "Delay", a->Delay, index, total);
	PackAddIntEx(p, "Jitter", a->Jitter, index, total);
	PackAddIntEx(p, "Loss", a->Loss, index, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, index, total);
	PackAddIntEx(p, "UniqueId", a->UniqueId, index, total);
	PackAddStrEx(p, "RedirectUrl", a->RedirectUrl, index, total);
	if (a->IsIPv6)
	{
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index, total);
	}
	else
	{
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, index, total);
	}
}
void OutRpcAccess(PACK *p, ACCESS *a)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	OutRpcAccessEx(p, a, 0, 1);
}

// RPC_ENUM_ACCESS_LIST
void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p)
{
	UINT i;
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_ENUM_ACCESS_LIST));
	PackGetStr(p, "HubName", a->HubName, sizeof(a->HubName));
	a->NumAccess = PackGetIndexCount(p, "Protocol");
	a->Accesses = ZeroMalloc(sizeof(ACCESS) * a->NumAccess);

	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		InRpcAccessEx(e, p, i);
	}
}
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a)
{
	UINT i;
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", a->HubName);

	PackSetCurrentJsonGroupName(p, "AccessList");
	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		OutRpcAccessEx(p, e, i, a->NumAccess);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	Free(a->Accesses);
}

// AUTHDATA
void *InRpcAuthData(PACK *p, UINT *authtype, char *username)
{
	wchar_t tmp[MAX_SIZE];
	AUTHPASSWORD *pw;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	AUTHRADIUS *radius;
	AUTHNT *nt;
	BUF *b;
	char plain_pw[MAX_SIZE];
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}
	if (authtype == NULL)
	{
		return NULL;
	}

	*authtype = PackGetInt(p, "AuthType");

	switch (*authtype)
	{
	case AUTHTYPE_PASSWORD:
		pw = ZeroMalloc(sizeof(AUTHPASSWORD));
		PackGetData2(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackGetData2(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));

		if (PackGetStr(p, "Auth_Password", plain_pw, sizeof(plain_pw)))
		{
			if (IsZero(pw->HashedKey, sizeof(pw->HashedKey)))
			{
				HashPassword(pw->HashedKey, username, plain_pw);
				GenerateNtPasswordHash(pw->NtLmSecureHash, plain_pw);
			}
		}
		return pw;

	case AUTHTYPE_USERCERT:
		usercert = ZeroMalloc(sizeof(AUTHUSERCERT));
		usercert->UserX = PackGetX(p, "UserX");
		return usercert;

	case AUTHTYPE_ROOTCERT:
		rootcert = ZeroMalloc(sizeof(AUTHROOTCERT));
		b = PackGetBuf(p, "Serial");
		if (b != NULL)
		{
			rootcert->Serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
		{
			rootcert->CommonName = CopyUniStr(tmp);
		}
		return rootcert;

	case AUTHTYPE_RADIUS:
		radius = ZeroMalloc(sizeof(AUTHRADIUS));
		if (PackGetUniStr(p, "RadiusUsername", tmp, sizeof(tmp)))
		{
			radius->RadiusUsername = CopyUniStr(tmp);
		}
		else
		{
			radius->RadiusUsername = CopyUniStr(L"");
		}
		return radius;

	case AUTHTYPE_NT:
		nt = ZeroMalloc(sizeof(AUTHNT));
		if (PackGetUniStr(p, "NtUsername", tmp, sizeof(tmp)))
		{
			nt->NtUsername = CopyUniStr(tmp);
		}
		else
		{
			nt->NtUsername = CopyUniStr(L"");
		}
		return nt;
	}

	return NULL;
}
void OutRpcAuthData(PACK *p, void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = authdata;
	AUTHUSERCERT *usercert = authdata;
	AUTHROOTCERT *rootcert = authdata;
	AUTHRADIUS *radius = authdata;
	AUTHNT *nt = authdata;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", authtype);

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackAddData(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));
		break;

	case AUTHTYPE_USERCERT:
		PackAddX(p, "UserX", usercert->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rootcert->Serial != NULL)
		{
			PackAddData(p, "Serial", rootcert->Serial->data, rootcert->Serial->size);
		}
		if (rootcert->CommonName != NULL)
		{
			PackAddUniStr(p, "CommonName", rootcert->CommonName);
		}
		break;

	case AUTHTYPE_RADIUS:
		PackAddUniStr(p, "RadiusUsername", radius->RadiusUsername);
		break;

	case AUTHTYPE_NT:
		PackAddUniStr(p, "NtUsername", nt->NtUsername);
		break;
	}
}
void FreeRpcAuthData(void *authdata, UINT authtype)
{
	FreeAuthData(authtype, authdata);
}

// RPC_SET_USER
void InRpcSetUser(RPC_SET_USER *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->UpdatedTime = PackGetInt64(p, "UpdatedTime");
	t->ExpireTime = PackGetInt64(p, "ExpireTime");
	t->AuthData = InRpcAuthData(p, &t->AuthType, t->Name);
	t->NumLogin = PackGetInt(p, "NumLogin");
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}

void OutRpcSetUser(PACK *p, RPC_SET_USER *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	PackAddTime64(p, "CreatedTime", t->CreatedTime);
	PackAddTime64(p, "UpdatedTime", t->UpdatedTime);
	PackAddTime64(p, "ExpireTime", t->ExpireTime);
	OutRpcAuthData(p, t->AuthData, t->AuthType);
	PackAddInt(p, "NumLogin", t->NumLogin);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetUser(RPC_SET_USER *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeRpcAuthData(t->AuthData, t->AuthType);
	if (t->Policy)
	{
		Free(t->Policy);
	}
}

// RPC_ENUM_USER
void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumUser = PackGetIndexCount(p, "Name");
	t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * t->NumUser);

	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "GroupName", e->GroupName, sizeof(e->GroupName), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->AuthType = PackGetIntEx(p, "AuthType", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);
		e->DenyAccess = PackGetBoolEx(p, "DenyAccess", i);

		e->IsTrafficFilled = PackGetBoolEx(p, "IsTrafficFilled", i);
		InRpcTrafficEx(&e->Traffic, p, i);

		e->IsExpiresFilled = PackGetBoolEx(p, "IsExpiresFilled", i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "UserList");
	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumUser);
		PackAddStrEx(p, "GroupName", e->GroupName, i, t->NumUser);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumUser);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumUser);
		PackAddIntEx(p, "AuthType", e->AuthType, i, t->NumUser);
		PackAddTime64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumUser);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumUser);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumUser);

		PackAddBoolEx(p, "IsTrafficFilled", e->IsTrafficFilled, i, t->NumUser);
		OutRpcTrafficEx(&e->Traffic, p, i, t->NumUser);

		PackAddBoolEx(p, "IsExpiresFilled", e->IsExpiresFilled, i, t->NumUser);
		PackAddTime64Ex(p, "Expires", e->Expires, i, t->NumUser);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumUser(RPC_ENUM_USER *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Users);
}

// RPC_SET_GROUP
void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetGroup(RPC_SET_GROUP *t)
{
	Free(t->Policy);
}

// RPC_ENUM_GROUP
void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumGroup = PackGetIndexCount(p, "Name");
	t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
		e->DenyAccess = PackGetBoolEx(p, "DenyAccess", i);
	}
}
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "GroupList");
	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumGroup);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumGroup);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumGroup);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumGroup);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumGroup);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Groups);
}

// RPC_DELETE_USER
void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_SESSION
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumSession = PackGetIndexCount(p, "Name");
	t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Username", e->Username, sizeof(e->Username), i);
		e->Ip = PackGetIntEx(p, "Ip", i);
		PackGetIpEx(p, "ClientIP", &e->ClientIP, i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->MaxNumTcp = PackGetIntEx(p, "MaxNumTcp", i);
		e->CurrentNumTcp = PackGetIntEx(p, "CurrentNumTcp", i);
		e->PacketSize = PackGetInt64Ex(p, "PacketSize", i);
		e->PacketNum = PackGetInt64Ex(p, "PacketNum", i);
		e->RemoteSession = PackGetBoolEx(p, "RemoteSession", i);
		e->LinkMode = PackGetBoolEx(p, "LinkMode", i);
		e->SecureNATMode = PackGetBoolEx(p, "SecureNATMode", i);
		e->BridgeMode = PackGetBoolEx(p, "BridgeMode", i);
		e->Layer3Mode = PackGetBoolEx(p, "Layer3Mode", i);
		e->Client_BridgeMode = PackGetBoolEx(p, "Client_BridgeMode", i);
		e->Client_MonitorMode = PackGetBoolEx(p, "Client_MonitorMode", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
		e->VLanId = PackGetIntEx(p, "VLanId", i);
		PackGetDataEx2(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i);
		e->IsDormantEnabled = PackGetBoolEx(p, "IsDormantEnabled", i);
		e->IsDormant = PackGetBoolEx(p, "IsDormant", i);
		e->LastCommDormant = PackGetInt64Ex(p, "LastCommDormant", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
	}
}
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "SessionList");
	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumSession);
		PackAddStrEx(p, "Username", e->Username, i, t->NumSession);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumSession);
		PackAddIpEx(p, "ClientIP", &e->ClientIP, i, t->NumSession);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumSession);
		PackAddIntEx(p, "MaxNumTcp", e->MaxNumTcp, i, t->NumSession);
		PackAddIntEx(p, "CurrentNumTcp", e->CurrentNumTcp, i, t->NumSession);
		PackAddInt64Ex(p, "PacketSize", e->PacketSize, i, t->NumSession);
		PackAddInt64Ex(p, "PacketNum", e->PacketNum, i, t->NumSession);
		PackAddBoolEx(p, "RemoteSession", e->RemoteSession, i, t->NumSession);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumSession);
		PackAddBoolEx(p, "LinkMode", e->LinkMode, i, t->NumSession);
		PackAddBoolEx(p, "SecureNATMode", e->SecureNATMode, i, t->NumSession);
		PackAddBoolEx(p, "BridgeMode", e->BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Layer3Mode", e->Layer3Mode, i, t->NumSession);
		PackAddBoolEx(p, "Client_BridgeMode", e->Client_BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Client_MonitorMode", e->Client_MonitorMode, i, t->NumSession);
		PackAddIntEx(p, "VLanId", e->VLanId, i, t->NumSession);
		PackAddDataEx(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i, t->NumSession);
		PackAddBoolEx(p, "IsDormantEnabled", e->IsDormantEnabled, i, t->NumSession);
		PackAddBoolEx(p, "IsDormant", e->IsDormant, i, t->NumSession);
		PackAddTime64Ex(p, "LastCommDormant", e->LastCommDormant, i, t->NumSession);
		PackAddTime64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumSession);
		PackAddTime64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumSession);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumSession(RPC_ENUM_SESSION *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Sessions);
}

// RPC_KEY_PAIR
void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Cert = PackGetX(p, "Cert");
	t->Key = PackGetK(p, "Key");
	t->Flag1 = PackGetInt(p, "Flag1");
}
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddX(p, "Cert", t->Cert);
	PackAddK(p, "Key", t->Key);
	PackAddInt(p, "Flag1", t->Flag1);
}
void FreeRpcKeyPair(RPC_KEY_PAIR *t)
{
	FreeX(t->Cert);
	FreeK(t->Key);
}

// NODE_INFO
void InRpcNodeInfo(NODE_INFO *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(NODE_INFO));
	PackGetStr(p, "ClientProductName", t->ClientProductName, sizeof(t->ClientProductName));
	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ClientOsName", t->ClientOsName, sizeof(t->ClientOsName));
	PackGetStr(p, "ClientOsVer", t->ClientOsVer, sizeof(t->ClientOsVer));
	PackGetStr(p, "ClientOsProductId", t->ClientOsProductId, sizeof(t->ClientOsProductId));
	PackGetStr(p, "ClientHostname", t->ClientHostname, sizeof(t->ClientHostname));
	PackGetStr(p, "ServerHostname", t->ServerHostname, sizeof(t->ServerHostname));
	PackGetStr(p, "ProxyHostname", t->ProxyHostname, sizeof(t->ProxyHostname));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	t->ClientProductVer = PackGetInt(p, "ClientProductVer");
	t->ClientProductBuild = PackGetInt(p, "ClientProductBuild");
	t->ServerProductVer = PackGetInt(p, "ServerProductVer");
	t->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	t->ClientIpAddress = PackGetIp32(p, "ClientIpAddress");
	PackGetData2(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	t->ClientPort = PackGetInt(p, "ClientPort");
	t->ServerIpAddress = PackGetIp32(p, "ServerIpAddress");
	PackGetData2(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	t->ServerPort = PackGetInt(p, "ServerPort2");
	t->ProxyIpAddress = PackGetIp32(p, "ProxyIpAddress");
	PackGetData2(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
}
void OutRpcNodeInfo(PACK *p, NODE_INFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ClientProductName", t->ClientProductName);
	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ClientOsName", t->ClientOsName);
	PackAddStr(p, "ClientOsVer", t->ClientOsVer);
	PackAddStr(p, "ClientOsProductId", t->ClientOsProductId);
	PackAddStr(p, "ClientHostname", t->ClientHostname);
	PackAddStr(p, "ServerHostname", t->ServerHostname);
	PackAddStr(p, "ProxyHostname", t->ProxyHostname);
	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	PackAddInt(p, "ClientProductVer", t->ClientProductVer);
	PackAddInt(p, "ClientProductBuild", t->ClientProductBuild);
	PackAddInt(p, "ServerProductVer", t->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", t->ServerProductBuild);
	PackAddIp32(p, "ClientIpAddress", t->ClientIpAddress);
	PackAddData(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	PackAddInt(p, "ClientPort", t->ClientPort);
	PackAddIp32(p, "ServerIpAddress", t->ServerIpAddress);
	PackAddData(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	PackAddInt(p, "ServerPort2", t->ServerPort);
	PackAddIp32(p, "ProxyIpAddress", t->ProxyIpAddress);
	PackAddData(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	PackAddInt(p, "ProxyPort", t->ProxyPort);
}

// RPC_SESSION_STATUS
void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SESSION_STATUS));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "Username", t->Username, sizeof(t->Username));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetStr(p, "RealUsername", t->RealUsername, sizeof(t->RealUsername));
	t->ClientIp = PackGetIp32(p, "SessionStatus_ClientIp");
	PackGetData2(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackGetStr(p, "SessionStatus_ClientHostName", t->ClientHostName, sizeof(t->ClientHostName));
	PackGetIp(p, "Client_Ip_Address", &t->ClientIpAddress);

	InRpcClientGetConnectionStatus(&t->Status, p);
	InRpcNodeInfo(&t->NodeInfo, p);
}
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "Username", t->Username);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddStr(p, "RealUsername", t->RealUsername);
	PackAddIp32(p, "SessionStatus_ClientIp", t->ClientIp);
	PackAddData(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackAddStr(p, "SessionStatus_ClientHostName", t->ClientHostName);
	PackAddIp(p, "Client_Ip_Address", &t->ClientIpAddress);

	OutRpcClientGetConnectionStatus(p, &t->Status);
	OutRpcNodeInfo(p, &t->NodeInfo);
}
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

// RPC_DELETE_SESSION
void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

// RPC_ENUM_MAC_TABLE
void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumMacTable = PackGetIndexCount(p, "SessionName");
	t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		PackGetDataEx2(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i);
		e->VlanId = PackGetIntEx(p, "VlanId", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
		e->RemoteItem = PackGetBoolEx(p, "RemoteItem", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
	}
}
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "MacTable");
	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumMacTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumMacTable);
		PackAddDataEx(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i, t->NumMacTable);
		PackAddIntEx(p, "VlanId", e->VlanId, i, t->NumMacTable);
		PackAddTime64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumMacTable);
		PackAddTime64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumMacTable);
		PackAddBoolEx(p, "RemoteItem", e->RemoteItem, i, t->NumMacTable);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumMacTable);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->MacTables);
}

// RPC_ENUM_IP_TABLE
void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumIpTable = PackGetIndexCount(p, "SessionName");
	t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		e->Ip = PackGetIp32Ex(p, "Ip", i);
		if (PackGetIpEx(p, "IpV6", &e->IpV6, i) == false)
		{
			UINTToIP(&e->IpV6, e->Ip);
		}
		PackGetIp(p, "IpAddress", &e->IpAddress);
		e->DhcpAllocated = PackGetBoolEx(p, "DhcpAllocated", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
		e->RemoteItem = PackGetBoolEx(p, "RemoteItem", i);
		PackGetStrEx(p, "RemoteHostname", e->RemoteHostname, sizeof(e->RemoteHostname), i);
	}
}
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	PackSetCurrentJsonGroupName(p, "IpTable");
	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumIpTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumIpTable);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumIpTable);
		PackAddIpEx(p, "IpV6", &e->IpV6, i, t->NumIpTable);
		PackAddIpEx(p, "IpAddress", &e->IpAddress, i, t->NumIpTable);
		PackAddBoolEx(p, "DhcpAllocated", e->DhcpAllocated, i, t->NumIpTable);
		PackAddTime64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumIpTable);
		PackAddTime64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumIpTable);
		PackAddBoolEx(p, "RemoteItem", e->RemoteItem, i, t->NumIpTable);
		PackAddStrEx(p, "RemoteHostname", e->RemoteHostname, i, t->NumIpTable);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->IpTables);
}

// RPC_DELETE_TABLE
void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

// Adjoin RPC_ENUM_IP_TABLE
void AdjoinRpcEnumIpTable(RPC_ENUM_IP_TABLE *dest, RPC_ENUM_IP_TABLE *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumIpTable == 0)
	{
		return;
	}

	old_num = dest->NumIpTable;
	dest->NumIpTable += src->NumIpTable;
	dest->IpTables = ReAlloc(dest->IpTables, sizeof(RPC_ENUM_IP_TABLE_ITEM) * dest->NumIpTable);

	n = 0;
	for (i = old_num;i < dest->NumIpTable;i++)
	{
		Copy(&dest->IpTables[i], &src->IpTables[n++], sizeof(RPC_ENUM_IP_TABLE_ITEM));
	}
}

// Adjoin RPC_ENUM_MAC_TABLE
void AdjoinRpcEnumMacTable(RPC_ENUM_MAC_TABLE *dest, RPC_ENUM_MAC_TABLE *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumMacTable == 0)
	{
		return;
	}

	old_num = dest->NumMacTable;
	dest->NumMacTable += src->NumMacTable;
	dest->MacTables = ReAlloc(dest->MacTables, sizeof(RPC_ENUM_MAC_TABLE_ITEM) * dest->NumMacTable);

	n = 0;
	for (i = old_num;i < dest->NumMacTable;i++)
	{
		Copy(&dest->MacTables[i], &src->MacTables[n++], sizeof(RPC_ENUM_MAC_TABLE_ITEM));
	}
}

// Adjoin RPC_ENUM_SESSION
void AdjoinRpcEnumSession(RPC_ENUM_SESSION *dest, RPC_ENUM_SESSION *src)
{
	UINT old_num;
	UINT i, n;
	if (dest == NULL || src == NULL)
	{
		return;
	}

	if (src->NumSession == 0)
	{
		return;
	}

	old_num = dest->NumSession;
	dest->NumSession += src->NumSession;
	dest->Sessions = ReAlloc(dest->Sessions, sizeof(RPC_ENUM_SESSION_ITEM) * dest->NumSession);

	n = 0;
	for (i = old_num;i < dest->NumSession;i++)
	{
		Copy(&dest->Sessions[i], &src->Sessions[n++], sizeof(RPC_ENUM_SESSION_ITEM));
	}
}

// RPC_KEEP
void InRpcKeep(RPC_KEEP *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_KEEP));
	t->UseKeepConnect = PackGetBool(p, "UseKeepConnect");
	PackGetStr(p, "KeepConnectHost", t->KeepConnectHost, sizeof(t->KeepConnectHost));
	t->KeepConnectPort = PackGetInt(p, "KeepConnectPort");
	t->KeepConnectProtocol = PackGetInt(p, "KeepConnectProtocol");
	t->KeepConnectInterval = PackGetInt(p, "KeepConnectInterval");
}
void OutRpcKeep(PACK *p, RPC_KEEP *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "UseKeepConnect", t->UseKeepConnect);
	PackAddStr(p, "KeepConnectHost", t->KeepConnectHost);
	PackAddInt(p, "KeepConnectPort", t->KeepConnectPort);
	PackAddInt(p, "KeepConnectProtocol", t->KeepConnectProtocol);
	PackAddInt(p, "KeepConnectInterval", t->KeepConnectInterval);
}

// test RPC function
UINT StTest(ADMIN *a, RPC_TEST *t)
{
	Format(t->StrValue, sizeof(t->StrValue), "%u", t->IntValue);

	return ERR_NO_ERROR;
}

// RPC_TEST
void InRpcTest(RPC_TEST *t, PACK *p)
{
	Zero(t, sizeof(RPC_TEST));
	t->IntValue = PackGetInt(p, "IntValue");
	t->Int64Value = PackGetInt64(p, "Int64Value");
	PackGetStr(p, "StrValue", t->StrValue, sizeof(t->StrValue));
	PackGetUniStr(p, "UniStrValue", t->UniStrValue, sizeof(t->UniStrValue));
}
void OutRpcTest(PACK *p, RPC_TEST *t)
{
	PackAddInt(p, "IntValue", t->IntValue);
	PackAddInt64(p, "Int64Value", t->Int64Value);
	PackAddStr(p, "StrValue", t->StrValue);
	PackAddUniStr(p, "UniStrValue", t->UniStrValue);
}
void FreeRpcTest(RPC_TEST *t)
{
}

// Admin RPC call
PACK *AdminCall(RPC *rpc, char *function_name, PACK *p)
{
	// Validate arguments
	if (rpc == NULL || function_name == NULL)
	{
		return NULL;
	}
	if (p == NULL)
	{
		p = NewPack();
	}

//	Debug("Admin RPC Call: %s\n", function_name);

	return RpcCall(rpc, function_name, p);
}

// Check whether the source IP address is permitted to admin connection
bool CheckAdminSourceAddress(SOCK *sock, char *hubname)
{
	BUF *b;
	char *s;
	bool ok = false;
	// Validate arguments
	if (sock == NULL)
	{
		return false;
	}

	b = ReadDump(ADMINIP_TXT);
	if (b == NULL)
	{
		return true;
	}

	while (true)
	{
		UINT i;
		TOKEN_LIST *t;
		IP ip;
		IP mask;
		IP ip1;
		IP ip2;
		s = CfgReadNextLine(b);

		if (s == NULL)
		{
			break;
		}

		Trim(s);

		i = SearchStrEx(s, "//", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		i = SearchStrEx(s, "#", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		Trim(s);

		t = ParseToken(s, " \t");
		if (t != NULL)
		{
			if (t->NumTokens >= 1)
			{
				if (t->NumTokens == 1 || StrCmpi(hubname, t->Token[1]) == 0)
				{
					if (ParseIpAndMask46(t->Token[0], &ip, &mask))
					{
						if (IsIP4(&sock->RemoteIP) && IsIP4(&ip))
						{
							IPAnd4(&ip1, &sock->RemoteIP, &mask);
							IPAnd4(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
						else if (IsIP6(&sock->RemoteIP) && IsIP6(&ip))
						{
							IPAnd6(&ip1, &sock->RemoteIP, &mask);
							IPAnd6(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
					}
					else if (StrToIP(&ip, t->Token[0]))
					{
						if (CmpIpAddr(&sock->RemoteIP, &ip) == 0)
						{
							ok = true;
						}
					}

					if (StrCmpi(t->Token[0], "*") == 0)
					{
						ok = true;
					}
				}
			}

			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ok;
}

// Accept admin connection
UINT AdminAccept(CONNECTION *c, PACK *p)
{
	ADMIN *a;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR null_password[SHA1_SIZE];
	UCHAR secure_null_password[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	CEDAR *cedar;
	SOCK *sock;
	RPC *rpc;
	UINT err;
	SERVER *server = NULL;
	RPC_WINVER ver;
	bool accept_empty_password;
	bool is_empty_password = false;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	cedar = c->Cedar;
	sock = c->FirstSock;

	if (cedar != NULL)
	{
		server = cedar->Server;
	}

	accept_empty_password = PackGetBool(p, "accept_empty_password");

	// Get client OS version
	InRpcWinVer(&ver, p);

	// Get hub name
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false)
	{
		// without hub name
		StrCpy(hubname, sizeof(hubname), "");
	}

	// Check source IP address
	if (CheckAdminSourceAddress(sock, hubname) == false)
	{
		SLog(c->Cedar, "LA_IP_DENIED", c->Name);
		return ERR_IP_ADDRESS_DENIED;
	}

	// Get password information
	if (PackGetDataSize(p, "secure_password") != SHA1_SIZE)
	{
		// Malformed information
		return ERR_PROTOCOL_ERROR;
	}
	PackGetData(p, "secure_password", secure_password);

	if (StrLen(hubname) == 0)
	{
		// Server admin mode
		SLog(c->Cedar, "LA_CONNECTED_1", c->Name);
	}
	else
	{
		// Hub admin mode
		if (server != NULL && server->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			// Connection with hub admin mode to cluster member is not permitted
			return ERR_NOT_ENOUGH_RIGHT;
		}
		SLog(c->Cedar, "LA_CONNECTED_2", c->Name, hubname);
	}

	// Check password
	err = AdminCheckPassword(cedar, c->Random, secure_password,
		StrLen(hubname) != 0 ? hubname : NULL, accept_empty_password, &is_empty_password);

	if (err != ERR_NO_ERROR)
	{
		// Error occured
		SLog(c->Cedar, "LA_ERROR", c->Name, GetUniErrorStr(err), err);
		return err;
	}

	SLog(c->Cedar, "LA_OK", c->Name);

	HashAdminPassword(null_password, "");
	SecurePassword(secure_null_password, null_password, c->Random);

	if (Cmp(secure_null_password, secure_password, SHA1_SIZE) == 0)
	{
		if (sock->RemoteIP.addr[0] != 127)
		{
			// The client tried to use blank password for hub admin mode from remote
			if (StrLen(hubname) != 0)
			{
				return ERR_NULL_PASSWORD_LOCAL_ONLY;
			}
		}
	}


	// Reply success result
	p = NewPack();
	if (accept_empty_password && is_empty_password)
	{
		PackAddBool(p, "empty_password", true);
	}
	HttpServerSend(sock, p);
	FreePack(p);

	// Construct ADMIN object
	a = ZeroMalloc(sizeof(ADMIN));
	a->ServerAdmin = ((StrLen(hubname) == 0) ? true : false);
	a->HubName = (StrLen(hubname) != 0 ? hubname : NULL);
	a->Server = c->Cedar->Server;
	a->ClientBuild = c->ClientBuild;

	Copy(&a->ClientWinVer, &ver, sizeof(RPC_WINVER));

	// Timeout setting
	SetTimeout(sock, INFINITE);

	// RPC Server
	rpc = StartRpcServer(sock, AdminDispatch, a);

	a->Rpc = rpc;

	SLog(c->Cedar, "LA_RPC_START", c->Name, rpc->Name);

	RpcServer(rpc);
	RpcFree(rpc);

	if (a->LogFileList != NULL)
	{
		// Free cached log file list, if it exists
		FreeEnumLogFile(a->LogFileList);
	}

	// Free ADMIN object
	Free(a);

	return ERR_NO_ERROR;
}

// Check for admin password
UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname,
						bool accept_empty_password, bool *is_password_empty)
{
	UCHAR check[SHA1_SIZE];
	bool b_dummy;
	// Validate arguments
	if (c == NULL || random == NULL || secure_password == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (is_password_empty == NULL)
	{
		is_password_empty = &b_dummy;
	}

	*is_password_empty = false;

	if (hubname == NULL || StrLen(hubname) == 0)
	{
		// Server admin mode
		Lock(c->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(c->Server->HashedPassword))
			{
				// blank password
				*is_password_empty = true;
			}

			SecurePassword(check, c->Server->HashedPassword, random);
		}
		Unlock(c->lock);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			// Password incorrect
			return ERR_ACCESS_DENIED;
		}
	}
	else
	{
		HUB *h;

#if	0
		if (c->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			// In cluster member mode, hub admin mode is disabled
			return ERR_FARM_MEMBER_HUB_ADMIN;
		}
#endif

		// Hub admin mode
		LockHubList(c);
		{
			h = GetHub(c, hubname);
		}
		UnlockHubList(c);

		if (h == NULL)
		{
			// Specified hub is not found
			return ERR_HUB_NOT_FOUND;
		}

		Lock(h->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(h->HashedPassword))
			{
				// User specified blank password
				*is_password_empty = true;
			}

			SecurePassword(check, h->HashedPassword, random);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			// Incorrect password
			return ERR_ACCESS_DENIED;
		}
	}

	return ERR_NO_ERROR;
}

// Hash admin password
void HashAdminPassword(void *hash, char *password)
{
	// Validate arguments
	if (hash == NULL || password == NULL)
	{
		return;
	}

	Sha0(hash, password, StrLen(password));
}

// Disconnect admin connection
void AdminDisconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	// Validate arguments
	if (rpc == NULL)
	{
		return;
	}

	s = (SESSION *)rpc->Param;
	sock = rpc->Sock;

	EndRpc(rpc);

	Disconnect(sock);
	ReleaseSession(s);
}

// Admin connection main routine
SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd, bool *empty_password)
{
	UCHAR secure_password[SHA1_SIZE];
	SESSION *s;
	SOCK *sock;
	PACK *p;
	RPC_WINVER ver;
	// connect
	s = NewRpcSessionEx2(cedar, o, err, client_name, hWnd);
	if (s == NULL)
	{
		return NULL;
	}

	// Get socket
	sock = s->Connection->FirstSock;

	// Generate connect method
	p = NewPack();

	PackAddClientVersion(p, s->Connection);

	PackAddStr(p, "method", "admin");
	PackAddBool(p, "accept_empty_password", true);

	// Windows version on client
	GetWinVer(&ver);
	OutRpcWinVer(p, &ver);

	// Secure Password
	SecurePassword(secure_password, hashed_password, s->Connection->Random);

	PackAddData(p, "secure_password", secure_password, sizeof(secure_password));

	// HUB name
	if (hubname != NULL)
	{
		PackAddStr(p, "hubname", hubname);
	}

	if (HttpClientSend(sock, p) == false)
	{
		// disconnect
		FreePack(p);
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		// disconnect
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	if (GetErrorFromPack(p) != 0)
	{
		// error
		ReleaseSession(s);
		*err = GetErrorFromPack(p);
		FreePack(p);
		return NULL;
	}

	if (empty_password != NULL)
	{
		*empty_password = PackGetBool(p, "empty_password");
	}

	FreePack(p);

	return s;
}

// Admin connection
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name)
{
	return AdminConnectEx2(cedar, o, hubname, hashed_password, err, client_name, NULL);
}
RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd)
{
	SESSION *s;
	SOCK *sock;
	RPC *rpc;
	UCHAR hashed_password_2[SHA1_SIZE];
	bool empty_password = false;
	// Validate arguments
	if (cedar == NULL || o == NULL || hashed_password == NULL || err == NULL)
	{
		return NULL;
	}

	if (client_name == NULL)
	{
		client_name = CEDAR_MANAGER_STR;
	}

	Copy(hashed_password_2, hashed_password, SHA1_SIZE);

	s = AdminConnectMain(cedar, o, hubname, hashed_password_2, err, client_name, hWnd, &empty_password);

	if (s == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;

	// RPC start
	rpc = StartRpcClient(sock, s);

	rpc->IsVpnServer = true;
	Copy(&rpc->VpnServerClientOption, o, sizeof(CLIENT_OPTION));
	StrCpy(rpc->VpnServerHubName, sizeof(rpc->VpnServerHubName), hubname);
	StrCpy(rpc->VpnServerClientName, sizeof(rpc->VpnServerClientName), client_name);

	if (empty_password == false)
	{
		Copy(rpc->VpnServerHashedPassword, hashed_password_2, SHA1_SIZE);
	}
	else
	{
		HashAdminPassword(rpc->VpnServerHashedPassword, "");
	}

	// timeout setting
	SetTimeout(sock, INFINITE);

	return rpc;
}

// Reconnect admin connection
UINT AdminReconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	CEDAR *cedar;
	UINT err;
	bool empty_password = false;
	// Validate arguments
	if (rpc == NULL || rpc->IsVpnServer == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	s = (SESSION *)rpc->Param;
	cedar = s->Cedar;
	AddRef(cedar->ref);

	sock = rpc->Sock;
	Disconnect(sock);
	ReleaseSock(sock);
	ReleaseSession(s);
	rpc->Param = NULL;

	rpc->Sock = NULL;

	s = AdminConnectMain(cedar, &rpc->VpnServerClientOption,
		rpc->VpnServerHubName,
		rpc->VpnServerHashedPassword,
		&err,
		rpc->VpnServerClientName, NULL, &empty_password);

	ReleaseCedar(cedar);

	if (s == NULL)
	{
		return err;
	}

	if (empty_password)
	{
		HashAdminPassword(rpc->VpnServerHashedPassword, "");
	}

	rpc->Param = s;
	rpc->Sock = s->Connection->FirstSock;
	AddRef(rpc->Sock->ref);

	return ERR_NO_ERROR;
}

// Identify blank password
bool SiIsEmptyPassword(void *hash_password)
{
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (hash_password == NULL)
	{
		return false;
	}

	Sha0(hash, "", 0);

	if (Cmp(hash_password, hash, SHA1_SIZE) == 0)
	{
		return true;
	}

	return false;
}

