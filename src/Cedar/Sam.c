// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Sam.c
// Security Accounts Manager

#include "Sam.h"

#include "Account.h"
#include "Cedar.h"
#include "Connection.h"
#include "Hub.h"
#include "IPC.h"
#include "Proto_PPP.h"
#include "Radius.h"
#include "Server.h"

#include "Mayaqua/Encoding.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include <string.h>

#ifdef OS_UNIX
#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <unistd.h>
#endif

PID OpenChildProcess(const char* path, char* const parameter[], int fd[] )
{
#ifdef OS_WIN32
	// not implemented
	return -1;
#else // OS_WIN32
	// UNIX
	int fds[2][2];
	PID pid;

	if (path == NULL || parameter == NULL || fd == NULL)
	{
		return (PID)-1;
	}

	if (pipe(fds[0]) != 0)
	{
		return (PID)-1;
	}

	if (pipe(fds[1]) != 0)
	{
		close(fds[0][0]);
		close(fds[0][1]);

		return (PID)-1;
	}

	pid = fork();
	if (pid == (PID)0) {
		int iError;

		close(fds[0][1]);
		close(fds[1][0]);

		if (dup2(fds[0][0], fileno(stdin)) < 0 || dup2(fds[1][1], fileno(stdout)) < 0 )
		{
			close(fds[0][0]);
			close(fds[1][1]);

			_exit(EXIT_FAILURE);
		}

		iError = execvp(path, parameter);

		// We should never come here 
		close(fds[0][0]);
		close(fds[1][1]);

		_exit(iError);
	}
	else if (pid > (PID)0)
	{
		close(fds[0][0]);
		close(fds[1][1]);

		fd[0] = fds[1][0];
		fd[1] = fds[0][1];

		return pid;
	}
	else
	{
		close(fds[0][0]);
		close(fds[1][1]);

		close(fds[0][1]);
		close(fds[1][0]);

		return -1;
	}
#endif // OS_WIN32
}

void CloseChildProcess(PID pid, int* fd )
{
#ifdef OS_WIN32
	// not implemented
#else // OS_WIN32
	if( fd != 0 )
	{
			close(fd[0]);
			close(fd[1]);
	}

	if( pid > 0 )
	{
		kill(pid, SIGTERM);
	}
#endif // OS_WIN32
}

bool SmbAuthenticate(char* name, char* password, char* domainname, char* groupname, UINT timeout, UCHAR* challenge8, UCHAR* MsChapV2_ClientResponse, UCHAR* nt_pw_hash_hash)
{
	bool  auth = false;
	int   fds[2];
	FILE* out, *in;
	PID   pid;
	char  ntlm_timeout[32];
	char* proc_parameter[6];

    // DNS Name 255 chars + OU names are limited to 64 characters +  cmdline 32 + 1
    char  requiremember[352];

	if (name == NULL || password == NULL || domainname == NULL || groupname == NULL)
	{
		Debug("Sam.c - SmbAuthenticate - wrong password parameter\n");
		return false;
	}

	if (password[0] == '\0' && (challenge8 == NULL || MsChapV2_ClientResponse == NULL || nt_pw_hash_hash == NULL))
	{
		Debug("Sam.c - SmbAuthenticate - wrong MsCHAPv2 parameter\n");
		return false;
	}

	// Truncate string if unsafe char
	EnSafeStr(domainname, '\0');

	if (strlen(domainname) > 255)
	{
		// there is no domainname longer then 255 chars!
		// http://tools.ietf.org/html/rfc1035 section 2.3.4
		domainname[255] = '\0';
	}
	
	// set timeout to 15 minutes even if timeout is disabled, to prevent ntlm_auth from hung up
	if (timeout <= 0 || timeout > 900)
	{
		timeout = 999;
	}
	
	snprintf(ntlm_timeout, sizeof(ntlm_timeout), "%is", timeout);
	Debug("Sam.c - timeout for ntlm_auth %s\n", ntlm_timeout);

	proc_parameter[0] = "timeout";
	proc_parameter[1] = ntlm_timeout;
	proc_parameter[2] = "ntlm_auth";
	proc_parameter[3] = "--helper-protocol=ntlm-server-1";
	proc_parameter[4] = 0;

	if (strlen(groupname) > 1)
	{
		// Truncate string if unsafe char
		EnSafeStr(groupname, '\0');

		snprintf(requiremember, sizeof(requiremember), "--require-membership-of=%s\\%s", domainname, groupname);

		proc_parameter[4] = requiremember;
		proc_parameter[5] = 0;
	}

	pid = OpenChildProcess("timeout", proc_parameter, fds);

	if (pid < 0)
	{
		Debug("Sam.c - SmbCheckLogon - error fork child process (ntlm_auth)\n");
		return false;
	}

	out = fdopen(fds[1], "w");
	if (out == 0)
	{
		CloseChildProcess(pid, fds);

		Debug("Sam.c - cant open out pipe (ntlm_auth)\n");
		return false;
	}

	in = fdopen(fds[0], "r");
	if (in == 0)
	{
		fclose(out);
		CloseChildProcess(pid, fds);

		Debug("Sam.c - cant open in pipe (ntlm_auth)\n");
		return false;
	}

	{
		char *base64 = Base64FromBin(NULL, name, StrLen(name));
		fputs("Username:: ", out);
		fputs(base64, out);
		fputs("\n", out);
		Free(base64);

		base64 = Base64FromBin(NULL, domainname, StrLen(domainname));
		fputs("NT-Domain:: ", out);
		fputs(base64, out);
		fputs("\n", out);
		Free(base64);

		if (IsEmptyStr(password) == false)
		{
			Debug("SmbAuthenticate(): Using password authentication...\n");

			base64 = Base64FromBin(NULL, password, StrLen(password));
			fputs("Password:: ", out);
			fputs(base64, out);
			fputs("\n", out);
			Free(base64);
		}
		else
		{
			Debug("SmbAuthenticate(): Using MsChapV2 authentication...\n");

			char *mschapv2_client_response = CopyBinToStr(MsChapV2_ClientResponse, 24);
			base64 = Base64FromBin(NULL, mschapv2_client_response, 48);
			Free(mschapv2_client_response);
			fputs("NT-Response:: ", out);
			fputs(base64, out);
			fputs("\n", out);
			Free(base64);

			char *base64_challenge8 = CopyBinToStr(challenge8, 8);
			base64 = Base64FromBin(NULL, base64_challenge8, 16);
			Free(base64_challenge8);
			fputs("LANMAN-Challenge:: ", out);
			fputs(base64, out);
			fputs("\n", out);
			Free(base64);

			fputs("Request-User-Session-Key: Yes\n", out);
 		}

		// Start authentication
		fputs( ".\n", out );
		fflush (out);
		// Request send!

		char answer[300];
		Zero(answer, sizeof(answer));

		while (fgets(answer, sizeof(answer)-1, in))
		{
			char* response_parameter;

			if (strncmp(answer, ".\n", sizeof(answer)-1 ) == 0)
			{
				break;
			}

			/* Indicates a base64 encoded structure */
			response_parameter = strstr(answer, ":: ");
			if (!response_parameter) {
				char* newline;

				response_parameter = strstr(answer, ": ");

				if (!response_parameter) {
					continue;
				}

				response_parameter[0] ='\0';
				response_parameter++;
				response_parameter[0] ='\0';
				response_parameter++;

				newline  = strstr(response_parameter, "\n");
				if( newline )
					newline[0] = '\0';
			} else {
				response_parameter[0] ='\0';
				response_parameter++;
				response_parameter[0] ='\0';
				response_parameter++;
				response_parameter[0] ='\0';
				response_parameter++;

				const UINT end = Base64Decode(response_parameter, response_parameter, StrLen(response_parameter));
				response_parameter[end] = '\0';
			}

			if (strncmp(answer, "Authenticated", sizeof(answer)-1 ) == 0)
			{
				if (strcmp(response_parameter, "Yes") == 0)
				{
					Debug("Authenticated!\n");
					auth = true;
				}
				else if (strcmp(response_parameter, "No") == 0)
				{
					Debug("Authentication failed!\n");
					auth = false;
				}
			}
			else if (strncmp(answer, "User-Session-Key", sizeof(answer)-1 ) == 0)
			{
				if (nt_pw_hash_hash != NULL)
				{
					BUF* Buf = StrToBin(response_parameter);
					Copy(nt_pw_hash_hash, Buf->Buf, 16);
					FreeBuf(Buf);
				}
			}
		}
	}

	fclose(in);
	fclose(out);

	CloseChildProcess(pid, fds);

	return auth;
}


bool SmbCheckLogon(char* name, char* password, char* domainname, char* groupname, UINT timeout)
{
	return SmbAuthenticate(name, password, domainname, groupname, timeout, NULL, NULL, NULL);
}

bool SmbPerformMsChapV2Auth(char* name, char* domainname, char* groupname, UCHAR* challenge8, UCHAR* MsChapV2_ClientResponse, UCHAR* nt_pw_hash_hash, UINT timeout)
{
	return SmbAuthenticate(name, "", domainname, groupname, timeout, challenge8, MsChapV2_ClientResponse, nt_pw_hash_hash);
}

// Password encryption
void SecurePassword(void *secure_password, void *password, void *random)
{
	BUF *b;
	// Validate arguments
	if (secure_password == NULL || password == NULL || random == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, password, SHA1_SIZE);
	WriteBuf(b, random, SHA1_SIZE);
	Sha0(secure_password, b->Buf, b->Size);

	FreeBuf(b);
}

// Generate 160bit random number
void GenRandom(void *random)
{
	// Validate arguments
	if (random == NULL)
	{
		return;
	}

	Rand(random, SHA1_SIZE);
}

// Anonymous authentication of user
bool SamAuthUserByAnonymous(HUB *h, char *username)
{
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return false;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_ANONYMOUS)
				{
					b = true;
				}
			}
			Unlock(u->lock);
		}
		ReleaseUser(u);
	}
	AcUnlock(h);

	return b;
}

// Plaintext password authentication of user
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast, UCHAR *mschap_v2_server_response_20, RADIUS_LOGIN_OPTION *opt)
{
	bool b = false;
	wchar_t *name = NULL;
	wchar_t *groupname = NULL;
	UINT timeout = 90;
	bool auth_by_nt = false;
	HUB *h;
	// Validate arguments
	if (hub == NULL || c == NULL || username == NULL || password == NULL || opt == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		return false;
	}

	h = hub;

	AddRef(h->ref);

	// Get the user name on authentication system
	AcLock(hub);
	{
		USER *u;

		// Find exact user first
		u = AcGetUser(hub, username);
		if (u == NULL && ast)
		{
			u = AcGetUser(hub, "*");
		}

		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_RADIUS)
				{
					// Radius authentication
					AUTHRADIUS *auth = (AUTHRADIUS *)u->AuthData;
					if (auth->RadiusUsername == NULL || UniStrLen(auth->RadiusUsername) == 0)
					{
						if( IsEmptyStr(h->RadiusRealm) == false )
						{	
							char name_and_realm[MAX_SIZE];
							StrCpy(name_and_realm, sizeof(name_and_realm), username);
							StrCat(name_and_realm, sizeof(name_and_realm), "@");
							StrCat(name_and_realm, sizeof(name_and_realm), h->RadiusRealm);
							name = CopyStrToUni(name_and_realm);
						}
						else
						{
							name = CopyStrToUni(username);
						}
					}
					else
					{
						name = CopyUniStr(auth->RadiusUsername);
					}
					auth_by_nt = false;
				}
				else if (u->AuthType == AUTHTYPE_NT)
				{
					// NT authentication
					AUTHNT *auth = (AUTHNT *)u->AuthData;
					if (auth->NtUsername == NULL || UniStrLen(auth->NtUsername) == 0)
					{
						name = CopyStrToUni(username);
					}
					else
					{
						name = CopyUniStr(auth->NtUsername);
					}

					groupname = CopyStrToUni(u->GroupName);
					
					if (u->Policy)
					{
						timeout = u->Policy->TimeOut;
					}

					auth_by_nt = true;
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(hub);

	if (name != NULL)
	{
		if (auth_by_nt == false)
		{
			// Radius authentication
			char radius_server_addr[MAX_SIZE];
			UINT radius_server_port;
			char radius_secret[MAX_SIZE];
			char suffix_filter[MAX_SIZE];
			wchar_t suffix_filter_w[MAX_SIZE];
			UINT interval;
			EAP_CLIENT *eap = NULL;
			char password1[MAX_SIZE];
			UCHAR client_challenge[16];
			UCHAR server_challenge[16];
			UCHAR challenge8[8];
			UCHAR client_response[24];
			UCHAR ntlm_hash[MD5_SIZE];

			Zero(suffix_filter, sizeof(suffix_filter));
			Zero(suffix_filter_w, sizeof(suffix_filter_w));

			// MSCHAPv2 / EAP wrapper for SEVPN
			if (c->IsInProc == false && StartWith(password, IPC_PASSWORD_MSCHAPV2_TAG) == false)
			{
				char client_ip_str[MAX_SIZE];
				char utf8[MAX_SIZE];

				// Convert the user name to a Unicode string
				UniToStr(utf8, sizeof(utf8), name);
				utf8[MAX_SIZE-1] = 0;

				Zero(client_ip_str, sizeof(client_ip_str));
				if (c != NULL && c->FirstSock != NULL)
				{
					IPToStr(client_ip_str, sizeof(client_ip_str), &c->FirstSock->RemoteIP);
				}

				if (hub->RadiusConvertAllMsChapv2AuthRequestToEap)
				{
					// Do EAP or PEAP
					eap = HubNewEapClient(hub->Cedar, hub->Name, client_ip_str, utf8, opt->In_VpnProtocolState, false, NULL, 0);

					// Prepare MSCHAP response and replace plain password
					if (eap != NULL)
					{
						char server_challenge_hex[MAX_SIZE];
						char client_challenge_hex[MAX_SIZE];
						char client_response_hex[MAX_SIZE];
						char eap_client_hex[64];

						MsChapV2Client_GenerateChallenge(client_challenge);
						GenerateNtPasswordHash(ntlm_hash, password);
						Copy(server_challenge, eap->MsChapV2Challenge.Chap_ChallengeValue, 16);
						MsChapV2_GenerateChallenge8(challenge8, client_challenge, server_challenge, utf8);
						MsChapV2Client_GenerateResponse(client_response, challenge8, ntlm_hash);

						BinToStr(server_challenge_hex, sizeof(server_challenge_hex),
								server_challenge, sizeof(server_challenge));
						BinToStr(client_challenge_hex, sizeof(client_challenge_hex),
								client_challenge, sizeof(client_challenge));
						BinToStr(client_response_hex, sizeof(client_response_hex),
								client_response, sizeof(client_response));
						BinToStr(eap_client_hex, sizeof(eap_client_hex), &eap, 8);
						Format(password1, sizeof(password1), "%s%s:%s:%s:%s:%s",
										IPC_PASSWORD_MSCHAPV2_TAG,
										utf8,
										server_challenge_hex,
										client_challenge_hex,
										client_response_hex,
										eap_client_hex);
						password = password1;
					}
				}
				else
				{
					// Todo: Do MSCHAPv2
				}
			}

			// Get the Radius server information
			if (GetRadiusServerEx2(hub, radius_server_addr, sizeof(radius_server_addr), &radius_server_port, radius_secret, sizeof(radius_secret), &interval, suffix_filter, sizeof(suffix_filter)))
			{
				Unlock(hub->lock);

				StrToUni(suffix_filter_w, sizeof(suffix_filter_w), suffix_filter);

				if (UniIsEmptyStr(suffix_filter_w) || UniEndWith(name, suffix_filter_w))
				{
					// Attempt to login
					b = RadiusLogin(c, radius_server_addr, radius_server_port,
						radius_secret, StrLen(radius_secret),
						name, password, interval, mschap_v2_server_response_20, opt, hub->Name);

					if (b)
					{
						opt->Out_IsRadiusLogin = true;
					}
				}

				Lock(hub->lock);
			}
			else
			{
				HLog(hub, "LH_NO_RADIUS_SETTING", name);
			}

			if (eap != NULL)
			{
				ReleaseEapClient(eap);
			}
		}
		else
		{
			// NT authentication
#ifdef	OS_WIN32
			IPC_MSCHAP_V2_AUTHINFO mschap;
			Unlock(hub->lock);

			if (ParseAndExtractMsChapV2InfoFromPassword(&mschap, password) == false)
			{
				// Plaintext password authentication
				b = MsCheckLogon(name, password);
			}
			else
			{
				UCHAR challenge8[8];
				UCHAR nt_pw_hash_hash[16];
				char nt_name[MAX_SIZE];

				UniToStr(nt_name, sizeof(nt_name), name);

				// MS-CHAPv2 authentication
				MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge,
					mschap.MsChapV2_ServerChallenge,
					mschap.MsChapV2_PPPUsername);

				Debug("MsChapV2_PPPUsername = %s, nt_name = %s\n", mschap.MsChapV2_PPPUsername, nt_name);

				b = MsPerformMsChapV2AuthByLsa(nt_name, challenge8, mschap.MsChapV2_ClientResponse, nt_pw_hash_hash);

				if (b)
				{
					if (mschap_v2_server_response_20 != NULL)
					{
						MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
							mschap.MsChapV2_ClientResponse, challenge8);
					}
				}
			}

			Lock(hub->lock);
#else	// OS_WIN32
			// Unix / Samba Winbind

			IPC_MSCHAP_V2_AUTHINFO mschap;
			Unlock(hub->lock);

			char nt_name[MAX_SIZE];
			char nt_username[MAX_SIZE];
			char nt_groupname[MAX_SIZE];
			char nt_domainname[MAX_SIZE];
			UCHAR challenge8[8];
			UCHAR nt_pw_hash_hash[16];

			nt_groupname[0] = 0;

			UniToStr(nt_name, sizeof(nt_name), name);

			if (groupname != NULL)
				UniToStr(nt_groupname, sizeof(nt_groupname), groupname);

			ParseNtUsername(nt_name, nt_username, sizeof(nt_username), nt_domainname, sizeof(nt_domainname), false);

			if (ParseAndExtractMsChapV2InfoFromPassword(&mschap, password) == false)
			{
				// Plaintext password authentication
				b = SmbCheckLogon(nt_username, password, nt_domainname, nt_groupname, timeout);
			}
			else
			{
				// MS-CHAPv2 authentication
				MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge,
					mschap.MsChapV2_ServerChallenge,
					mschap.MsChapV2_PPPUsername);

				Debug("MsChapV2_PPPUsername = %s, nt_name = %s\n", mschap.MsChapV2_PPPUsername, nt_name);

				b = SmbPerformMsChapV2Auth(nt_username, nt_domainname, nt_groupname, challenge8, mschap.MsChapV2_ClientResponse, nt_pw_hash_hash, timeout);

				if (b)
				{
					if (mschap_v2_server_response_20 != NULL)
					{
						MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
							mschap.MsChapV2_ClientResponse, challenge8);
					}
				}
			}

			Lock(hub->lock);
#endif	// OS_WIN32 / OS_LINUX
		}

		// Memory release
		if( groupname != NULL )
			Free(groupname);
		Free(name);
	}

	ReleaseHub(h);

	return b;
}

// Certificate authentication of user
bool SamAuthUserByCert(HUB *h, char *username, X *x)
{
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL || x == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) != 0)
	{
		return false;
	}

	// Check expiration date
	if (CheckXDateNow(x) == false)
	{
		return false;
	}

	// Check the Certification Revocation List
	if (IsValidCertInHub(h, x) == false)
	{
		// Bad
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_NG_CERT", username, tmp);
		return false;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_USERCERT)
				{
					// Check whether to matche with the registered certificate
					AUTHUSERCERT *auth = (AUTHUSERCERT *)u->AuthData;
					if (CompareX(auth->UserX, x))
					{
						b = true;
					}
				}
				else if (u->AuthType == AUTHTYPE_ROOTCERT)
				{
					// Check whether the certificate has been signed by the root certificate
					AUTHROOTCERT *auth = (AUTHROOTCERT *)u->AuthData;
					if (h->HubDb != NULL)
					{
						LockList(h->HubDb->RootCertList);
						{
							X *root_cert;
							root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
							if (root_cert != NULL)
							{
								b = true;
								if (auth->CommonName != NULL && UniIsEmptyStr(auth->CommonName) == false)
								{
									// Compare the CN
									if (UniStrCmpi(x->subject_name->CommonName, auth->CommonName) != 0)
									{
										b = false;
									}
								}
								if (auth->Serial != NULL && auth->Serial->size >= 1)
								{
									// Compare the serial number
									if (CompareXSerial(x->serial, auth->Serial) == false)
									{
										b = false;
									}
								}
							}
						}
						UnlockList(h->HubDb->RootCertList);
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (b)
	{
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_OK_CERT", username, tmp);
	}

	return b;
}

// Get the root certificate that signed the specified certificate from the list
X *GetIssuerFromList(LIST *cert_list, X *cert)
{
	UINT i;
	X *ret = NULL;
	// Validate arguments
	if (cert_list == NULL || cert == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(cert_list);i++)
	{
		X *x = LIST_DATA(cert_list, i);
		// Name comparison
		if (CheckXDateNow(x))
		{
			if (CompareName(x->subject_name, cert->issuer_name))
			{
				// Get the public key of the root certificate
				K *k = GetKFromX(x);

				if (k != NULL)
				{
					// Check the signature
					if (CheckSignature(cert, k))
					{
						ret = x;
					}
					FreeK(k);
				}
			}
		}
		if (CompareX(x, cert))
		{
			// Complete identical
			ret = x;
		}
	}

	return ret;
}

// Get the policy to be applied for the user
POLICY *SamGetUserPolicy(HUB *h, char *username)
{
	POLICY *ret = NULL;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return NULL;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			USERGROUP *g = NULL;
			Lock(u->lock);
			{
				if (u->Policy != NULL)
				{
					ret = ClonePolicy(u->Policy);
				}

				g = u->Group;

				if (g != NULL)
				{
					AddRef(g->ref);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
			u = NULL;

			if (ret == NULL)
			{
				if (g != NULL)
				{
					Lock(g->lock);
					{
						ret = ClonePolicy(g->Policy);
					}
					Unlock(g->lock);
				}
			}

			if (g != NULL)
			{
				ReleaseGroup(g);
			}
		}
	}
	AcUnlock(h);

	return ret;
}

// Password authentication of user
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err)
{
	bool b = false;
	UCHAR secure_password_check[SHA1_SIZE];
	bool is_mschap = false;
	IPC_MSCHAP_V2_AUTHINFO mschap;
	UINT dummy = 0;
	// Validate arguments
	if (h == NULL || username == NULL || secure_password == NULL)
	{
		return false;
	}
	if (err == NULL)
	{
		err = &dummy;
	}

	*err = 0;

	Zero(&mschap, sizeof(mschap));

	is_mschap = ParseAndExtractMsChapV2InfoFromPassword(&mschap, mschap_v2_password);

	if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0)
	{
		// Administrator mode
		SecurePassword(secure_password_check, h->SecurePassword, random);
		if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_PASSWORD)
				{
					AUTHPASSWORD *auth = (AUTHPASSWORD *)u->AuthData;

					if (is_mschap == false)
					{
						// Normal password authentication
						SecurePassword(secure_password_check, auth->HashedKey, random);
						if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
						{
							b = true;
						}
					}
					else
					{
						// MS-CHAP v2 authentication via PPP
						UCHAR challenge8[8];
						UCHAR client_response[24];

						if (IsZero(auth->NtLmSecureHash, MD5_SIZE))
						{
							// NTLM hash is not registered in the user account
							*err = ERR_MSCHAP2_PASSWORD_NEED_RESET;
						}
						else
						{
							UCHAR nt_pw_hash_hash[16];
							Zero(challenge8, sizeof(challenge8));
							Zero(client_response, sizeof(client_response));

							MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge, mschap.MsChapV2_ServerChallenge,
								mschap.MsChapV2_PPPUsername);

							MsChapV2Client_GenerateResponse(client_response, challenge8, auth->NtLmSecureHash);

							if (Cmp(client_response, mschap.MsChapV2_ClientResponse, 24) == 0)
							{
								// Hash matched
								b = true;

								// Calculate the response
								GenerateNtPasswordHashHash(nt_pw_hash_hash, auth->NtLmSecureHash);
								MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
									client_response, challenge8);
							}
						}
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	return b;
}

// Make sure that the user exists
bool SamIsUser(HUB *h, char *username)
{
	bool b;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return false;
	}

	AcLock(h);
	{
		b = AcIsUser(h, username);
	}
	AcUnlock(h);

	return b;
}

// Get the type of authentication used by the user
UINT SamGetUserAuthType(HUB *h, char *username)
{
	UINT authtype;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return INFINITE;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u == NULL)
		{
			authtype = INFINITE;
		}
		else
		{
			authtype = u->AuthType;
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	return authtype;
}

