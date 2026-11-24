// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Stfa.c

#include "Stfa.h"

#include "CedarType.h"
//#include "CMInner.h"
#include "Server.h"
#include "Admin.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include "../PenCore/resource.h"

// Get data from RPC_STFA_CONFIG
char* StfaGetHubConfigData(RPC_STFA_CONFIG* sc, char* name)
{
	UINT i;
	// Validate arguments
	if (sc == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < sc->NumItem;i++)
	{
		STFA_PARAM* a = &sc->Items[i];

		if (StrCmpi(a->Name, name) == 0)
		{
			return a->Value;
		}
	}
	return NULL;
}

int StfaSetHubConfigData(RPC_STFA_CONFIG* sc, char* name, char* value)
{
	UINT i;
	// Validate arguments
	if (sc == NULL || name == NULL || value == NULL)
	{
		return -1;
	}

	for (i = 0;i < sc->NumItem;i++)
	{
		STFA_PARAM* a = &sc->Items[i];

		if (StrLen(a->Name) == 0)
		{
			StrCpy(a->Name, sizeof(a->Name), name);
			StrCpy(a->Value, sizeof(a->Value), value);
			return i;
		}
		else if (StrCmpi(a->Name, name) == 0)
		{
			StrCpy(a->Value, sizeof(a->Value), value);
			return i;
		}
	}
	return -1;
}

// Delete the STFA configuration of Virtual HUB
void DeleteAllHubStfaConfig(HUB* h, bool lock)
{
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->StfaConfigList);
		LockList(h->StfaCodeList);
	}

	for (i = 0;i < LIST_NUM(h->StfaConfigList);i++)
	{
		Free(LIST_DATA(h->StfaConfigList, i));
	}
	for (i = 0;i < LIST_NUM(h->StfaCodeList);i++)
	{
		Free(LIST_DATA(h->StfaCodeList, i));
	}

	DeleteAll(h->StfaConfigList);
	DeleteAll(h->StfaCodeList);

	if (lock)
	{
		UnlockList(h->StfaConfigList);
		UnlockList(h->StfaCodeList);
	}
}

// Start the STFA receiving thread
void StfaStartRecvThread(HUB* h)
{
	THREAD* t;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	h->HaltStfaRecv = false;
	h->StfaRecvEvent = NewEvent();

	t = NewThread(StfaRecvReplyThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// Stop the STFA receiving thread
void StfaStopRecvThread(HUB* h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	h->HaltStfaRecv = true;
	Set(h->StfaRecvEvent);

	WaitThread(h->StfaRecvReplyThread, INFINITE);
	ReleaseThread(h->StfaRecvReplyThread);
	h->StfaRecvReplyThread = NULL;
	h->HaltStfaRecv = false;

	ReleaseEvent(h->StfaRecvEvent);
	h->StfaRecvEvent = NULL;
}

int StfaGetConfigParams(LIST* scl, HUB_STFA* stfa, bool bSend)
{
	int ni, num;
	int i;
	if (scl == NULL || stfa == NULL)
	{
		return 0;
	}

	LockList(scl);
	{
		ni = LIST_NUM(scl);
		num = 0;
		for (i = 0;i < ni;i++)
		{
			STFA_PARAM* a = LIST_DATA(scl, i);

			if (StrCmp(a->Name, "MailServer") == 0)
			{
				StrCpy(stfa->mail_server, sizeof(stfa->mail_server), a->Value);
				num++;
			}
			else if (StrCmp(a->Name, "MailServerUser") == 0)
			{
				StrCpy(stfa->mail_server_user, sizeof(stfa->mail_server_user), a->Value);
				num++;
			}
			else if (StrCmp(a->Name, "MailServerPassword") == 0)
			{
				StrCpy(stfa->mail_server_pass, sizeof(stfa->mail_server_pass), a->Value);
				num++;
			}
			else if (StrCmp(a->Name, "MailFrom") == 0)
			{
				StrCpy(stfa->mail_server_from, sizeof(stfa->mail_server_from), a->Value);
				if (bSend) num++;
			}
			else if (StrCmp(a->Name, "MailServerSendingProtocol") == 0)
			{
				StrCpy(stfa->mail_server_send_protocol, sizeof(stfa->mail_server_send_protocol), a->Value);
				if (bSend) num++;
			}
			else if (StrCmp(a->Name, "MailServerReceivingProtocol") == 0)
			{
				StrCpy(stfa->mail_server_recv_protocol, sizeof(stfa->mail_server_recv_protocol), a->Value);
				if (!bSend) num++;
			}
			else if (StrCmp(a->Name, "SmsServerForwardReplySubject") == 0)
			{
				StrCpy(stfa->sms_server_forward_subject, sizeof(stfa->sms_server_forward_subject), a->Value);
				if (!bSend) num+= 100;
			}

			if (!bSend) continue;			//the following part of the SMS configuration is used only for sending
			if (StrCmp(a->Name, "SmsServer") == 0)
			{
				StrCpy(stfa->sms_server, sizeof(stfa->sms_server), a->Value);
				num += 100;
			}
			else if (StrCmp(a->Name, "SmsServerUser") == 0)
			{
				StrCpy(stfa->sms_server_user, sizeof(stfa->sms_server_user), a->Value);
				num += 100;
			}
			else if (StrCmp(a->Name, "SmsServerPassword") == 0)
			{
				StrCpy(stfa->sms_server_pass, sizeof(stfa->sms_server_pass), a->Value);
				num += 100;
			}
			else if (StrCmp(a->Name, "SmsServerSendingProtocol") == 0)
			{
				StrCpy(stfa->sms_server_send_protocol, sizeof(stfa->sms_server_send_protocol), a->Value);
				num += 100;
			}
		}
	}
	UnlockList(scl);
	return num;
}
bool StfaSearchAndAddConfigParam(LIST* scl, char* name, bool badd)
{
	int i, ni, ne;
	STFA_PARAM* a;

	if (scl == NULL || name == NULL) return false;
	
	ni = LIST_NUM(scl);
	ne = -1;
	for (i = 0;i < ni;i++)
	{
		a = LIST_DATA(scl, i);
		if (StrLen(a->Name) == 0)
		{
			ne = i;
		}
		else if (StrCmp(a->Name, name) == 0)
		{
			return true;
		}
	}
// not found:
	if (badd)
	{
		if (ne < 0)
		{
			a = ZeroMalloc(sizeof(STFA_PARAM));
			StrCpy(a->Name, sizeof(a->Name), name);
			Insert(scl, a);
		}
		else
		{
			a = LIST_DATA(scl, ne);
			StrCpy(a->Name, sizeof(a->Name), name);
		}
		return true;
	}
	return false;
}

void StfaAddEmptyConfigParams(LIST* scl)
{
	if (scl == NULL )
	{
		return;
	}

	LockList(scl);
	{
		StfaSearchAndAddConfigParam(scl, "MailServer", true);
		StfaSearchAndAddConfigParam(scl, "MailServerUser", true);
		StfaSearchAndAddConfigParam(scl, "MailServerPassword", true);
		StfaSearchAndAddConfigParam(scl, "MailFrom", true);
		StfaSearchAndAddConfigParam(scl, "MailServerSendingProtocol", true);
		StfaSearchAndAddConfigParam(scl, "MailServerReceivingProtocol", true);
		StfaSearchAndAddConfigParam(scl, "SmsServerForwardReplySubject", true);
		StfaSearchAndAddConfigParam(scl, "SmsServer", true);
		StfaSearchAndAddConfigParam(scl, "SmsServerUser", true);
		StfaSearchAndAddConfigParam(scl, "SmsServerPassword", true);
		StfaSearchAndAddConfigParam(scl, "SmsServerSendingProtocol", true);
	}
	UnlockList(scl);
}


void StfaClearCodeList( HUB* h, char* username)
{
	STFA_CODE* a = NULL;
	char ID[SHA1_SIZE];
	UINT NumItem, i;

	// Get list
	Sha1(ID, username, strlen(username));
	LockList(h->StfaCodeList);
	{
		NumItem = LIST_NUM(h->StfaCodeList);

		for (i = 0;i < NumItem;i++)
		{
			if ((a = LIST_DATA(h->StfaCodeList, i)) == NULL) continue;

			if (Cmp(a->StfaUserId, ID, SHA1_SIZE) == 0)	// found the user in the list
			{
				Free(a);
				Delete(h->StfaCodeList, a);
				break;
			}
		}
	}
	UnlockList(h->StfaCodeList);
}

/////////////////////////////////////////////////

char* StfaGenCode(char* buff, UINT size, UINT64 num)
{
	UINT64 rnd;
	char b[MAX_SIZE];

	if (buff == NULL || size < 7)
	{
		return NULL;
	}
	if (num == 0)
	{
		num = SystemTime64();
	}

	rnd = num % 10000;
	rnd = rnd * Rand16();

	sprintf(b, "00001%d", (rnd % 1000000L));
	strcpy(buff, &(b[strlen(b) - 6]));
	return buff;
}


bool StfaGetUserInfo(HUB* h, char* username, char* mail_str, UINT mail_str_size, char* sms_str, UINT sms_str_size)
{
	bool bRet = false;
	USER* u;
	TOKEN_LIST* tokens;
	int i;
	char* ch;

	u = AcGetUser(h, username);
	if (u)
	{
		Lock(u->lock);
		{
			tokens = ParseToken(u->StfaMailPhone, " ,;");
			if (tokens != NULL)
			{
				for (i = 0; i < tokens->NumTokens; i++)
				{
					ch = tokens->Token[i];
					if (strstr(ch, "@") != NULL)
					{
						if (mail_str != NULL)
						{
							StrCpy(&(mail_str[0]), mail_str_size, ch);
						}
						bRet = true;
					}
					else if (strstr(ch, "+") != NULL)
					{
						if (sms_str != NULL)
						{
							StrCpy(&(sms_str[0]), sms_str_size, ch);
						}
						bRet = true;
					}
				}
				FreeToken(tokens);
			}
		}
		Unlock(u->lock);
		ReleaseUser(u);
	}
	return bRet;
}


bool StfaCheck(HUB* h, char* username, char* stfausercode, NODE_INFO* node)
{
	UINT NumItem, i;
	STFA_CODE* a = NULL;
	char buff[MAX_SIZE];
	UINT64 now = SystemTime64();
	bool bRet = false;
	char ID[SHA1_SIZE];
	char clID[SHA1_SIZE];
	char ipstr[16];



	if (h->StfaConfigList == NULL)		// STFA is not configured on the server
	{
		return true;
	}

	if (StfaGetUserInfo(h, username, NULL, 0, NULL, 0 ) == false)		// STFA is not configured for the user
	{
		return true;
	}


	// Get list
	Sha1(ID, username, strlen(username));
	IPToStr32(ipstr, sizeof(ipstr), node->ClientIpAddress);
	StrCpy(buff, sizeof(buff), node->ClientHostname);
	StrCat(buff, sizeof(buff), ipstr);
	Sha1(clID, buff, strlen(buff));

	LockList(h->StfaCodeList);
	{

		NumItem = LIST_NUM(h->StfaCodeList);

		for (i = 0;i < NumItem;i++)
		{
			if ((a = LIST_DATA(h->StfaCodeList, i)) == NULL) continue;

			if (Cmp(a->StfaUserId, ID, SHA1_SIZE) == 0 && Cmp(a->StfaClntId, clID, SHA1_SIZE) == 0 )	// found the user in the list
			{
				if (strcmp(a->StfaCodeSrv, stfausercode) == 0)
				{
					if (StrLen(a->StfaCodeSrv) > 0) bRet = true;
				}
				break;
			}
			a = NULL;
		}
		if (a == NULL)	// not found, so add the user to the list and send the code to this user
		{
			a = ZeroMalloc(sizeof(STFA_CODE));
			Copy(a->StfaUserId, ID, SHA1_SIZE);
			Copy(a->StfaClntId, clID, SHA1_SIZE);
			a->StfaCreatedTime = now;

			if (StfaGenCode(buff, sizeof(buff), now) != NULL)
			{
				strcpy(a->StfaCodeSrv, buff);
			}
			else strcpy(a->StfaCodeSrv, "123098");

			Insert(h->StfaCodeList, a);
			StfaSendCode(h, username, a, node );
		}
		else
		{
			if (!bRet)		// found the user, but the user's code don't match the server's code or is empty
			{
				if (a->bAck)		// user replied to the mail
				{
					bRet = true;
				}
				else if (now - a->StfaCreatedTime > (1000LL * 60) * STFA_REPLY_WAIT_X)    // the user has not replied for x minutes
				{
					if ((StrLen(a->StfaCodeSrv) == 0) || (now - a->StfaCreatedTime > (1000LL * 60) * 30))    // code is more than 30 minutes old
					{
						if (StfaGenCode(buff, sizeof(buff), now) != NULL)
						{
							strcpy(a->StfaCodeSrv, buff);
						}
						else strcpy(a->StfaCodeSrv, "456765");
					}
					a->StfaCreatedTime = now;
					StfaSendCode(h, username, a, node );			// try again
				}
			}
		}
	}
	UnlockList(h->StfaCodeList);
	return bRet;
}

void StfaSendCode(HUB* h, char* username, STFA_CODE* c, NODE_INFO* node )
{
	THREAD* t;
	STFA_SEND_CODE* data;

	data = ZeroMalloc(sizeof(STFA_SEND_CODE));
	data->h = h;
	data->username = username;
	data->c = c;
	data->node = node;

	t = NewThread(StfaSendMailSmsThread, data);
	WaitThreadInit(t);
	Free(data);
	ReleaseThread(t);
}

void StfaSendMailSmsThread(THREAD* t, void* param)
{

	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}
	STFA_SEND_CODE sc, *data;
	CEDAR* cdr;
	HUB* hb;
	LIST* scl;
	HUB_STFA stfa;
	USER* u;

	bool bOK = false;
	char mail_str[MAX_SIZE];
	char sms_str[MAX_SIZE];
	char buffs[MAX_SIZE];
	char hb_name[MAX_SIZE];
	char clnthostname[MAX_SIZE];
	char ipstr[16];
	char* ch;
//	TOKEN_LIST* tokens;
	int i;
	int num = 0, ni = 0;

	data = (STFA_SEND_CODE*)param;
	if (data->c == NULL || data->h == NULL)
	{
		return;
	}
	scl = data->h->StfaConfigList;
	if (scl == NULL)
	{
		return;
	}

	AddRef(t->ref);

	hb = data->h;
	cdr = hb->Cedar;
	StrCpy(hb_name, sizeof(hb_name), hb->Name);

	StrCpy(clnthostname, sizeof(clnthostname), data->node->ClientHostname );
	IPToStr32( ipstr, sizeof(ipstr), data->node->ClientIpAddress);

	Zero(&stfa, sizeof(stfa));
	mail_str[0] = '\0';
	sms_str[0] = '\0';

	if ( ( scl == NULL )	||	// STFA is not configured on the server	
		 ( StfaGetUserInfo(hb, data->username, mail_str, sizeof(mail_str), sms_str, sizeof(sms_str)) == false)  )  //  STFA is not configured for the user	   
	{
		data->c->bAck = true;		
		ReleaseThread(t);
		return;
	}

	data->c->bAck = false;		
	memcpy(&sc, data, sizeof(sc));

   // Get options
	num = StfaGetConfigParams(scl, &stfa, true);

	int nm, ns;
	nm = num % 100;
	ns = num / 100;
	// sending email:	nm==5  required  or 6 for checking reply
	// sending sms:		ns==4  required and nm>=4 for checking reply 

	if (ns == 0 && (nm == 5 || nm == 6)) { /* OK */ }
	else if (ns == 4 && (nm == 0 || nm >= 4)) { /* OK */ }
	else
	{
		data->c->bAck = false;
		data->c->StfaCreatedTime = 0LL;
		data->c->StfaCodeSrv[0] = '\0';
	}
	
	GetServerProductName(cdr->Server, buffs, sizeof(buffs));

	NoticeThreadInit(t);

	int retm, rets;
	retm = StfaSendMail(mail_str, &stfa, buffs, sc.c, clnthostname, ipstr);
	rets = StfaSendSms(sms_str, &stfa, buffs, sc.c, clnthostname, ipstr);

	if (retm < 0 && rets < 0)		// error 
	{
		HUB h;
		STFA_CODE* c = NULL;

		LockHubList(cdr);
		h.Name = hb_name;
		hb = Search(cdr->HubList, &h);
		if (hb == NULL)
		{
			UnlockHubList(cdr);
			ReleaseThread(t);
			return;
		}

		UnlockHubList(cdr);

		// Get list
		LockList(hb->StfaCodeList);
		{
			ni = LIST_NUM(hb->StfaCodeList);

			for (i = 0;i < ni;i++)
			{
				if ((c = LIST_DATA(hb->StfaCodeList, i)) == NULL) continue;

				if (Cmp(c->StfaUserId, sc.c->StfaUserId, SHA1_SIZE) == 0 && Cmp(c->StfaClntId, sc.c->StfaClntId, SHA1_SIZE) == 0)	// found the user in the list
				{
					c->StfaCreatedTime = 0LL;
					c->bAck = false;
					c->StfaCodeSrv[0] = '\0';
					break;
				}
			}
		}
		UnlockList(hb->StfaCodeList);
	}

	ReleaseThread(t);
}

// STFA receiving thread
void StfaRecvReplyThread(THREAD* t, void* param)
{
	HUB* hub;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	hub = (HUB*)param;
	hub->StfaRecvReplyThread = t;

	AddRef(t->ref);
	NoticeThreadInit(t);

	UINT i, num;
	UINT interval;
	STFA_CODE* a = NULL;
	bool bRet;
	LIST* scl = hub->StfaConfigList;
	HUB_STFA	stfa;

	while (true)
	{

		if (hub->HaltStfaRecv)
		{
			break;
		}

		// Check the list of sended emails
		LockList(hub->StfaCodeList);
		{
			UINT64 now = SystemTime64();

			num = LIST_NUM(hub->StfaCodeList);
			bRet = false;
			for (i = 0;i < num;i++)
			{
				if ((a = LIST_DATA(hub->StfaCodeList, i)) == NULL) continue;

				if ( (a->bAck == false) && ( now - a->StfaCreatedTime < 1000LL*60*(STFA_REPLY_WAIT_X+1)) )
				{
					if (StrLen(a->StfaCodeSrv) > 0)    // found the unacknowledged code
					{
						bRet = true;
					}
					break;
				}
			}
		}
		UnlockList(hub->StfaCodeList);
		if (bRet)
		{
			int n = StfaGetConfigParams(scl, &stfa, false);
			if ( (n % 100) == 4)  // 4 parameters for checking email reply and/or 1 for sms    - it's OK
			{
				StfaCheckReply(hub->StfaCodeList, &stfa);
			}
		}

		interval = 1000 * 10;
		Wait(hub->StfaRecvEvent, interval);
		if (hub->HaltStfaRecv)
		{
			break;
		}
	}

	return;
}

int StfaSendMail(char* mailto, HUB_STFA* stfa, char* servername, STFA_CODE* sc, char* clnthostname, char* ipstr)
{
	char *mu;
	UCHAR hash[SHA1_SIZE];

	mu = CopyStr(mailto);
	StrUpper(mu);
	Sha1(hash, mu, strlen(mu));
	Copy(sc->StfaUserMailH, hash, sizeof(sc->StfaUserMailH)); 
	Free(mu);

	return StfaSendMailSms( mailto, stfa, servername, sc, clnthostname, ipstr, true);
}

int StfaSendSms(char* smsto, HUB_STFA* stfa, char* servername, STFA_CODE* sc, char* clnthostname, char* ipstr)
{
	char sto[MAX_SIZE];

	if (StrLen(smsto) < 9) return -1;

	StrCpy(sc->StfaUserPhone, sizeof(sc->StfaUserPhone), smsto);
	Format(sto, MAX_SIZE, "%s@[%s]", smsto, stfa->sms_server);
	return StfaSendMailSms(sto, stfa, servername, sc, clnthostname, ipstr, false);
}

int StfaSendMailSms(char* smsmailto, HUB_STFA* stfa, char *servername, STFA_CODE *sc, char* clnthostname, char* ipstr, bool bmail )
{
	char *ch, buff[MAX_SIZE];
	char* recvBuff = NULL;
	char* buff_b64 = NULL;
	char* smsmail_to = smsmailto;
	char* smsmail_server;
	char* smsmail_server_user;
	char* smsmail_server_pass;
	char* smsmail_from;
	SOCK* s = NULL;
	int retcode = -1;
	UINT port = 25;
	UINT buffSize = 0;
	int size, num;

	bool bSecure = false;
	bool bAuthPlain = false;
	bool bAuthLogin = false;

	if (smsmail_to == NULL || stfa == NULL || sc == NULL ) return -1;
	if (strlen(smsmail_to) < 4) return -2;
	if (sc->StfaCreatedTime == 0) return -3;
	if (StrLen(sc->StfaCodeSrv) == 0) return -4;

	if (servername == NULL) servername = "SoftEther VPN server";

	if (bmail)
	{
		if (StrCmpi(stfa->mail_server_send_protocol, "SMTPS:") == 0)
		{
			bSecure = true;
			port = 465;
		}
		num = 5;
		if (bSecure) num++;
		num = atoi(stfa->mail_server_send_protocol + num);
		if (num != 0) port = num;
		smsmail_server = stfa->mail_server;
		smsmail_server_user = stfa->mail_server_user;
		smsmail_server_pass = stfa->mail_server_pass;
		smsmail_from = stfa->mail_server_from;
	}
	else
	{
		if (StrCmpi(stfa->sms_server_send_protocol, "SMTPS:") == 0)
		{
			bSecure = true;
			port = 465;
		}
		num = 5;
		if (bSecure) num++;
		num = atoi(stfa->sms_server_send_protocol + num);
		if (num != 0) port = num;
		smsmail_server = stfa->sms_server;
		smsmail_server_user = stfa->sms_server_user;
		smsmail_server_pass = stfa->sms_server_pass;
		smsmail_from = " ";
	}
	retcode = -1;
	sprintf(buff, "%s", smsmail_server);
	s = Connect(buff, port);
	if (s == NULL) goto CLEANUP;

	SetTimeout(s, 1000);
	// Start the SSL
	if (bSecure)
	{
		if (StartSSLEx(s, NULL, NULL, 0, NULL) == false)
		{
			goto CLEANUP;
		}
	}
	if (Recv(s, buff, sizeof(buff), bSecure) == 0) goto CLEANUP;
	if (strstr(buff, "220 ") == NULL)  goto CLEANUP;
	if (bmail && strstr(buff, smsmail_server) == NULL)  goto CLEANUP;

	char hostname[1024];
	GetMachineName(hostname, sizeof(hostname) - 1);
	sprintf(buff, "EHLO %s\r\n", hostname);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "250")) != recvBuff)  goto CLEANUP;
	if (bmail && strstr(recvBuff, smsmail_server) == NULL)  goto CLEANUP;

	while ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) != NULL)
	{
		if ((ch = strstr(recvBuff, "250-AUTH")) == recvBuff)
		{
			if (strstr(recvBuff, " PLAIN") != NULL) bAuthPlain = true;
			if (strstr(recvBuff, " LOGIN") != NULL) bAuthLogin = true;
		}
		if (IsEmptyRecvBuff(s, bSecure)) break;
	}

	if (bAuthPlain)
	{
		strcpy(buff, "");
		strcpy(&(buff[1]), smsmail_server_user);
		int b64l = strlen(smsmail_server_user) + 2;
		strcpy(&(buff[b64l]), smsmail_server_pass);
		b64l += strlen(smsmail_server_pass);

		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "AUTH PLAIN %s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "235 ")) != recvBuff)  goto CLEANUP;
		if (strstr(recvBuff, "2.7.0") == NULL) goto CLEANUP;					// 2.7.0 =  Authentication successful
		FreeSafe((void**) & buff_b64);
	}
	else if(bAuthLogin)
	{
		strcpy(buff, "AUTH LOGIN\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "334 VXNlcm5hbWU6")) != recvBuff)  goto CLEANUP;

		strcpy(buff, smsmail_server_user);
		int b64l = strlen(smsmail_server_user);
		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "%s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "334 UGFzc3dvcmQ6")) != recvBuff)  goto CLEANUP;
		FreeSafe((void**)&buff_b64);

		strcpy(buff, smsmail_server_pass);
		b64l = strlen(smsmail_server_pass);
		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "%s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "235 ")) != recvBuff)  goto CLEANUP;
		if (strstr(recvBuff, "2.7.0") == NULL) goto CLEANUP;					// 2.7.0 =  Authentication successful
		FreeSafe((void**)&buff_b64);
	}
	else if (!bmail)	// SMS gateway can read user/passsword from Subject:
	{

	}
	else goto CLEANUP;


	sprintf(buff, "MAIL FROM: SoftEtherVPNServer<%s>\r\n", smsmail_from);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "250 ")) != recvBuff)  goto CLEANUP;
	if (strstr(recvBuff, " Ok") == NULL)
	{
		if (strstr(recvBuff, " OK") == NULL) goto CLEANUP;
	}

	sprintf(buff, "RCPT TO: %s\r\n", smsmail_to);		
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "250 ")) != recvBuff)  goto CLEANUP;
	if (strstr(recvBuff, " Ok") == NULL)
	{
		if (strstr(recvBuff, " OK") == NULL) goto CLEANUP;
	}

 	sprintf(buff, "DATA\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "354 ")) != recvBuff)  goto CLEANUP;
	if (strstr(recvBuff, "<CR><LF>.<CR><LF>") == NULL) goto CLEANUP;
	
	sprintf(buff, "From: SoftEtherVPNServer<%s>\r\n", smsmail_from);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;

	sprintf(buff, "To: %s\r\n", smsmail_to);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;

	StrCpy(buff, sizeof(buff), "Content-Transfer-Encoding: 8bit\r\n");
	SendAdd(s, buff, strlen(buff));
 	if (SendNow(s, bSecure) == false) goto CLEANUP;

	StrCpy(buff, sizeof(buff), "Content-Type: text/plain; charset=UTF-8\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;

	if (bmail)
	{
		Format(buff, sizeof(buff), "Subject: %s: STFA code ID=%lld\r\n", servername, sc->StfaCreatedTime);
	}
	else	// SMS also needs it, but Subject is used to send the login/password phrase : login=username&pass=password
	{
		Format(buff, sizeof(buff), "Subject: login=%s&pass=%s\r\n", smsmail_server_user, smsmail_server_pass);
	}
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;

/*	char s_frmt[MAX_SIZE], s_frmt_loc[MAX_SIZE];
	if (bmail)
	{
		StrCpy( s_frmt_loc, sizeof(s_frmt_loc), _SS("SC_STFA_MAIL_BODY_1"));
		StrCpy((char*)&s_frmt, sizeof(s_frmt), _SS("SC_STFA_MAIL_BODY_2"));
	}
	else
	{
		StrCpy((char*)& s_frmt_loc, sizeof(s_frmt_loc), _SS("SC_STFA_SMS_BODY_1"));
		StrCpy((char*)&s_frmt, sizeof(s_frmt), _SS("SC_STFA_SMS_BODY_2"));
	}

	if (StrLen(s_frmt_loc) > 7)       // localized message is at least "%s %s %s"
	{
		Format( buff, sizeof(buff), s_frmt_loc, sc->StfaCodeSrv, clnthostname, ipstr);
		SendAdd(s, buff, StrLen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
	}
	if (StrLen(s_frmt) > 7)       // english message is at least "%s %s %s"
	{
		if (StrLen(s_frmt_loc) > 7) 
		{
			StrCpy(buff, sizeof(buff), "\r\n---------------------------------------------------\r\n");
			SendAdd(s, buff, strlen(buff));
			if (SendNow(s, bSecure) == false) goto CLEANUP;
		}
		Format(buff, sizeof(buff), s_frmt, sc->StfaCodeSrv, clnthostname, ipstr);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
	}
*/
	wchar_t s_frmt[MAX_SIZE], s_frmt_loc[MAX_SIZE], wbuff[MAX_SIZE];
	wchar_t wCode[MAX_SIZE], wHost[MAX_SIZE], wIpstr[MAX_SIZE];
	BYTE butf8[MAX_SIZE * 6];
	if (bmail)
	{
		UniStrCpy(s_frmt_loc, sizeof(s_frmt_loc), _UU("SC_STFA_MAIL_BODY_1"));
		UniStrCpy(s_frmt, sizeof(s_frmt), _UU("SC_STFA_MAIL_BODY_2"));
	}
	else
	{
		UniStrCpy(s_frmt_loc, sizeof(s_frmt_loc), _UU("SC_STFA_SMS_BODY_1"));
		UniStrCpy(s_frmt, sizeof(s_frmt), _UU("SC_STFA_SMS_BODY_2"));
	}

	StrToUni(wCode, sizeof(wCode), sc->StfaCodeSrv);
	StrToUni(wHost, sizeof(wHost), clnthostname);
	StrToUni(wIpstr, sizeof(wIpstr), ipstr);
	if (UniStrLen(s_frmt_loc) > 7)       // localized message is at least "%s %s %s"
	{
		UniFormat(wbuff, sizeof(wbuff), s_frmt_loc, wCode, wHost, wIpstr);
		UniToUtf8(butf8, sizeof(butf8), wbuff);
		SendAdd(s, butf8, StrLen((char*)butf8));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
	}
	if (UniStrLen(s_frmt) > 7)       // english message is at least "%s %s %s"
	{
		if (UniStrLen(s_frmt_loc) > 7)
		{
			StrCpy(buff, sizeof(buff), "\r\n---------------------------------------------------\r\n");
			SendAdd(s, buff, strlen(buff));
			if (SendNow(s, bSecure) == false) goto CLEANUP;
		}
		UniFormat(wbuff, sizeof(wbuff), s_frmt, wCode, wHost, wIpstr);
		UniToUtf8(butf8, sizeof(butf8), wbuff);
		SendAdd(s, butf8, StrLen((char*)butf8));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
	}

	sprintf(buff, "\r\n.\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "250 ")) != recvBuff)  goto CLEANUP;
	if (strstr(recvBuff, " Ok:") == NULL)
	{
		if (strstr(recvBuff, " OK:") == NULL) goto CLEANUP;
	}

	sprintf(buff, "QUIT\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) goto CLEANUP;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;

	retcode = 0;
CLEANUP:

	if (recvBuff != NULL) Free(recvBuff);
	if (buff_b64 != NULL) Free(buff_b64);

	Disconnect(s);
	ReleaseSock(s);

	return retcode;
}

STFA_CODE* StfaGetCodeTable(int* size, LIST* scdl)
{
	int ni=0, i;
	STFA_CODE* table;

	if (scdl == NULL || size == NULL ) return NULL;
	table = NULL;
	LockList(scdl);
	{
		ni = LIST_NUM(scdl);
		table = ZeroMalloc(sizeof(STFA_CODE) * ni);
		for (i = 0;i < ni;i++)
		{
			STFA_CODE* a = LIST_DATA(scdl, i);
			Copy( &(table[i]), a, sizeof( STFA_CODE));
		}
	}
	UnlockList(scdl);
	*size = ni;
	return table;
}
void StfaACKCode(LIST* scdl, UINT64 ID)
{
	int ni, i;

	if (scdl == NULL )  return;

	LockList(scdl);
	{
		ni = LIST_NUM(scdl);
		for (i = 0;i < ni;i++)
		{
			STFA_CODE* a = LIST_DATA(scdl, i);
			if (a->StfaCreatedTime == ID)
			{
				a->bAck = true;
			}
		}
	}
	UnlockList(scdl);
}

SOCK* StfaConnectPop3(UINT port, HUB_STFA* stfa, bool bSecure, UINT **msg_table, int *msgCount )
{
	UINT ret=0;
	char* ch, buff[MAX_SIZE];
	char* recvBuff = NULL;
	SOCK* s = NULL;
	int retcode = 0;
	UINT msg;
	UINT buffSize = 0;

	if (stfa == NULL) return 0;

	char* mail_server = stfa->mail_server;
	char* mail_server_user = stfa->mail_server_user;
	char* mail_server_pass = stfa->mail_server_pass;

	*msgCount = 0;

	sprintf(buff, "%s", mail_server);
	s = Connect(buff, port);
	if (s == NULL) return NULL;

	SetTimeout(s, 1000);
	// Start the SSL
	if (bSecure)
	{
		if (StartSSLEx(s, NULL, NULL, 0, NULL) == false)
		{
			Disconnect(s);
			ReleaseSock(s);
			return NULL;
		}
	}
	if (Recv(s, buff, sizeof(buff), bSecure) == 0) return s;
	if (strstr(buff, "+OK") == NULL) return s;

	sprintf(buff, "USER %s\r\n", mail_server_user);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  return s;
	if (Recv(s, buff, sizeof(buff), bSecure) == 0)  return s;
	if (strstr(buff, "+OK") == NULL)   return s;

	sprintf(buff, "PASS %s\r\n", mail_server_pass);
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  return s;
	if (Recv(s, buff, sizeof(buff), bSecure) == 0) return s;
	if (strstr(buff, "+OK") == NULL)   return s;

	buffSize = 0;
	recvBuff = NULL;
	sprintf(buff, "LIST\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  return s;
	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL)  return s;
	if ((ch = strstr(recvBuff, "+OK")) == NULL)  goto CLEANUP;
	strcpy(buff, ch + (strlen("+OK")));

	ret = atoi(buff);
	UINT* mt = *msg_table;

	if (mt == NULL) mt = ZeroMalloc(sizeof(UINT) * ret);
	else mt = ReAlloc( mt, sizeof(UINT) * ret);

	for (int i = 0; i < ret; i++)
	{
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) continue;
		if ((ch = strstr(recvBuff, " ")) != NULL)
		{
			msg = atoi(recvBuff);
			mt[i] = msg;
		}
	}
	Recv(s, buff, sizeof(buff), bSecure);		// read rest

CLEANUP:

	Free(recvBuff);
	*msg_table = mt;
	*msgCount = ret;
	return s;
}

SOCK* StfaConnectImap(UINT port, HUB_STFA* stfa, bool bSecure, UINT** msg_table, int *msgCount)
{
	int ret = 0;
	char* ch, buff[MAX_SIZE];
	char* recvBuff = NULL;
	char* buff_b64 = NULL;
	SOCK* s = NULL;
	int retcode = 0;
	UINT msg;
	UINT buffSize = 0;
	bool bAuthPlain, bAuthLogin;

	if (stfa == NULL) return 0;

	char* mail_server = stfa->mail_server;
	char* mail_server_user = stfa->mail_server_user;
	char* mail_server_pass = stfa->mail_server_pass;

	*msgCount = 0;
	UINT* mt = *msg_table;

	sprintf(buff, "%s", mail_server);
	s = Connect(buff, port);
	if (s == NULL) return NULL;

	SetTimeout(s, 1000);
	// Start the SSL
	if (bSecure)
	{
		if (StartSSLEx(s, NULL, NULL, 0, NULL) == false)
		{
			Disconnect(s);
			ReleaseSock(s);
			return NULL;
		}
	}

	if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
	if ((ch = strstr(recvBuff, "* OK")) != recvBuff)  goto CLEANUP;
	if ((ch = strstr(recvBuff, "[CAPABILITY")) == NULL)  goto CLEANUP;

	bAuthPlain = bAuthLogin = false;
	if ((ch = strstr(recvBuff, "AUTH=PLAIN")) != NULL)  bAuthPlain = true;
	if ((ch = strstr(recvBuff, "AUTH=LOGIN")) != NULL)  bAuthLogin = true;

	if (bAuthPlain)
	{
		sprintf(buff, "AP authenticate plain\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "+")) != recvBuff)  goto CLEANUP;

		strcpy(buff, "");
		strcpy(&(buff[1]), mail_server_user);
		int b64l = strlen(mail_server_user) + 2;
		strcpy(&(buff[b64l]), mail_server_pass);
		b64l += strlen(mail_server_pass);
		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "%s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "AP OK ")) != recvBuff)  goto CLEANUP;
		if (strstr(recvBuff, "Logged in") == NULL) goto CLEANUP;					// "Logged in" =  Authentication successful
		FreeSafe((void**)&buff_b64);
	}
	else if (bAuthLogin)
	{
		sprintf(buff, "AL authenticate login\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "+ VXNlcm5hbWU6")) != recvBuff)  goto CLEANUP;

		strcpy(buff, mail_server_user);
		int b64l = strlen(mail_server_user);
		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "%s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "+ UGFzc3dvcmQ6")) != recvBuff)  goto CLEANUP;

		FreeSafe((void**)&buff_b64);
		strcpy(buff, mail_server_pass);
		b64l = strlen(mail_server_pass);
		buff_b64 = (char*)Base64FromBin(&buffSize, buff, b64l);
		sprintf(buff, "%s\r\n", buff_b64);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "AL OK ")) != recvBuff)  goto CLEANUP;
		if (strstr(recvBuff, "Logged in") == NULL) goto CLEANUP;					// "Logged in" =  Authentication successful
		FreeSafe((void**)&buff_b64);
	}
	else  // login
	{
		sprintf(buff, "LL login %s %s\r\n", mail_server_user, mail_server_pass);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) goto CLEANUP;
		if ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) == NULL) goto CLEANUP;
		if ((ch = strstr(recvBuff, "LL OK ")) != recvBuff)  goto CLEANUP;
		if (strstr(recvBuff, "Logged in") == NULL) goto CLEANUP;					// "Logged in" =  Authentication successful
	}

	sprintf(buff, "NS namespace\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  goto CLEANUP;
	if (Recv(s, buff, sizeof(buff), bSecure) == 0)  goto CLEANUP;
	if (strstr(buff, "* NAMESPACE") != buff)   goto CLEANUP;
	if (strstr(buff, "NS OK ") == NULL)   goto CLEANUP;
	if ((ch = strstr(buff, "((\"")) == NULL) goto CLEANUP;
	char* ch1 = strstr(ch + 3, "\"");
	if (ch1 != NULL)
	{
		ch1[1] = '\x00';
		sprintf(buff, "LI list %s \"*\"\r\n", &(ch[2]));
	}
	else
	{
		sprintf(buff, "LI list \"\" \"*\"\r\n");
	}
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  goto CLEANUP;
	if (Recv(s, buff, sizeof(buff), bSecure) == 0)  goto CLEANUP;
	if (strstr(buff, "* LIST") != buff)   goto CLEANUP;
	if (strstr(buff, "LI OK ") == NULL)   goto CLEANUP;
	if (strstr(buff, " INBOX") == NULL)   goto CLEANUP;

	sprintf(buff, "SE select \"INBOX\"\r\n");
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false)  goto CLEANUP;

	while ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) != NULL)
	{
		if (strstr(recvBuff, "*") == recvBuff)
		{
			if (strstr(recvBuff, "EXIST") != NULL )
			{
				ret = atoi(recvBuff + 1);
			}
		}
		else if (strstr(recvBuff, "SE OK") == recvBuff)
		{
			break;
		}
		else if (IsEmptyRecvBuff(s, bSecure))
		{
			break;
		}
	}

	if (mt == NULL) mt = ZeroMalloc(sizeof(UINT) * ret);
	else mt = ReAlloc(mt, sizeof(UINT) * ret);

	for (int i = 0; i < ret; i++)
	{
		mt[i] = i + 1;
	}

CLEANUP:

	Free(recvBuff);
	*msg_table = mt;
	*msgCount = ret;

	return s;
}


int StfaGetTopOfMessageBody(SOCK* s, char** recvBuff, UINT* buffSize, bool bimap, UINT msg)
{
	int retcode = 0;
	char* ch, buff[MAX_SIZE];
	bool bSecure = s->SecureMode;
	char* recvb = *recvBuff;

	if (bimap == false)
	{
		sprintf(buff, "TOP %d 8\r\n", msg);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) return -1;

		if ((recvb = RecvLineEx(s, recvb, buffSize)) == NULL) retcode = 0;
		else if ((ch = strstr(recvb, "+OK")) != NULL) retcode = 1;
	}
	else
	{
		sprintf(buff, "FE fetch %d (BODY[HEADER.FIELDS (Received Subject From)] BODY[TEXT]<0.500>)\r\n", msg);
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) return -1;

		sprintf(buff, "* %d FETCH", msg);
		if ((recvb = RecvLineEx(s, recvb, buffSize)) == NULL) retcode = 0;
		else if ((ch = strstr(recvb, buff)) != NULL) retcode = 1;
	}

	*recvBuff = recvb;
	return retcode;
}

int StfaDelMessage(SOCK* s, bool bimap, UINT msg)
{
	int retcode = 0;
	char buff[MAX_SIZE];
	bool bSecure = s->SecureMode;

	if (bimap == false)
	{
		sprintf(buff, "DELE %d\r\n", msg);
	}
	else
	{
		sprintf(buff, "DL store %d +FLAGS (\\Deleted)\r\n", msg);
	}
	
	SendAdd(s, buff, strlen(buff));
	if (SendNow(s, bSecure) == false) return -1;
	Recv(s, buff, sizeof(buff), bSecure);

	return retcode;
}

void StfaEndReadMessages(SOCK* s, bool bimap)
{
	char buff[MAX_SIZE];
	bool bSecure;

	if(s == NULL) return;
	
	bSecure = s->SecureMode;
	if (bimap == false)
	{
		sprintf(buff, "QUIT\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) return;
		Recv(s, buff, sizeof(buff), bSecure);
	}
	else
	{
		sprintf(buff, "EX expunge\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) return;
		Recv(s, buff, sizeof(buff), bSecure);

		sprintf(buff, "LO logout\r\n");
		SendAdd(s, buff, strlen(buff));
		if (SendNow(s, bSecure) == false) return;
		Recv(s, buff, sizeof(buff), bSecure);
	}
}


void StfaCheckReply(LIST* scdl, HUB_STFA* stfa)
{
	char* ch, buff[MAX_SIZE];
	char* recvBuff = NULL;
	SOCK* s = NULL;
	int retcode = 0;
	UINT port;
	UINT buffSize = 0;
	int size, num;
	STFA_CODE *code_table = NULL;
	int cdt_size = 0;
	bool bSecure = false;
	char mailh[SHA1_SIZE];
	bool bimap = false;
	int msgCount;
	UINT i, msg, *msg_table;

	if (scdl == NULL || stfa == NULL) return;

	port = 110;			// POP3
	if (StrCmpi(stfa->mail_server_recv_protocol, "POP3S:") == 0)
	{
		bSecure = true;
		port = 995;
	}
	else if(StrCmpi(stfa->mail_server_recv_protocol, "IMAP:") == 0)
	{
		port = 143;
		bimap = true;
	}
	else if (StrCmpi(stfa->mail_server_recv_protocol, "IMAPS:") == 0)
	{
		bSecure = true;
		port = 993;
		bimap = true;
	}
	num = 5;
	if (bSecure) num++;
	num = atoi(stfa->mail_server_send_protocol + num);
	if (num != 0) port = num;

	retcode = -1;
	msg_table = NULL;
	msgCount = 0;

	if (bimap == false)
	{
		s = StfaConnectPop3(port, stfa, bSecure, &msg_table, &msgCount );
	}
	else
	{
		s = StfaConnectImap(port, stfa, bSecure, &msg_table, &msgCount);
	}

	int day, year, month;
	char* ch1;
	bool bRecvFrom, bRecvFor, bSubject, bFound, bFrom;

	time_t timestamp, time_now = time(NULL);
	struct tm datetime;

	if (msgCount > 0) // get list off sended STFA ID
	{
		code_table = StfaGetCodeTable( &cdt_size, scdl );
	}
	for (i = 0; i < msgCount; i++)
	{

		if ((retcode = StfaGetTopOfMessageBody(s, &recvBuff, &buffSize, bimap, msg_table[i])) < 0) goto CLEANUP;
		else if (retcode == 0) continue;

		bRecvFrom = bRecvFor = bSubject = bFound = bFrom = false;
		retcode = 0;
		int checksms = 0;
		bool bBody = false;
		int iph = -1;
		int icd = -1;
		UINT64 sub_id = 0LL;
		Zero(mailh, sizeof(mailh) );

		while ((recvBuff = RecvLineEx(s, recvBuff, &buffSize)) != NULL)
		{
			size = strlen(recvBuff);
			if (strstr(recvBuff, "Received: from") == recvBuff)
			{
				bRecvFrom = true;
			}
			if (bRecvFrom)
			{
				if (strstr(recvBuff, ">;") != NULL) bRecvFor = true;	
			}
			if (bRecvFor)
			{
				if ((ch = strstr(recvBuff, ", ")) != NULL)	
				{
					day = atoi(ch + 2);
					if (day == 0)
					{
						if ((ch1 = strstr(ch + 2, " ")) != NULL) day = atoi(ch1);
					}
					if ((ch1 = strstr(ch, " Jan ")) != NULL) month = 1;
					else if ((ch1 = strstr(ch, " Feb ")) != NULL) month = 2;
					else if ((ch1 = strstr(ch, " Mar ")) != NULL) month = 3;
					else if ((ch1 = strstr(ch, " Apr ")) != NULL) month = 4;
					else if ((ch1 = strstr(ch, " May ")) != NULL) month = 5;
					else if ((ch1 = strstr(ch, " Jun ")) != NULL) month = 6;
					else if ((ch1 = strstr(ch, " Jul ")) != NULL) month = 7;
					else if ((ch1 = strstr(ch, " Aug ")) != NULL) month = 8;
					else if ((ch1 = strstr(ch, " Sep ")) != NULL) month = 9;
					else if ((ch1 = strstr(ch, " Oct ")) != NULL) month = 10;
					else if ((ch1 = strstr(ch, " Nov ")) != NULL) month = 11;
					else if ((ch1 = strstr(ch, " Dec ")) != NULL) month = 12;
					else month = 0;
				}
				if (ch1 != NULL) year = atoi(ch1 + 5); else year = 0;
				bRecvFrom = bRecvFor = false;
			}
			if ((strstr(recvBuff, "Subject: ") == recvBuff) || (bSubject && (recvBuff[0] == ' ' || recvBuff[0] == '\t')))
			{
				bSubject = true;
				for (retcode = 0; retcode < cdt_size; retcode++)
				{
					sprintf(buff, "ID=%lld!!", code_table[retcode].StfaCreatedTime);
					if (strstr(recvBuff, buff) != NULL)		// found reply
					{
						sub_id = code_table[retcode].StfaCreatedTime;
						checksms = -1;
						break;
					}
				}
				if (checksms ==0 )   // check SMS reply
				{
					if (strlen((char*)stfa->sms_server_forward_subject) > 0 && SearchStr(recvBuff, (char*)stfa->sms_server_forward_subject, 0) >= 0)
					{
						checksms = 1;
					}
				}
			}
			else bSubject = false;

			if (!bBody && ((strstr(recvBuff, "From: ") == recvBuff) || (bFrom && (recvBuff[0] == ' ' || recvBuff[0] == '\t'))))		//From: User Name <user.name@mail.server.domain>
			{
				int j, l;
				bFrom = true;
				ch = strstr(recvBuff, "<");
				if (ch != NULL)
				{ 
					Trim(ch);
					StrUpper(ch);
					l = strlen(ch);
					for (j = 1; j < l && ch[j] != '>'; j++);		// ch[0] = '<', 
					if (ch[j] == '>')
					{
						ch++;						
						Sha1(mailh, ch, l - 2);
					}
				}
			}
			else bFrom = false;

			if (bBody && (bFound == false) )
			{
				if (checksms > 0)
				{
					if (iph < 0)
					{
						iph = StfaCheckEagleReplyPhone(recvBuff, code_table, cdt_size);
					}
					if (icd < 0)
					{
						icd = StfaCheckEagleReplyCode(recvBuff, code_table, cdt_size);
					}
					if (iph >= 0 && icd >= 0)
					{
						for (retcode = icd; retcode < cdt_size; retcode++)
						{
							if (StrCmp((char*)code_table[retcode].StfaUserPhone, (char*)code_table[iph].StfaUserPhone) == 0)		// found reply from the user's phone
							{
								if (StrCmp((char*)code_table[retcode].StfaCodeSrv, (char*)code_table[icd].StfaCodeSrv) == 0)		// found correct code in reply message
								{
									bFound = true;
									break;
								}
							}
						}
					}
				}
				else if (checksms < 0 && sub_id >0LL )
				{
					for (retcode = 0; retcode < cdt_size; retcode++)
					{
						if ( code_table[retcode].StfaCreatedTime == sub_id )		// found reply 
						{
							if ( Cmp(code_table[retcode].StfaUserMailH, mailh, SHA1_SIZE ) == 0)		// found correct email
							{
								bFound = true;
								break;
							}
						}
					}
				}
			}

			if (strlen(recvBuff) == 0)  bBody = true;

			if (IsEmptyRecvBuff(s, bSecure))
			{
				break;
			}
		}

		if (year > 1900)
		{
			datetime.tm_year = year - 1900;
			datetime.tm_mon = month - 1;
			datetime.tm_mday = day;
			datetime.tm_hour = 23;
			datetime.tm_min = 59;
			datetime.tm_sec = 59;
			datetime.tm_isdst = -1;
			timestamp = mktime(&datetime);
		}
		if (bFound) StfaACKCode(scdl, code_table[retcode].StfaCreatedTime );

		if ((time_now - timestamp > 60 * 60 * 24) 	// 1 day  => DELETE old message
			|| (bFound))					// DELETE founded reply
		{
			if( (retcode = StfaDelMessage(s, bimap, msg_table[i])) < 0) goto CLEANUP;
		}
	}

	StfaEndReadMessages(s, bimap);


CLEANUP:
	if (code_table != NULL) Free(code_table);
	if (recvBuff != NULL) Free(recvBuff); 
	if (msg_table != NULL) Free(msg_table);

	Disconnect(s);
	ReleaseSock(s);

	return;
}

int StfaCheckEagleReplyPhone( char *recvBuff, STFA_CODE *code_table, int cdt_size)
{
	int i, l;
	char* cFrom = "From: ";
	char* ch;

	l = strlen(recvBuff);
	if ((i = SearchStr(recvBuff, cFrom, 0)) >= 0)
	{
		i += strlen(cFrom);
		for (;i < l && ( *(ch=&(recvBuff[i]))) == ' '; i++) { /* skip spaces */ };
		if (i >= l) return -1;
		
		for (i = 0; i < cdt_size; i++)
		{
			if (strcmp(ch, (char*)code_table[i].StfaUserPhone) == 0)
				return i;
		}
	}
	return -1;
}

int StfaCheckEagleReplyCode(char* recvBuff, STFA_CODE* code_table, int cdt_size)
{
	int i, l;
	char* cMessage = "Message: ";
	char* ch;

	l = strlen(recvBuff);
	if ((i = SearchStr(recvBuff, cMessage, 0)) >= 0)
	{
		i += strlen(cMessage);
		for (;i < l && ( *(ch = &(recvBuff[i]))) == ' '; i++) { /* skip spaces */ };
		if (i >= l) return -1;

		for (i = 0; i < cdt_size; i++)
		{
			if (strcmp(ch, (char*)code_table[i].StfaCodeSrv) == 0)
				return i;
		}
	}
	return -1;
}

