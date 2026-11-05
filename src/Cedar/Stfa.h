// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Stfa.h
// Header of Stfa.c
#include "Cedar.h"

#ifndef STFA_H
#define STFA_H


struct STFA_CODE
{
	char StfaUserId[SHA1_SIZE];	// = hasded username
	char StfaClntId[SHA1_SIZE];	// = hasded client device name and ip adress
	UINT64 StfaCreatedTime;			// date and time of StfaCode creation 
	char StfaCodeSrv[8];			// Generated TFA code 
	char StfaUserPhone[16];		// User's phone number, if defined
	char StfaUserMailH[SHA1_SIZE];		// User's hashed email, if defined
	bool bAck;						// Acknowledgement
};

struct STFA_SEND_CODE
{
	HUB* h;
	char * username;
	NODE_INFO* node;				// client node info	
	STFA_CODE* c;
};

// HUB STFA structure
struct HUB_STFA
{
	char mail_server[MAX_SERVER_STR_LEN + 1];		// mail_server.domain
	char mail_server_user[MAX_SERVER_STR_LEN + 1];		// mail_server account name
	char mail_server_pass[MAX_SERVER_STR_LEN + 1];		// mail_server account password
	char mail_server_from[MAX_SERVER_STR_LEN + 1];		// sender of an email
	char mail_server_send_protocol[MAX_SERVER_STR_LEN + 1];	// smtp:port	or smtp:  if port=25 (default)
																// smtps:port	or smtps:  if port=465
	char mail_server_recv_protocol[MAX_SERVER_STR_LEN + 1];	// pop3:port	or pop3:  if port=110 (default) 
																// pop3s:port	or pop3s:  if port=995
																// imap:port	or imap:  if port=143
																// iamps:port	or imaps:  if port=993
	char sms_server[MAX_SERVER_STR_LEN + 1];			// sms_server (gateway) address
	char sms_server_user[MAX_SERVER_STR_LEN + 1];		// sms_server account name
	char sms_server_pass[MAX_SERVER_STR_LEN + 1];		// sms_server account password
	char sms_server_send_protocol[MAX_SERVER_STR_LEN + 1];		// smtp:port	or smtp:  if port=25 (default)
																// smtps:port	or smtps:  if port=465
	char sms_server_forward_subject[MAX_SERVER_STR_LEN + 1];	// Subject of message forwarded by SMS gateway to mail server

};




// Function prototype
void DeleteAllHubStfaConfig(HUB* h, bool lock);
char* StfaGetHubConfigData(RPC_STFA_CONFIG* sc, char* name);
int StfaSetHubConfigData(RPC_STFA_CONFIG* sc, char* name, char* value);
int StfaGetConfigParams(LIST* scl, HUB_STFA* stfa, bool bSend);
bool StfaGetUserInfo(HUB* h, char* username, char* mail_str, UINT mail_str_size, char* sms_str, UINT sms_str_size);
bool StfaSearchAndAddConfigParam(LIST* scl, char* name, bool badd);
void StfaAddEmptyConfigParams(LIST* scl);
STFA_CODE* StfaGetCodeTable(int* size, LIST* scdl);
void StfaACKCode(LIST* scdl, UINT64 ID);
void StfaClearCodeList(HUB* h, char* username);
bool StfaCheck(HUB* h, char* username, char* stfausercode, NODE_INFO* node);
char* StfaGenCode(char* buff, UINT size, UINT64 num);
void StfaSendCode(HUB* h, char* username, STFA_CODE* c, NODE_INFO* node );
void StfaSendMailSmsThread(THREAD* t, void* param);
int StfaSendMail(char* mailto, HUB_STFA* stfa, char* servername, STFA_CODE* sc, char *clnthostname, char * ipstr);
int StfaSendSms(char* smsto, HUB_STFA* stfa, char* servername, STFA_CODE* sc, char* clnthostname, char* ipstr);
int StfaSendMailSms(char* mailto, HUB_STFA* stfa, char* servername, STFA_CODE* sc, char* clnthostname, char* ipstr, bool bmail);
void StfaRecvReplyThread(THREAD* t, void* param);
SOCK* StfaConnectPop3(UINT port, HUB_STFA* stfa, bool bSecure, UINT** msg_table, int* msgCount);
SOCK* StfaConnectImap(UINT port, HUB_STFA* stfa, bool bSecure, UINT** msg_table, int* msgCount);
int StfaGetTopOfMessageBody(SOCK* s, char** recvBuff, UINT* buffSize, bool bimap, UINT msg);
int StfaDelMessage(SOCK* s, bool bimap, UINT msg);
void StfaEndReadMessages(SOCK* s, bool bimap);
void StfaCheckReply(LIST* scdl, HUB_STFA* stfa);
int StfaCheckEagleReplyPhone(char* recvBuff, STFA_CODE* code_table, int cdt_size);
int StfaCheckEagleReplyCode(char* recvBuff, STFA_CODE* code_table, int cdt_size);
void StfaStartRecvThread(HUB* h);
void StfaStopRecvThread(HUB* h);



#endif // STFA_H
