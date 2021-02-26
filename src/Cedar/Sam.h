// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Sam.h
// Header of Sam.c

#ifndef	SAM_H
#define	SAM_H


// Function prototype
bool SamIsUser(HUB *h, char *username);
UINT SamGetUserAuthType(HUB *h, char *username);
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err);
bool SamAuthUserByAnonymous(HUB *h, char *username);
bool SamAuthUserByCert(HUB *h, char *username, X *x);
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast, UCHAR *mschap_v2_server_response_20, RADIUS_LOGIN_OPTION *opt);
POLICY *SamGetUserPolicy(HUB *h, char *username);

void GenRandom(void *random);
void SecurePassword(void *secure_password, void *password, void *random);
X *GetIssuerFromList(LIST *cert_list, X *cert);

#endif	// SAM_H

