// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AzureClient.h
// Header of AzureClient.c

#ifndef	AZURE_CLIENT_H
#define	AZURE_CLIENT_H

#include "Cedar.h"
#include "DDNS.h"

#include "Mayaqua/MayaType.h"

// Constants
#define	AZURE_SERVER_PORT					443
#define AZURE_PROTOCOL_CONTROL_SIGNATURE	"ACTL"
#define	AZURE_PROTOCOL_DATA_SIANGTURE		"AZURE_CONNECT_SIGNATURE!"
#define	AZURE_PROTOCOL_CONTROL_TIMEOUT_DEFAULT	(5 * 1000)			// Default timeout
#define	AZURE_CONNECT_INITIAL_RETRY_INTERVAL	(1 * 1000)			// Initial re-connection interval (15 * 1000)
#define	AZURE_CONNECT_MAX_RETRY_INTERVAL		(60 * 60 * 1000)	// Maximum re-connection interval

#define	AZURE_DOMAIN_SUFFIX					".vpnazure.net"

#define	AZURE_SERVER_MAX_KEEPALIVE			(5 * 60 * 1000)
#define	AZURE_SERVER_MAX_TIMEOUT			(10 * 60 * 1000)

#define	AZURE_VIA_PROXY_TIMEOUT				5000


// Azure custom configuration
struct AZURE_CUSTOM_CONFIG
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// VPN Azure server name
	UINT ServerPort;						// VPN Azure port number
	char Hostname[MAX_HOST_NAME_LEN + 1];	// VPN Azure client hostname
	UCHAR HashedPassword[SHA1_SIZE];		// Hashed passwords
	X *ClientX;								// VPN Azure client certificate
	K *ClientK;								// VPN Azure client private key
	X *ServerCert;							// VPN Azure server certificate
	bool VerifyServer;						// Verify server certificate
	bool AddDefaultCA;						// Use default trust store to verify server
};

// Communications parameter
struct AZURE_PARAM
{
	UINT ControlKeepAlive;
	UINT ControlTimeout;
	UINT DataTimeout;
	UINT SslTimeout;
	bool UseCustom;
	bool UseEncryption;
};

// VPN Azure Client
struct AZURE_CLIENT
{
	CEDAR *Cedar;
	SERVER *Server;
	LOCK *Lock;
	DDNS_CLIENT_STATUS DDnsStatus;
	volatile bool IsEnabled;
	volatile bool UseCustom;
	EVENT *Event;
	volatile bool Halt;
	THREAD *MainThread;
	volatile UINT IpStatusRevision;
	DDNS_CLIENT_STATUS DDnsStatusCopy;
	SOCK *CurrentSock;
	char ConnectingAzureIp[MAX_SIZE];
	AZURE_PARAM AzureParam;
	volatile UINT DDnsTriggerInt;
	volatile bool IsConnected;
	AZURE_CUSTOM_CONFIG *CustomConfig;
};


// Function prototype
AZURE_CLIENT *NewAzureClient(CEDAR *cedar, SERVER *server, AZURE_CUSTOM_CONFIG *config);
void FreeAzureClient(AZURE_CLIENT *ac);
void AcApplyCurrentConfig(AZURE_CLIENT *ac, DDNS_CLIENT_STATUS *ddns_status, AZURE_CUSTOM_CONFIG *config, bool disconnect);
void AcMainThread(THREAD *thread, void *param);
void AcSetEnable(AZURE_CLIENT *ac, bool enabled, bool use_custom);
void AcWaitForRequest(AZURE_CLIENT *ac, SOCK *s, AZURE_PARAM *param);


#endif	// AZURE_CLIENT_H


