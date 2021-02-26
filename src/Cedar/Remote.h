// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Remote.h
// Header of Remote.c

#ifndef	REMOTE_H
#define	REMOTE_H

// RPC execution function
typedef PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p);

// RPC object
struct RPC
{
	SOCK *Sock;						// Socket
	bool ServerMode;				// Server mode
	RPC_DISPATCHER *Dispatch;		// Execution routine
	void *Param;					// Parameters
	bool ServerAdminMode;			// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// Managing HUB name
	char Name[MAX_SIZE];			// RPC session name
	LOCK *Lock;						// Lock
	bool IsVpnServer;				// Whether VPN Server management RPC
	CLIENT_OPTION VpnServerClientOption;
	char VpnServerHubName[MAX_HUBNAME_LEN + 1];
	UCHAR VpnServerHashedPassword[SHA1_SIZE];
	char VpnServerClientName[MAX_PATH];
};

// Function prototype
RPC *StartRpcClient(SOCK *s, void *param);
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param);
PACK *RpcCallInternal(RPC *r, PACK *p);
PACK *RpcCall(RPC *r, char *function_name, PACK *p);
void RpcServer(RPC *r);
bool RpcRecvNextCall(RPC *r);
PACK *CallRpcDispatcher(RPC *r, PACK *p);
void RpcError(PACK *p, UINT err);
bool RpcIsOk(PACK *p);
UINT RpcGetError(PACK *p);
void EndRpc(RPC *rpc);
void RpcFree(RPC *rpc);
void RpcFreeEx(RPC *rpc, bool no_disconnect);

#endif	// REMOTE_H

