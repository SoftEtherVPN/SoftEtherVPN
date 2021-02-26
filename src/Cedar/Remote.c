// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Remote.c
// Remote Procedure Call

#include "CedarPch.h"

// End of RPC
void EndRpc(RPC *rpc)
{
	RpcFree(rpc);
}

// Release the RPC
void RpcFree(RPC *rpc)
{
	RpcFreeEx(rpc, false);
}
void RpcFreeEx(RPC *rpc, bool no_disconnect)
{
	// Validate arguments
	if (rpc == NULL)
	{
		return;
	}

	if (no_disconnect == false)
	{
		Disconnect(rpc->Sock);
	}

	ReleaseSock(rpc->Sock);

	DeleteLock(rpc->Lock);

	Free(rpc);
}

// Get error
UINT RpcGetError(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return ERR_DISCONNECTED;
	}

	return PackGetInt(p, "error_code");
}

// Error checking
bool RpcIsOk(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	if (PackGetInt(p, "error") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Error code setting
void RpcError(PACK *p, UINT err)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "error", 1);
	PackAddInt(p, "error_code", err);
}

// Start the RPC dispatcher
PACK *CallRpcDispatcher(RPC *r, PACK *p)
{
	char func_name[MAX_SIZE];
	// Validate arguments
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (PackGetStr(p, "function_name", func_name, sizeof(func_name)) == false)
	{
		return NULL;
	}

	return r->Dispatch(r, func_name, p);
}

// Wait for the next RPC call
bool RpcRecvNextCall(RPC *r)
{
	UINT size;
	void *tmp;
	SOCK *s;
	BUF *b;
	PACK *p;
	PACK *ret;
	// Validate arguments
	if (r == NULL)
	{
		return false;
	}

	s = r->Sock;

	if (RecvAll(s, &size, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}

	size = Endian32(size);

	if (size > MAX_PACK_SIZE)
	{
		return false;
	}

	tmp = MallocEx(size, true);

	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	p = BufToPack(b);
	FreeBuf(b);

	if (p == NULL)
	{
		return false;
	}

	ret = CallRpcDispatcher(r, p);
	FreePack(p);

	if (ret == NULL)
	{
		ret = PackError(ERR_NOT_SUPPORTED);
	}

	b = PackToBuf(ret);
	FreePack(ret);

	size = Endian32(b->Size);
	SendAdd(s, &size, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);

	if (SendNow(s, s->SecureMode) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// RPC server operation
void RpcServer(RPC *r)
{
	SOCK *s;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	s = r->Sock;

	while (true)
	{
		// Wait for the next RPC call
		if (RpcRecvNextCall(r) == false)
		{
			// Communication error
			break;
		}
	}
}

// RPC call
PACK *RpcCall(RPC *r, char *function_name, PACK *p)
{
	PACK *ret;
	UINT num_retry = 0;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || function_name == NULL)
	{
		return NULL;
	}

//	Debug("RpcCall: %s\n", function_name);

	Lock(r->Lock);
	{
		if (p == NULL)
		{
			p = NewPack();
		}

		PackAddStr(p, "function_name", function_name);

RETRY:
		err = 0;
		ret = RpcCallInternal(r, p);

		if (ret == NULL)
		{
			if (r->IsVpnServer && r->Sock != NULL)
			{
				if (num_retry < 1)
				{
					num_retry++;

					// Attempt to reconnect the RPC to the VPN Server
					err = AdminReconnect(r);

					if (err == ERR_NO_ERROR)
					{
						goto RETRY;
					}
				}
			}
		}

		FreePack(p);

		if (ret == NULL)
		{
			if (err == 0)
			{
				err = ERR_DISCONNECTED;
			}

			ret = PackError(err);
			PackAddInt(ret, "error_code", err);
		}
	}
	Unlock(r->Lock);

	return ret;
}

// RPC internal call
PACK *RpcCallInternal(RPC *r, PACK *p)
{
	BUF *b;
	UINT size;
	PACK *ret;
	void *tmp;
	// Validate arguments
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (r->Sock == NULL)
	{
		return NULL;
	}

	b = PackToBuf(p);

	size = Endian32(b->Size);
	SendAdd(r->Sock, &size, sizeof(UINT));
	SendAdd(r->Sock, b->Buf, b->Size);
	FreeBuf(b);

	if (SendNow(r->Sock, r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	if (RecvAll(r->Sock, &size, sizeof(UINT), r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	size = Endian32(size);
	if (size > MAX_PACK_SIZE)
	{
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(r->Sock, tmp, size, r->Sock->SecureMode) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	ret = BufToPack(b);
	if (ret == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	FreeBuf(b);

	return ret;
}

// Start the RPC server
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param)
{
	RPC *r;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMallocEx(sizeof(RPC), true);
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = true;
	r->Dispatch = dispatch;

	// Name generation
	Format(r->Name, sizeof(r->Name), "RPC-%u", s->socket);

	return r;
}

// Start the RPC client
RPC *StartRpcClient(SOCK *s, void *param)
{
	RPC *r;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(RPC));
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = false;

	return r;
}

