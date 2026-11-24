export * from '$vpnrpc';
import { VpnServerRpc } from '$vpnrpc';

// No credentials: the whole /admin tree is served behind HTTP basic auth
// (see AdminWebProcGet in src/Cedar/Admin.c), so the browser replays the
// Authorization header on every JSON-RPC call for us.
export const rpc = new VpnServerRpc();
