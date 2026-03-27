<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcServerStatus } from '$lib/rpc';
	import { translateHubType } from '$lib/translation';
	import { createQuery } from '@tanstack/svelte-query';

	const locale = getLocale();

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	let query = createQuery(() => ({
		queryKey: [dashboardKey, 'status'],
		queryFn: rpc.GetServerStatus,
		initialData: new VpnRpcServerStatus(),
		enabled: open,
		refetchInterval: 5000
	}));
</script>

<Modal bind:open>
	<div class="max-h-[70vh]">
		<h3 class="ml-2 card-title">{m.SM_SERVER_STATUS()}</h3>
		<table class="table-pin-rows table mt-2 table-zebra table-sm">
			<thead>
				<tr>
					<th>{m.SM_STATUS_COLUMN_1()}</th>
					<th>{m.SM_STATUS_COLUMN_2()}</th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>{m.SM_ST_SERVER_TYPE()}</td>
					<td>{translateHubType(query.data.ServerType_u32)}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_TCP()}</td>
					<td>{query.data.NumTcpConnections_u32 - 1}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_HUB_TOTAL()}</td>
					<td>{query.data.NumHubTotal_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_SESSION_TOTAL()}</td>
					<td>{query.data.NumSessionsTotal_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_MAC_TABLE()}</td>
					<td>{query.data.NumMacTables_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_IP_TABLE()}</td>
					<td>{query.data.NumIpTables_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_USERS()}</td>
					<td>{query.data.NumUsers_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_NUM_GROUPS()}</td>
					<td>{query.data.NumGroups_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_CLIENT_LICENSE()}</td>
					<td>{query.data.AssignedClientLicenses_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_BRIDGE_LICENSE()}</td>
					<td>{query.data.AssignedBridgeLicenses_u32}</td>
				</tr>
				<tr>
					<td>{m.SM_ST_SEND_UCAST_NUM()}</td>
					<td>
						{m.SM_ST_NUM_PACKET_STR({
							input0: number(locale, query.data['Send.UnicastCount_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_SEND_UCAST_SIZE()}</td>
					<td>
						{m.SM_ST_SIZE_BYTE_STR({
							input0: number(locale, query.data['Send.UnicastBytes_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_SEND_BCAST_NUM()}</td>
					<td>
						{m.SM_ST_NUM_PACKET_STR({
							input0: number(locale, query.data['Send.BroadcastCount_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_SEND_BCAST_SIZE()}</td>
					<td>
						{m.SM_ST_SIZE_BYTE_STR({
							input0: number(locale, query.data['Send.BroadcastBytes_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_RECV_UCAST_NUM()}</td>
					<td>
						{m.SM_ST_NUM_PACKET_STR({
							input0: number(locale, query.data['Recv.UnicastCount_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_RECV_UCAST_SIZE()}</td>
					<td>
						{m.SM_ST_SIZE_BYTE_STR({
							input0: number(locale, query.data['Recv.UnicastBytes_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_RECV_BCAST_NUM()}</td>
					<td>
						{m.SM_ST_NUM_PACKET_STR({
							input0: number(locale, query.data['Recv.BroadcastCount_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_RECV_BCAST_SIZE()}</td>
					<td>
						{m.SM_ST_SIZE_BYTE_STR({
							input0: number(locale, query.data['Recv.BroadcastBytes_u64'])
						})}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_START_TIME()}</td>
					<td>
						{datetime(locale, query.data.StartTime_dt, { dateStyle: 'short', timeStyle: 'medium' })}
					</td>
				</tr>
				<tr>
					<td>{m.SM_ST_CURRENT_TICK()}</td>
					<td>{query.data.CurrentTick_u64}</td>
				</tr>
			</tbody>
		</table>
	</div>
</Modal>
