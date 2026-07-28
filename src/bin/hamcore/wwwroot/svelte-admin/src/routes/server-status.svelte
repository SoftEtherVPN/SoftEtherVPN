<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcServerStatus } from '$lib/rpc';
	import { translateHubType } from '$lib/translation';
	import { createQuery } from '@tanstack/svelte-query';
	import ServerIcon from '@lucide/svelte/icons/server';

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

<Modal class="*:first:max-w-2xl" bind:open>
	<div class="max-h-[70vh]">
		<div class="mb-3 flex items-center gap-2">
			<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
				<ServerIcon size={18} />
			</span>
			<h3 class="text-lg font-semibold">{m.SM_SERVER_STATUS()}</h3>
			{#if query.isFetching}
				<span class="loading loading-xs loading-spinner opacity-60"></span>
			{/if}
		</div>

		<!-- Key metrics at a glance -->
		<div class="stats mb-3 w-full stats-vertical border border-base-300 sm:stats-horizontal">
			<div class="stat gap-1 px-4 py-3">
				<div class="stat-title text-xs">{m.SM_ST_NUM_HUB_TOTAL()}</div>
				<div class="stat-value text-2xl tabular-nums">
					{number(locale, query.data.NumHubTotal_u32)}
				</div>
			</div>
			<div class="stat gap-1 px-4 py-3">
				<div class="stat-title text-xs">{m.SM_ST_NUM_SESSION_TOTAL()}</div>
				<div class="stat-value text-2xl tabular-nums">
					{number(locale, query.data.NumSessionsTotal_u32)}
				</div>
			</div>
			<div class="stat gap-1 px-4 py-3">
				<div class="stat-title text-xs">{m.SM_ST_NUM_USERS()}</div>
				<div class="stat-value text-2xl tabular-nums">
					{number(locale, query.data.NumUsers_u32)}
				</div>
			</div>
			<div class="stat gap-1 px-4 py-3">
				<div class="stat-title text-xs">{m.SM_ST_NUM_TCP()}</div>
				<div class="stat-value text-2xl tabular-nums">
					{number(locale, Math.max(query.data.NumTcpConnections_u32 - 1, 0))}
				</div>
			</div>
		</div>

		<div class="overflow-x-auto">
			<table class="table-pin-rows table table-zebra table-sm">
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
							{datetime(locale, query.data.StartTime_dt, {
								dateStyle: 'short',
								timeStyle: 'medium'
							})}
						</td>
					</tr>
					<tr>
						<td>{m.SM_ST_CURRENT_TICK()}</td>
						<td>{query.data.CurrentTick_u64}</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</Modal>
