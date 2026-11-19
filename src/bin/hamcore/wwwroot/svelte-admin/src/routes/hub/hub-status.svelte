<script lang="ts">
	import InfoIcon from '@lucide/svelte/icons/info';
	import { m } from '$lib/paraglide/messages';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { createQuery } from '@tanstack/svelte-query';
	import { rpc, VpnRpcHubStatus } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import Modal from '$lib/components/ui/modal.svelte';
	import { translateHubOnline, translateHubType, translateSecureNat } from '$lib/rpc/labels';

	interface Props {
		hub: string;
		open: boolean;
	}

	let { hub, open = $bindable() }: Props = $props();
	const locale = getLocale();
	const timestamp = { dateStyle: 'medium', timeStyle: 'medium' } as const;

	const query = createQuery(() => ({
		queryKey: hubKeys.status(hub),
		queryFn: () => rpc.GetHubStatus(new VpnRpcHubStatus({ HubName_str: hub })),
		initialData: new VpnRpcHubStatus(),
		enabled: open,
		refetchInterval: 5000
	}));
</script>

<Modal bind:open>
	<div class="max-h-[70vh]">
		<div class="mb-3 flex items-center gap-2">
			<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
				<InfoIcon size={18} />
			</span>
			<h3 class="text-lg font-semibold">{m.SM_HUB_STATUS_CAPTION({ input0: hub })}</h3>
			{#if query.isFetching}
				<span class="loading loading-xs loading-spinner opacity-60"></span>
			{/if}
		</div>

		<div class="overflow-x-auto">
			<table class="table table-pin-rows table-zebra table-sm">
				<thead>
					<tr>
						<th>{m.CM_ST_COLUMN_1()}</th>
						<th>{m.CM_ST_COLUMN_2()}</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td>{m.SM_HUB_COLUMN_1()}</td>
						<td>{query.data.HubName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_2()}</td>
						<td>
							<span
								class={[
									'badge badge-sm',
									query.data.Online_bool ? 'badge-success' : 'badge-error'
								]}>
								{translateHubOnline(query.data.Online_bool)}
							</span>
						</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_3()}</td>
						<td>
							{translateHubType(query.data.HubType_u32)}
						</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_SECURE_NAT()}</td>
						<td>{translateSecureNat(query.data.SecureNATEnabled_bool)}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_NUM_ACCESSES()}</td>
						<td>{query.data.NumAccessLists_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_4()}</td>
						<td>{query.data.NumUsers_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_5()}</td>
						<td>{query.data.NumGroups_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_6()}</td>
						<td>{query.data.NumSessions_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_7()}</td>
						<td>{query.data.NumMacTables_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_8()}</td>
						<td>{query.data.NumIpTables_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_9()}</td>
						<td>{query.data.NumLogin_u32}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_10()}</td>
						<td>{datetime(locale, query.data.LastLoginTime_dt, timestamp)}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_COLUMN_11()}</td>
						<td>{datetime(locale, query.data.LastCommTime_dt, timestamp)}</td>
					</tr>
					<tr>
						<td>{m.SM_HUB_CREATED_TIME()}</td>
						<td>{datetime(locale, query.data.CreatedTime_dt, timestamp)}</td>
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
				</tbody>
			</table>
		</div>
	</div>
</Modal>
