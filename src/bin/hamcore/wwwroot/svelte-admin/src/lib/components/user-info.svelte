<script lang="ts">
	import InfoIcon from '@lucide/svelte/icons/info';
	import Modal from './ui/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { createQuery } from '@tanstack/svelte-query';
	import { rpc, VpnRpcSetUser } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';

	interface Props {
		hub: string;
		name: string;
		open: boolean;
	}

	let { hub, name, open = $bindable() }: Props = $props();
	const locale = getLocale();

	const query = createQuery(() => ({
		queryKey: hubKeys.user(hub, name),
		queryFn: () => rpc.GetUser(new VpnRpcSetUser({ HubName_str: hub, Name_str: name })),
		initialData: new VpnRpcSetUser(),
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
			<h3 class="text-lg font-semibold">{m.SM_USERINFO_CAPTION({ input0: name })}</h3>
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
						<td>{m.SM_USERINFO_NAME()}</td>
						<td>{query.data.Name_str}</td>
					</tr>
					<tr>
						<td>{m.SM_USERINFO_GROUP()}</td>
						<td>{query.data.GroupName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_USERINFO_CREATE()}</td>
						<td>
							{datetime(locale, query.data.CreatedTime_dt, {
								dateStyle: 'short',
								timeStyle: 'medium'
							})}
						</td>
					</tr>
					<tr>
						<td>{m.SM_USERINFO_UPDATE()}</td>
						<td>
							{datetime(locale, query.data.UpdatedTime_dt, {
								dateStyle: 'short',
								timeStyle: 'medium'
							})}
						</td>
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
						<td>{m.SM_USERINFO_NUMLOGIN()}</td>
						<td>{query.data.NumLogin_u32}</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</Modal>
