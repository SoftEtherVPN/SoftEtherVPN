<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { getLocale } from '$lib/paraglide/runtime';
	import { datetime } from '$lib/paraglide/registry';
	import { serverKeys } from '$lib/queryKeys';
	import { rpc, VpnRpcConnectionInfo, VpnRpcEnumConnection } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { translateConnectionType } from '$lib/translation';
	import X from '@lucide/svelte/icons/x';
	import Info from '@lucide/svelte/icons/info';
	import NetworkIcon from '@lucide/svelte/icons/network';
	import Button from '$lib/components/button.svelte';

	const locale = getLocale();
	const client = useQueryClient();

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();
	const query = createQuery(() => ({
		queryKey: serverKeys.connections.list(),
		queryFn: rpc.EnumConnection,
		initialData: new VpnRpcEnumConnection(),
		enabled: open,
		refetchInterval: 5000
	}));

	const disconnect = createMutation(() => ({
		mutationFn: rpc.DisconnectConnection,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: serverKeys.connections.all });
		}
	}));

	let selectedDetail = $state<string | undefined>(undefined);

	const infoDetail = createQuery(() => ({
		queryKey: serverKeys.connections.detail(selectedDetail ?? ''),
		queryFn: () => rpc.GetConnectionInfo(new VpnRpcConnectionInfo({ Name_str: selectedDetail! })),
		initialData: new VpnRpcConnectionInfo(),
		enabled: selectedDetail != undefined,
		retry: false,
		retryOnMount: false
	}));
</script>

<Modal class="*:first:max-w-3xl" bind:open>
	<div class="max-h-[70vh]">
		<div class="mb-3 flex items-center gap-2">
			<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
				<NetworkIcon size={18} />
			</span>
			<h3 class="text-lg font-semibold">{m.D_SM_CONNECTION__S_TITLE({ input0: location.host })}</h3>
			<span class="badge badge-soft badge-sm tabular-nums">
				{query.data.ConnectionList.length}
			</span>
			{#if query.isFetching}
				<span class="loading loading-xs loading-spinner opacity-60"></span>
			{/if}
		</div>

		{#if query.data.ConnectionList.length === 0}
			<div class="flex flex-col items-center justify-center gap-3 py-14 text-center opacity-40">
				<NetworkIcon size={36} />
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="table table-pin-rows table-zebra table-sm">
					<thead>
						<tr>
							<th>{m.SM_CONN_COLUMN_1()}</th>
							<th>{m.SM_CONN_COLUMN_2()}</th>
							<th>{m.SM_CONN_COLUMN_3()}</th>
							<th>{m.SM_CONN_COLUMN_4()}</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each query.data.ConnectionList as connection (connection.Name_str)}
							<tr>
								<td>{connection.Name_str}</td>
								<td>{connection.Ip_ip}:{connection.Port_u32}</td>
								<td>
									{datetime(locale, connection.ConnectedTime_dt, {
										dateStyle: 'short',
										timeStyle: 'short'
									})}
								</td>
								<td>{translateConnectionType(connection.Type_u32)}</td>
								<td>
									<div class="tooltip" data-tip={m.D_SM_CONNECTION__B_DISCONNECT()}>
										<Button
											onclick={() => disconnect.mutateAsync({ Name_str: connection.Name_str })}
											class="btn btn-square btn-soft btn-error btn-xs">
											<X />
										</Button>
									</div>
									<div class="tooltip" data-tip={m.D_SM_CONNECTION__IDOK()}>
										<button
											onclick={() => (selectedDetail = connection.Name_str)}
											class="btn btn-square btn-soft btn-info btn-xs">
											<Info />
										</button>
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
</Modal>

{#if selectedDetail != undefined && !infoDetail.isError}
	<Modal class="*:first:max-w-3xl" open onclose={() => (selectedDetail = undefined)}>
		<div class="max-h-[70vh]">
			<h3 class="text-lg font-semibold">
				{m.SM_CONNINFO_CAPTION({ input0: infoDetail.data.Name_str })}
			</h3>
			<div class="overflow-x-auto">
				<table class="table table-pin-rows mt-2 table-zebra table-sm">
					<thead>
						<tr>
							<th>{m.SM_STATUS_COLUMN_1()}</th>
							<th>{m.SM_STATUS_COLUMN_2()}</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td>{m.SM_CONNINFO_NAME()}</td>
							<td>{infoDetail.data.Name_str}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_TYPE()}</td>
							<td>{translateConnectionType(infoDetail.data.Type_u32)}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_HOSTNAME()}</td>
							<td>{infoDetail.data.Hostname_str}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_PORT()}</td>
							<td>{infoDetail.data.Port_u32}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_TIME()}</td>
							<td>
								{datetime(locale, infoDetail.data.ConnectedTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_SERVER_STR()}</td>
							<td>{infoDetail.data.ServerStr_str}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_SERVER_VER()}</td>
							<td>{infoDetail.data.ServerVer_u32}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_SERVER_BUILD()}</td>
							<td>{infoDetail.data.ServerBuild_u32}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_CLIENT_STR()}</td>
							<td>{infoDetail.data.ClientStr_str}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_CLIENT_VER()}</td>
							<td>{infoDetail.data.ClientVer_u32}</td>
						</tr>
						<tr>
							<td>{m.SM_CONNINFO_CLIENT_BUILD()}</td>
							<td>{infoDetail.data.ClientBuild_u32}</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</Modal>
{/if}
