<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcEnumHubItem, VpnRpcSetHubOnline } from '$lib/rpc';
	import { translateHubOnline, translateHubType } from '$lib/translation';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import Button from '$lib/components/button.svelte';
	import { resolve } from '$app/paths';

	const locale = getLocale();
	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: [dashboardKey, 'hub'],
		queryFn: async () => (await rpc.EnumHub()).HubList,
		initialData: []
	}));

	let selectedKey = $state<string | undefined>(undefined);
	let selected = $derived(
		selectedKey ? query.data.find((r) => r.HubName_str == selectedKey) : undefined
	);

	function select(row: VpnRpcEnumHubItem) {
		if (selected?.HubName_str == row.HubName_str) selectedKey = undefined;
		else selectedKey = row.HubName_str;
	}

	let canStart = $derived(selected != null && !selected.Online_bool);
	let canStop = $derived(selected != null && selected.Online_bool);

	const toggleHub = createMutation(() => ({
		mutationFn: rpc.SetHubOnline,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'hub'] });
		}
	}));

	const deleteHubMutation = createMutation(() => ({
		mutationFn: rpc.DeleteHub,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'hub'] });
		}
	}));

	function start() {
		return toggleHub.mutateAsync(
			new VpnRpcSetHubOnline({ HubName_str: selected?.HubName_str, Online_bool: true })
		);
	}

	function stop() {
		if (selected == undefined) return;
		return confirm({ message: m.CM_OFFLINE_MSG({ input0: selected.HubName_str }) }, () =>
			toggleHub.mutateAsync(
				new VpnRpcSetHubOnline({ HubName_str: selected!.HubName_str, Online_bool: false })
			)
		);
	}

	function deleteHub() {
		if (selected == undefined) return;
		return confirm({ message: m.CM_DELETE_HUB_MSG({ input0: selected.HubName_str }) }, () =>
			deleteHubMutation.mutateAsync({ HubName_str: selected.HubName_str })
		);
	}
</script>

<!-- Virtual Hub Table -->
<div class="card bg-base-100 shadow dark:bg-base-300">
	<div class="card-body gap-4 p-4">
		<div class="h-56 overflow-x-auto">
			<table class="table w-max">
				<thead>
					<tr>
						<th>{m.SM_HUB_COLUMN_1()}</th>
						<th>{m.SM_HUB_COLUMN_2()}</th>
						<th>{m.SM_HUB_COLUMN_3()}</th>
						<th>{m.SM_HUB_COLUMN_4()}</th>
						<th>{m.SM_HUB_COLUMN_5()}</th>
						<th>{m.SM_HUB_COLUMN_6()}</th>
						<th>{m.SM_HUB_COLUMN_7()}</th>
						<th>{m.SM_HUB_COLUMN_8()}</th>
						<th>{m.SM_HUB_COLUMN_9()}</th>
						<th>{m.SM_HUB_COLUMN_10()}</th>
						<th>{m.SM_HUB_COLUMN_11()}</th>
						<th>{m.SM_SESS_COLUMN_6()}</th>
						<th>{m.SM_SESS_COLUMN_7()}</th>
					</tr>
				</thead>
				<tbody>
					{#each query.data as hub (hub.HubName_str)}
						{@const transferBytes =
							hub['Ex.Recv.BroadcastBytes_u64'] +
							hub['Ex.Recv.UnicastBytes_u64'] +
							hub['Ex.Send.BroadcastBytes_u64'] +
							hub['Ex.Send.UnicastBytes_u64']}
						{@const transferPackets =
							hub['Ex.Recv.BroadcastCount_u64'] +
							hub['Ex.Recv.UnicastCount_u64'] +
							hub['Ex.Send.BroadcastCount_u64'] +
							hub['Ex.Send.UnicastCount_u64']}
						<tr
							class={{ 'bg-base-300 dark:bg-base-100': selected?.HubName_str == hub.HubName_str }}
							onclick={() => select(hub)}>
							<td class="font-medium">{hub.HubName_str}</td>
							<td>
								<span class={['badge badge-sm', hub.Online_bool ? 'badge-success' : 'badge-error']}>
									{translateHubOnline(hub.Online_bool)}
								</span>
							</td>
							<td>{translateHubType(hub.HubType_u32)}</td>
							<td>{hub.NumUsers_u32}</td>
							<td>{hub.NumGroups_u32}</td>
							<td>{hub.NumSessions_u32}</td>
							<td>{hub.NumMacTables_u32}</td>
							<td>{hub.NumIpTables_u32}</td>
							<td>{hub.NumLogin_u32}</td>
							<td>
								{datetime(locale, hub.LastLoginTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</td>
							<td>
								{datetime(locale, hub.LastCommTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</td>
							<td>{number(locale, transferBytes)}</td>
							<td>{number(locale, transferPackets)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<!-- Hub action buttons -->
		<div class="flex flex-wrap gap-2">
			<a
				class="btn btn-sm btn-primary"
				class:btn-disabled={selected == undefined}
				href={selected && resolve('/hub/[name]', { name: selected.HubName_str })}>
				{m.D_SM_SERVER__IDOK()}
			</a>
			<Button class="btn btn-sm btn-success" onclick={start} disabled={!canStart}>
				{m.D_SM_SERVER__B_ONLINE()}
			</Button>
			<Button class="btn btn-sm btn-warning" onclick={stop} disabled={!canStop}>
				{m.D_SM_SERVER__B_OFFLINE()}
			</Button>
			<button class="btn btn-sm btn-neutral not-dark:btn-soft" disabled={selected == undefined}>
				{m.D_SM_SERVER__B_HUB_STATUS()}
			</button>
			<a href="#/hub/create" class="btn btn-sm btn-neutral not-dark:btn-soft">
				{m.D_SM_SERVER__B_CREATE()}
			</a>
			<button class="btn btn-sm btn-neutral not-dark:btn-soft" disabled={selected == undefined}>
				{m.D_SM_SERVER__B_EDIT()}
			</button>
			<Button class="btn btn-sm btn-error" onclick={deleteHub} disabled={selected == undefined}>
				{m.D_SM_SERVER__B_DELETE()}
			</Button>
		</div>
	</div>
</div>
