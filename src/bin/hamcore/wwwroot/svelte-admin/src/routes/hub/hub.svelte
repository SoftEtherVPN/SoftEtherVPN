<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { hubKeys } from '$lib/queryKeys';
	import { rpc, VpnRpcEnumHubItem, VpnRpcSetHubOnline } from '$lib/rpc';
	import { translateHubOnline, translateHubType } from '$lib/translation';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import Button from '$lib/components/button.svelte';
	import DataTable, { type DataTableColumn } from '$lib/components/data-table.svelte';
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import LayersIcon from '@lucide/svelte/icons/layers';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis-vertical';

	const locale = getLocale();
	const timestamp = { dateStyle: 'medium', timeStyle: 'medium' } as const;
	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.list(),
		queryFn: async () => (await rpc.EnumHub()).HubList,
		initialData: []
	}));

	let selectedKey = $state<string | number | undefined>(undefined);
	let selected = $derived(query.data.find((r) => r.HubName_str === selectedKey));

	let canStart = $derived(selected != null && !selected.Online_bool);
	let canStop = $derived(selected != null && selected.Online_bool);

	const toggleHub = createMutation(() => ({
		mutationFn: rpc.SetHubOnline,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.all });
		}
	}));

	const deleteHubMutation = createMutation(() => ({
		mutationFn: rpc.DeleteHub,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.all });
		}
	}));

	function totalTransferBytes(hub: VpnRpcEnumHubItem) {
		return (
			hub['Ex.Recv.BroadcastBytes_u64'] +
			hub['Ex.Recv.UnicastBytes_u64'] +
			hub['Ex.Send.BroadcastBytes_u64'] +
			hub['Ex.Send.UnicastBytes_u64']
		);
	}

	function totalTransferPackets(hub: VpnRpcEnumHubItem) {
		return (
			hub['Ex.Recv.BroadcastCount_u64'] +
			hub['Ex.Recv.UnicastCount_u64'] +
			hub['Ex.Send.BroadcastCount_u64'] +
			hub['Ex.Send.UnicastCount_u64']
		);
	}

	function hubHref(hub: VpnRpcEnumHubItem) {
		return resolve('/hub/[name]', { name: hub.HubName_str });
	}

	function start(hub: VpnRpcEnumHubItem | undefined = selected) {
		if (hub == undefined) return;
		return toggleHub.mutateAsync(
			new VpnRpcSetHubOnline({ HubName_str: hub.HubName_str, Online_bool: true })
		);
	}

	function stop(hub: VpnRpcEnumHubItem | undefined = selected) {
		if (hub == undefined) return;
		return confirm({ message: m.CM_OFFLINE_MSG({ input0: hub.HubName_str }) }, () =>
			toggleHub.mutateAsync(
				new VpnRpcSetHubOnline({ HubName_str: hub.HubName_str, Online_bool: false })
			)
		);
	}

	function deleteHub(hub: VpnRpcEnumHubItem | undefined = selected) {
		if (hub == undefined) return;
		return confirm({ message: m.CM_DELETE_HUB_MSG({ input0: hub.HubName_str }) }, () =>
			deleteHubMutation.mutateAsync({ HubName_str: hub.HubName_str })
		);
	}

	const columns: DataTableColumn<VpnRpcEnumHubItem>[] = $derived([
		{ header: m.SM_HUB_COLUMN_1(), value: 'HubName_str', primary: true, class: 'font-medium' },
		{ header: m.SM_HUB_COLUMN_2(), cell: onlineCell, sortBy: 'Online_bool' },
		{
			header: m.SM_HUB_COLUMN_3(),
			value: (hub) => translateHubType(hub.HubType_u32),
			sortBy: 'HubType_u32'
		},
		{ header: m.SM_HUB_COLUMN_4(), value: 'NumUsers_u32' },
		{ header: m.SM_HUB_COLUMN_5(), value: 'NumGroups_u32' },
		{ header: m.SM_HUB_COLUMN_6(), value: 'NumSessions_u32' },
		{ header: m.SM_HUB_COLUMN_7(), value: 'NumMacTables_u32' },
		{ header: m.SM_HUB_COLUMN_8(), value: 'NumIpTables_u32' },
		{ header: m.SM_HUB_COLUMN_9(), value: 'NumLogin_u32' },
		{
			header: m.SM_HUB_COLUMN_10(),
			value: (hub) => datetime(locale, hub.LastLoginTime_dt, timestamp),
			sortBy: 'LastLoginTime_dt',
			cardSpan: 2
		},
		{
			header: m.SM_HUB_COLUMN_11(),
			value: (hub) => datetime(locale, hub.LastCommTime_dt, timestamp),
			sortBy: 'LastCommTime_dt',
			cardSpan: 2
		},
		{
			header: m.SM_SESS_COLUMN_6(),
			value: (hub) => number(locale, totalTransferBytes(hub)),
			sortBy: totalTransferBytes,
			class: 'tabular-nums'
		},
		{
			header: m.SM_SESS_COLUMN_7(),
			value: (hub) => number(locale, totalTransferPackets(hub)),
			sortBy: totalTransferPackets,
			class: 'tabular-nums',
			cardSpan: 2
		}
	]);
</script>

{#snippet onlineCell(hub: VpnRpcEnumHubItem)}
	<span class={['badge badge-sm', hub.Online_bool ? 'badge-success' : 'badge-error']}>
		{translateHubOnline(hub.Online_bool)}
	</span>
{/snippet}

<div class="card border border-base-300 bg-base-100">
	<div class="card-body gap-4 p-4">
		<DataTable
			rows={query.data}
			{columns}
			rowKey={(hub) => hub.HubName_str}
			bind:selectedKey
			loading={query.isFetching && query.data.length === 0}
			rowsPerPage={10}
			searchable
			tableClass="w-max"
			onrowdblclick={(hub) => goto(hubHref(hub))}>
			<!-- `id` is provided by DataTable and is unique per row and per layout. -->
			{#snippet rowActions(hub, id)}
				<button
					class="btn btn-square btn-ghost btn-xs"
					aria-label={hub.HubName_str}
					popovertarget={id}
					style={`anchor-name:--${id}`}
					onclick={(e) => e.stopPropagation()}>
					<EllipsisIcon size={16} />
				</button>
				<ul
					class="menu dropdown dropdown-end z-10 w-44 rounded-box bg-base-100 p-2 shadow-lg dark:bg-base-200"
					popover
					{id}
					style={`position-anchor:--${id}`}>
					<li>
						<a href={hubHref(hub)}>{m.D_SM_SERVER__IDOK()}</a>
					</li>
					{#if !hub.Online_bool}
						<li>
							<button popovertarget={id} popovertargetaction="hide" onclick={() => start(hub)}>
								{m.D_SM_SERVER__B_ONLINE()}
							</button>
						</li>
					{:else}
						<li>
							<button popovertarget={id} popovertargetaction="hide" onclick={() => stop(hub)}>
								{m.D_SM_SERVER__B_OFFLINE()}
							</button>
						</li>
					{/if}
					<li>
						<button class="text-error" onclick={() => deleteHub(hub)}>
							{m.D_SM_SERVER__B_DELETE()}
						</button>
					</li>
				</ul>
			{/snippet}

			{#snippet empty()}
				<div class="flex h-56 flex-col items-center justify-center gap-4 text-center">
					<LayersIcon size={40} class="opacity-30" />
					<a href="#/hub/create" class="btn btn-primary btn-sm">
						{m.D_SM_SERVER__B_CREATE()}
					</a>
				</div>
			{/snippet}

			{#snippet actions()}
				<div class="flex flex-wrap items-center gap-2">
					<a
						class="btn btn-primary btn-sm"
						class:btn-disabled={selected == undefined}
						href={selected && hubHref(selected)}>
						{m.D_SM_SERVER__IDOK()}
					</a>
					<Button class="btn btn-sm btn-success" onclick={() => start()} disabled={!canStart}>
						{m.D_SM_SERVER__B_ONLINE()}
					</Button>
					<Button class="btn btn-sm btn-warning" onclick={() => stop()} disabled={!canStop}>
						{m.D_SM_SERVER__B_OFFLINE()}
					</Button>
					<button class="btn btn-neutral btn-sm not-dark:btn-soft" disabled={selected == undefined}>
						{m.D_SM_SERVER__B_HUB_STATUS()}
					</button>
					<a href="#/hub/create" class="btn btn-neutral btn-sm not-dark:btn-soft">
						{m.D_SM_SERVER__B_CREATE()}
					</a>
					<button class="btn btn-neutral btn-sm not-dark:btn-soft" disabled={selected == undefined}>
						{m.D_SM_SERVER__B_EDIT()}
					</button>
					<Button
						class="btn btn-error btn-sm"
						onclick={() => deleteHub()}
						disabled={selected == undefined}>
						{m.D_SM_SERVER__B_DELETE()}
					</Button>
					{#if query.isFetching}
						<span class="loading loading-xs loading-spinner opacity-60"></span>
					{/if}
				</div>
			{/snippet}
		</DataTable>
	</div>
</div>
