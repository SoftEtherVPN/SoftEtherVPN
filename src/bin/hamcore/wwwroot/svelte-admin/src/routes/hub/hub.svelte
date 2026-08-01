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
	import { resolve } from '$app/paths';
	import LayersIcon from '@lucide/svelte/icons/layers';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis-vertical';

	const locale = getLocale();
	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.list(),
		queryFn: async () => (await rpc.EnumHub()).HubList,
		initialData: []
	}));

	let showSkeleton = $derived(query.isFetching && query.data.length === 0);
	let showEmpty = $derived(!query.isFetching && query.data.length === 0);

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
			await client.invalidateQueries({ queryKey: hubKeys.all });
		}
	}));

	const deleteHubMutation = createMutation(() => ({
		mutationFn: rpc.DeleteHub,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.all });
		}
	}));

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
</script>

<!-- Per-row actions menu, shared between the desktop table and the mobile cards -->
{#snippet actionsMenu(hub: VpnRpcEnumHubItem, id: string)}
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
			<a href={resolve('/hub/[name]', { name: hub.HubName_str })}>
				{m.D_SM_SERVER__IDOK()}
			</a>
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

<!-- Virtual Hub Table -->
<div class="card border border-base-300 bg-base-100">
	<div class="card-body gap-4 p-4">
		{#if showEmpty}
			<!-- Empty state: no hubs yet, offer to create one -->
			<div class="flex h-56 flex-col items-center justify-center gap-4 text-center">
				<LayersIcon size={40} class="opacity-30" />
				<a href="#/hub/create" class="btn btn-primary btn-sm">
					{m.D_SM_SERVER__B_CREATE()}
				</a>
			</div>
		{:else}
			<!-- Desktop: full table -->
			<div class="hidden h-56 overflow-x-auto sm:block">
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
							<th class="w-10"></th>
						</tr>
					</thead>
					<tbody>
						{#if showSkeleton}
							{#each Array.from({ length: 4 }) as _, i (i)}
								<tr>
									<td colspan="14">
										<div class="h-5 w-full skeleton"></div>
									</td>
								</tr>
							{/each}
						{:else}
							{#each query.data as hub, i (hub.HubName_str)}
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
									class="hover:bg-base-300"
									class:bg-base-200={selected?.HubName_str == hub.HubName_str}
									onclick={() => select(hub)}>
									<td class="font-medium">{hub.HubName_str}</td>
									<td>
										<span
											class={['badge badge-sm', hub.Online_bool ? 'badge-success' : 'badge-error']}>
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
									<td class="text-end">
										{@render actionsMenu(hub, `hub-actions-${i}`)}
									</td>
								</tr>
							{/each}
						{/if}
					</tbody>
				</table>
			</div>

			<!-- Mobile: stacked cards -->
			<div class="flex flex-col gap-2 sm:hidden">
				{#if showSkeleton}
					{#each Array.from({ length: 3 }) as _, i (i)}
						<div class="h-28 w-full skeleton"></div>
					{/each}
				{:else}
					{#each query.data as hub, i (hub.HubName_str)}
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
						<div
							role="button"
							tabindex="0"
							class={[
								'rounded-box border p-3',
								selected?.HubName_str == hub.HubName_str
									? 'border-primary bg-base-200'
									: 'border-base-300'
							]}
							onclick={() => select(hub)}
							onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && select(hub)}>
							<div class="flex items-center justify-between gap-2">
								<div class="flex items-center gap-2">
									<span class="font-medium">{hub.HubName_str}</span>
									<span
										class={['badge badge-sm', hub.Online_bool ? 'badge-success' : 'badge-error']}>
										{translateHubOnline(hub.Online_bool)}
									</span>
								</div>
								{@render actionsMenu(hub, `hub-actions-m-${i}`)}
							</div>
							<div class="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_3()}</span>
									<br />
									{translateHubType(hub.HubType_u32)}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_4()}</span>
									<br />
									{hub.NumUsers_u32}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_5()}</span>
									<br />
									{hub.NumGroups_u32}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_6()}</span>
									<br />
									{hub.NumSessions_u32}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_7()}</span>
									<br />
									{hub.NumMacTables_u32}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_8()}</span>
									<br />
									{hub.NumIpTables_u32}
								</div>
								<div>
									<span class="opacity-60">{m.SM_HUB_COLUMN_9()}</span>
									<br />
									{hub.NumLogin_u32}
								</div>
								<div class="tabular-nums">
									<span class="opacity-60">{m.SM_SESS_COLUMN_6()}</span>
									<br />
									{number(locale, transferBytes)}
								</div>
								<div class="col-span-2 tabular-nums">
									<span class="opacity-60">{m.SM_SESS_COLUMN_7()}</span>
									<br />
									{number(locale, transferPackets)}
								</div>
								<div class="col-span-2">
									<span class="opacity-60">{m.SM_HUB_COLUMN_10()}</span>
									<br />
									{datetime(locale, hub.LastLoginTime_dt, {
										dateStyle: 'medium',
										timeStyle: 'medium'
									})}
								</div>
								<div class="col-span-2">
									<span class="opacity-60">{m.SM_HUB_COLUMN_11()}</span>
									<br />
									{datetime(locale, hub.LastCommTime_dt, {
										dateStyle: 'medium',
										timeStyle: 'medium'
									})}
								</div>
							</div>
						</div>
					{/each}
				{/if}
			</div>
		{/if}

		<!-- Hub action buttons -->
		<div class="flex flex-wrap items-center gap-2">
			<a
				class="btn btn-primary btn-sm"
				class:btn-disabled={selected == undefined}
				href={selected && resolve('/hub/[name]', { name: selected.HubName_str })}>
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
	</div>
</div>
