<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { serverKeys } from '$lib/queryKeys';
	import { rpc, VpnRpcListener, VpnRpcListenerListItem } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import CreateListener from './create-listener.svelte';
	import Button from '$lib/components/button.svelte';
	import DataTable, { type DataTableColumn } from '$lib/components/data-table.svelte';
	import { confirm } from '$lib/components/confirm-dialog.svelte';

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: serverKeys.listeners(),
		queryFn: async () => (await rpc.EnumListener()).ListenerList,
		initialData: []
	}));

	let selectedKey = $state<string | number | undefined>(undefined);
	let selected = $derived(query.data.find((r) => r.Ports_u32 === selectedKey));

	const columns: DataTableColumn<VpnRpcListenerListItem>[] = $derived([
		{
			header: m.CM_LISTENER_COLUMN_1(),
			value: (l) => `TCP ${l.Ports_u32}`,
			sortBy: 'Ports_u32',
			primary: true
		},
		{ header: m.CM_LISTENER_COLUMN_2(), cell: statusCell, sortBy: 'Enables_bool' }
	]);

	let createOpen = $state(false);
	let canStart = $derived(selected != null && !selected.Enables_bool);
	let canStop = $derived(selected != null && selected.Enables_bool);

	const toggleListener = createMutation(() => ({
		mutationFn: rpc.EnableListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: serverKeys.listeners() });
		}
	}));

	const deleteMutation = createMutation(() => ({
		mutationFn: rpc.DeleteListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: serverKeys.listeners() });
		}
	}));

	function deleteListener() {
		if (selected == undefined) return;
		return confirm({ message: m.CM_DELETE_LISTENER_MSG({ input0: selected!.Ports_u32 }) }, () =>
			deleteMutation.mutateAsync(
				new VpnRpcListener({ Port_u32: selected!.Ports_u32, Enable_bool: false })
			)
		);
	}

	function start() {
		return toggleListener.mutateAsync(
			new VpnRpcListener({ Port_u32: selected?.Ports_u32, Enable_bool: true })
		);
	}

	function stop() {
		if (selected == undefined) return;
		return confirm({ message: m.CM_STOP_LISTENER_MSG({ input0: selected!.Ports_u32 }) }, () =>
			toggleListener.mutateAsync(
				new VpnRpcListener({ Port_u32: selected!.Ports_u32, Enable_bool: false })
			)
		);
	}
</script>

{#snippet statusCell(l: VpnRpcListenerListItem)}
	{#if l.Enables_bool}
		<span class="text-xs font-medium text-success">{m.CM_LISTENER_ONLINE()}</span>
	{:else if l.Errors_bool}
		<span class="text-xs font-medium text-error">{m.CM_LISTENER_ERROR()}</span>
	{:else}
		<span class="text-xs font-medium text-warning">{m.CM_LISTENER_OFFLINE()}</span>
	{/if}
{/snippet}

<div class="card border border-base-300 bg-base-100">
	<div class="card-body gap-3 p-4">
		<p class="font-semibold">{m.D_SM_SERVER__STATIC1()}</p>
		<p class="text-sm opacity-70">{m.D_SM_SERVER__STATIC2()}</p>
		<div class="flex gap-3">
			<div class="flex-1">
				<DataTable
					rows={query.data}
					{columns}
					rowKey={(l) => l.Ports_u32}
					bind:selectedKey
					loading={query.isFetching && query.data.length === 0}
					tableClass="table-xs"
					skeletonRows={3} />
			</div>
			<div class="flex flex-col gap-2">
				<Button
					class="btn w-20 btn-neutral btn-sm not-dark:btn-soft"
					onclick={() => (createOpen = true)}>
					{m.D_SM_SERVER__B_CREATE_LISTENER()}
				</Button>
				<Button
					disabled={selected == undefined}
					class="btn w-20 btn-error btn-sm not-dark:btn-soft"
					onclick={deleteListener}>
					{m.D_SM_SERVER__B_DELETE_LISTENER()}
				</Button>
				<Button
					disabled={!canStart}
					onclick={start}
					class="btn w-20 btn-sm btn-success not-dark:btn-soft">
					{m.D_SM_SERVER__B_START()}
				</Button>
				<Button
					disabled={!canStop}
					onclick={stop}
					class="btn w-20 btn-sm btn-warning not-dark:btn-soft">
					{m.D_SM_SERVER__B_STOP()}
				</Button>
			</div>
		</div>
	</div>
</div>

<CreateListener bind:open={createOpen} />
