<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcListener, VpnRpcListenerListItem } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import CreateListener from './create-listener.svelte';
	import Button from '$lib/components/button.svelte';

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: [dashboardKey, 'listener'],
		queryFn: async () => (await rpc.EnumListener()).ListenerList,
		initialData: []
	}));

	let selectedKey = $state<number | undefined>(undefined);
	let selected = $derived(
		selectedKey ? query.data.find((r) => r.Ports_u32 == selectedKey) : undefined
	);

	function select(row: VpnRpcListenerListItem) {
		if (selected?.Ports_u32 == row.Ports_u32) selectedKey = undefined;
		else selectedKey = row.Ports_u32;
	}

	let createOpen = $state(false);
	let canStart = $derived(selected != null && !selected.Enables_bool);
	let canStop = $derived(selected != null && selected.Enables_bool);

	const toggleListener = createMutation(() => ({
		mutationFn: rpc.EnableListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'listener'] });
		}
	}));

	const deleteMutation = createMutation(() => ({
		mutationFn: rpc.DeleteListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'listener'] });
		}
	}));

	async function deleteListener() {
		if (selected == undefined) return;
		if (confirm(m.CM_DELETE_LISTENER_MSG({ input0: selected!.Ports_u32 })))
			await deleteMutation.mutateAsync(
				new VpnRpcListener({ Port_u32: selected.Ports_u32, Enable_bool: false })
			);
	}

	function start() {
		return toggleListener.mutateAsync(
			new VpnRpcListener({ Port_u32: selected?.Ports_u32, Enable_bool: true })
		);
	}

	async function stop() {
		if (selected == undefined) return;
		if (confirm(m.CM_STOP_LISTENER_MSG({ input0: selected!.Ports_u32 })))
			await toggleListener.mutateAsync(
				new VpnRpcListener({ Port_u32: selected!.Ports_u32, Enable_bool: false })
			);
	}
</script>

<div class="card bg-base-300">
	<div class="card-body gap-3 p-4">
		<p class="font-semibold">{m.D_SM_SERVER__STATIC1()}</p>
		<p class="text-sm opacity-70">{m.D_SM_SERVER__STATIC2()}</p>
		<div class="flex gap-3">
			<div class="flex-1 overflow-x-auto">
				<table class="table table-xs">
					<thead>
						<tr>
							<th>{m.CM_LISTENER_COLUMN_1()}</th>
							<th>{m.CM_LISTENER_COLUMN_2()}</th>
						</tr>
					</thead>
					<tbody>
						{#each query.data as l (l.Ports_u32)}
							<tr
								class:bg-base-100={selected?.Ports_u32 == l.Ports_u32}
								class="hover:bg-base-100"
								onclick={() => select(l)}>
								<td>TCP {l.Ports_u32}</td>
								<td>
									{#if l.Enables_bool}
										<span class="text-xs font-medium text-success">
											{m.CM_LISTENER_ONLINE()}
										</span>
									{:else if l.Errors_bool}
										<span class="text-xs font-medium text-error">
											{m.CM_LISTENER_ERROR()}
										</span>
									{:else}
										<span class="text-xs font-medium text-warning">
											{m.CM_LISTENER_OFFLINE()}
										</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<div class="flex flex-col gap-2">
				<Button
					class="btn w-20 btn-sm btn-neutral not-dark:btn-soft"
					onclick={() => (createOpen = true)}>
					{m.D_SM_SERVER__B_CREATE_LISTENER()}
				</Button>
				<Button
					disabled={selected == undefined}
					class="btn w-20 btn-sm btn-neutral not-dark:btn-soft"
					onclick={deleteListener}>
					{m.D_SM_SERVER__B_DELETE_LISTENER()}
				</Button>
				<Button
					disabled={!canStart}
					onclick={start}
					class="btn w-20 btn-sm btn-neutral not-dark:btn-soft">
					{m.D_SM_SERVER__B_START()}
				</Button>
				<Button
					disabled={!canStop}
					onclick={stop}
					class="btn w-20 btn-sm btn-neutral not-dark:btn-soft">
					{m.D_SM_SERVER__B_STOP()}
				</Button>
			</div>
		</div>
	</div>
</div>

<CreateListener bind:open={createOpen} />
