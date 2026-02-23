<script lang="ts">
	import Button from '$lib/components/button.svelte';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnEtherIpId, VpnRpcEnumHubItem } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import AddDetail from './add-detail.svelte';

	interface Props {
		show: boolean;
		hubs: VpnRpcEnumHubItem[];
	}

	let { show, hubs }: Props = $props();
	const client = useQueryClient();

	const etherIpQuery = createQuery(() => ({
		queryKey: ['ipsec', 'detail'],
		queryFn: async () => (await rpc.EnumEtherIpId()).Settings,
		initialData: [] as VpnEtherIpId[]
	}));

	// ── EtherIP detail table selection ────────────────────────────────────────

	let selectedId = $state<string | undefined>(undefined);
	let addModalOpen = $state(false);

	function selectEntry(id: string) {
		selectedId = selectedId === id ? undefined : id;
	}

	// ── Delete EtherIP entry ──────────────────────────────────────────────────

	const deleteMutation = createMutation(() => ({
		mutationFn: (data: VpnEtherIpId) => rpc.DeleteEtherIpId(data),
		onSuccess: async () => {
			selectedId = undefined;
			await client.invalidateQueries({ queryKey: ['ipsec', 'detail'] });
		}
	}));

	function deleteEntry() {
		if (!selectedId) return;
		const entry = etherIpQuery.data.find((e) => e.Id_str === selectedId);
		if (!entry) return;
		return confirm({ message: entry.Id_str }, () =>
			deleteMutation.mutateAsync(new VpnEtherIpId({ Id_str: entry.Id_str }))
		);
	}
</script>

<div
	id="etherip-detail-card"
	class="card mt-6 bg-base-100 shadow dark:bg-base-300"
	class:hidden={!show}>
	<div class="card-body">
		<!-- Header row -->
		<h2 class="card-title">{m.D_SM_ETHERIP__S_TITLE()}</h2>
		<p class="text-sm opacity-70">{m.D_SM_ETHERIP__S01()}</p>

		<p class="text-sm font-medium">{m.D_SM_ETHERIP__S_BOLD()}</p>
		<!-- Table -->
		<div class="overflow-x-auto">
			<table class="table table-sm">
				<thead>
					<tr>
						<th>{m.SM_ETHERIP_COLUMN_0()}</th>
						<th>{m.SM_ETHERIP_COLUMN_1()}</th>
						<th>{m.SM_ETHERIP_COLUMN_2()}</th>
					</tr>
				</thead>
				<tbody>
					{#each etherIpQuery.data as entry (entry.Id_str)}
						<tr
							class={selectedId === entry.Id_str
								? 'cursor-pointer bg-primary/10 hover:bg-base-200'
								: 'cursor-pointer hover:bg-base-200'}
							onclick={() => selectEntry(entry.Id_str)}>
							<td class="font-mono">{entry.Id_str}</td>
							<td>{entry.HubName_str}</td>
							<td>{entry.UserName_str}</td>
						</tr>
					{/each}
					{#if etherIpQuery.data.length === 0}
						<tr>
							<td colspan="3" class="py-4 text-center opacity-50">—</td>
						</tr>
					{/if}
				</tbody>
			</table>
		</div>

		<!-- Delete button -->
		<div class="flex justify-end gap-2">
			<button
				type="button"
				class="btn btn-sm btn-neutral not-dark:btn-soft"
				onclick={() => (addModalOpen = true)}>
				{m.D_SM_ETHERIP__B_ADD()}
			</button>
			<Button
				type="button"
				class="btn btn-outline btn-sm btn-error"
				disabled={!selectedId}
				loading={deleteMutation.isPending}
				onclick={deleteEntry}>
				{m.D_SM_ETHERIP__B_DELETE()}
			</Button>
		</div>
	</div>
</div>

<AddDetail bind:open={addModalOpen} {hubs} />
