<script lang="ts">
	import Button from '$lib/components/button.svelte';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnEtherIpId, VpnRpcEnumHubItem } from '$lib/rpc';
	import { ipsecKeys } from '$lib/queryKeys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import AddDetail from './add-detail.svelte';
	import DataTable, { type DataTableColumn } from '$lib/components/data-table.svelte';

	interface Props {
		show: boolean;
		hubs: VpnRpcEnumHubItem[];
	}

	let { show, hubs }: Props = $props();
	const client = useQueryClient();

	const etherIpQuery = createQuery(() => ({
		queryKey: ipsecKeys.etherIpIds(),
		queryFn: async () => (await rpc.EnumEtherIpId()).Settings,
		initialData: [] as VpnEtherIpId[]
	}));

	// ── EtherIP detail table selection ────────────────────────────────────────

	let selectedId = $state<string | number | undefined>(undefined);
	let addModalOpen = $state(false);

	const columns: DataTableColumn<VpnEtherIpId>[] = $derived([
		{ header: m.SM_ETHERIP_COLUMN_0(), value: 'Id_str', primary: true, class: 'font-mono' },
		{ header: m.SM_ETHERIP_COLUMN_1(), value: 'HubName_str' },
		{ header: m.SM_ETHERIP_COLUMN_2(), value: 'UserName_str' }
	]);

	// ── Delete EtherIP entry ──────────────────────────────────────────────────

	const deleteMutation = createMutation(() => ({
		mutationFn: (data: VpnEtherIpId) => rpc.DeleteEtherIpId(data),
		onSuccess: async () => {
			selectedId = undefined;
			await client.invalidateQueries({ queryKey: ipsecKeys.etherIpIds() });
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
		<DataTable
			rows={etherIpQuery.data}
			{columns}
			rowKey={(entry) => entry.Id_str}
			bind:selectedKey={selectedId}
			loading={etherIpQuery.isFetching && etherIpQuery.data.length === 0}
			tableClass="table-sm"
			skeletonRows={3} />

		<!-- Delete button -->
		<div class="flex justify-end gap-2">
			<button
				type="button"
				class="btn btn-neutral btn-sm not-dark:btn-soft"
				onclick={() => (addModalOpen = true)}>
				{m.D_SM_ETHERIP__B_ADD()}
			</button>
			<Button
				type="button"
				class="btn btn-outline btn-error btn-sm"
				disabled={!selectedId}
				loading={deleteMutation.isPending}
				onclick={deleteEntry}>
				{m.D_SM_ETHERIP__B_DELETE()}
			</Button>
		</div>
	</div>
</div>

<AddDetail bind:open={addModalOpen} {hubs} />
