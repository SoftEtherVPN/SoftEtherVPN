<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcDeleteUser, VpnRpcEnumGroup, VpnRpcEnumGroupItem } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import MemberList from './member-list.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import DataTable, { type DataTableColumn } from '$lib/components/ui/data-table.svelte';
	import { confirm } from '$lib/components/ui/confirm-dialog.svelte';

	let { params }: PageProps = $props();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.groups(params.name),
		queryFn: () => rpc.EnumGroup(new VpnRpcEnumGroup({ HubName_str: params.name })),
		initialData: new VpnRpcEnumGroup()
	}));

	const deleteMutation = createMutation(() => ({
		mutationFn: rpc.DeleteGroup,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.groups(params.name) });
		}
	}));

	let selectedKey = $state<string | number | undefined>(undefined);
	let selected = $derived(query.data.GroupList.find((r) => r.Name_str === selectedKey));
	let memberListOpen = $state(false);

	const columns: DataTableColumn<VpnRpcEnumGroupItem>[] = $derived([
		{ header: m.SM_GROUPLIST_NAME(), value: 'Name_str', primary: true },
		{ header: m.SM_GROUPLIST_REALNAME(), value: 'Realname_utf' },
		{ header: m.SM_GROUPLIST_NOTE(), value: 'Note_utf', cardSpan: 2 },
		{ header: m.SM_GROUPLIST_NUMUSERS(), value: 'NumUsers_u32' }
	]);

	function groupHref(group: string) {
		return resolve('/hub/[name]/groups/[group]', { name: params.name, group });
	}

	let editHref = $derived(selected ? groupHref(selected.Name_str) : undefined);

	function deleteGroup() {
		if (selected == undefined) return;

		var payload = new VpnRpcDeleteUser({
			HubName_str: params.name,
			Name_str: selected.Name_str
		});
		return confirm({ message: m.SM_GROUP_DELETE_MSG({ input0: selected.Name_str }) }, () =>
			deleteMutation.mutateAsync(payload)
		);
	}
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto] p-4">
	<div>
		<h2 class="text-xl font-bold">{m.D_SM_GROUP__CAPTION()}</h2>
		<span class="text-sm font-light">{m.D_SM_GROUP__S_TITLE({ input0: params.name })}</span>
	</div>

	<div class="max-h-[75vh] overflow-auto">
		<DataTable
			rows={query.data.GroupList}
			{columns}
			rowKey={(group) => group.Name_str}
			bind:selectedKey
			loading={query.isFetching && query.data.GroupList.length === 0}
			rowsPerPage={15}
			searchable
			tableClass="table-pin-rows"
			onrowdblclick={(group) => goto(groupHref(group.Name_str))} />
	</div>

	<div class="flex justify-end gap-2">
		<a
			href={resolve('/hub/[name]/groups/create', { name: params.name })}
			class="btn btn-primary btn-sm">
			{m.D_SM_GROUP__B_CREATE()}
		</a>
		<a
			href={editHref}
			class:btn-disabled={!selected}
			class="btn btn-neutral btn-sm not-dark:btn-soft">
			{m.D_SM_GROUP__IDOK()}
		</a>
		<Button disabled={!selected} onclick={deleteGroup} class="btn btn-error btn-sm">
			{m.D_SM_USER__B_DELETE()}
		</Button>
		<button class="btn btn-sm" onclick={() => query.refetch()}>{m.D_SM_GROUP__B_REFRESH()}</button>
		<button
			disabled={!selected}
			class="btn btn-neutral btn-sm"
			onclick={() => (memberListOpen = true)}>
			{m.D_SM_GROUP__B_USER()}
		</button>
	</div>
</div>

<MemberList hub={params.name} name={selected?.Name_str} bind:open={memberListOpen} />
