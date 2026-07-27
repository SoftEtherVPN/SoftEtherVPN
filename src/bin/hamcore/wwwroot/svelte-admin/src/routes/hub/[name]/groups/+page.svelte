<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createQuery } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcEnumGroup, VpnRpcEnumGroupItem } from '$lib/rpc';
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';

	let { params }: PageProps = $props();

	const query = createQuery(() => ({
		queryKey: ['hub', params.name, 'groups'],
		queryFn: ({ queryKey }) => rpc.EnumGroup(new VpnRpcEnumGroup({ HubName_str: queryKey[1] })),
		initialData: new VpnRpcEnumGroup()
	}));

	let selectedKey = $state<string | undefined>(undefined);
	let selected = $derived(
		selectedKey ? query.data.GroupList.find((r) => r.Name_str == selectedKey) : undefined
	);

	function groupHref(group: string) {
		return resolve('/hub/[name]/groups/[group]', { name: params.name, group });
	}

	let editHref = $derived(selected ? groupHref(selected.Name_str) : undefined);

	function select(row: VpnRpcEnumGroupItem) {
		if (selected?.Name_str == row.Name_str) selectedKey = undefined;
		else selectedKey = row.Name_str;
	}

	function refresh() {
		query.refetch();
	}
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto] p-4">
	<div>
		<h2 class="text-xl font-bold">{m.D_SM_GROUP__CAPTION()}</h2>
		<span class="text-sm font-light">{m.D_SM_GROUP__S_TITLE({ input0: params.name })}</span>
	</div>

	<div class="max-h-[75vh] overflow-auto">
		<table class="table-pin-rows table">
			<thead>
				<tr>
					<th>{m.SM_GROUPLIST_NAME()}</th>
					<th>{m.SM_GROUPLIST_REALNAME()}</th>
					<th>{m.SM_GROUPLIST_NOTE()}</th>
					<th>{m.SM_GROUPLIST_NUMUSERS()}</th>
				</tr>
			</thead>
			<tbody>
				{#each query.data.GroupList as group (group.Name_str)}
					<tr
						class={{ 'bg-base-300 dark:bg-base-100': selected?.Name_str == group.Name_str }}
						onclick={() => select(group)}
						ondblclick={() => goto(groupHref(group.Name_str))}>
						<td>{group.Name_str}</td>
						<td>{group.Realname_utf}</td>
						<td>{group.Note_utf}</td>
						<td>{group.NumUsers_u32}</td>
					</tr>
				{/each}
			</tbody>
		</table>
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
		<button disabled={!selected} class="btn btn-error btn-sm">{m.D_SM_USER__B_DELETE()}</button>
		<button class="btn btn-sm" onclick={refresh}>{m.D_SM_GROUP__B_REFRESH()}</button>
		<button disabled={!selected} class="btn btn-neutral btn-sm">{m.D_SM_GROUP__B_USER()}</button>
	</div>
</div>
