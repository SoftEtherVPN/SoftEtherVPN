<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createQuery } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcEnumUser } from '$lib/rpc';
	import UserTable from '$lib/components/user-table.svelte';

	let { params }: PageProps = $props();

	const query = createQuery(() => ({
		queryKey: ['hub', params.name, 'users'],
		queryFn: ({ queryKey }) => rpc.EnumUser(new VpnRpcEnumUser({ HubName_str: queryKey[1] })),
		initialData: new VpnRpcEnumUser()
	}));

	let selectedId = $state<string | undefined>(undefined);
	let selected = $derived(
		selectedId ? query.data.UserList.find((r) => r.Name_str == selectedId) : undefined
	);

	function refresh() {
		query.refetch();
	}
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto] p-4">
	<div>
		<h2 class="text-xl font-bold">{m.D_SM_USER__CAPTION()}</h2>
		<span class="text-sm font-light">{m.D_SM_USER__S_TITLE({ input0: params.name })}</span>
	</div>

	<div class="max-h-[75vh] overflow-y-auto">
		<UserTable class="rounded-box" users={query.data.UserList} bind:selectedId />
	</div>

	<div class="mt-4 flex justify-end gap-2">
		<button class="btn btn-primary btn-sm">{m.D_SM_USER__B_CREATE()}</button>
		<button disabled={!selected} class="btn btn-accent btn-sm">{m.D_SM_USER__IDOK()}</button>
		<button disabled={!selected} class="btn btn-neutral btn-sm">{m.D_SM_USER__B_STATUS()}</button>
		<button disabled={!selected} class="btn btn-error btn-sm">{m.D_SM_USER__B_DELETE()}</button>
		<button class="btn btn-sm" onclick={refresh}>{m.D_SM_USER__B_REFRESH()}</button>
	</div>
</div>
