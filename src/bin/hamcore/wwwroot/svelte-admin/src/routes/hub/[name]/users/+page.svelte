<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcDeleteUser, VpnRpcEnumUser } from '$lib/rpc';
	import { hubKeys } from '$lib/queryKeys';
	import UserTable from '$lib/components/user-table.svelte';
	import { resolve } from '$app/paths';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import Button from '$lib/components/button.svelte';
	import UserInfo from '$lib/components/user-info.svelte';

	let { params }: PageProps = $props();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.users(params.name),
		queryFn: () => rpc.EnumUser(new VpnRpcEnumUser({ HubName_str: params.name })),
		initialData: new VpnRpcEnumUser()
	}));

	const deleteMutation = createMutation(() => ({
		mutationFn: rpc.DeleteUser,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.users(params.name) });
		}
	}));

	let selectedId = $state<string | undefined>(undefined);
	let selected = $derived(
		selectedId ? query.data.UserList.find((r) => r.Name_str == selectedId) : undefined
	);

	let viewInfoOpen = $state(false);

	function userHref(user: string) {
		return resolve('/hub/[name]/users/[user]', { name: params.name, user });
	}

	let editHref = $derived(selected ? userHref(selected.Name_str) : undefined);

	function deleteUser() {
		if (selected == undefined) return;

		var payload = new VpnRpcDeleteUser({
			HubName_str: params.name,
			Name_str: selected.Name_str
		});
		return confirm({ message: m.SM_USER_DELETE_MSG({ input0: selected.Name_str }) }, () =>
			deleteMutation.mutateAsync(payload)
		);
	}
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto] p-4">
	<div>
		<h2 class="text-xl font-bold">{m.D_SM_USER__CAPTION()}</h2>
		<span class="text-sm font-light">{m.D_SM_USER__S_TITLE({ input0: params.name })}</span>
	</div>

	<div class="max-h-[75vh] overflow-y-auto">
		<UserTable class="rounded-box" hub={params.name} users={query.data.UserList} bind:selectedId />
	</div>

	<div class="mt-4 flex justify-end gap-2">
		<a
			class="btn btn-primary btn-sm"
			href={resolve('/hub/[name]/users/create', { name: params.name })}>
			{m.D_SM_USER__B_CREATE()}
		</a>
		<a class="btn btn-accent btn-sm" class:btn-disabled={!selected} href={editHref}>
			{m.D_SM_USER__IDOK()}
		</a>
		<button
			class="btn btn-neutral btn-sm"
			disabled={!selected}
			onclick={() => (viewInfoOpen = true)}>
			{m.D_SM_USER__B_STATUS()}
		</button>
		<Button class="btn btn-error btn-sm" disabled={!selected} onclick={deleteUser}>
			{m.D_SM_USER__B_DELETE()}
		</Button>
		<button class="btn btn-sm" onclick={() => query.refetch()}>{m.D_SM_USER__B_REFRESH()}</button>
	</div>
</div>

{#if selectedId}
	<UserInfo hub={params.name} name={selectedId} bind:open={viewInfoOpen} />
{/if}
