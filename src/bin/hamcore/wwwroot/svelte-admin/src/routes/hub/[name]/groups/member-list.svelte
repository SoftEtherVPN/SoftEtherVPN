<script lang="ts">
	import { resolve } from '$app/paths';
	import Button from '$lib/components/button.svelte';
	import { confirm } from '$lib/components/confirm-dialog.svelte';
	import Modal from '$lib/components/modal.svelte';
	import UserInfo from '$lib/components/user-info.svelte';
	import UserTable from '$lib/components/user-table.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnRpcDeleteUser, VpnRpcEnumUser } from '$lib/rpc';
	import { hubKeys } from '$lib/queryKeys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';

	interface Props {
		hub: string;
		name?: string;
		open: boolean;
	}

	let { hub, name, open = $bindable() }: Props = $props();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.users(hub),
		queryFn: () => rpc.EnumUser(new VpnRpcEnumUser({ HubName_str: hub })),
		select: (d) => d.UserList.filter((u) => u.GroupName_str == name),
		initialData: new VpnRpcEnumUser(),
		enabled: !!name && open
	}));

	const deleteMutation = createMutation(() => ({
		mutationFn: rpc.DeleteUser,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.users(hub) });
		}
	}));

	let selectedId = $state<string | undefined>(undefined);
	let selected = $derived(query.data.find((u) => u.Name_str == selectedId));
	let viewInfoOpen = $state(false);

	function userHref(user: string) {
		return resolve('/hub/[name]/users/[user]', { name: hub, user });
	}

	let editHref = $derived(selected ? userHref(selected.Name_str) : undefined);

	function deleteUser() {
		if (selected == undefined) return;

		var payload = new VpnRpcDeleteUser({
			HubName_str: hub,
			Name_str: selected.Name_str
		});
		return confirm({ message: m.SM_USER_DELETE_MSG({ input0: selected.Name_str }) }, () =>
			deleteMutation.mutateAsync(payload)
		);
	}
</script>

<Modal class="*:first:max-w-4xl" bind:open>
	<h3 class="font-semibold">{m.D_SM_USER__CAPTION()}</h3>
	<p class="text-sm">{m.SM_GROUP_MEMBER_STR({ input0: name ?? '' })}</p>
	<div class="overflow-x-auto">
		{#if query.isSuccess}
			<UserTable {hub} class="table-zebra table-sm" users={query.data} bind:selectedId />
		{/if}
	</div>

	<div class="modal-action">
		<a class="btn btn-primary btn-sm" href={resolve('/hub/[name]/users/create', { name: hub })}>
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
</Modal>

{#if selectedId}
	<UserInfo {hub} name={selectedId} bind:open={viewInfoOpen} />
{/if}
