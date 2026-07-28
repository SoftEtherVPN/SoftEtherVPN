<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import UserTable from '$lib/components/user-table.svelte';
	import { rpc, VpnRpcEnumUser } from '$lib/rpc';
	import { createQuery } from '@tanstack/svelte-query';

	interface Props {
		hub: string;
		name?: string;
		open: boolean;
	}

	let { hub, name, open = $bindable() }: Props = $props();

	let selectedId = $state<string | undefined>(undefined);

	const query = createQuery(() => ({
		queryKey: ['hub', hub, 'users'],
		queryFn: ({ queryKey }) => rpc.EnumUser(new VpnRpcEnumUser({ HubName_str: queryKey[1] })),
		select: (d) => d.UserList.filter((u) => u.GroupName_str == name),
		enabled: !!name && open
	}));
</script>

<Modal class="*:first:max-w-2xl" bind:open>
	<div class="overflow-x-auto">
		{#if query.isSuccess}
			<UserTable class="table-zebra table-sm" users={query.data} bind:selectedId />
		{/if}
	</div>
</Modal>
