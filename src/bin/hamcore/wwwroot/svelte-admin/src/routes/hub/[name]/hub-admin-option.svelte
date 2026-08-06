<script lang="ts">
	import Modal from '$lib/components/ui/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnRpcAdminOption } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import { createQuery } from '@tanstack/svelte-query';
	import ShieldCogCornerIcon from '@lucide/svelte/icons/shield-cog-corner';
	const id = $props.id();

	interface Props {
		open: boolean;
		hub: string;
	}

	let { open = $bindable(), hub }: Props = $props();

	const query = createQuery(() => ({
		queryKey: hubKeys.admin(hub),
		queryFn: () => rpc.GetHubAdminOptions(new VpnRpcAdminOption({ HubName_str: hub })),
		enabled: open
	}));
</script>

<Modal {id} class="*:first:max-w-2xl" bind:open>
	<div class="mb-3 flex items-center gap-2">
		<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
			<ShieldCogCornerIcon size={18} />
		</span>
		<h3 class="text-lg font-semibold">{m.D_SM_ADMIN_OPTION__CAPTION()}</h3>
		{#if query.isFetching}
			<span class="loading loading-xs loading-spinner opacity-60"></span>
		{/if}
	</div>
	<p>{m.D_SM_ADMIN_OPTION__S_INFO({ input0: hub })}</p>
</Modal>
