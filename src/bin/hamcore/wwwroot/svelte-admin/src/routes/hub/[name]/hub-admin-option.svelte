<script lang="ts">
	import Modal from '$lib/components/ui/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnAdminOption, VpnRpcAdminOption } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import ShieldCogCornerIcon from '@lucide/svelte/icons/shield-cog-corner';
	import InfoIcon from '@lucide/svelte/icons/info';
	import Button from '$lib/components/ui/button.svelte';
	const id = $props.id();

	interface Props {
		open: boolean;
		hub: string;
	}

	let { open = $bindable(), hub }: Props = $props();
	let selected = $state<VpnAdminOption>();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.admin(hub),
		queryFn: () => rpc.GetHubAdminOptions(new VpnRpcAdminOption({ HubName_str: hub })),
		enabled: open,
		initialData: new VpnRpcAdminOption()
	}));

	const mutation = createMutation(() => ({
		mutationFn: rpc.SetHubAdminOptions,
		onSuccess: () => {
			client.invalidateQueries({ queryKey: hubKeys.message(hub) });
			open = false;
		}
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
	<div class="mt-4 grid grid-cols-2 gap-2">
		<select class="select" bind:value={selected}>
			{#each query.data.AdminOptionList as option (option.Name_str)}
				<option value={option}>{option.Name_str} - {option.Value_u32}</option>
			{/each}
		</select>
		{#if selected}
			<input class="input" type="number" bind:value={selected.Value_u32} />
		{/if}
	</div>
	{#if selected}
		<div class="my-4 alert alert-outline">
			<InfoIcon size={32} />
			<div>
				<span class="font-bold">{m.D_SM_ADMIN_OPTION__S_BOLD()}</span>
				<p>{selected.Descrption_utf}</p>
			</div>
		</div>
	{/if}
	<div class="my-4 alert alert-soft alert-info">
		<InfoIcon size={32} />
		<div>
			<p>{m.D_SM_ADMIN_OPTION__STATIC1()}</p>
			<p>{m.D_SM_ADMIN_OPTION__STATIC2()}</p>
		</div>
	</div>
	<div class="flex justify-end gap-2">
		<Button
			class="btn btn-primary btn-sm"
			disabled={!query.isSuccess}
			onclick={() => mutation.mutateAsync(query.data)}>
			{m.D_SM_ADMIN_OPTION__IDOK()}
		</Button>
		<button command="request-close" commandfor={id} class="btn btn-secondary btn-sm">
			{m.D_SM_ADMIN_OPTION__IDCANCEL()}
		</button>
	</div>
</Modal>
