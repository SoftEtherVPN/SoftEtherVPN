<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcListener } from '$lib/rpc';
	import InfoIcon from '@lucide/svelte/icons/info';
	import { createMutation, useQueryClient } from '@tanstack/svelte-query';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	const client = useQueryClient();
	const createListener = createMutation(() => ({
		mutationFn: rpc.CreateListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'listener'] });
			open = false;
		}
	}));

	function mutate() {
		return createListener.mutateAsync(
			new VpnRpcListener({ Port_u32: valueParsed, Enable_bool: true })
		);
	}

	let createValue = $state('');
	let valueParsed = $derived(parseInt(createValue));
	let isValidValue = $derived(!isNaN(valueParsed) && 1 <= valueParsed && valueParsed <= 65535);
</script>

<Modal bind:open>
	<h3 class="font-semibold">{m.D_SM_CREATE_LISTENER__CAPTION()}</h3>
	<p class="text-sm">{m.D_SM_CREATE_LISTENER__STATIC1()}</p>

	<div class="my-6 flex w-full items-center justify-center gap-2">
		{m.D_SM_CREATE_LISTENER__STATIC3()}
		<input class="input w-24" min={1} max={65535} bind:value={createValue} type="number" />
		{m.D_SM_CREATE_LISTENER__STATIC4()}
	</div>

	<div role="alert" class="alert alert-info">
		<InfoIcon />
		<span>{m.D_SM_CREATE_LISTENER__STATIC2()}</span>
	</div>

	<div class="modal-action">
		<button class="btn" onclick={mutate} disabled={!isValidValue}>
			{m.D_SM_CREATE_LISTENER__IDOK()}
		</button>
		<form method="dialog">
			<button class="btn btn-outline">
				{m.D_SM_CREATE_LISTENER__IDCANCEL()}
			</button>
		</form>
	</div>
</Modal>
