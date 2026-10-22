<script lang="ts">
	import Button from '$lib/components/ui/button.svelte';
	import Modal from '$lib/components/ui/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, Util_Base64_Decode, VpnRpcMsg } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import ClipboardListIcon from '@lucide/svelte/icons/clipboard-list';
	import InfoIcon from '@lucide/svelte/icons/info';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';

	interface Props {
		open: boolean;
		hub: string;
	}

	const id = $props.id();
	let { open = $bindable(), hub }: Props = $props();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.message(hub),
		queryFn: () => rpc.GetHubMsg(new VpnRpcMsg({ HubName_str: hub })),
		enabled: open
	}));

	const mutation = createMutation(() => ({
		mutationFn: rpc.SetHubMsg,
		onSuccess: () => {
			client.invalidateQueries({ queryKey: hubKeys.message(hub) });
			open = false;
		}
	}));

	let checked = $state(false);
	let value = $state('');

	const decoder = new TextDecoder();
	$effect(() => {
		if (!open || !query.isSuccess || !query.data) return;
		const bin = query.data.Msg_bin;
		const canDecode = bin != undefined && bin.length != 0;
		const unicodeStr = canDecode ? decoder.decode(Util_Base64_Decode(bin)) : '';
		checked = unicodeStr.length != 0;
		value = unicodeStr;
	});

	const encoder = new TextEncoder();
	function submit() {
		var body = new VpnRpcMsg({
			HubName_str: hub,
			Msg_bin: checked ? encoder.encode(value) : new Uint8Array()
		});
		return mutation.mutateAsync(body);
	}
</script>

<Modal {id} class="*:first:max-w-2xl" bind:open>
	<div class="mb-3 flex items-center gap-2">
		<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
			<ClipboardListIcon size={18} />
		</span>
		<h3 class="text-lg font-semibold">{m.D_SM_MSG__CAPTION()}</h3>
		{#if query.isFetching}
			<span class="loading loading-xs loading-spinner opacity-60"></span>
		{/if}
	</div>
	<p>{m.D_SM_MSG__S_MSG_2({ input0: hub })}</p>
	<label class="my-2 label">
		<input type="checkbox" class="toggle toggle-primary toggle-sm" bind:checked />
		{m.D_SM_MSG__C_USEMSG()}
	</label>
	<div>
		<textarea disabled={!checked} class="textarea w-full" rows="15" bind:value></textarea>
	</div>
	<div class="my-4 alert alert-soft alert-info">
		<InfoIcon size={18} />
		<div>
			<h5 class="font-bold">{m.D_SM_MSG__STATIC1()}</h5>
			<p>{m.D_SM_MSG__S_INFO()}</p>
		</div>
	</div>
	<div class="flex justify-end gap-2">
		<Button class="btn btn-primary btn-sm" onclick={submit}>{m.D_SM_MSG__IDOK()}</Button>
		<button command="request-close" commandfor={id} class="btn btn-secondary btn-sm">
			{m.D_SM_MSG__IDCANCEL()}
		</button>
	</div>
</Modal>
