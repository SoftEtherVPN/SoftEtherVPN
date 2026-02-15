<script lang="ts">
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import {
		Dialog,
		DialogClose,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import { Input } from '$lib/components/ui/input';
	import { m } from '$lib/paraglide/messages';
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
			await client.invalidateQueries({ queryKey: ['listener'] });
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

<Dialog bind:open>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>{m.D_SM_CREATE_LISTENER__CAPTION()}</DialogTitle>
			<DialogDescription>
				{m.D_SM_CREATE_LISTENER__STATIC1()}
			</DialogDescription>
		</DialogHeader>
		<div>
			<div class="flex w-full items-center justify-center gap-2">
				{m.D_SM_CREATE_LISTENER__STATIC3()}
				<Input min={1} max={65535} bind:value={createValue} type="number" class="w-24" />
				{m.D_SM_CREATE_LISTENER__STATIC4()}
			</div>
			<Alert class="mt-6">
				<InfoIcon />
				<AlertDescription>
					{m.D_SM_CREATE_LISTENER__STATIC2()}
				</AlertDescription>
			</Alert>
		</div>
		<DialogFooter>
			<Button onclick={mutate} disabled={!isValidValue}>
				{m.D_SM_CREATE_LISTENER__IDOK()}
			</Button>
			<DialogClose class={buttonVariants({ variant: 'outline' })}>
				{m.D_SM_CREATE_LISTENER__IDCANCEL()}
			</DialogClose>
		</DialogFooter>
	</DialogContent>
</Dialog>
