<script lang="ts">
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import { Dialog, DialogClose, DialogContent, DialogFooter } from '$lib/components/ui/dialog';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnRpcListener } from '$lib/rpc';
	import { createMutation, useQueryClient } from '@tanstack/svelte-query';

	interface Props {
		open: boolean;
		port: number;
	}

	let { open = $bindable(), port }: Props = $props();

	const client = useQueryClient();
	const deleteListener = createMutation(() => ({
		mutationFn: rpc.DeleteListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: ['listener'] });
			open = false;
		}
	}));

	function mutate() {
		return deleteListener.mutateAsync(new VpnRpcListener({ Port_u32: port, Enable_bool: false }));
	}
</script>

<Dialog bind:open>
	<DialogContent>
		<div>
			<p>{m.CM_DELETE_LISTENER_MSG({ input0: port })}</p>
		</div>
		<DialogFooter>
			<Button onClickPromise={mutate}>{m.SEC_YES()}</Button>
			<DialogClose class={buttonVariants({ variant: 'outline' })}>{m.SEC_NO()}</DialogClose>
		</DialogFooter>
	</DialogContent>
</Dialog>
