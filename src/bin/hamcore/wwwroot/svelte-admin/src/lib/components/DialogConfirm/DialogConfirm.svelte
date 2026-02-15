<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { Button, buttonVariants } from '../ui/button';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '../ui/dialog';
	import DialogClose from '../ui/dialog/dialog-close.svelte';
	import { getState } from './dialog-confirm-state.svelte';

	let state = getState();

	const getOpen = () => true;

	async function setOpen(r: boolean) {
		if (r) return;
		state.resolve(r);
	}
</script>

{#if state.props}
	<Dialog bind:open={getOpen, setOpen}>
		<DialogContent>
			<DialogHeader>
				{#if state.props.title}
					<DialogTitle>{state.props.title}</DialogTitle>
				{/if}
				<DialogDescription>{state.props.message}</DialogDescription>
			</DialogHeader>
			<DialogFooter>
				<DialogClose class={buttonVariants({ variant: 'outline' })}>{m.SEC_NO()}</DialogClose>
				<Button onclick={() => state.resolve(true)}>{m.SEC_YES()}</Button>
			</DialogFooter>
		</DialogContent>
	</Dialog>
{/if}
