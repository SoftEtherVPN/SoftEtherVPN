<script lang="ts">
	import type { HTMLDialogAttributes } from 'svelte/elements';

	const id = $props.id();

	let dialog: HTMLDialogElement;

	let {
		open = $bindable(false),
		children,
		onclose,
		class: classValue,
		...rest
	}: HTMLDialogAttributes = $props();

	$effect(() => {
		if (open && !dialog.open) dialog.showModal();
		if (!open && dialog.open) dialog.requestClose();
	});

	const closeHandler: HTMLDialogAttributes['onclose'] = (e) => {
		open = false;
		onclose?.(e);
	};
</script>

<dialog {id} bind:this={dialog} onclose={closeHandler} class={['modal', classValue]} {...rest}>
	<div class="modal-box">
		{@render children?.()}
	</div>
	<form method="dialog" class="modal-backdrop">
		<button>close</button>
	</form>
</dialog>
