<script lang="ts">
	import type { Attachment } from 'svelte/attachments';
	import type { HTMLDialogAttributes } from 'svelte/elements';

	const id = $props.id();

	let {
		open = $bindable(false),
		children,
		onclose,
		class: classValue,
		...rest
	}: HTMLDialogAttributes = $props();

	const attachment: Attachment<HTMLDialogElement> = (dialog) => {
		$effect(() => {
			if (open && !dialog.open) dialog.showModal();
			if (!open && dialog.open) dialog.requestClose();
		});
	};

	const closeHandler: HTMLDialogAttributes['onclose'] = (e) => {
		open = false;
		onclose?.(e);
	};
</script>

<dialog {id} {@attach attachment} onclose={closeHandler} class={['modal', classValue]} {...rest}>
	<div class="modal-box">
		{@render children?.()}
	</div>
	<form method="dialog" class="modal-backdrop">
		<button>close</button>
	</form>
</dialog>
