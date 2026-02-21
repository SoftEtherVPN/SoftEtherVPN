<script lang="ts" module>
	import type { Component } from 'svelte';
	import InfoIcon from '@lucide/svelte/icons/info';

	interface MessageProps {
		message: string;
		title?: string;
		icon?: Component;
	}

	interface MessageState extends MessageProps {
		callback: () => PromiseLike<unknown> | unknown;
		resolver: PromiseWithResolvers<boolean>;
	}

	const noop = () => {};

	let dialogState = $state<MessageState>({
		message: '',
		callback: noop,
		resolver: Promise.withResolvers()
	});
	let open = $state(false);

	export function confirm(
		props: MessageProps,
		onsuccess: () => Promise<unknown>
	): Promise<boolean> {
		dialogState = {
			...props,
			callback: onsuccess,
			resolver: Promise.withResolvers()
		};
		open = true;
		return dialogState.resolver.promise;
	}
</script>

<script lang="ts">
	import Modal from './modal.svelte';
	import Button from './button.svelte';
	import { m } from '$lib/paraglide/messages';

	const id = $props.id();

	let Icon = $derived(dialogState.icon ?? InfoIcon);

	const close = async (v: boolean) => {
		if (v) {
			try {
				if (dialogState.callback) {
					let r = dialogState.callback();
					await Promise.resolve(r);
				}
				dialogState.resolver.resolve(true);
			} catch (ex) {
				dialogState.resolver.reject(ex);
			}
		} else {
			dialogState.resolver.resolve(false);
		}

		open = false;
	};
</script>

<Modal
	{id}
	role="alertdialog"
	aria-labelledby="{id}-title"
	aria-describedby="{id}-desc"
	bind:open
	onclose={() => close(false)}>
	<div class="flex gap-3">
		<Icon size={20} class="mt-0.5 shrink-0 text-warning" />
		<div class="flex flex-col gap-1.5">
			<p id="{id}-title" class="font-semibold">{dialogState.title ?? m.PRODUCT_NAME_VPN_SMGR()}</p>
			<p id="{id}-desc" class="text-sm opacity-75">{dialogState.message}</p>
		</div>
	</div>
	<div class="modal-action mt-4">
		<button class="btn btn-outline btn-sm" onclick={() => close(false)}>{m.SEC_NO()}</button>
		<Button class="btn btn-sm btn-error" onclick={() => close(true)}>{m.SEC_YES()}</Button>
	</div>
</Modal>
