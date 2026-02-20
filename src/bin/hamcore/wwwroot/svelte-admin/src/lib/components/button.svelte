<script lang="ts">
	import type { HTMLButtonAttributes } from 'svelte/elements';

	interface Props extends HTMLButtonAttributes {
		loading?: boolean;
	}

	let {
		loading = $bindable(false),
		onclick,
		children,
		disabled: disable,
		...rest
	}: Props = $props();

	let disabled = $derived(disable || loading);

	const onclickHandler: HTMLButtonAttributes['onclick'] = async (e) => {
		try {
			loading = true;
			let r = onclick?.(e);
			await Promise.resolve(r);
			return r;
		} finally {
			loading = false;
		}
	};
</script>

<button {disabled} onclick={onclickHandler} {...rest}>
	{#if loading}
		<span class="loading loading-spinner"></span>
	{/if}
	{@render children?.()}
</button>
