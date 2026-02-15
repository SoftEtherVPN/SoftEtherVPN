<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLDivElement>> = $props();
</script>

<div
	bind:this={ref}
	role="list"
	data-slot="item-group"
	class={cn("group/item-group flex flex-col", className)}
	{...restProps}
>
	{@render children?.()}
</div>
