<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLParagraphElement>> = $props();
</script>

<p
	bind:this={ref}
	data-slot="field-description"
	class={cn(
		"text-muted-foreground text-sm leading-normal font-normal group-has-[[data-orientation=horizontal]]/field:text-balance",
		"last:mt-0 nth-last-2:-mt-1 [[data-variant=legend]+&]:-mt-1.5",
		"[&>a:hover]:text-primary [&>a]:underline [&>a]:underline-offset-4",
		className
	)}
	{...restProps}
>
	{@render children?.()}
</p>
